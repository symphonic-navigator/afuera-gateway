/**
 * Sidecar-facing WebSocket uplink: GET /uplink/:uplinkId
 * (docs/specs/ollama-relay.md). Ported behaviourally from ollama-uplink
 * apps/relay/server/src/uplink.ts, with two deliberate changes:
 *
 *  - Sidecars are looked up by the server-assigned uplink UUID in the path
 *    (the original keyed by name); the hello `name` must still equal the
 *    stored uplink name.
 *  - Hardening: a new connection only replaces an established one after it
 *    has PROVEN the PSK (first successfully decrypted frame). A wrong-PSK
 *    connection therefore cannot boot a healthy sidecar off its slot.
 *
 * Hard rule (ollama-uplink AGENTS.md, applies here): prompts/responses are
 * NEVER logged or stored — only connection/operational status.
 */

import {
  decodeMessage,
  deriveSessionKeys,
  encodeMessage,
  generateNonce,
  generateSessionId,
  type Message,
  TunnelSession,
} from "@afuera/ollama-protocol";
import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import { audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import type { UplinkRegistry } from "./registry.js";
import { wsTransport } from "./ws-transport.js";

export const UPLINK_PING_INTERVAL_MS = 30_000;
export const UPLINK_PONG_TIMEOUT_MS = 90_000;
export const UPLINK_HANDSHAKE_TIMEOUT_MS = 10_000;

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
  ollamaRegistry: UplinkRegistry;
}

interface UplinkRow {
  id: string;
  user_id: string;
  name: string;
  psk_hash: string;
}

// decodeMessage only guarantees `kind` is a string; every other field is
// unvalidated, so the hello shape must be checked before any use.
function isHelloShape(msg: Message): msg is Extract<Message, { kind: "hello" }> {
  if (msg.kind !== "hello") return false;
  const hello = msg as { name?: unknown; nonce_s?: unknown; models?: unknown };
  return (
    typeof hello.name === "string" &&
    hello.name.length > 0 &&
    typeof hello.nonce_s === "string" &&
    Array.isArray(hello.models) &&
    hello.models.every((m) => typeof m === "string")
  );
}

function persistModels(db: AppDatabase, uplinkId: string, models: string[]): void {
  db.prepare("UPDATE ollama_uplinks SET models = ?, updated_at = ? WHERE id = ?").run(
    JSON.stringify(models),
    new Date().toISOString(),
    uplinkId,
  );
}

export function ollamaUplinkRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db, ollamaRegistry } = ctx;

  app.get("/uplink/:uplinkId", { websocket: true }, (socket: WebSocket, req) => {
    const { uplinkId } = req.params as { uplinkId: string };
    const row = db
      .prepare("SELECT id, user_id, name, psk_hash FROM ollama_uplinks WHERE id = ?")
      .get(uplinkId) as UplinkRow | undefined;
    if (!row) {
      socket.close();
      return;
    }
    handleConnection(app, db, ollamaRegistry, row, socket, req.ip);
  });
}

function handleConnection(
  app: FastifyInstance,
  db: AppDatabase,
  registry: UplinkRegistry,
  row: UplinkRow,
  ws: WebSocket,
  ip: string | null,
): void {
  const timeout = setTimeout(() => {
    ws.close();
  }, UPLINK_HANDSHAKE_TIMEOUT_MS);
  ws.once("message", (data: Buffer) => {
    clearTimeout(timeout);
    try {
      const hello = decodeMessage(new Uint8Array(data));
      // The hello name must match the stored uplink name — a uniform close,
      // no detail (the same close a wrong PSK produces one frame later).
      if (!isHelloShape(hello) || hello.name !== row.name) {
        ws.close();
        return;
      }
      const nonceR = generateNonce();
      const sessionId = generateSessionId();
      const keys = deriveSessionKeys(
        Buffer.from(row.psk_hash, "hex"),
        Buffer.from(hello.nonce_s, "base64"),
        nonceR,
      );
      ws.send(
        encodeMessage({
          kind: "hello_ack",
          nonce_r: Buffer.from(nonceR).toString("base64"),
          session_id: sessionId,
        }),
      );
      const session = new TunnelSession(wsTransport(ws), keys, sessionId, "relay");

      // The connection is registered (and takes over any previous one) only
      // once the sidecar has proven the PSK with a decryptable frame.
      let registered = false;
      const registerProved = (): void => {
        if (registered) return;
        registered = true;
        const previous = registry.get(row.id);
        if (previous && previous.session !== session) previous.session.close();
        registry.register({
          uplinkId: row.id,
          userId: row.user_id,
          name: row.name,
          connectedAt: new Date().toISOString(),
          models: hello.models,
          session,
        });
        persistModels(db, row.id, hello.models);
        audit(db, "ollama_sidecar_connect", {
          userId: row.user_id,
          metadata: { uplink_id: row.id, name: row.name },
          ip,
        });
        startLiveness(app, ws, session);
      };

      session.onMessage((msg) => {
        registerProved();
        if (msg.kind === "model_update") {
          registry.updateModels(row.id, msg.models);
          persistModels(db, row.id, msg.models);
        }
      });
      session.onRequestOpen(() => {
        // Sidecars never legitimately open requests towards the relay; the
        // frame still counts as PSK proof.
        registerProved();
      });
      session.onClose(() => {
        // A proven reconnect may have replaced this entry; only unregister
        // if the registry still points at this session.
        if (registry.get(row.id)?.session === session) {
          registry.unregister(row.id);
        }
        if (registered) {
          audit(db, "ollama_sidecar_disconnect", {
            userId: row.user_id,
            metadata: { uplink_id: row.id, name: row.name },
            ip,
          });
        }
      });
    } catch {
      ws.close();
    }
  });
  ws.once("error", () => {
    ws.close();
  });
}

// Relay-side liveness: ping on an interval and close the session when no
// inbound frame (pong or otherwise) has arrived within the timeout window.
function startLiveness(app: FastifyInstance, ws: WebSocket, session: TunnelSession): void {
  let lastSeen = Date.now();
  ws.on("message", () => {
    lastSeen = Date.now();
  });
  const timer = setInterval(() => {
    if (Date.now() - lastSeen > UPLINK_PONG_TIMEOUT_MS) {
      app.log.info("ollama sidecar liveness timeout");
      session.close();
      return;
    }
    try {
      session.send({ kind: "ping", ts: Date.now() });
    } catch {
      session.close();
    }
  }, UPLINK_PING_INTERVAL_MS);
  timer.unref();
  session.onClose(() => {
    clearInterval(timer);
  });
}
