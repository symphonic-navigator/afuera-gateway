/**
 * Test sidecar: acts as a real ollama-uplink sidecar against the server's
 * /uplink/<id> WebSocket endpoint — same handshake, same encrypted frames
 * (via @afuera/ollama-protocol), canned/streamed responses like real Ollama.
 */

import { WebSocket } from "ws";
import {
  decodeMessage,
  deriveSessionKeys,
  encodeMessage,
  generateNonce,
  hashPsk,
  type Message,
  type RequestOpenMessage,
  type Responder,
  TunnelSession,
} from "@afuera/ollama-protocol";
import { wsTransport } from "../src/ollama/ws-transport.js";

export interface SidecarRequest {
  msg: RequestOpenMessage;
  responder: Responder;
}

export interface ConnectOptions {
  /** ws://host/uplink/<id> */
  relayUrl: string;
  name: string;
  psk: string;
  models?: string[];
  onRequest?: (msg: RequestOpenMessage, responder: Responder) => void;
}

export class TestSidecar {
  private constructor(
    readonly session: TunnelSession,
    readonly requests: SidecarRequest[],
    readonly cancels: string[],
    readonly closed: Promise<void>,
  ) {}

  /** Full handshake + PSK proof (model_update). Throws if the server closes during the handshake. */
  static async connect(opts: ConnectOptions): Promise<TestSidecar> {
    const ws = new WebSocket(opts.relayUrl);
    const models = opts.models ?? [];
    const nonceS = generateNonce();
    await new Promise<void>((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    });
    ws.send(
      encodeMessage({
        kind: "hello",
        name: opts.name,
        nonce_s: Buffer.from(nonceS).toString("base64"),
        models,
      }),
    );
    const ack = await new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("handshake timeout")), 5_000);
      ws.once("message", (data: Buffer) => {
        clearTimeout(timer);
        try {
          resolve(decodeMessage(new Uint8Array(data)));
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
      ws.once("close", () => {
        clearTimeout(timer);
        reject(new Error("connection closed during handshake"));
      });
      ws.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    if (ack.kind !== "hello_ack") throw new Error("unexpected handshake response");
    const keys = deriveSessionKeys(hashPsk(opts.psk), nonceS, Buffer.from(ack.nonce_r, "base64"));
    const session = new TunnelSession(wsTransport(ws), keys, ack.session_id, "sidecar");
    const requests: SidecarRequest[] = [];
    const cancels: string[] = [];
    session.onRequestOpen((msg, responder) => {
      requests.push({ msg, responder });
      responder.onCancel(() => cancels.push(msg.request_id));
      opts.onRequest?.(msg, responder);
    });
    // Like the real sidecar: the first encrypted frame doubles as PSK proof.
    session.send({ kind: "model_update", models });
    const closed = new Promise<void>((resolve) => session.onClose(resolve));
    return new TestSidecar(session, requests, cancels, closed);
  }

  close(): void {
    this.session.close();
  }
}

/** Open a raw WS, send a hello, and resolve when the server closes the socket. */
export async function connectExpectClose(opts: {
  relayUrl: string;
  name?: string;
  models?: string[];
}): Promise<void> {
  const ws = new WebSocket(opts.relayUrl);
  const closed = new Promise<void>((resolve) => {
    ws.once("close", () => resolve());
    ws.once("error", () => resolve());
  });
  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("close", () => reject(new Error("closed before open")));
    ws.once("error", reject);
  }).catch(() => undefined);
  try {
    ws.send(
      encodeMessage({
        kind: "hello",
        name: opts.name ?? "whatever",
        nonce_s: Buffer.from(generateNonce()).toString("base64"),
        models: opts.models ?? [],
      }),
    );
  } catch {
    // socket already closed — that's the expected outcome anyway
  }
  await closed;
}

/** Poll until `cond` holds (test synchronisation without fixed sleeps). */
export async function waitFor(
  cond: () => boolean | Promise<boolean>,
  timeoutMs = 5_000,
  intervalMs = 10,
): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (await cond()) return;
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}
