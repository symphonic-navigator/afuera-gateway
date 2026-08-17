/**
 * Per-user Ollama relay — business logic #2 (docs/specs/ollama-relay.md).
 *
 * Uplink management (session or agk_ with scope `ollama:manage`) and the
 * client-facing proxy `/ollama/:name/api/*` + `/ollama/:name/v1/*` (session
 * or agk_ with scope `ollama:use`). Unlike the gateway proxy, NO server-side
 * decryption is involved: session keys derive from the stored PSK hash, so
 * session tokens work here and rotate-dek has no interaction.
 *
 * Two identity planes:
 *  - client-facing: (authenticated user_id, name) → uplink row. Name
 *    collisions ACROSS users are fine by design.
 *  - sidecar-facing: uplink UUID in the WS URL + PSK proof (see uplink.ts).
 *
 * Hard rule: request/response payloads are NEVER logged or audited — only
 * operational metadata (uplink name, status).
 */

import { randomBytes, randomUUID } from "node:crypto";
import type { PendingRequest } from "@afuera/ollama-protocol";
import { base64urlEncode } from "@afuera/crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import type { UplinkRegistry } from "../ollama/registry.js";
import { asBody, authGuard, sha256Hex } from "../security.js";

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
  ollamaRegistry: UplinkRegistry;
}

const UPLINK_NAME_RE = /^[a-z0-9-]{2,64}$/;

/** Headers never forwarded into the tunnel (hop-by-hop + auth + framing). */
const REQUEST_HEADER_DENYLIST = new Set([
  "host",
  "authorization",
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "upgrade",
]);

/** Headers never sent back to the client (hop-by-hop, cookies, framing). */
const RESPONSE_HEADER_DENYLIST = new Set([
  "connection",
  "content-encoding",
  "content-length",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "set-cookie",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

interface UplinkRow {
  id: string;
  user_id: string;
  name: string;
  models: string;
  created_at: string;
}

/** wss:// URL the sidecar dials out to (carries the uplink UUID). */
function relayUrl(config: AppConfig, req: FastifyRequest, uplinkId: string): string {
  const base = config.publicBaseUrl;
  if (base) {
    const url = new URL(base);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    return `${url.origin}${url.pathname.replace(/\/+$/, "")}/uplink/${uplinkId}`;
  }
  const proto = req.protocol === "https" ? "wss" : "ws";
  const host = req.headers.host ?? "localhost";
  return `${proto}://${host}/uplink/${uplinkId}`;
}

export function ollamaRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db, config, ollamaRegistry } = ctx;

  const manageAccess = [authGuard(db, { session: true, apiKey: true, scope: "ollama:manage" })];

  // -------------------------------------------------------------------------
  // uplink management
  // -------------------------------------------------------------------------

  // Create an uplink. The PSK is returned EXACTLY ONCE; the server stores
  // only SHA-256(utf8(psk)).
  app.post("/v1/ollama/uplinks", { preHandler: manageAccess }, async (req, reply) => {
    const auth = req.auth!;
    const body = asBody(req);
    const name = body["name"];
    if (typeof name !== "string" || !UPLINK_NAME_RE.test(name)) {
      return reply.code(400).send({ error: "bad_request" });
    }
    const id = randomUUID();
    const psk = base64urlEncode(randomBytes(32));
    const now = new Date().toISOString();
    try {
      db.prepare(
        `INSERT INTO ollama_uplinks (id, user_id, name, psk_hash, models, created_at, updated_at)
         VALUES (?, ?, ?, ?, '[]', ?, ?)`,
      ).run(id, auth.userId, name, sha256Hex(psk), now, now);
    } catch {
      // UNIQUE(user_id, name) — same name already taken by this user.
      return reply.code(409).send({ error: "conflict" });
    }
    audit(db, "ollama_uplink_created", {
      userId: auth.userId,
      metadata: { uplink_id: id, name },
      ip: req.ip,
    });
    return reply.code(201).send({ id, name, psk, relay_url: relayUrl(config, req, id) });
  });

  // List own uplinks (never psk_hash).
  app.get("/v1/ollama/uplinks", { preHandler: manageAccess }, async (req, reply) => {
    const auth = req.auth!;
    const rows = db
      .prepare(
        `SELECT id, user_id, name, models, created_at FROM ollama_uplinks
         WHERE user_id = ? ORDER BY created_at`,
      )
      .all(auth.userId) as UplinkRow[];
    return reply.send({
      uplinks: rows.map((r) => ({
        id: r.id,
        name: r.name,
        models: JSON.parse(r.models) as string[],
        online: ollamaRegistry.get(r.id) !== undefined,
        created_at: r.created_at,
      })),
    });
  });

  // Delete an uplink and drop its active connection. Uniform 404 for
  // unknown OR foreign ids (no existence signal).
  app.delete("/v1/ollama/uplinks/:id", { preHandler: manageAccess }, async (req, reply) => {
    const auth = req.auth!;
    const { id } = req.params as { id: string };
    const result = db
      .prepare("DELETE FROM ollama_uplinks WHERE id = ? AND user_id = ?")
      .run(id, auth.userId);
    if (result.changes === 0) {
      return reply.code(404).send({ error: "not_found" });
    }
    ollamaRegistry.get(id)?.session.close();
    audit(db, "ollama_uplink_deleted", {
      userId: auth.userId,
      metadata: { uplink_id: id },
      ip: req.ip,
    });
    return reply.send({ ok: true });
  });

  // -------------------------------------------------------------------------
  // client-facing proxy (session or agk_ with ollama:use)
  // -------------------------------------------------------------------------

  // Encapsulated plugin so the raw-body parsers shadow JSON parsing ONLY
  // within the proxy scope (same approach as the gateway proxy).
  void app.register((instance, _opts, done) => {
    const rawBody = { parseAs: "buffer" as const };
    const bufferParser = (
      _req: FastifyRequest,
      body: unknown,
      done: (err: null, body?: unknown) => void,
    ): void => {
      done(null, body);
    };
    instance.addContentTypeParser("application/json", rawBody, bufferParser);
    instance.addContentTypeParser("*", rawBody, bufferParser);

    const proxyGuard = authGuard(db, { session: true, apiKey: true, scope: "ollama:use" });

    const handler = async (req: FastifyRequest, reply: FastifyReply) => {
      const auth = req.auth!;
      const { name } = req.params as { name: string };

      const uplink = db
        .prepare("SELECT id, user_id, name FROM ollama_uplinks WHERE user_id = ? AND name = ?")
        .get(auth.userId, name) as Pick<UplinkRow, "id" | "user_id" | "name"> | undefined;
      if (!uplink) return reply.code(404).send({ error: "unknown_uplink" });
      const entry = ollamaRegistry.get(uplink.id);
      if (!entry) return reply.code(503).send({ error: "uplink_offline" });

      // Path suffix after /ollama/:name, INCLUDING the query string, taken
      // from the raw URL so percent-encoding is forwarded verbatim.
      const rawUrl = req.raw.url ?? "";
      const prefix = `/ollama/${name}`;
      let path = rawUrl.startsWith(prefix) ? rawUrl.slice(prefix.length) : "/";
      if (path === "") path = "/";
      else if (path.startsWith("?")) path = `/${path}`;

      const headers: Record<string, string> = {};
      for (const [headerName, value] of Object.entries(req.headers)) {
        if (REQUEST_HEADER_DENYLIST.has(headerName.toLowerCase())) continue;
        if (typeof value === "string") headers[headerName] = value;
        else if (Array.isArray(value)) headers[headerName] = value.join(", ");
      }

      const method = req.method;
      const body =
        Buffer.isBuffer(req.body) && req.body.length > 0 && method !== "GET" && method !== "HEAD"
          ? (req.body as Uint8Array)
          : null;

      let pending: PendingRequest;
      try {
        pending = entry.session.openRequest({ method, path, headers, body });
      } catch {
        // Session died between the registry lookup and openRequest.
        return reply.code(503).send({ error: "uplink_offline" });
      }

      pipeTunnel(req, reply, db, auth.userId, name, pending, config.ollamaProxyTimeoutMs);
      return undefined;
    };

    for (const base of ["/ollama/:name/api", "/ollama/:name/v1"]) {
      for (const url of [base, `${base}/*`]) {
        instance.route({
          method: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
          url,
          config: {
            rateLimit: {
              max: config.rateLimitOllama.max,
              timeWindow: config.rateLimitOllama.timeWindow,
              // Per presented token (API key or session access token).
              keyGenerator: (req: FastifyRequest) => req.headers.authorization ?? req.ip,
            },
          },
          preHandler: [proxyGuard],
          handler,
        });
      }
    }
    done();
  });
}

/**
 * Stream a tunnelled response back to the HTTP client: response_head sets
 * status + headers, chunks pass through in order (SSE/NDJSON stay chunked),
 * response_end ends the response. Overall timeout → cancel + 504; client
 * disconnect → cancel; sidecar error frame → 502. Audits ollama_proxy_call
 * once, with operational metadata only — never payload data.
 */
function pipeTunnel(
  req: FastifyRequest,
  reply: FastifyReply,
  db: AppDatabase,
  userId: string,
  uplinkName: string,
  pending: PendingRequest,
  timeoutMs: number,
): void {
  reply.hijack();
  let headSent = false;
  let finished = false;

  const finish = (status: number): void => {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    audit(db, "ollama_proxy_call", {
      userId,
      metadata: { uplink: uplinkName, status },
      ip: req.ip,
    });
  };

  const timer = setTimeout(() => {
    if (pending.settled) return;
    pending.cancel();
    if (!headSent) {
      reply.raw.writeHead(504, { "content-type": "application/json" });
      reply.raw.end(JSON.stringify({ error: "uplink_timeout" }));
    } else {
      reply.raw.end();
    }
    finish(504);
  }, timeoutMs);
  timer.unref();

  pending.onHead((status, headers) => {
    headSent = true;
    const out: Record<string, string> = {};
    for (const [headerName, value] of Object.entries(headers)) {
      if (RESPONSE_HEADER_DENYLIST.has(headerName.toLowerCase())) continue;
      out[headerName] = value;
    }
    out["transfer-encoding"] = "chunked";
    reply.raw.writeHead(status, out);
  });
  pending.onChunk((data) => {
    reply.raw.write(data);
  });
  pending.onEnd(() => {
    finish(reply.raw.statusCode);
    reply.raw.end();
  });
  pending.onError(() => {
    if (!headSent) {
      reply.raw.writeHead(502, { "content-type": "application/json" });
    }
    reply.raw.end(JSON.stringify({ error: "uplink_error" }));
    finish(502);
  });
  // Fastify has already consumed req.raw for body parsing, so its "close"
  // event is unreliable; the response socket close is the dependable signal.
  reply.raw.on("close", () => {
    if (!pending.settled) {
      pending.cancel();
      finish(reply.raw.statusCode);
    }
  });
}
