/**
 * API gateway — business logic #1 ("upstream key translation"),
 * docs/specs/gateway.md.
 *
 * Admins define named upstream APIs; users store their own upstream API key
 * per defined API, encrypted client-side under their DEK (§4.1 blob, AAD
 * "gateway-credential:<api_name>"). The proxy route translates an
 * `agk_` API key into the user's upstream credential: it derives the API-KEK
 * from the presented token, transiently unwraps the user's DEK, decrypts the
 * credential, and forwards the request upstream with the real key injected.
 *
 * Threat model (see gateway.md): the server is zero-knowledge AT REST, but a
 * request bearing an `agk_` token transiently arms it with the user's DEK.
 * Therefore the proxy path accepts `agk_` tokens ONLY (session tokens carry
 * no key material — proxying with a session is impossible by design), the
 * DEK and upstream key are zeroized in a `finally`, and keys/tokens/blobs
 * are never logged.
 */

import { Readable } from "node:stream";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { dataAAD, decryptBlob, unwrapDekWithApiKey, utf8Decode, zeroize } from "@afuera/crypto";
import { audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import {
  asBody,
  authGuard,
  isNonEmptyString,
  isValidBlob,
  unauthorized,
} from "../security.js";

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
}

interface GatewayApiRow {
  name: string;
  base_url: string;
  description: string | null;
  auth_header: string;
  auth_scheme: string;
}

const API_NAME_RE = /^[a-z0-9-]{2,64}$/;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HEADER_SCHEME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]*$/;

/** Headers never forwarded upstream (hop-by-hop + auth + framing). */
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

/**
 * Headers never sent back to the client: hop-by-hop, upstream cookies, and
 * framing headers (undici transparently decompresses, so the upstream
 * content-encoding/content-length no longer describe the body we stream).
 */
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

const USER_AGENT = "afuera-gateway/0.1 (+https://github.com/afuera/gateway)";

/**
 * Validate + normalize a base_url on write: https only (http only via the
 * dev/test escape hatch), no userinfo/query/hash, no path traversal.
 * Returns origin + path prefix without trailing slash.
 */
function normalizeBaseUrl(value: unknown, allowHttp: boolean): string | null {
  if (typeof value !== "string" || value.length === 0 || value.includes("..")) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && !(allowHttp && url.protocol === "http:")) return null;
  if (url.username !== "" || url.password !== "") return null;
  if (url.search !== "" || url.hash !== "") return null;
  return url.origin + url.pathname.replace(/\/+$/, "");
}

export function gatewayRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db, config } = ctx;

  const adminOnly = [
    authGuard(db, { session: true }),
    async (req: FastifyRequest, reply: FastifyReply) => {
      const auth = req.auth!;
      // Session path only + env-configured admin list. Empty list = no admins.
      if (auth.type !== "session" || !config.adminUsers.includes(auth.userId)) {
        return reply.code(403).send({ error: "forbidden" });
      }
      return undefined;
    },
  ];

  const credentialAccess = [authGuard(db, { session: true, apiKey: true, scope: "gateway:manage" })];

  // -------------------------------------------------------------------------
  // upstream API catalog
  // -------------------------------------------------------------------------

  // Admin: define an upstream API.
  app.post("/v1/gateway/apis", { preHandler: adminOnly }, async (req, reply) => {
    const auth = req.auth!;
    const body = asBody(req);
    const name = body["name"];
    const description = body["description"];
    const authHeader = body["auth_header"] ?? "Authorization";
    const authScheme = body["auth_scheme"] ?? "Bearer";

    if (typeof name !== "string" || !API_NAME_RE.test(name)) {
      return reply.code(400).send({ error: "bad_request" });
    }
    const baseUrl = normalizeBaseUrl(body["base_url"], config.gatewayAllowHttp);
    if (baseUrl === null) {
      return reply.code(400).send({ error: "invalid_base_url" });
    }
    if (description !== undefined && description !== null && typeof description !== "string") {
      return reply.code(400).send({ error: "bad_request" });
    }
    if (typeof authHeader !== "string" || !HEADER_NAME_RE.test(authHeader)) {
      return reply.code(400).send({ error: "bad_request" });
    }
    if (typeof authScheme !== "string" || !HEADER_SCHEME_RE.test(authScheme)) {
      return reply.code(400).send({ error: "bad_request" });
    }

    try {
      db.prepare(
        `INSERT INTO gateway_apis (name, base_url, description, auth_header, auth_scheme, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        name,
        baseUrl,
        (description as string | null) ?? null,
        authHeader,
        authScheme,
        auth.userId,
        new Date().toISOString(),
      );
    } catch {
      return reply.code(409).send({ error: "conflict" });
    }
    audit(db, "gateway_api_defined", {
      userId: auth.userId,
      metadata: { api_name: name, base_url: baseUrl },
      ip: req.ip,
    });
    return reply.code(201).send({ name, base_url: baseUrl });
  });

  // Any authenticated path: the public catalog.
  app.get(
    "/v1/gateway/apis",
    { preHandler: [authGuard(db, { session: true, apiKey: true })] },
    async (_req, reply) => {
      const rows = db
        .prepare("SELECT name, base_url, description FROM gateway_apis ORDER BY name")
        .all() as Pick<GatewayApiRow, "name" | "base_url" | "description">[];
      return reply.send({ apis: rows });
    },
  );

  // Admin: remove an upstream API (credentials cascade).
  app.delete("/v1/gateway/apis/:name", { preHandler: adminOnly }, async (req, reply) => {
    const auth = req.auth!;
    const { name } = req.params as { name: string };
    const result = db.prepare("DELETE FROM gateway_apis WHERE name = ?").run(name);
    if (result.changes === 0) {
      return reply.code(404).send({ error: "unknown_api" });
    }
    audit(db, "gateway_api_removed", {
      userId: auth.userId,
      metadata: { api_name: name },
      ip: req.ip,
    });
    return reply.send({ ok: true });
  });

  // -------------------------------------------------------------------------
  // per-user upstream credentials (blobs written client-side, stored verbatim)
  // -------------------------------------------------------------------------

  // Upsert own credential blob for a defined API.
  app.put(
    "/v1/gateway/credentials/:apiName",
    { preHandler: credentialAccess },
    async (req, reply) => {
      const auth = req.auth!;
      const { apiName } = req.params as { apiName: string };
      const body = asBody(req);
      const blob = body["blob"];
      if (!isValidBlob(blob)) {
        return reply.code(400).send({ error: "bad_request" });
      }
      const api = db.prepare("SELECT name FROM gateway_apis WHERE name = ?").get(apiName);
      if (!api) {
        return reply.code(404).send({ error: "unknown_api" });
      }
      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO gateway_credentials (user_id, api_name, blob, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (user_id, api_name) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at`,
      ).run(auth.userId, apiName, blob, now, now);
      audit(db, "gateway_credential_set", {
        userId: auth.userId,
        metadata: { api_name: apiName },
        ip: req.ip,
      });
      return reply.send({ ok: true });
    },
  );

  // List own credentials (metadata only — never blobs).
  app.get("/v1/gateway/credentials", { preHandler: credentialAccess }, async (req, reply) => {
    const auth = req.auth!;
    const rows = db
      .prepare(
        `SELECT api_name, created_at, updated_at FROM gateway_credentials
         WHERE user_id = ? ORDER BY api_name`,
      )
      .all(auth.userId) as { api_name: string; created_at: string; updated_at: string }[];
    return reply.send({ credentials: rows });
  });

  // Fetch one own credential blob (client may want to rotate/inspect it).
  app.get(
    "/v1/gateway/credentials/:apiName",
    { preHandler: credentialAccess },
    async (req, reply) => {
      const auth = req.auth!;
      const { apiName } = req.params as { apiName: string };
      const row = db
        .prepare(
          `SELECT api_name, blob, created_at, updated_at FROM gateway_credentials
           WHERE user_id = ? AND api_name = ?`,
        )
        .get(auth.userId, apiName) as
        | { api_name: string; blob: string; created_at: string; updated_at: string }
        | undefined;
      if (!row) {
        return reply.code(404).send({ error: "credential_not_found" });
      }
      return reply.send(row);
    },
  );

  // Delete own credential.
  app.delete(
    "/v1/gateway/credentials/:apiName",
    { preHandler: credentialAccess },
    async (req, reply) => {
      const auth = req.auth!;
      const { apiName } = req.params as { apiName: string };
      const result = db
        .prepare("DELETE FROM gateway_credentials WHERE user_id = ? AND api_name = ?")
        .run(auth.userId, apiName);
      if (result.changes === 0) {
        return reply.code(404).send({ error: "credential_not_found" });
      }
      audit(db, "gateway_credential_deleted", {
        userId: auth.userId,
        metadata: { api_name: apiName },
        ip: req.ip,
      });
      return reply.send({ ok: true });
    },
  );

  // -------------------------------------------------------------------------
  // the proxy (core): agk_ token → DEK unwrap → credential decrypt → upstream
  // -------------------------------------------------------------------------

  // Registered in an encapsulated plugin so the raw-body content type parsers
  // (which shadow the default JSON parser) apply ONLY to the proxy routes —
  // everything key-adjacent elsewhere keeps normal JSON parsing.
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

    const proxyGuard = authGuard(db, { apiKey: true, scope: "gateway:use" });

    const handler = async (req: FastifyRequest, reply: FastifyReply) => {
      const auth = req.auth!;
      // The guard restricts this route to the API-key path.
      if (auth.type !== "apikey") return unauthorized(reply);
      const { apiName } = req.params as { apiName: string };
      const header = req.headers.authorization ?? "";
      const token = header.slice("Bearer ".length).trim();

      let dek: Uint8Array | null = null;
      let upstreamKey: Uint8Array | null = null;
      try {
        // §5.4 steps 1–5, server side: derive the API-KEK from the presented
        // token and unwrap the user's DEK. Any failure → uniform 401.
        const keyRow = db
          .prepare(
            `SELECT k.wrapped_dek, u.dek_version
             FROM api_keys k JOIN user_crypto u ON u.user_id = k.user_id
             WHERE k.key_id = ?`,
          )
          .get(auth.keyId) as { wrapped_dek: string; dek_version: number } | undefined;
        if (!keyRow) return unauthorized(reply);
        try {
          dek = unwrapDekWithApiKey(token, keyRow.wrapped_dek, keyRow.dek_version).dek;
        } catch {
          return unauthorized(reply);
        }

        // Post-auth states: unknown upstream / missing credential.
        const api = db
          .prepare("SELECT name, base_url, description, auth_header, auth_scheme FROM gateway_apis WHERE name = ?")
          .get(apiName) as GatewayApiRow | undefined;
        if (!api) return reply.code(404).send({ error: "unknown_api" });
        const credential = db
          .prepare("SELECT blob FROM gateway_credentials WHERE user_id = ? AND api_name = ?")
          .get(auth.userId, apiName) as { blob: string } | undefined;
        if (!credential) {
          return reply.code(404).send({ error: "credential_not_found" });
        }

        // AAD binds user, "gateway-credential:<api_name>" and the CURRENT
        // dek_version — blobs cannot be swapped between users or upstreams.
        try {
          upstreamKey = decryptBlob(
            dek,
            credential.blob,
            dataAAD(auth.userId, `gateway-credential:${apiName}`, keyRow.dek_version),
          );
        } catch {
          // Stored blob fails integrity under the current DEK/version.
          audit(db, "gateway_credential_decrypt_failed", {
            userId: auth.userId,
            metadata: { api_name: apiName },
            ip: req.ip,
          });
          return reply.code(500).send({ error: "credential_decrypt_failed" });
        }

        // Target: base_url + raw wildcard suffix + original query string.
        // The suffix is taken from the RAW url (not decoded params) so
        // percent-encoding is forwarded verbatim.
        const rawUrl = req.raw.url ?? "";
        let rest = rawUrl.startsWith(`/gateway/${apiName}`)
          ? rawUrl.slice(`/gateway/${apiName}`.length)
          : "";
        if (rest === "") rest = "/";
        else if (rest.startsWith("?")) rest = `/${rest}`;
        const target = api.base_url + rest;

        const headers: Record<string, string> = {};
        for (const [name, value] of Object.entries(req.headers)) {
          if (REQUEST_HEADER_DENYLIST.has(name.toLowerCase())) continue;
          if (typeof value === "string") headers[name] = value;
          else if (Array.isArray(value)) headers[name] = value.join(", ");
        }
        // Inject the real upstream credential. Empty scheme → raw key.
        const keyText = utf8Decode(upstreamKey);
        headers[api.auth_header.toLowerCase()] =
          api.auth_scheme === "" ? keyText : `${api.auth_scheme} ${keyText}`;
        if (!Object.keys(headers).some((h) => h.toLowerCase() === "user-agent")) {
          headers["user-agent"] = USER_AGENT;
        }

        const method = req.method;
        const body =
          Buffer.isBuffer(req.body) && req.body.length > 0 && method !== "GET" && method !== "HEAD"
            ? req.body
            : undefined;

        let upstream: Response;
        try {
          upstream = await fetch(target, {
            method,
            headers,
            ...(body !== undefined ? { body } : {}),
            redirect: "manual",
            signal: AbortSignal.timeout(config.gatewayUpstreamTimeoutMs),
          });
        } catch {
          audit(db, "gateway_proxy_call", {
            userId: auth.userId,
            metadata: { api_name: apiName, upstream_status: null, error: "upstream_unreachable" },
            ip: req.ip,
          });
          return reply.code(502).send({ error: "upstream_error" });
        }

        reply.code(upstream.status);
        upstream.headers.forEach((value, name) => {
          if (RESPONSE_HEADER_DENYLIST.has(name.toLowerCase())) return;
          void reply.header(name, value);
        });
        audit(db, "gateway_proxy_call", {
          userId: auth.userId,
          metadata: { api_name: apiName, upstream_status: upstream.status },
          ip: req.ip,
        });
        if (upstream.body === null || method === "HEAD") {
          return reply.send();
        }
        return reply.send(
          Readable.fromWeb(upstream.body as unknown as WebReadableStream<Uint8Array>),
        );
      } finally {
        // Memory hygiene: drop everything key-like immediately after use.
        if (dek) zeroize(dek);
        if (upstreamKey) zeroize(upstreamKey);
      }
    };

    for (const url of ["/gateway/:apiName", "/gateway/:apiName/*"]) {
      instance.route({
        method: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        url,
        config: {
          rateLimit: {
            max: config.rateLimitGateway.max,
            timeWindow: config.rateLimitGateway.timeWindow,
            // Per API key (the proxy is keyed by the presented token).
            keyGenerator: (req: FastifyRequest) => req.headers.authorization ?? req.ip,
          },
        },
        preHandler: [proxyGuard],
        handler,
      });
    }
    done();
  });
}
