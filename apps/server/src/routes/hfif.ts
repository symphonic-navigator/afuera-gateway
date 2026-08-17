/**
 * Per-user Hugging Face Inference Endpoints proxy ("hfif") — business
 * logic #3, docs/specs/hfif.md. Ported from the reference Python project
 * hf-inference-proxy (proxy.py), made per-user with the gateway's threat
 * model.
 *
 * Each user stores ONE HF access token, encrypted client-side under their
 * DEK (§4.1 blob, AAD dataAAD(user_id, "hfif-credential", dek_version)).
 * Client-facing /hfif/* routes accept `agk_` tokens ONLY (scope hfif:use):
 * the presented token arms the server transiently with the user's DEK, the
 * HF token is decrypted in memory for the duration of the request, used as
 * Bearer against the HF control plane / inference endpoint, and zeroized in
 * a `finally`. Tokens, prompts and completions are never logged.
 */

import { Readable } from "node:stream";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { dataAAD, decryptBlob, unwrapDekWithApiKey, utf8Decode, zeroize } from "@afuera/crypto";
import { audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import {
  HfClient,
  normalizeEndpoint,
  type NormalizedEndpoint,
} from "../hfif/client.js";
import {
  asBody,
  authGuard,
  isValidBlob,
  unauthorized,
  type AuthContext,
} from "../security.js";

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
}

interface HfCredentialRow {
  blob: string;
  created_at: string;
  updated_at: string;
}

type ApiKeyAuth = Extract<AuthContext, { type: "apikey" }>;

/** OpenAI-style error body (ported from the reference proxy). */
function openAiError(message: string): { error: { message: string } } {
  return { error: { message } };
}

/**
 * agk_ token → derive API-KEK → unwrap DEK → decrypt the stored HF token.
 * Returns the HF token bytes, or null on ANY failure (caller answers the
 * uniform 401). The unwrapped DEK is zeroized before returning.
 */
function decryptHfToken(db: AppDatabase, auth: ApiKeyAuth, token: string): Uint8Array | null {
  const keyRow = db
    .prepare(
      `SELECT k.wrapped_dek, u.dek_version
       FROM api_keys k JOIN user_crypto u ON u.user_id = k.user_id
       WHERE k.key_id = ?`,
    )
    .get(auth.keyId) as { wrapped_dek: string; dek_version: number } | undefined;
  if (!keyRow) return null;
  let dek: Uint8Array;
  try {
    dek = unwrapDekWithApiKey(token, keyRow.wrapped_dek, keyRow.dek_version).dek;
  } catch {
    return null;
  }
  try {
    const credential = db
      .prepare("SELECT blob FROM hf_credentials WHERE user_id = ?")
      .get(auth.userId) as Pick<HfCredentialRow, "blob"> | undefined;
    if (!credential) return null;
    // AAD binds user, record type "hfif-credential" and the CURRENT
    // dek_version — blobs cannot be swapped between users or versions.
    return decryptBlob(
      dek,
      credential.blob,
      dataAAD(auth.userId, "hfif-credential", keyRow.dek_version),
    );
  } catch {
    return null;
  } finally {
    zeroize(dek);
  }
}

export function hfifRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db, config } = ctx;

  const tokenManage = [authGuard(db, { session: true, apiKey: true, scope: "hfif:manage" })];
  const proxyGuard = [authGuard(db, { apiKey: true, scope: "hfif:use" })];

  const hfifRateLimit = {
    rateLimit: {
      max: config.rateLimitHfif.max,
      timeWindow: config.rateLimitHfif.timeWindow,
      // Per API key (the proxy is keyed by the presented token).
      keyGenerator: (req: FastifyRequest) => req.headers.authorization ?? req.ip,
    },
  };

  const clientConfig = {
    apiBase: config.hfApiBase,
    whoamiUrl: config.hfWhoamiUrl,
    resumeTimeoutMs: config.hfifResumeTimeoutMs,
    resumePollMs: config.hfifResumePollMs,
  };

  /**
   * Shared arming step for every route that talks to HF: agk_-only,
   * decrypt the HF token. Calls `fn` with a ready client; zeroizes the HF
   * token buffer afterwards. Any arming failure → uniform 401.
   */
  async function withHfClient(
    req: FastifyRequest,
    reply: FastifyReply,
    fn: (client: HfClient, hfToken: string, auth: ApiKeyAuth) => Promise<unknown>,
  ): Promise<unknown> {
    const auth = req.auth!;
    if (auth.type !== "apikey") return unauthorized(reply);
    const header = req.headers.authorization ?? "";
    const token = header.slice("Bearer ".length).trim();
    const hfToken = decryptHfToken(db, auth, token);
    if (hfToken === null) return unauthorized(reply);
    try {
      // Note: the HF token is briefly a JS string for header use; JS
      // strings cannot be reliably zeroed (same documented limitation as
      // the gateway). The Buffer copies ARE zeroed.
      const hfTokenText = utf8Decode(hfToken);
      return await fn(new HfClient(hfTokenText, clientConfig), hfTokenText, auth);
    } finally {
      zeroize(hfToken);
    }
  }

  // -------------------------------------------------------------------------
  // token management (session OR agk_ with hfif:manage)
  // -------------------------------------------------------------------------

  // Upsert the user's HF token blob (written client-side, stored verbatim).
  app.put("/v1/hfif/token", { preHandler: tokenManage }, async (req, reply) => {
    const auth = req.auth!;
    const blob = asBody(req)["blob"];
    if (!isValidBlob(blob)) {
      return reply.code(400).send({ error: "bad_request" });
    }
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO hf_credentials (user_id, blob, created_at, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (user_id) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at`,
    ).run(auth.userId, blob, now, now);
    audit(db, "hfif_token_set", { userId: auth.userId, ip: req.ip });
    return reply.send({ ok: true });
  });

  // Read back the blob (client may re-wrap/inspect it). Never decrypted here.
  app.get("/v1/hfif/token", { preHandler: tokenManage }, async (req, reply) => {
    const auth = req.auth!;
    const row = db
      .prepare("SELECT blob, created_at, updated_at FROM hf_credentials WHERE user_id = ?")
      .get(auth.userId) as HfCredentialRow | undefined;
    if (!row) {
      return reply.send({ exists: false, created_at: null, updated_at: null });
    }
    return reply.send({
      exists: true,
      created_at: row.created_at,
      updated_at: row.updated_at,
      blob: row.blob,
    });
  });

  // Delete the stored HF token.
  app.delete("/v1/hfif/token", { preHandler: tokenManage }, async (req, reply) => {
    const auth = req.auth!;
    const result = db.prepare("DELETE FROM hf_credentials WHERE user_id = ?").run(auth.userId);
    if (result.changes === 0) {
      return reply.code(404).send({ error: "credential_not_found" });
    }
    audit(db, "hfif_token_deleted", { userId: auth.userId, ip: req.ip });
    return reply.send({ ok: true });
  });

  // Token capability check (needs the DEK → agk_ with hfif:use OR hfif:manage).
  app.post(
    "/v1/hfif/token/check",
    { preHandler: [authGuard(db, { apiKey: true })] },
    async (req, reply) => {
      const auth = req.auth!;
      if (auth.type !== "apikey") return unauthorized(reply);
      if (!auth.scopes.has("hfif:use") && !auth.scopes.has("hfif:manage")) {
        audit(db, "api_key_access_denied", {
          userId: auth.userId,
          metadata: { key_id: auth.keyId, required_scope: "hfif:use|hfif:manage", path: req.url },
          ip: req.ip,
        });
        return unauthorized(reply);
      }
      return withHfClient(req, reply, async (client) => {
        const { check, networkError } = await client.checkToken();
        if (networkError) {
          return reply.code(502).send({ error: "upstream_error" });
        }
        return reply.send(check);
      });
    },
  );

  // -------------------------------------------------------------------------
  // OpenAI-compatible client API (agk_ + hfif:use only, per-key rate limit)
  // -------------------------------------------------------------------------

  // Always a FRESH endpoint list (uncached) — clients see current state.
  app.get(
    "/hfif/v1/models",
    { config: hfifRateLimit, preHandler: proxyGuard },
    async (req, reply) =>
      withHfClient(req, reply, async (client) => {
        let endpoints: NormalizedEndpoint[];
        try {
          endpoints = (await client.listEndpoints()).map(normalizeEndpoint);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          return reply.code(502).send(openAiError(`upstream error: ${message}`));
        }
        const created = Math.floor(Date.now() / 1000);
        const data = endpoints.map((ep) => ({
          id: ep.repository ?? ep.name,
          object: "model",
          created,
          owned_by: "huggingface",
          meta: {
            endpoint_name: ep.name,
            state: ep.state,
            task: ep.task,
            framework: ep.framework,
            instance: ep.instance,
            vendor: ep.vendor,
            region: ep.region,
          },
        }));
        return reply.send({ object: "list", data });
      }),
  );

  // Detailed normalized endpoint list (for a future dashboard).
  app.get(
    "/hfif/endpoints",
    { config: hfifRateLimit, preHandler: proxyGuard },
    async (req, reply) =>
      withHfClient(req, reply, async (client) => {
        try {
          const endpoints = (await client.listEndpoints()).map(normalizeEndpoint);
          return reply.send({ endpoints });
        } catch {
          return reply.code(502).send({ error: "upstream_error" });
        }
      }),
  );

  // Manual resume/pause (pause stops GPU cost). Returns the normalized
  // endpoint after the wait completes; 503 on failure/timeout.
  for (const action of ["resume", "pause"] as const) {
    app.post(
      `/hfif/endpoints/:name/${action}`,
      { config: hfifRateLimit, preHandler: proxyGuard },
      async (req, reply) =>
        withHfClient(req, reply, async (client, _token, auth) => {
          const { name } = req.params as { name: string };
          const result =
            action === "resume"
              ? await client.resumeEndpoint(name, true)
              : await client.pauseEndpoint(name, true);
          if (result === null) {
            return reply.code(503).send({ error: "endpoint_unavailable" });
          }
          audit(db, action === "resume" ? "hfif_endpoint_resumed" : "hfif_endpoint_paused", {
            userId: auth.userId,
            metadata: { endpoint_name: name },
            ip: req.ip,
          });
          return reply.send(normalizeEndpoint(result));
        }),
    );
  }

  // -------------------------------------------------------------------------
  // the proxy (core): /hfif/v1/{chat/completions,completions,embeddings}
  // -------------------------------------------------------------------------

  const proxyHandler = async (req: FastifyRequest, reply: FastifyReply) =>
    withHfClient(req, reply, async (client, hfTokenText, auth) => {
      const body = req.body;
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        return reply.code(400).send(openAiError("invalid json body"));
      }
      const model = (body as Record<string, unknown>)["model"];
      if (typeof model !== "string" || model.length === 0) {
        return reply.code(400).send(openAiError("missing 'model' field"));
      }

      // Fresh endpoint list; find by repository slug, fallback endpoint name.
      let endpoints: NormalizedEndpoint[];
      try {
        endpoints = (await client.listEndpoints()).map(normalizeEndpoint);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return reply.code(502).send(openAiError(`upstream error: ${message}`));
      }
      let ep =
        endpoints.find((e) => e.repository === model) ??
        endpoints.find((e) => e.name === model);
      if (!ep) {
        return reply.code(404).send(openAiError(`model '${model}' not found`));
      }

      // Auto-resume if not running (control-plane, no inference cost yet).
      if (ep.state !== "running" || !ep.url) {
        const resumed = await client.resumeEndpoint(ep.name ?? model, true);
        if (resumed === null) {
          return reply.code(503).send(openAiError(`endpoint '${model}' could not be started`));
        }
        const norm = normalizeEndpoint(resumed);
        if (norm.url) ep = norm;
      }
      if (!ep.url) {
        return reply.code(503).send(openAiError(`endpoint '${model}' has no URL`));
      }

      // Invocation URLs come from HF's status.url — passed through as-is,
      // except the scheme check (https in production; AG_HFIF_ALLOW_HTTP is
      // the dev/test escape hatch). The HF token is injected into this call.
      let invocationBase: string;
      try {
        const parsed = new URL(ep.url);
        if (parsed.protocol !== "https:" && !(config.hfifAllowHttp && parsed.protocol === "http:")) {
          return reply.code(502).send(openAiError("endpoint URL rejected: https required"));
        }
        invocationBase = ep.url.replace(/\/+$/, "");
      } catch {
        return reply.code(502).send(openAiError("endpoint URL is invalid"));
      }

      // The suffix is taken from the RAW url ("/hfif" prefix stripped) so
      // the original /v1 path + query string are forwarded verbatim.
      const rawUrl = req.raw.url ?? "";
      const suffix = rawUrl.startsWith("/hfif/") ? rawUrl.slice("/hfif".length) : "/";
      const target = invocationBase + suffix;

      const isStream = Boolean((body as Record<string, unknown>)["stream"]);
      const headers: Record<string, string> = {
        authorization: `Bearer ${hfTokenText}`,
        "content-type": "application/json",
        accept: isStream ? "text/event-stream" : "application/json",
      };
      const rawBody = JSON.stringify(body);
      // Long timeout: cold-start requests can take minutes.
      const signal = AbortSignal.timeout(config.hfifUpstreamTimeoutMs);

      if (isStream) {
        // SSE passthrough, chunked 1:1; upstream errors (before OR during
        // the stream) are emitted as SSE error frames on a 200 response.
        let upstream: Response;
        try {
          upstream = await fetch(target, { method: "POST", headers, body: rawBody, signal });
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          audit(db, "hfif_proxy_call", {
            userId: auth.userId,
            metadata: { model, status: null },
            ip: req.ip,
          });
          void reply.code(200).header("content-type", "text/event-stream");
          return reply.send(`data: ${JSON.stringify(openAiError(`upstream error: ${message}`))}\n\n`);
        }
        audit(db, "hfif_proxy_call", {
          userId: auth.userId,
          metadata: { model, status: upstream.status },
          ip: req.ip,
        });
        void reply.code(200).header("content-type", "text/event-stream");
        if (upstream.body === null) return reply.send();
        const upstreamBody = upstream.body;
        const pump = async function* (): AsyncGenerator<Uint8Array | string> {
          try {
            for await (const chunk of Readable.fromWeb(
              upstreamBody as unknown as WebReadableStream<Uint8Array>,
            )) {
              yield chunk;
            }
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            yield `data: ${JSON.stringify(openAiError(`upstream error: ${message}`))}\n\n`;
          }
        };
        return reply.send(Readable.from(pump()));
      }

      // Non-stream: status + content-type + body passthrough.
      let upstream: Response;
      try {
        upstream = await fetch(target, { method: "POST", headers, body: rawBody, signal });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        audit(db, "hfif_proxy_call", {
          userId: auth.userId,
          metadata: { model, status: null },
          ip: req.ip,
        });
        return reply.code(502).send(openAiError(`upstream error: ${message}`));
      }
      audit(db, "hfif_proxy_call", {
        userId: auth.userId,
        metadata: { model, status: upstream.status },
        ip: req.ip,
      });
      const payload = Buffer.from(await upstream.arrayBuffer());
      void reply.code(upstream.status);
      const contentType = upstream.headers.get("content-type");
      if (contentType !== null) void reply.header("content-type", contentType);
      return reply.send(payload);
    });

  for (const path of ["/hfif/v1/chat/completions", "/hfif/v1/completions", "/hfif/v1/embeddings"]) {
    app.post(path, { config: hfifRateLimit, preHandler: proxyGuard }, proxyHandler);
  }
}
