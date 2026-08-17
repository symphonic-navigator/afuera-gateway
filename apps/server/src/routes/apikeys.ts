/**
 * API key management (spec §5.3 step 7, §5.8). Session path only.
 */

import type { FastifyInstance } from "fastify";
import { audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import { asBody, authGuard, isNonEmptyString, isValidBlob } from "../security.js";

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
}

/**
 * Issuable scopes. "keys:manage" is reserved → 400 (spec §4.2).
 * "gateway:use" / "gateway:manage" belong to the gateway business layer
 * (docs/specs/gateway.md); "ollama:use" / "ollama:manage" to the Ollama
 * relay layer (docs/specs/ollama-relay.md); "hfif:use" / "hfif:manage" to
 * the HF Inference Endpoints proxy (docs/specs/hfif.md).
 */
const ALLOWED_SCOPES = new Set([
  "data:read",
  "data:write",
  "gateway:use",
  "gateway:manage",
  "ollama:use",
  "ollama:manage",
  "hfif:use",
  "hfif:manage",
]);

interface ApiKeyRow {
  key_id: string;
  user_id: string;
  expires_at: string | null;
  created_at: string;
  last_used_at: string | null;
  revoked: number;
}

export function apiKeyRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db } = ctx;
  const sessionOnly = [authGuard(db, { session: true })];

  // -- §5.3 step 7: store a new API key ---------------------------------------
  app.post("/v1/api-keys", { preHandler: sessionOnly }, async (req, reply) => {
    const auth = req.auth!;
    const body = asBody(req);
    const keyId = body["key_id"];
    const keyHash = body["key_hash"];
    const wrappedDek = body["wrapped_dek"];
    const scopes = body["scopes"];
    const expiresAt = body["expires_at"];

    if (!isNonEmptyString(keyId) || !isValidBlob(wrappedDek)) {
      return reply.code(400).send({ error: "bad_request" });
    }
    if (typeof keyHash !== "string" || !/^[0-9a-f]{64}$/.test(keyHash)) {
      return reply.code(400).send({ error: "bad_request" });
    }
    if (
      !Array.isArray(scopes) ||
      scopes.length === 0 ||
      scopes.some((s) => typeof s !== "string")
    ) {
      return reply.code(400).send({ error: "bad_request" });
    }
    // Reserved or unknown scopes (incl. "keys:manage") → 400 (spec §4.2).
    if ((scopes as string[]).some((s) => !ALLOWED_SCOPES.has(s))) {
      return reply.code(400).send({ error: "invalid_scope" });
    }
    if (expiresAt !== undefined && expiresAt !== null && !isNonEmptyString(expiresAt)) {
      return reply.code(400).send({ error: "bad_request" });
    }

    const now = new Date().toISOString();
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO api_keys
             (key_id, user_id, key_hash, wrapped_dek, expires_at, created_at, last_used_at, revoked)
           VALUES (?, ?, ?, ?, ?, ?, NULL, 0)`,
        ).run(keyId, auth.userId, keyHash, wrappedDek, (expiresAt as string | null) ?? null, now);
        const insertScope = db.prepare(
          "INSERT INTO api_key_permissions (key_id, scope, granted_at) VALUES (?, ?, ?)",
        );
        for (const scope of new Set(scopes as string[])) {
          insertScope.run(keyId, scope, now);
        }
      })();
    } catch {
      // Duplicate key_id or key_hash — uniform error.
      return reply.code(409).send({ error: "conflict" });
    }
    audit(db, "api_key_created", {
      userId: auth.userId,
      metadata: { key_id: keyId, scopes },
      ip: req.ip,
    });
    return reply.code(201).send({ key_id: keyId });
  });

  // -- list own keys (metadata only — never key_hash / wrapped_dek) -----------
  app.get("/v1/api-keys", { preHandler: sessionOnly }, async (req, reply) => {
    const auth = req.auth!;
    const rows = db
      .prepare(
        `SELECT key_id, user_id, expires_at, created_at, last_used_at, revoked
         FROM api_keys WHERE user_id = ? ORDER BY created_at`,
      )
      .all(auth.userId) as ApiKeyRow[];
    const scopeStmt = db.prepare("SELECT scope FROM api_key_permissions WHERE key_id = ?");
    return reply.send({
      keys: rows.map((r) => ({
        key_id: r.key_id,
        scopes: (scopeStmt.all(r.key_id) as { scope: string }[]).map((s) => s.scope),
        created_at: r.created_at,
        last_used_at: r.last_used_at,
        expires_at: r.expires_at,
        revoked: r.revoked !== 0,
      })),
    });
  });

  // -- §5.8: revoke (soft delete) ----------------------------------------------
  app.post("/v1/api-keys/:keyId/revoke", { preHandler: sessionOnly }, async (req, reply) => {
    const auth = req.auth!;
    const { keyId } = req.params as { keyId: string };
    const result = db
      .prepare("UPDATE api_keys SET revoked = 1 WHERE key_id = ? AND user_id = ?")
      .run(keyId, auth.userId);
    if (result.changes === 0) {
      // Unknown or foreign key — no existence signal beyond 404.
      return reply.code(404).send({ error: "not_found" });
    }
    audit(db, "api_key_revoked", {
      userId: auth.userId,
      metadata: { key_id: keyId },
      ip: req.ip,
    });
    return reply.send({ ok: true });
  });
}
