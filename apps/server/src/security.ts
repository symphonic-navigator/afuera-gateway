/**
 * Server-side token model + authentication guard (spec §5.2, §5.4, §5.9).
 *
 * Zero-knowledge rules enforced here:
 *  - session tokens and API keys are stored as SHA-256 hashes only;
 *  - unknown user / bad signature / revoked / expired / missing scope all
 *    produce the SAME 401 { error: "unauthorized" }.
 */

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { base64urlDecode, base64urlEncode, parseApiKeyToken } from "@afuera/crypto";
import { audit } from "./audit.js";
import type { AppConfig } from "./config.js";
import type { AppDatabase } from "./db/index.js";

// ---------------------------------------------------------------------------
// primitives
// ---------------------------------------------------------------------------

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Opaque 256-bit session token, base64url-encoded (spec §5.9). */
export function newOpaqueToken(): string {
  return base64urlEncode(randomBytes(32));
}

/**
 * Anti-enumeration fake nonce for unknown users (spec §5.2): syntactically
 * valid (32 bytes, base64url) but never stored, so verification fails
 * uniformly later.
 */
export function fakeChallengeNonce(serverSecret: string, userId: string): string {
  return base64urlEncode(createHmac("sha256", serverSecret).update(userId).digest());
}

// ---------------------------------------------------------------------------
// session tokens (spec §5.9)
// ---------------------------------------------------------------------------

export interface IssuedSession {
  accessToken: string;
  accessExpiresAt: string;
  refreshToken: string;
  refreshExpiresAt: string;
  familyId: string;
}

interface TokenRow {
  token_hash: string;
  user_id: string;
  kind: "access" | "refresh";
  family_id: string;
  expires_at: string;
  created_at: string;
  revoked: number;
}

function insertToken(
  db: AppDatabase,
  row: Omit<TokenRow, "created_at" | "revoked">,
): void {
  db.prepare(
    `INSERT INTO auth_tokens (token_hash, user_id, kind, family_id, expires_at, created_at, revoked)
     VALUES (?, ?, ?, ?, ?, ?, 0)`,
  ).run(row.token_hash, row.user_id, row.kind, row.family_id, row.expires_at, new Date().toISOString());
}

/** Issue a fresh access+refresh token pair in a new family (login). */
export function issueSession(db: AppDatabase, cfg: AppConfig, userId: string): IssuedSession {
  const now = Date.now();
  const familyId = randomUUID();
  const accessToken = newOpaqueToken();
  const refreshToken = newOpaqueToken();
  const accessExpiresAt = new Date(now + cfg.accessTokenTtlMs).toISOString();
  const refreshExpiresAt = new Date(now + cfg.refreshTokenTtlMs).toISOString();
  insertToken(db, {
    token_hash: sha256Hex(accessToken),
    user_id: userId,
    kind: "access",
    family_id: familyId,
    expires_at: accessExpiresAt,
  });
  insertToken(db, {
    token_hash: sha256Hex(refreshToken),
    user_id: userId,
    kind: "refresh",
    family_id: familyId,
    expires_at: refreshExpiresAt,
  });
  return { accessToken, accessExpiresAt, refreshToken, refreshExpiresAt, familyId };
}

export type RotateResult =
  | { ok: true; userId: string; accessToken: string; accessExpiresAt: string; refreshToken: string; refreshExpiresAt: string }
  | { ok: false; reason: "invalid" | "expired" | "reuse"; userId: string | null };

/**
 * Refresh-token rotation (spec §5.9). Atomically: the presented refresh
 * token is invalidated and a new pair in the SAME family is issued.
 * Presenting an already-rotated (revoked) refresh token is treated as
 * theft: the WHOLE family is revoked and `refresh_reuse_detected` audited.
 */
export function rotateRefreshToken(
  db: AppDatabase,
  cfg: AppConfig,
  refreshToken: string,
  ip: string | null,
): RotateResult {
  const hash = sha256Hex(refreshToken);
  return db.transaction((): RotateResult => {
    const row = db
      .prepare("SELECT * FROM auth_tokens WHERE token_hash = ? AND kind = 'refresh'")
      .get(hash) as TokenRow | undefined;
    if (!row) return { ok: false, reason: "invalid", userId: null };

    if (row.revoked !== 0) {
      // Reuse of a rotated token → nuke the whole family.
      db.prepare("UPDATE auth_tokens SET revoked = 1 WHERE family_id = ?").run(row.family_id);
      audit(db, "refresh_reuse_detected", {
        userId: row.user_id,
        metadata: { family_id: row.family_id },
        ip,
      });
      return { ok: false, reason: "reuse", userId: row.user_id };
    }
    if (Date.parse(row.expires_at) <= Date.now()) {
      return { ok: false, reason: "expired", userId: row.user_id };
    }

    // Atomic consume: only succeeds if still unrevoked.
    const consumed = db
      .prepare("UPDATE auth_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0")
      .run(hash);
    if (consumed.changes !== 1) {
      db.prepare("UPDATE auth_tokens SET revoked = 1 WHERE family_id = ?").run(row.family_id);
      audit(db, "refresh_reuse_detected", {
        userId: row.user_id,
        metadata: { family_id: row.family_id },
        ip,
      });
      return { ok: false, reason: "reuse", userId: row.user_id };
    }

    const now = Date.now();
    const accessToken = newOpaqueToken();
    const newRefreshToken = newOpaqueToken();
    const accessExpiresAt = new Date(now + cfg.accessTokenTtlMs).toISOString();
    const refreshExpiresAt = new Date(now + cfg.refreshTokenTtlMs).toISOString();
    insertToken(db, {
      token_hash: sha256Hex(accessToken),
      user_id: row.user_id,
      kind: "access",
      family_id: row.family_id,
      expires_at: accessExpiresAt,
    });
    insertToken(db, {
      token_hash: sha256Hex(newRefreshToken),
      user_id: row.user_id,
      kind: "refresh",
      family_id: row.family_id,
      expires_at: refreshExpiresAt,
    });
    return {
      ok: true,
      userId: row.user_id,
      accessToken,
      accessExpiresAt,
      refreshToken: newRefreshToken,
      refreshExpiresAt,
    };
  })();
}

/** Invalidate every token of a family (logout, refresh-reuse). */
export function revokeFamily(db: AppDatabase, familyId: string): void {
  db.prepare("UPDATE auth_tokens SET revoked = 1 WHERE family_id = ?").run(familyId);
}

/** Invalidate every token of a user (master rotation, spec §5.6 step 7). */
export function deleteUserTokens(db: AppDatabase, userId: string): void {
  db.prepare("DELETE FROM auth_tokens WHERE user_id = ?").run(userId);
}

/** Lazy cleanup of expired tokens/challenges (spec: cleanup on read is fine). */
export function purgeExpired(db: AppDatabase): void {
  const now = new Date().toISOString();
  db.prepare("DELETE FROM auth_tokens WHERE expires_at < ?").run(now);
  db.prepare("DELETE FROM challenges WHERE expires_at < ?").run(now);
}

// ---------------------------------------------------------------------------
// authentication guard
// ---------------------------------------------------------------------------

export type AuthContext =
  | { type: "session"; userId: string }
  | { type: "apikey"; userId: string; keyId: string; scopes: Set<string> };

declare module "fastify" {
  interface FastifyRequest {
    auth: AuthContext | null;
  }
}

export interface GuardOptions {
  /** Allow the session (access token) path. */
  session?: boolean;
  /** Allow the API key path. */
  apiKey?: boolean;
  /** Scope required on the API key path (e.g. "data:read"). */
  scope?: string;
}

const UNAUTHORIZED = { error: "unauthorized" } as const;

export function unauthorized(reply: FastifyReply): FastifyReply {
  return reply.code(401).send(UNAUTHORIZED);
}

interface ApiKeyRow {
  key_id: string;
  user_id: string;
  expires_at: string | null;
  revoked: number;
}

/**
 * preHandler factory. Path selection: bearer tokens starting with "agk_"
 * take the API-key path (spec §5.4), everything else the session path.
 * All failures are the uniform 401.
 */
export function authGuard(db: AppDatabase, opts: GuardOptions) {
  return async function guard(req: FastifyRequest, reply: FastifyReply): Promise<unknown> {
    req.auth = null;
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return unauthorized(reply);
    const token = header.slice("Bearer ".length).trim();
    if (!token) return unauthorized(reply);

    if (token.startsWith("agk_")) {
      if (!opts.apiKey) return unauthorized(reply);
      let parsed;
      try {
        parsed = parseApiKeyToken(token);
      } catch {
        return unauthorized(reply);
      }
      const row = db
        .prepare("SELECT key_id, user_id, expires_at, revoked FROM api_keys WHERE key_hash = ?")
        .get(sha256Hex(parsed.apiKey)) as ApiKeyRow | undefined;
      if (
        !row ||
        row.revoked !== 0 ||
        (row.expires_at !== null && Date.parse(row.expires_at) <= Date.now())
      ) {
        return unauthorized(reply);
      }
      const scopes = new Set(
        (
          db.prepare("SELECT scope FROM api_key_permissions WHERE key_id = ?").all(row.key_id) as {
            scope: string;
          }[]
        ).map((r) => r.scope),
      );
      if (opts.scope && !scopes.has(opts.scope)) {
        audit(db, "api_key_access_denied", {
          userId: row.user_id,
          metadata: { key_id: row.key_id, required_scope: opts.scope, path: req.url },
          ip: req.ip,
        });
        return unauthorized(reply);
      }
      db.prepare("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?").run(
        new Date().toISOString(),
        row.key_id,
      );
      req.auth = { type: "apikey", userId: row.user_id, keyId: row.key_id, scopes };
      return undefined;
    }

    if (!opts.session) return unauthorized(reply);
    const row = db
      .prepare("SELECT * FROM auth_tokens WHERE token_hash = ? AND kind = 'access'")
      .get(sha256Hex(token)) as TokenRow | undefined;
    if (!row || row.revoked !== 0 || Date.parse(row.expires_at) <= Date.now()) {
      return unauthorized(reply);
    }
    req.auth = { type: "session", userId: row.user_id };
    return undefined;
  };
}

// ---------------------------------------------------------------------------
// body validation helpers (malformed → 400; never an enumeration signal)
// ---------------------------------------------------------------------------

export function asBody(req: FastifyRequest): Record<string, unknown> {
  return (req.body ?? {}) as Record<string, unknown>;
}

export function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/** base64url-decode `v`, requiring exactly `len` bytes. */
export function decodeB64url(v: unknown, len: number): Uint8Array | null {
  if (typeof v !== "string") return null;
  try {
    const bytes = base64urlDecode(v);
    return bytes.length === len ? bytes : null;
  } catch {
    return null;
  }
}

/** §4.1 blob: version || nonce(24) || ct || tag(16) → ≥ 41 raw bytes. */
export function isValidBlob(v: unknown): v is string {
  if (typeof v !== "string" || v.length === 0) return false;
  try {
    return base64urlDecode(v).length >= 41;
  } catch {
    return false;
  }
}
