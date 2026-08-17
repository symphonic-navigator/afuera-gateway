/**
 * Registration + challenge-response login + session lifecycle
 * (spec §5.1, §5.2, §5.9).
 */

import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { base64urlEncode, verifyLoginChallenge } from "@afuera/crypto";
import { audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import {
  asBody,
  decodeB64url,
  fakeChallengeNonce,
  isNonEmptyString,
  isValidBlob,
  issueSession,
  purgeExpired,
  revokeFamily,
  rotateRefreshToken,
  sha256Hex,
  unauthorized,
} from "../security.js";

export const REFRESH_COOKIE = "ag_refresh";

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
}

interface ChallengeRow {
  nonce: string;
  user_id: string;
  expires_at: string;
  consumed: number;
}

export function authRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db, config } = ctx;
  const strict = { rateLimit: config.rateLimitStrict };

  // -- §5.1 step 10: register ------------------------------------------------
  app.post("/v1/users/register", async (req, reply) => {
    const body = asBody(req);
    const userId = body["user_id"];
    const authPublicKey = body["auth_public_key"];
    const wrappedDekMaster = body["wrapped_dek_master"];
    if (
      !isNonEmptyString(userId) ||
      !decodeB64url(authPublicKey, 32) ||
      !isValidBlob(wrappedDekMaster)
    ) {
      return reply.code(400).send({ error: "bad_request" });
    }
    const now = new Date().toISOString();
    try {
      db.prepare(
        `INSERT INTO user_crypto
           (user_id, auth_public_key, encrypted_data_blob, wrapped_dek_master,
            dek_version, master_version, created_at, updated_at)
         VALUES (?, ?, NULL, ?, 1, 1, ?, ?)`,
      ).run(userId, authPublicKey as string, wrappedDekMaster, now, now);
    } catch {
      // Duplicate user_id (or any constraint conflict) — uniform error.
      return reply.code(409).send({ error: "conflict" });
    }
    audit(db, "register", { userId, ip: req.ip });
    return reply.code(201).send({ user_id: userId, dek_version: 1, master_version: 1 });
  });

  // -- §5.2 step 2: challenge -------------------------------------------------
  app.post("/v1/auth/challenge", { config: strict }, async (req, reply) => {
    const body = asBody(req);
    const userId = body["user_id"];
    if (!isNonEmptyString(userId)) {
      return reply.code(400).send({ error: "bad_request" });
    }
    purgeExpired(db);
    const expiresAt = new Date(Date.now() + config.challengeTtlMs).toISOString();
    const user = db
      .prepare("SELECT user_id FROM user_crypto WHERE user_id = ?")
      .get(userId) as { user_id: string } | undefined;

    let nonce: string;
    if (user) {
      nonce = base64urlEncode(randomBytes(32));
      db.prepare(
        "INSERT INTO challenges (nonce, user_id, expires_at, consumed) VALUES (?, ?, ?, 0)",
      ).run(nonce, userId, expiresAt);
    } else {
      // Anti-enumeration: syntactically valid but never stored — the
      // response is indistinguishable and verification fails uniformly.
      nonce = fakeChallengeNonce(config.serverSecret, userId);
    }
    return reply.send({ nonce, expires_at: expiresAt });
  });

  // -- §5.2 step 5: verify ----------------------------------------------------
  app.post("/v1/auth/verify", { config: strict }, async (req, reply) => {
    const body = asBody(req);
    const userId = body["user_id"];
    const nonce = body["nonce"];
    const signature = body["signature"];
    if (!isNonEmptyString(userId) || !isNonEmptyString(nonce) || !isNonEmptyString(signature)) {
      return reply.code(400).send({ error: "bad_request" });
    }

    // Consume the nonce atomically BEFORE verifying (single-use, §5.2/§6.1).
    const consumed = db
      .prepare("UPDATE challenges SET consumed = 1 WHERE nonce = ? AND user_id = ? AND consumed = 0")
      .run(nonce, userId);
    const challenge =
      consumed.changes === 1
        ? (db.prepare("SELECT * FROM challenges WHERE nonce = ?").get(nonce) as
            | ChallengeRow
            | undefined)
        : undefined;

    const user = db
      .prepare("SELECT user_id, auth_public_key FROM user_crypto WHERE user_id = ?")
      .get(userId) as { user_id: string; auth_public_key: string } | undefined;

    let ok = false;
    if (challenge && user && Date.parse(challenge.expires_at) > Date.now()) {
      const sig = decodeB64url(signature, 64);
      const pub = decodeB64url(user.auth_public_key, 32);
      const nonceBytes = decodeB64url(nonce, 32);
      if (sig && pub && nonceBytes) {
        try {
          ok = verifyLoginChallenge(pub, nonceBytes, challenge.expires_at, sig);
        } catch {
          ok = false;
        }
      }
    }

    if (!ok || !user) {
      audit(db, "login_failure", { userId: user?.user_id ?? null, ip: req.ip });
      return unauthorized(reply);
    }

    const session = issueSession(db, config, user.user_id);
    audit(db, "login_success", { userId: user.user_id, ip: req.ip });
    void reply.setCookie(REFRESH_COOKIE, session.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/v1/auth",
      expires: new Date(session.refreshExpiresAt),
    });
    return reply.send({
      access_token: session.accessToken,
      token_type: "Bearer",
      expires_at: session.accessExpiresAt,
    });
  });

  // -- §5.9: refresh (rotating) ------------------------------------------------
  app.post("/v1/auth/refresh", async (req, reply) => {
    const token = req.cookies[REFRESH_COOKIE];
    if (!token) return unauthorized(reply);
    const result = rotateRefreshToken(db, config, token, req.ip);
    if (!result.ok) {
      void reply.clearCookie(REFRESH_COOKIE, { path: "/v1/auth" });
      return unauthorized(reply);
    }
    void reply.setCookie(REFRESH_COOKIE, result.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/v1/auth",
      expires: new Date(result.refreshExpiresAt),
    });
    return reply.send({
      access_token: result.accessToken,
      token_type: "Bearer",
      expires_at: result.accessExpiresAt,
    });
  });

  // -- logout: invalidate the token family --------------------------------------
  app.post("/v1/auth/logout", async (req, reply) => {
    const token = req.cookies[REFRESH_COOKIE];
    if (token) {
      const row = db
        .prepare("SELECT family_id FROM auth_tokens WHERE token_hash = ?")
        .get(sha256Hex(token)) as { family_id: string } | undefined;
      if (row) revokeFamily(db, row.family_id);
    }
    void reply.clearCookie(REFRESH_COOKIE, { path: "/v1/auth" });
    return reply.send({ ok: true });
  });
}
