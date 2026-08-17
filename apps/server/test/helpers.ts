/**
 * Shared test helpers: in-memory app + client-side crypto drivers
 * (the client half of the spec §5 flows, via @afuera/crypto).
 */

import Database from "better-sqlite3";
import type { FastifyInstance } from "fastify";
import type { LightMyRequestResponse } from "fastify";
import {
  base64urlDecode,
  base64urlEncode,
  deriveLoginKeyMaterial,
  initializeUser,
  signLoginChallenge,
  type InitializedUser,
} from "@afuera/crypto";
import { buildApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { migrate } from "../src/db/migrate.js";
import type { AppDatabase } from "../src/db/index.js";
import { REFRESH_COOKIE } from "../src/routes/auth.js";

export interface TestApp {
  app: FastifyInstance;
  db: AppDatabase;
}

export function buildTestApp(config: Partial<AppConfig> = {}): TestApp {
  const db = new Database(":memory:");
  db.pragma("foreign_keys = ON");
  migrate(db);
  const app = buildApp({
    db,
    config: {
      serverSecret: "test-server-secret",
      // Keep limits out of the way; the rate-limit test sets its own.
      rateLimitGlobal: { max: 100_000, timeWindow: "1 minute" },
      rateLimitStrict: { max: 10_000, timeWindow: "1 minute" },
      ...config,
    },
  });
  return { app, db };
}

/** Client-side §5.1 + server registration. */
export async function registerUser(app: FastifyInstance): Promise<InitializedUser> {
  const user = initializeUser();
  const res = await app.inject({
    method: "POST",
    url: "/v1/users/register",
    payload: {
      user_id: user.registration.userId,
      auth_public_key: user.registration.authPublicKey,
      wrapped_dek_master: user.registration.wrappedDekMaster,
    },
  });
  if (res.statusCode !== 201) throw new Error(`register failed: ${res.statusCode} ${res.body}`);
  return user;
}

/** Client-side §5.2 steps 1–5. Returns the raw /v1/auth/verify response. */
export async function loginUser(
  app: FastifyInstance,
  userId: string,
  rootSecret: Uint8Array,
): Promise<LightMyRequestResponse> {
  const ch = await app.inject({
    method: "POST",
    url: "/v1/auth/challenge",
    payload: { user_id: userId },
  });
  if (ch.statusCode !== 200) throw new Error(`challenge failed: ${ch.statusCode} ${ch.body}`);
  const { nonce, expires_at: expiresAt } = ch.json() as { nonce: string; expires_at: string };
  const { authKeypair } = deriveLoginKeyMaterial(rootSecret);
  const signature = signLoginChallenge(authKeypair.secretKey, base64urlDecode(nonce), expiresAt);
  return app.inject({
    method: "POST",
    url: "/v1/auth/verify",
    payload: { user_id: userId, nonce, signature: base64urlEncode(signature) },
  });
}

export interface Session {
  accessToken: string;
  refreshCookie: string;
}

/** Full successful login; returns access token + refresh cookie value. */
export async function loginSession(
  app: FastifyInstance,
  userId: string,
  rootSecret: Uint8Array,
): Promise<Session> {
  const res = await loginUser(app, userId, rootSecret);
  if (res.statusCode !== 200) throw new Error(`login failed: ${res.statusCode} ${res.body}`);
  const cookie = res.cookies.find((c) => c.name === REFRESH_COOKIE);
  if (!cookie) throw new Error("no refresh cookie set");
  return {
    accessToken: (res.json() as { access_token: string }).access_token,
    refreshCookie: cookie.value,
  };
}

export function bearer(token: string): { authorization: string } {
  return { authorization: `Bearer ${token}` };
}

export function refreshCookieHeader(value: string): { cookie: string } {
  return { cookie: `${REFRESH_COOKIE}=${value}` };
}

export function auditEvents(db: AppDatabase): string[] {
  return (db.prepare("SELECT event FROM audit_log ORDER BY id").all() as { event: string }[]).map(
    (r) => r.event,
  );
}
