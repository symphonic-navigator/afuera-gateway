/**
 * HTTP integration: API key lifecycle (spec §5.3, §5.4, §5.8) and
 * scope enforcement on the data blob.
 */

import { describe, expect, it } from "vitest";
import { createApiKey, unwrapDekWithApiKey } from "@afuera/crypto";
import {
  auditEvents,
  bearer,
  buildTestApp,
  loginSession,
  registerUser,
  type Session,
  type TestApp,
} from "./helpers.js";
import type { InitializedUser } from "@afuera/crypto";

async function setup(): Promise<{
  app: TestApp["app"];
  db: TestApp["db"];
  user: InitializedUser;
  session: Session;
}> {
  const { app, db } = buildTestApp();
  const user = await registerUser(app);
  const session = await loginSession(app, user.registration.userId, user.rootSecret);
  return { app, db, user, session };
}

async function storeApiKey(
  app: TestApp["app"],
  session: Session,
  dek: Uint8Array,
  scopes: string[],
  expiresAt?: string,
) {
  const key = createApiKey(dek, 1);
  const res = await app.inject({
    method: "POST",
    url: "/v1/api-keys",
    headers: bearer(session.accessToken),
    payload: {
      key_id: key.keyId,
      key_hash: key.keyHash,
      wrapped_dek: key.wrappedDek,
      scopes,
      ...(expiresAt !== undefined ? { expires_at: expiresAt } : {}),
    },
  });
  return { key, res };
}

describe("API keys (spec §5.3, §5.4, §5.8)", () => {
  it("wrapped-dek-master is session-only: API key token → 401", async () => {
    const { app, user, session } = await setup();
    const { key, res } = await storeApiKey(app, session, user.dek, ["data:read"]);
    expect(res.statusCode).toBe(201);

    const viaApiKey = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(key.token),
    });
    expect(viaApiKey.statusCode).toBe(401);
    expect(viaApiKey.json()).toEqual({ error: "unauthorized" });
    await app.close();
  });

  it("create API key → GET wrapped-dek → client-side unwrap succeeds end-to-end", async () => {
    const { app, db, user, session } = await setup();
    const { key, res } = await storeApiKey(app, session, user.dek, ["data:read", "data:write"]);
    expect(res.statusCode).toBe(201);
    expect(res.json()).toEqual({ key_id: key.keyId });

    const wdk = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek",
      headers: bearer(key.token),
    });
    expect(wdk.statusCode).toBe(200);
    const body = wdk.json() as { wrapped_dek: string; dek_version: number; scopes: string[] };
    expect(body.dek_version).toBe(1);
    expect(body.scopes.sort()).toEqual(["data:read", "data:write"]);

    // true end-to-end: client recovers the DEK from the agk_ token alone
    const unwrapped = unwrapDekWithApiKey(key.token, body.wrapped_dek, body.dek_version);
    expect(Buffer.from(unwrapped.dek).equals(Buffer.from(user.dek))).toBe(true);
    expect(unwrapped.keyId).toBe(key.keyId);

    expect(auditEvents(db)).toContain("api_key_created");
    await app.close();
  });

  it("scope enforcement: no data:read → 401 on wrapped-dek; data:read without data:write → PUT blob rejected", async () => {
    const { app, db, user, session } = await setup();

    const writeOnly = await storeApiKey(app, session, user.dek, ["data:write"]);
    expect(writeOnly.res.statusCode).toBe(201);
    const wdk = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek",
      headers: bearer(writeOnly.key.token),
    });
    expect(wdk.statusCode).toBe(401);
    expect(wdk.json()).toEqual({ error: "unauthorized" });

    const readOnly = await storeApiKey(app, session, user.dek, ["data:read"]);
    const put = await app.inject({
      method: "PUT",
      url: "/v1/data/blob",
      headers: bearer(readOnly.key.token),
      payload: { encrypted_data_blob: "AQAAAA" },
    });
    expect(put.statusCode).toBe(401);

    // read-only key CAN read the blob
    const get = await app.inject({
      method: "GET",
      url: "/v1/data/blob",
      headers: bearer(readOnly.key.token),
    });
    expect(get.statusCode).toBe(200);

    // session path has full scopes implicitly
    const putSession = await app.inject({
      method: "PUT",
      url: "/v1/data/blob",
      headers: bearer(session.accessToken),
      payload: { encrypted_data_blob: "AQAAAA" },
    });
    expect(putSession.statusCode).toBe(200);

    expect(auditEvents(db).filter((e) => e === "api_key_access_denied")).toHaveLength(2);
    await app.close();
  });

  it("revoked key → 401; expired key → 401; last_used_at updates", async () => {
    const { app, db, user, session } = await setup();

    const revoked = await storeApiKey(app, session, user.dek, ["data:read"]);
    const rev = await app.inject({
      method: "POST",
      url: `/v1/api-keys/${revoked.key.keyId}/revoke`,
      headers: bearer(session.accessToken),
    });
    expect(rev.statusCode).toBe(200);
    const afterRevoke = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek",
      headers: bearer(revoked.key.token),
    });
    expect(afterRevoke.statusCode).toBe(401);

    const expired = await storeApiKey(
      app,
      session,
      user.dek,
      ["data:read"],
      new Date(Date.now() - 1000).toISOString(),
    );
    const afterExpiry = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek",
      headers: bearer(expired.key.token),
    });
    expect(afterExpiry.statusCode).toBe(401);

    // revoking someone else's / unknown key → uniform 404
    const nope = await app.inject({
      method: "POST",
      url: "/v1/api-keys/00000000-0000-4000-8000-000000000000/revoke",
      headers: bearer(session.accessToken),
    });
    expect(nope.statusCode).toBe(404);

    // last_used_at updates on successful use
    const live = await storeApiKey(app, session, user.dek, ["data:read"]);
    const before = db
      .prepare("SELECT last_used_at FROM api_keys WHERE key_id = ?")
      .get(live.key.keyId) as { last_used_at: string | null };
    expect(before.last_used_at).toBeNull();
    const use = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek",
      headers: bearer(live.key.token),
    });
    expect(use.statusCode).toBe(200);
    const after = db
      .prepare("SELECT last_used_at FROM api_keys WHERE key_id = ?")
      .get(live.key.keyId) as { last_used_at: string | null };
    expect(after.last_used_at).not.toBeNull();

    // list endpoint: metadata only, never key_hash / wrapped_dek
    const list = await app.inject({
      method: "GET",
      url: "/v1/api-keys",
      headers: bearer(session.accessToken),
    });
    expect(list.statusCode).toBe(200);
    const keys = (list.json() as { keys: Record<string, unknown>[] }).keys;
    expect(keys).toHaveLength(3);
    for (const k of keys) {
      expect(k).not.toHaveProperty("key_hash");
      expect(k).not.toHaveProperty("wrapped_dek");
      expect(k).toHaveProperty("scopes");
      expect(k).toHaveProperty("revoked");
    }
    const revokedEntry = keys.find((k) => k["key_id"] === revoked.key.keyId)!;
    expect(revokedEntry["revoked"]).toBe(true);

    expect(auditEvents(db)).toContain("api_key_revoked");
    await app.close();
  });

  it("keys:manage and unknown scopes → 400", async () => {
    const { app, user, session } = await setup();
    for (const scopes of [["keys:manage"], ["data:read", "keys:manage"], ["admin:*"]]) {
      const { res } = await storeApiKey(app, session, user.dek, scopes);
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ error: "invalid_scope" });
    }
    await app.close();
  });
});
