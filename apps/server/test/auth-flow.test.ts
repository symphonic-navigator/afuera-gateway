/**
 * HTTP integration: registration, challenge-response login, session tokens
 * (spec §5.1, §5.2, §5.9).
 */

import { describe, expect, it } from "vitest";
import {
  base64urlDecode,
  deriveLoginKeyMaterial,
  randomBytes,
  signLoginChallenge,
  base64urlEncode,
  unwrapDekMaster,
} from "@afuera/crypto";
import {
  auditEvents,
  bearer,
  buildTestApp,
  loginSession,
  loginUser,
  refreshCookieHeader,
  registerUser,
} from "./helpers.js";

describe("auth flow (spec §5.1, §5.2, §5.9)", () => {
  it("register → challenge → verify (real signing) → tokens issued; master wrapper roundtrip", async () => {
    const { app, db } = buildTestApp();
    const user = await registerUser(app);

    // duplicate registration → uniform conflict
    const dup = await app.inject({
      method: "POST",
      url: "/v1/users/register",
      payload: {
        user_id: user.registration.userId,
        auth_public_key: user.registration.authPublicKey,
        wrapped_dek_master: user.registration.wrappedDekMaster,
      },
    });
    expect(dup.statusCode).toBe(409);
    expect(dup.json()).toEqual({ error: "conflict" });

    // login
    const res = await loginUser(app, user.registration.userId, user.rootSecret);
    expect(res.statusCode).toBe(200);
    const body = res.json() as { access_token: string; token_type: string; expires_at: string };
    expect(body.token_type).toBe("Bearer");
    expect(body.access_token.length).toBeGreaterThan(20);
    const cookie = res.cookies.find((c) => c.name === "ag_refresh");
    expect(cookie).toBeDefined();
    expect(cookie!.httpOnly).toBe(true);
    expect(cookie!.secure).toBe(true);
    expect(cookie!.sameSite?.toLowerCase()).toBe("strict");

    // access token works on the session path; client unwraps the DEK (§5.2 steps 6–7)
    const wdm = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(body.access_token),
    });
    expect(wdm.statusCode).toBe(200);
    const { wrapped_dek_master, dek_version } = wdm.json() as {
      wrapped_dek_master: string;
      dek_version: number;
    };
    expect(dek_version).toBe(1);
    const dek = unwrapDekMaster(user.rootSecret, wrapped_dek_master, dek_version);
    expect(Buffer.from(dek).equals(Buffer.from(user.dek))).toBe(true);

    expect(auditEvents(db)).toEqual(
      expect.arrayContaining(["register", "login_success"]),
    );
    await app.close();
  });

  it("wrong signature → uniform 401; unknown user → valid-looking challenge, verify → same 401", async () => {
    const { app, db } = buildTestApp();
    const user = await registerUser(app);

    // --- unknown user: challenge looks real
    const unknownId = "00000000-0000-4000-8000-000000000000";
    const fakeCh = await app.inject({
      method: "POST",
      url: "/v1/auth/challenge",
      payload: { user_id: unknownId },
    });
    expect(fakeCh.statusCode).toBe(200);
    const fake = fakeCh.json() as { nonce: string; expires_at: string };
    expect(base64urlDecode(fake.nonce)).toHaveLength(32);
    expect(Date.parse(fake.expires_at)).toBeGreaterThan(Date.now());

    const fakeKey = deriveLoginKeyMaterial(randomBytes(32));
    const fakeSig = signLoginChallenge(
      fakeKey.authKeypair.secretKey,
      base64urlDecode(fake.nonce),
      fake.expires_at,
    );
    const fakeVerify = await app.inject({
      method: "POST",
      url: "/v1/auth/verify",
      payload: {
        user_id: unknownId,
        nonce: fake.nonce,
        signature: base64urlEncode(fakeSig),
      },
    });
    expect(fakeVerify.statusCode).toBe(401);
    expect(fakeVerify.json()).toEqual({ error: "unauthorized" });

    // --- known user, wrong signature: identical response
    const realCh = await app.inject({
      method: "POST",
      url: "/v1/auth/challenge",
      payload: { user_id: user.registration.userId },
    });
    const real = realCh.json() as { nonce: string; expires_at: string };
    const wrongKey = deriveLoginKeyMaterial(randomBytes(32));
    const wrongSig = signLoginChallenge(
      wrongKey.authKeypair.secretKey,
      base64urlDecode(real.nonce),
      real.expires_at,
    );
    const badVerify = await app.inject({
      method: "POST",
      url: "/v1/auth/verify",
      payload: {
        user_id: user.registration.userId,
        nonce: real.nonce,
        signature: base64urlEncode(wrongSig),
      },
    });
    expect(badVerify.statusCode).toBe(401);
    expect(badVerify.json()).toEqual(fakeVerify.json()); // no enumeration signal
    expect(badVerify.cookies).toEqual([]);

    expect(auditEvents(db).filter((e) => e === "login_failure")).toHaveLength(2);
    await app.close();
  });

  it("nonce is single-use: replaying a consumed challenge → 401", async () => {
    const { app } = buildTestApp();
    const user = await registerUser(app);

    const ch = await app.inject({
      method: "POST",
      url: "/v1/auth/challenge",
      payload: { user_id: user.registration.userId },
    });
    const { nonce, expires_at: expiresAt } = ch.json() as { nonce: string; expires_at: string };
    const { authKeypair } = deriveLoginKeyMaterial(user.rootSecret);
    const signature = base64urlEncode(
      signLoginChallenge(authKeypair.secretKey, base64urlDecode(nonce), expiresAt),
    );
    const payload = { user_id: user.registration.userId, nonce, signature };

    const first = await app.inject({ method: "POST", url: "/v1/auth/verify", payload });
    expect(first.statusCode).toBe(200);

    // same nonce + valid signature again → consumed atomically, replay fails
    const replay = await app.inject({ method: "POST", url: "/v1/auth/verify", payload });
    expect(replay.statusCode).toBe(401);
    expect(replay.json()).toEqual({ error: "unauthorized" });
    await app.close();
  });

  it("refresh rotates; rotated-token reuse kills the whole family and is audited; logout invalidates", async () => {
    const { app, db } = buildTestApp();
    const user = await registerUser(app);
    const s1 = await loginSession(app, user.registration.userId, user.rootSecret);

    // rotate once → new access token + new refresh cookie
    const r1 = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: refreshCookieHeader(s1.refreshCookie),
    });
    expect(r1.statusCode).toBe(200);
    const rotatedAccess = (r1.json() as { access_token: string }).access_token;
    const cookie2 = r1.cookies.find((c) => c.name === "ag_refresh")!.value;
    expect(cookie2).not.toBe(s1.refreshCookie);

    // theft: replay the OLD (rotated-out) refresh token
    const reuse = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: refreshCookieHeader(s1.refreshCookie),
    });
    expect(reuse.statusCode).toBe(401);

    // the whole family is dead now: newest refresh token and rotated access token fail
    const r2 = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: refreshCookieHeader(cookie2),
    });
    expect(r2.statusCode).toBe(401);
    const deadAccess = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(rotatedAccess),
    });
    expect(deadAccess.statusCode).toBe(401);
    expect(auditEvents(db)).toContain("refresh_reuse_detected");

    // logout invalidates the family
    const s2 = await loginSession(app, user.registration.userId, user.rootSecret);
    const out = await app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      headers: refreshCookieHeader(s2.refreshCookie),
    });
    expect(out.statusCode).toBe(200);
    const afterLogout = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(s2.accessToken),
    });
    expect(afterLogout.statusCode).toBe(401);
    const refreshAfterLogout = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: refreshCookieHeader(s2.refreshCookie),
    });
    expect(refreshAfterLogout.statusCode).toBe(401);
    await app.close();
  });
});
