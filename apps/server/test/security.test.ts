/**
 * HTTP integration: rate limiting (spec §6.1) and audit log coverage (§6.2).
 */

import { describe, expect, it } from "vitest";
import { base64urlEncode, randomBytes } from "@afuera/crypto";
import {
  auditEvents,
  bearer,
  buildTestApp,
  loginSession,
  registerUser,
} from "./helpers.js";
import { createApiKey } from "@afuera/crypto";

describe("security cross-cutting (spec §6.1, §6.2)", () => {
  it("strict rate limit: hammering /v1/auth/verify → 429", async () => {
    const { app } = buildTestApp({
      rateLimitStrict: { max: 3, timeWindow: "1 minute" },
    });
    const payload = {
      user_id: "00000000-0000-4000-8000-000000000000",
      nonce: base64urlEncode(randomBytes(32)),
      signature: base64urlEncode(randomBytes(64)),
    };
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await app.inject({ method: "POST", url: "/v1/auth/verify", payload });
      codes.push(res.statusCode);
    }
    expect(codes).toEqual([401, 401, 401, 429, 429]);
    await app.close();
  });

  it("strict rate limit also applies to /v1/auth/challenge", async () => {
    const { app } = buildTestApp({
      rateLimitStrict: { max: 2, timeWindow: "1 minute" },
    });
    const codes: number[] = [];
    for (let i = 0; i < 3; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/v1/auth/challenge",
        payload: { user_id: "u" },
      });
      codes.push(res.statusCode);
    }
    expect(codes).toEqual([200, 200, 429]);
    await app.close();
  });

  it("audit_log rows present for key events (append-only, with user_id and ip)", async () => {
    const { app, db } = buildTestApp();
    const user = await registerUser(app);

    // failed login (unknown user)
    const bad = await app.inject({
      method: "POST",
      url: "/v1/auth/verify",
      payload: {
        user_id: "00000000-0000-4000-8000-000000000000",
        nonce: base64urlEncode(randomBytes(32)),
        signature: base64urlEncode(randomBytes(64)),
      },
    });
    expect(bad.statusCode).toBe(401);

    // successful login
    const session = await loginSession(app, user.registration.userId, user.rootSecret);

    // api key create + revoke
    const key = createApiKey(user.dek, 1);
    await app.inject({
      method: "POST",
      url: "/v1/api-keys",
      headers: bearer(session.accessToken),
      payload: {
        key_id: key.keyId,
        key_hash: key.keyHash,
        wrapped_dek: key.wrappedDek,
        scopes: ["data:read"],
      },
    });
    await app.inject({
      method: "POST",
      url: `/v1/api-keys/${key.keyId}/revoke`,
      headers: bearer(session.accessToken),
    });

    const events = auditEvents(db);
    expect(events).toEqual(
      expect.arrayContaining([
        "register",
        "login_failure",
        "login_success",
        "api_key_created",
        "api_key_revoked",
      ]),
    );

    const rows = db
      .prepare("SELECT user_id, event, ip, created_at FROM audit_log ORDER BY id")
      .all() as { user_id: string | null; event: string; ip: string | null; created_at: string }[];
    const register = rows.find((r) => r.event === "register")!;
    expect(register.user_id).toBe(user.registration.userId);
    expect(register.ip).toBeTruthy();
    expect(Date.parse(register.created_at)).not.toBeNaN();
    const failure = rows.find((r) => r.event === "login_failure")!;
    expect(failure.user_id).toBeNull(); // unknown user → no user context
    await app.close();
  });
});
