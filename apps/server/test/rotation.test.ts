/**
 * HTTP integration: master rotation (spec §5.6) and DEK rotation (§5.7).
 */

import { describe, expect, it } from "vitest";
import {
  base64urlDecode,
  base64urlEncode,
  createApiKey,
  decryptData,
  encryptData,
  generateDek,
  reEncryptDataBlob,
  rewrapDekForMaster,
  rotateMaster,
  unwrapDekMaster,
} from "@afuera/crypto";
import {
  auditEvents,
  bearer,
  buildTestApp,
  loginSession,
  loginUser,
  registerUser,
} from "./helpers.js";

describe("key rotation (spec §5.6, §5.7)", () => {
  it("rotate-master: valid old-key signature → new key active, old tokens dead; bad signature → 401", async () => {
    const { app, db } = buildTestApp();
    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);

    // fetch current wrapper to build the rotation payload (§5.6 step 1)
    const wdm = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(session.accessToken),
    });
    const { wrapped_dek_master, dek_version } = wdm.json() as {
      wrapped_dek_master: string;
      dek_version: number;
    };

    // --- bad signature first: corrupted signature → uniform 401
    const rotation = rotateMaster(user.rootSecret, wrapped_dek_master, dek_version);
    const rotationPayload = (sig: string) => ({
      new_auth_public_key: rotation.update.newAuthPublicKey,
      new_wrapped_dek_master: rotation.update.newWrappedDekMaster,
      rotation_signature: sig,
    });
    const badSig = base64urlDecode(rotation.update.rotationSignature);
    badSig[0] = badSig[0]! ^ 0xff;
    const bad = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-master",
      headers: bearer(session.accessToken),
      payload: rotationPayload(base64urlEncode(badSig)),
    });
    expect(bad.statusCode).toBe(401);
    expect(bad.json()).toEqual({ error: "unauthorized" });

    // --- valid rotation
    const ok = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-master",
      headers: bearer(session.accessToken),
      payload: rotationPayload(rotation.update.rotationSignature),
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toEqual({ master_version: 2 });

    // old access token is dead (§5.6 step 7)
    const oldToken = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(session.accessToken),
    });
    expect(oldToken.statusCode).toBe(401);

    // old root secret can no longer log in
    const oldLogin = await loginUser(app, user.registration.userId, user.rootSecret);
    expect(oldLogin.statusCode).toBe(401);

    // new root secret logs in and unwraps the SAME DEK (dek_version unchanged)
    const newLogin = await loginUser(app, user.registration.userId, rotation.newRootSecret);
    expect(newLogin.statusCode).toBe(200);
    const newAccess = (newLogin.json() as { access_token: string }).access_token;
    const wdm2 = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(newAccess),
    });
    const body2 = wdm2.json() as { wrapped_dek_master: string; dek_version: number };
    expect(body2.dek_version).toBe(dek_version);
    const dek = unwrapDekMaster(rotation.newRootSecret, body2.wrapped_dek_master, body2.dek_version);
    expect(Buffer.from(dek).equals(Buffer.from(user.dek))).toBe(true);

    expect(auditEvents(db)).toContain("master_rotated");
    await app.close();
  });

  it("rotate-dek: version bumped, blob swapped, all API keys revoked; version gap → 409", async () => {
    const { app, db } = buildTestApp();
    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);

    // store a data blob and an API key under dek_version 1
    const plaintext = new TextEncoder().encode("secret payload");
    const blobV1 = encryptData(user.dek, plaintext, user.registration.userId, "record", 1);
    const put = await app.inject({
      method: "PUT",
      url: "/v1/data/blob",
      headers: bearer(session.accessToken),
      payload: { encrypted_data_blob: blobV1 },
    });
    expect(put.statusCode).toBe(200);

    const apiKey = createApiKey(user.dek, 1);
    const mk = await app.inject({
      method: "POST",
      url: "/v1/api-keys",
      headers: bearer(session.accessToken),
      payload: {
        key_id: apiKey.keyId,
        key_hash: apiKey.keyHash,
        wrapped_dek: apiKey.wrappedDek,
        scopes: ["data:read"],
      },
    });
    expect(mk.statusCode).toBe(201);

    // --- version gap → 409 (client must prove it knows the current version)
    const newDek = generateDek();
    const blobV2 = reEncryptDataBlob(
      user.dek,
      newDek,
      blobV1,
      user.registration.userId,
      "record",
      1,
      2,
    );
    const gap = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-dek",
      headers: bearer(session.accessToken),
      payload: {
        new_wrapped_dek_master: rewrapDekForMaster(user.rootSecret, newDek, 3),
        new_dek_version: 3,
        encrypted_data_blob: blobV2,
        revoke_all_api_keys: true,
      },
    });
    expect(gap.statusCode).toBe(409);

    // --- valid rotation (§5.7 step 7: single transaction)
    const res = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-dek",
      headers: bearer(session.accessToken),
      payload: {
        new_wrapped_dek_master: rewrapDekForMaster(user.rootSecret, newDek, 2),
        new_dek_version: 2,
        encrypted_data_blob: blobV2,
        revoke_all_api_keys: true,
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ dek_version: 2 });

    // blob swapped and decryptable under the new DEK / version
    const get = await app.inject({
      method: "GET",
      url: "/v1/data/blob",
      headers: bearer(session.accessToken),
    });
    const body = get.json() as { encrypted_data_blob: string; dek_version: number };
    expect(body.dek_version).toBe(2);
    expect(body.encrypted_data_blob).not.toBe(blobV1);
    const roundtrip = decryptData(
      newDek,
      body.encrypted_data_blob,
      user.registration.userId,
      "record",
      2,
    );
    expect(Buffer.from(roundtrip).equals(Buffer.from(plaintext))).toBe(true);

    // all API keys revoked → uniform 401 on the API path
    const viaKey = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek",
      headers: bearer(apiKey.token),
    });
    expect(viaKey.statusCode).toBe(401);

    // new master wrapper unwraps to the new DEK
    const wdm = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(session.accessToken),
    });
    const w = wdm.json() as { wrapped_dek_master: string; dek_version: number };
    const unwrapped = unwrapDekMaster(user.rootSecret, w.wrapped_dek_master, w.dek_version);
    expect(Buffer.from(unwrapped).equals(Buffer.from(newDek))).toBe(true);

    expect(auditEvents(db)).toContain("dek_rotated");
    await app.close();
  });
});
