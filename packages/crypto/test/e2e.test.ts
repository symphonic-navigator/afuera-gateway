import { describe, expect, it } from "vitest";
import {
  base64urlDecode,
  buildLoginMessage,
  createApiKey,
  decryptData,
  deriveLoginKeyMaterial,
  encryptData,
  hexEncode,
  initializeUser,
  mnemonicToRootSecret,
  randomBytes,
  reEncryptDataBlob,
  rewrapDekForMaster,
  rotateMaster,
  signLoginChallenge,
  unwrapDekMaster,
  unwrapDekWithApiKey,
  utf8,
  verifyLoginChallenge,
  verifyMasterRotationSignature,
  zeroize,
  generateDek,
} from "../src/index.js";

describe("full happy path (spec §5)", () => {
  it("initializeUser → login → encrypt → rotate master → data survives, old secret dead", () => {
    // §5.1 initialization
    const init = initializeUser();
    expect(init.mnemonic.split(" ")).toHaveLength(24);
    expect(init.registration.dekVersion).toBe(1);
    expect(init.registration.masterVersion).toBe(1);
    const userId = init.registration.userId;

    // mnemonic restores the same root secret
    expect(hexEncode(mnemonicToRootSecret(init.mnemonic))).toBe(hexEncode(init.rootSecret));

    // §5.2 login: re-derivation from the mnemonic yields the same public key
    const restoredSecret = mnemonicToRootSecret(init.mnemonic);
    const login = deriveLoginKeyMaterial(restoredSecret);
    expect(hexEncode(login.authKeypair.publicKey)).toBe(hexEncode(init.authKeypair.publicKey));
    expect(hexEncode(login.masterKek)).toBe(hexEncode(init.masterKek));

    // challenge-response signature verifies against the registered public key
    const nonce = randomBytes(32);
    const expiresAt = new Date(Date.now() + 30_000).toISOString();
    const signature = signLoginChallenge(login.authKeypair.secretKey, nonce, expiresAt);
    expect(
      verifyLoginChallenge(init.authKeypair.publicKey, nonce, expiresAt, signature),
    ).toBe(true);
    // ... and fails for a different nonce (replay)
    expect(
      verifyLoginChallenge(init.authKeypair.publicKey, randomBytes(32), expiresAt, signature),
    ).toBe(false);

    // unwrap DEK via master path (§5.2 step 7)
    const dek = unwrapDekMaster(restoredSecret, init.registration.wrappedDekMaster, 1);
    expect(hexEncode(dek)).toBe(hexEncode(init.dek));

    // encrypt some data under the DEK (§5.5)
    const blob = encryptData(dek, utf8("secret payload"), userId, "record", 1);

    // API key access works before rotation (§5.3/§5.4)
    const apiKey = createApiKey(dek, 1);
    expect(hexEncode(unwrapDekWithApiKey(apiKey.token, apiKey.wrappedDek, 1).dek)).toBe(
      hexEncode(dek),
    );

    // §5.6 master rotation
    const rotation = rotateMaster(restoredSecret, init.registration.wrappedDekMaster, 1);
    expect(rotation.newMnemonic.split(" ")).toHaveLength(24);
    expect(hexEncode(rotation.dek)).toBe(hexEncode(dek));
    expect(rotation.update.newAuthPublicKey).not.toBe(init.registration.authPublicKey);

    // rotation signature verifies against the OLD public key
    expect(
      verifyMasterRotationSignature(
        init.authKeypair.publicKey,
        base64urlDecode(rotation.update.newAuthPublicKey),
        base64urlDecode(rotation.update.rotationSignature),
      ),
    ).toBe(true);

    // old data still decryptable (dek_version unchanged)
    expect(new TextDecoder().decode(decryptData(dek, blob, userId, "record", 1))).toBe(
      "secret payload",
    );

    // old root secret can no longer unwrap the NEW master wrapper
    expect(() =>
      unwrapDekMaster(restoredSecret, rotation.update.newWrappedDekMaster, 1),
    ).toThrowError(expect.objectContaining({ code: "TAG_MISMATCH" }));

    // new root secret unwraps it, and the API key still works
    const newSecret = mnemonicToRootSecret(rotation.newMnemonic);
    expect(
      hexEncode(unwrapDekMaster(newSecret, rotation.update.newWrappedDekMaster, 1)),
    ).toBe(hexEncode(dek));
    expect(hexEncode(unwrapDekWithApiKey(apiKey.token, apiKey.wrappedDek, 1).dek)).toBe(
      hexEncode(dek),
    );
  });

  it("DEK rotation (§5.7): re-encrypt blob + re-wrap master; old API keys invalid", () => {
    const init = initializeUser();
    const userId = init.registration.userId;
    const blob = encryptData(init.dek, utf8("payload v1"), userId, "record", 1);
    const apiKey = createApiKey(init.dek, 1);

    const newDek = generateDek();
    const newBlob = reEncryptDataBlob(init.dek, newDek, blob, userId, "record", 1, 2);
    expect(new TextDecoder().decode(decryptData(newDek, newBlob, userId, "record", 2))).toBe(
      "payload v1",
    );

    const newWrappedMaster = rewrapDekForMaster(init.rootSecret, newDek, 2);
    expect(hexEncode(unwrapDekMaster(init.rootSecret, newWrappedMaster, 2))).toBe(
      hexEncode(newDek),
    );

    // old API key's wrapper is bound to dek_version 1 → useless after rotation
    expect(() => unwrapDekWithApiKey(apiKey.token, apiKey.wrappedDek, 2)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("login message layout matches spec §5.2 step 3", () => {
    const nonce = new Uint8Array(32).fill(0x11);
    const expiresAt = "2026-08-16T00:00:00.000Z";
    const msg = buildLoginMessage(nonce, expiresAt);
    const expected = new Uint8Array([
      ...new TextEncoder().encode("ag-login-v1"),
      0x00,
      ...nonce,
      0x00,
      ...new TextEncoder().encode(expiresAt),
    ]);
    expect(msg).toEqual(expected);
  });

  it("zeroize wipes a buffer", () => {
    const buf = randomBytes(32);
    zeroize(buf);
    expect(buf.every((b) => b === 0)).toBe(true);
  });
});
