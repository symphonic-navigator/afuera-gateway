import { describe, expect, it } from "vitest";
import {
  deriveApiKek,
  deriveAuthSeed,
  deriveMasterKek,
  deriveRootPrk,
  hexEncode,
  randomBytes,
  uuidv4,
} from "../src/index.js";
import { EXPECTED_AUTH_SEED_HEX, EXPECTED_MASTER_KEK_HEX, fixtureIkm } from "./fixtures.js";

describe("HKDF derivation (spec §9.1)", () => {
  it("is deterministic: same inputs → same output", () => {
    const ikm = fixtureIkm();
    expect(hexEncode(deriveMasterKek(ikm))).toBe(hexEncode(deriveMasterKek(ikm)));
    expect(hexEncode(deriveAuthSeed(ikm))).toBe(hexEncode(deriveAuthSeed(ikm)));
  });

  it("pins the exact master-kek-v1 vector from ikm 0x0001..1f", () => {
    expect(hexEncode(deriveMasterKek(fixtureIkm()))).toBe(EXPECTED_MASTER_KEK_HEX);
  });

  it("pins the exact auth-ed25519-seed-v1 vector from ikm 0x0001..1f", () => {
    expect(hexEncode(deriveAuthSeed(fixtureIkm()))).toBe(EXPECTED_AUTH_SEED_HEX);
  });

  it("domain separation: different info labels give different keys", () => {
    const ikm = fixtureIkm();
    expect(hexEncode(deriveMasterKek(ikm))).not.toBe(hexEncode(deriveAuthSeed(ikm)));
  });

  it("root PRK is 32 bytes and deterministic", () => {
    const ikm = fixtureIkm();
    expect(deriveRootPrk(ikm)).toHaveLength(32);
    expect(hexEncode(deriveRootPrk(ikm))).toBe(hexEncode(deriveRootPrk(ikm)));
  });

  it("API KEK: same key_id + api_key → same KEK; different key_id → different KEK", () => {
    const apiKey = randomBytes(32);
    const keyId = uuidv4();
    const kek1 = deriveApiKek(keyId, apiKey);
    expect(hexEncode(deriveApiKek(keyId, apiKey))).toBe(hexEncode(kek1));
    const otherId = uuidv4();
    expect(hexEncode(deriveApiKek(otherId, apiKey))).not.toBe(hexEncode(kek1));
  });
});
