import { describe, expect, it } from "vitest";
import {
  CryptoError,
  hexEncode,
  mnemonicToRootSecret,
  rootSecretToMnemonic,
} from "../src/index.js";
import { EXPECTED_MNEMONIC_0001_1F, fixtureIkm } from "./fixtures.js";

describe("mnemonic roundtrip (spec §9.3)", () => {
  it("BIP39.decode(BIP39.encode(root_secret)) === root_secret", () => {
    const rootSecret = fixtureIkm(); // 0x0001..1f
    const mnemonic = rootSecretToMnemonic(rootSecret);
    expect(mnemonic.split(" ")).toHaveLength(24);
    expect(hexEncode(mnemonicToRootSecret(mnemonic))).toBe(hexEncode(rootSecret));
  });

  it("matches the known BIP-39 vector for entropy 0x0001..1f", () => {
    // Cross-checked against @scure/bip39 test fixtures.
    expect(rootSecretToMnemonic(fixtureIkm())).toBe(EXPECTED_MNEMONIC_0001_1F);
  });

  it("tolerates extra whitespace / casing-normalized input", () => {
    const messy = "  " + EXPECTED_MNEMONIC_0001_1F.split(" ").join("   ") + "\n";
    expect(hexEncode(mnemonicToRootSecret(messy))).toBe(hexEncode(fixtureIkm()));
  });

  it("rejects an invalid mnemonic (bad checksum) with INVALID_FORMAT", () => {
    const bad = EXPECTED_MNEMONIC_0001_1F.replace("journey", "abandon");
    expect(() => mnemonicToRootSecret(bad)).toThrowError(
      expect.objectContaining({ code: "INVALID_FORMAT" }),
    );
  });

  it("rejects a 12-word mnemonic (only 24 words / 256 bits allowed)", () => {
    const twelve = EXPECTED_MNEMONIC_0001_1F.split(" ").slice(0, 12).join(" ");
    expect(() => mnemonicToRootSecret(twelve)).toThrowError(CryptoError);
  });
});
