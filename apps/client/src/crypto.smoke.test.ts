import { describe, expect, it } from "vitest";
import {
  BLOB_VERSION,
  deriveMasterKek,
  hexEncode,
  rootSecretToMnemonic,
} from "@afuera/crypto";

// Smoke test: the shared crypto package must work unchanged from the
// client's bundler/test environment (no Node-only APIs).
describe("@afuera/crypto smoke test (client bundle)", () => {
  it("exposes the blob format version", () => {
    expect(BLOB_VERSION).toBe(0x01);
  });

  it("derives the pinned master-kek-v1 vector (spec §9.1)", () => {
    const ikm = new Uint8Array(32).map((_, i) => i);
    expect(hexEncode(deriveMasterKek(ikm))).toBe(
      "16be15d5e2e15bcd10389583e5072f08cf3c58864a809016459d66a8f83ebee8",
    );
  });

  it("encodes a 24-word mnemonic", () => {
    expect(rootSecretToMnemonic(new Uint8Array(32)).split(" ")).toHaveLength(24);
  });
});
