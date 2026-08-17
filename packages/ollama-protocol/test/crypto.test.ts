/**
 * Ported from ollama-uplink packages/protocol/test/crypto.test.ts.
 * The HKDF test vectors are the exact values the original sidecar derives —
 * they must match for wire compatibility.
 */

import { describe, expect, it } from "vitest";
import {
  decodeMessage,
  decryptFrame,
  deriveSessionKeys,
  encodeMessage,
  encryptFrame,
  hashPsk,
  sha256Hex,
} from "../src/index.js";

const keys = deriveSessionKeys(
  hashPsk("test-psk"),
  new Uint8Array(16).fill(1),
  new Uint8Array(16).fill(2),
);
const aad = { sessionId: "session-1", direction: "s2r" as const, seq: 0 };
const plaintext = encodeMessage({ kind: "ping", ts: 42 });

describe("sha256Hex", () => {
  it("matches a known SHA-256 answer", () => {
    expect(sha256Hex("test")).toBe(
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    );
  });
});

describe("deriveSessionKeys", () => {
  it("is deterministic (wire-compatibility test vectors from ollama-uplink)", () => {
    expect(Buffer.from(keys.s2r).toString("hex")).toBe(
      "a293b7a0437dc8ffdb9ad49e3c36353c0ef2351d28b37df3848498fe92687a5a",
    );
    expect(Buffer.from(keys.r2s).toString("hex")).toBe(
      "2549a699a09cac372153cffeafb789e86aa7b36f2d23414db65b013abe3ffdb8",
    );
  });

  it("derives different keys per direction", () => {
    expect(Buffer.from(keys.s2r).toString("hex")).not.toBe(Buffer.from(keys.r2s).toString("hex"));
  });

  it("derives identical keys on both sides from the same inputs", () => {
    const psk = hashPsk("shared-secret");
    const nonceS = new Uint8Array(16).fill(7);
    const nonceR = new Uint8Array(16).fill(9);
    // The relay stores pskHash as hex and reconstructs the bytes (server flow).
    const relayKeys = deriveSessionKeys(
      Buffer.from(Buffer.from(psk).toString("hex"), "hex"),
      nonceS,
      nonceR,
    );
    // The sidecar hashes the PSK string directly (sidecar flow).
    const sidecarKeys = deriveSessionKeys(hashPsk("shared-secret"), nonceS, nonceR);
    expect(Buffer.from(relayKeys.s2r)).toEqual(Buffer.from(sidecarKeys.s2r));
    expect(Buffer.from(relayKeys.r2s)).toEqual(Buffer.from(sidecarKeys.r2s));
  });
});

describe("frame codec", () => {
  it("roundtrips a frame", () => {
    const frame = encryptFrame(keys.s2r, aad, plaintext);
    expect(decodeMessage(decryptFrame(keys.s2r, aad, frame))).toEqual({ kind: "ping", ts: 42 });
  });

  it("rejects a tampered ciphertext", () => {
    const frame = encryptFrame(keys.s2r, aad, plaintext);
    frame[30] = (frame[30] ?? 0) ^ 1;
    expect(() => decryptFrame(keys.s2r, aad, frame)).toThrow();
  });

  it("rejects the wrong key", () => {
    const other = deriveSessionKeys(
      hashPsk("other-psk"),
      new Uint8Array(16).fill(1),
      new Uint8Array(16).fill(2),
    );
    const frame = encryptFrame(keys.s2r, aad, plaintext);
    expect(() => decryptFrame(other.s2r, aad, frame)).toThrow();
  });

  it("rejects AAD mismatch (seq, direction, session)", () => {
    const frame = encryptFrame(keys.s2r, aad, plaintext);
    expect(() => decryptFrame(keys.s2r, { ...aad, seq: 1 }, frame)).toThrow();
    expect(() => decryptFrame(keys.r2s, { ...aad, direction: "r2s" }, frame)).toThrow();
    expect(() => decryptFrame(keys.s2r, { ...aad, sessionId: "other" }, frame)).toThrow();
  });

  it("rejects truncated frames", () => {
    expect(() => decryptFrame(keys.s2r, aad, new Uint8Array(10))).toThrow();
  });
});

describe("message codec", () => {
  it("rejects invalid frames", () => {
    expect(() => decodeMessage(encodeMessage({ kind: "ping", ts: 1 }))).not.toThrow();
    expect(() => decodeMessage(new TextEncoder().encode("not json"))).toThrow();
    expect(() => decodeMessage(new TextEncoder().encode("[1,2]"))).toThrow();
  });
});
