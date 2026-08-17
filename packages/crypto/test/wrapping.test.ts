import { describe, expect, it } from "vitest";
import {
  base64urlDecode,
  base64urlEncode,
  BLOB_VERSION,
  CryptoError,
  hexDecode,
  hexEncode,
  unwrapDek,
  wrapDek,
} from "../src/index.js";

describe("DEK wrapping roundtrip (spec §9.2)", () => {
  const kek = hexDecode("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
  const dek = new Uint8Array(32).map((_, i) => i + 1); // 0x0102...20

  it("decrypt(kek, wrapped, same aad) === dek", () => {
    const wrapped = wrapDek(kek, dek, "master", 1);
    const unwrapped = unwrapDek(kek, wrapped, "master", 1);
    expect(hexEncode(unwrapped)).toBe(hexEncode(dek));
  });

  it("wrong dek_version in AAD throws TAG_MISMATCH", () => {
    const wrapped = wrapDek(kek, dek, "master", 1);
    expect(() => unwrapDek(kek, wrapped, "master", 2)).toThrowError(CryptoError);
    expect(() => unwrapDek(kek, wrapped, "master", 2)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("wrong purpose in AAD throws TAG_MISMATCH", () => {
    const wrapped = wrapDek(kek, dek, "master", 1);
    expect(() => unwrapDek(kek, wrapped, "api:some-id", 1)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("wrong KEK throws TAG_MISMATCH", () => {
    const wrapped = wrapDek(kek, dek, "master", 1);
    const otherKek = hexDecode(
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    );
    expect(() => unwrapDek(otherKek, wrapped, "master", 1)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("blob starts with version byte 0x01", () => {
    const wrapped = wrapDek(kek, dek, "master", 1);
    expect(base64urlDecode(wrapped)[0]).toBe(BLOB_VERSION);
  });

  it("bad version byte throws UNSUPPORTED_VERSION", () => {
    const blob = base64urlDecode(wrapDek(kek, dek, "master", 1));
    blob[0] = 0x02;
    expect(() => unwrapDek(kek, base64urlEncode(blob), "master", 1)).toThrowError(
      expect.objectContaining({ code: "UNSUPPORTED_VERSION" }),
    );
  });
});
