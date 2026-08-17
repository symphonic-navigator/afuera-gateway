import { describe, expect, it } from "vitest";
import {
  base64urlDecode,
  base64urlEncode,
  decryptData,
  encryptData,
  generateDek,
  utf8,
  utf8Decode,
  uuidv4,
} from "../src/index.js";

describe("tamper detection (spec §9.4)", () => {
  const dek = generateDek();
  const userId = uuidv4();
  const recordType = "record";

  it("roundtrip: decryptData(encryptData(x)) === x", () => {
    const blob = encryptData(dek, utf8("hello"), userId, recordType, 1);
    expect(utf8Decode(decryptData(dek, blob, userId, recordType, 1))).toBe("hello");
  });

  it("flipped ciphertext byte → TAG_MISMATCH", () => {
    const blob = base64urlDecode(encryptData(dek, utf8("hello"), userId, recordType, 1));
    blob[30] = blob[30]! ^ 0x01; // inside ciphertext (blob: v1 + 24 nonce + ct)
    expect(() =>
      decryptData(dek, base64urlEncode(blob), userId, recordType, 1),
    ).toThrowError(expect.objectContaining({ code: "TAG_MISMATCH" }));
  });

  it("flipped tag byte → TAG_MISMATCH", () => {
    const blob = base64urlDecode(encryptData(dek, utf8("hello"), userId, recordType, 1));
    blob[blob.length - 1] = blob[blob.length - 1]! ^ 0x80;
    expect(() =>
      decryptData(dek, base64urlEncode(blob), userId, recordType, 1),
    ).toThrowError(expect.objectContaining({ code: "TAG_MISMATCH" }));
  });

  it("wrong AAD user_id → TAG_MISMATCH", () => {
    const blob = encryptData(dek, utf8("hello"), userId, recordType, 1);
    expect(() => decryptData(dek, blob, uuidv4(), recordType, 1)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("wrong AAD record_type → TAG_MISMATCH", () => {
    const blob = encryptData(dek, utf8("hello"), userId, recordType, 1);
    expect(() => decryptData(dek, blob, userId, "other", 1)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("wrong AAD dek_version → TAG_MISMATCH", () => {
    const blob = encryptData(dek, utf8("hello"), userId, recordType, 1);
    expect(() => decryptData(dek, blob, userId, recordType, 2)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("nonce uniqueness sanity: two encryptions of the same plaintext differ", () => {
    const a = encryptData(dek, utf8("hello"), userId, recordType, 1);
    const b = encryptData(dek, utf8("hello"), userId, recordType, 1);
    expect(a).not.toBe(b);
  });
});
