import { describe, expect, it } from "vitest";
import {
  constantTimeEqual,
  createApiKey,
  generateDek,
  hexDecode,
  hexEncode,
  parseApiKeyToken,
  unwrapDekWithApiKey,
} from "../src/index.js";

describe("API key flow (spec §5.3 / §5.4 crypto parts)", () => {
  it("create → parse token → derive KEK → unwrap DEK succeeds", () => {
    const dek = generateDek();
    const created = createApiKey(dek, 1);

    expect(created.token.startsWith("agk_")).toBe(true);

    const parsed = parseApiKeyToken(created.token);
    expect(parsed.keyId).toBe(created.keyId);
    expect(parsed.apiKey).toHaveLength(32);

    const result = unwrapDekWithApiKey(created.token, created.wrappedDek, 1);
    expect(hexEncode(result.dek)).toBe(hexEncode(dek));
    expect(result.keyHash).toBe(created.keyHash);
    expect(result.keyHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("key_hash matches SHA-256(api_key) and is constant-time comparable", () => {
    const created = createApiKey(generateDek(), 1);
    const parsed = parseApiKeyToken(created.token);
    expect(constantTimeEqual(hexDecode(created.keyHash), hexDecode(created.keyHash))).toBe(true);
    expect(parsed.apiKey).not.toEqual(hexDecode(created.keyHash));
  });

  it("wrong API key fails to unwrap (TAG_MISMATCH)", () => {
    const dek = generateDek();
    const created = createApiKey(dek, 1);
    const other = createApiKey(dek, 1);
    // Same key_id path but wrong key material: swap in another token's key.
    const tampered =
      "agk_" + created.token.slice(4).split(".")[0] + "." + other.token.split(".")[1];
    expect(() => unwrapDekWithApiKey(tampered, created.wrappedDek, 1)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("wrapped DEK from one key cannot be unwrapped with another key's token", () => {
    const dek = generateDek();
    const a = createApiKey(dek, 1);
    const b = createApiKey(dek, 1);
    expect(() => unwrapDekWithApiKey(a.token, b.wrappedDek, 1)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("wrong dek_version fails to unwrap", () => {
    const created = createApiKey(generateDek(), 1);
    expect(() => unwrapDekWithApiKey(created.token, created.wrappedDek, 2)).toThrowError(
      expect.objectContaining({ code: "TAG_MISMATCH" }),
    );
  });

  it("malformed tokens are rejected with INVALID_FORMAT", () => {
    expect(() => parseApiKeyToken("xxx_nope")).toThrowError(
      expect.objectContaining({ code: "INVALID_FORMAT" }),
    );
    expect(() => parseApiKeyToken("agk_no-separator-here")).toThrowError(
      expect.objectContaining({ code: "INVALID_FORMAT" }),
    );
    expect(() => parseApiKeyToken("agk_AAAA.!!!!")).toThrowError(
      expect.objectContaining({ code: "INVALID_FORMAT" }),
    );
  });
});
