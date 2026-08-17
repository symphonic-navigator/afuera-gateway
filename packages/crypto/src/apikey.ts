/**
 * API-key operations (spec §5.3, §5.4) — pure crypto parts only.
 *
 * Display token format:
 *   "agk_" + base64url(key_id raw 16 bytes) + "." + base64url(api_key)
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { CryptoError } from "./errors.js";
import { deriveApiKek } from "./hkdf.js";
import { unwrapDek, wrapDek, API_KEY_LEN } from "./keys.js";
import {
  base64urlDecode,
  base64urlEncode,
  bytesToUuid,
  hexEncode,
  randomBytes,
  uuidv4,
  uuidToBytes,
} from "./utils.js";

export const API_KEY_TOKEN_PREFIX = "agk_";

export interface CreatedApiKey {
  /** Display token, shown to the user exactly once: "agk_<key_id>.<api_key>". */
  token: string;
  /** UUIDv4 of the key. */
  keyId: string;
  /** SHA-256(api_key) hex — the server-side lookup index (spec §5.3 step 6). */
  keyHash: string;
  /** DEK wrapped under this key's API KEK (spec §5.3 step 5), base64url blob. */
  wrappedDek: string;
}

export interface ParsedApiKeyToken {
  keyId: string;
  apiKey: Uint8Array;
}

/**
 * Create an API key (spec §5.3 steps 1–6): random 256-bit key, fresh
 * UUIDv4 key_id, API KEK via HKDF (salt = key_id bytes), DEK wrapped
 * under it, and the SHA-256 lookup hash. Server storage is step 7 and
 * out of scope here.
 */
export function createApiKey(dek: Uint8Array, dekVersion: number): CreatedApiKey {
  const apiKey = randomBytes(API_KEY_LEN);
  const keyId = uuidv4();
  const apiKek = deriveApiKek(keyId, apiKey);
  const wrappedDek = wrapDek(apiKek, dek, `api:${keyId}`, dekVersion);
  const keyHash = hexEncode(sha256(apiKey));
  const token =
    API_KEY_TOKEN_PREFIX + base64urlEncode(uuidToBytes(keyId)) + "." + base64urlEncode(apiKey);
  return { token, keyId, keyHash, wrappedDek };
}

/** Parse an "agk_..." display token back into key_id and raw key material. */
export function parseApiKeyToken(token: string): ParsedApiKeyToken {
  if (!token.startsWith(API_KEY_TOKEN_PREFIX)) {
    throw new CryptoError("INVALID_FORMAT", "API key token must start with \"agk_\"");
  }
  const body = token.slice(API_KEY_TOKEN_PREFIX.length);
  const dot = body.indexOf(".");
  if (dot === -1) {
    throw new CryptoError("INVALID_FORMAT", "API key token is missing the \".\" separator");
  }
  const keyIdBytes = base64urlDecode(body.slice(0, dot));
  const apiKey = base64urlDecode(body.slice(dot + 1));
  if (apiKey.length !== API_KEY_LEN) {
    throw new CryptoError(
      "INVALID_FORMAT",
      `API key must be ${API_KEY_LEN} bytes, got ${apiKey.length}`,
    );
  }
  return { keyId: bytesToUuid(keyIdBytes), apiKey };
}

/**
 * Crypto part of spec §5.4: given the full display token and the
 * server-supplied wrapped DEK + current DEK version, recover the DEK.
 * Server-side checks (hash lookup, revocation, expiry, scope) are steps
 * 3–4 and out of scope here.
 */
export function unwrapDekWithApiKey(
  token: string,
  wrappedDekB64: string,
  dekVersion: number,
): { dek: Uint8Array; keyId: string; keyHash: string } {
  const { keyId, apiKey } = parseApiKeyToken(token);
  const apiKek = deriveApiKek(keyId, apiKey);
  const dek = unwrapDek(apiKek, wrappedDekB64, `api:${keyId}`, dekVersion);
  return { dek, keyId, keyHash: hexEncode(sha256(apiKey)) };
}
