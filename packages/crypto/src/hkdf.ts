/**
 * HKDF-SHA-256 key derivation, exactly per spec §3.
 *
 * Root hierarchy (single extract, info-label separation):
 *   prk        = HKDF-Extract(salt="ag-root-v1", ikm=root_secret)
 *   auth_seed  = HKDF-Expand(prk, info="auth-ed25519-seed-v1", 32)
 *   master_kek = HKDF-Expand(prk, info="master-kek-v1", 32)
 *
 * API-key hierarchy:
 *   prk     = HKDF-Extract(salt=key_id bytes, ikm=api_key)
 *   api_kek = HKDF-Expand(prk, info="api-kek-v1", 32)
 *
 * The `key_id bytes` salt is the 16 raw bytes of the UUID (see
 * `uuidToBytes` in utils.ts); salts/info labels are UTF-8 encoded
 * protocol constants, never secrets.
 */

import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8, uuidToBytes } from "./utils.js";

export const HKDF_SALT_ROOT = "ag-root-v1";
export const HKDF_INFO_AUTH_ED25519_SEED = "auth-ed25519-seed-v1";
export const HKDF_INFO_MASTER_KEK = "master-kek-v1";
export const HKDF_INFO_API_KEK = "api-kek-v1";

const KEY_LEN = 32;

/** HKDF-Extract(salt="ag-root-v1", ikm=root_secret) — the root PRK. */
export function deriveRootPrk(rootSecret: Uint8Array): Uint8Array {
  return extract(sha256, rootSecret, utf8(HKDF_SALT_ROOT));
}

/** Ed25519 seed for the auth key pair (spec §5.1 step 5). */
export function deriveAuthSeed(rootSecret: Uint8Array): Uint8Array {
  return expand(sha256, deriveRootPrk(rootSecret), utf8(HKDF_INFO_AUTH_ED25519_SEED), KEY_LEN);
}

/** Master KEK — wraps the DEK for the root-secret path (spec §5.1 step 7). */
export function deriveMasterKek(rootSecret: Uint8Array): Uint8Array {
  return expand(sha256, deriveRootPrk(rootSecret), utf8(HKDF_INFO_MASTER_KEK), KEY_LEN);
}

/**
 * API KEK for one API key (spec §5.3 steps 3–4).
 * `keyId` is the canonical UUID string; its 16 raw bytes are the HKDF salt.
 */
export function deriveApiKek(keyId: string, apiKey: Uint8Array): Uint8Array {
  const prk = extract(sha256, apiKey, uuidToBytes(keyId));
  return expand(sha256, prk, utf8(HKDF_INFO_API_KEK), KEY_LEN);
}
