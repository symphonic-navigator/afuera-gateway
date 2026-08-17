/**
 * XChaCha20-Poly1305 blob encryption per spec §4.1 and §5.5.
 *
 * Blob format (before base64url):
 *   version (1 B, 0x01) || nonce (24 B, random) || ciphertext || tag (16 B)
 *
 * AAD:
 *   data:  utf8(user_id) || 0x00 || utf8(record_type) || 0x00 || utf8(dek_version)
 *   wrap:  utf8("dek-wrap") || 0x00 || utf8(purpose) || 0x00 || utf8(dek_version)
 *          purpose ∈ { "master", "api:<key_id>" }
 *
 * `dek_version` is encoded as its decimal string ("1", "2", ...) per the
 * spec's utf8(dek_version) wording.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CryptoError } from "./errors.js";
import { base64urlDecode, base64urlEncode, concatBytes, randomBytes, utf8 } from "./utils.js";

export const BLOB_VERSION = 0x01;
export const NONCE_LEN = 24;
export const TAG_LEN = 16;
/** version || nonce || tag — minimum blob overhead. */
export const BLOB_OVERHEAD = 1 + NONCE_LEN + TAG_LEN;

/** AAD for user data blobs (spec §4.1). */
export function dataAAD(userId: string, recordType: string, dekVersion: number): Uint8Array {
  return concatBytes(utf8(userId), utf8("\0"), utf8(recordType), utf8("\0"), utf8(String(dekVersion)));
}

export type WrapPurpose = "master" | `api:${string}`;

/** AAD for DEK wrapping (spec §4.1). */
export function wrapAAD(purpose: WrapPurpose, dekVersion: number): Uint8Array {
  return concatBytes(
    utf8("dek-wrap"),
    utf8("\0"),
    utf8(purpose),
    utf8("\0"),
    utf8(String(dekVersion)),
  );
}

/**
 * Encrypt `plaintext` under `key` with a fresh random 192-bit nonce,
 * returning the base64url-encoded blob (spec §5.5 encryptData).
 */
export function encryptBlob(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): string {
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return base64urlEncode(concatBytes(new Uint8Array([BLOB_VERSION]), nonce, ct));
}

/**
 * Decrypt a base64url blob (spec §5.5 decryptData).
 *
 * Throws `UNSUPPORTED_VERSION` if the version byte is not 0x01,
 * `INVALID_FORMAT` on malformed input, and `TAG_MISMATCH` on any AEAD
 * failure (wrong key, wrong AAD, tampered ciphertext/tag).
 */
export function decryptBlob(key: Uint8Array, blobB64: string, aad: Uint8Array): Uint8Array {
  const blob = base64urlDecode(blobB64);
  if (blob.length < BLOB_OVERHEAD) {
    throw new CryptoError("INVALID_FORMAT", `blob too short: ${blob.length} bytes`);
  }
  if (blob[0] !== BLOB_VERSION) {
    throw new CryptoError(
      "UNSUPPORTED_VERSION",
      `unsupported blob version 0x${blob[0]!.toString(16).padStart(2, "0")}`,
    );
  }
  const nonce = blob.subarray(1, 1 + NONCE_LEN);
  const ct = blob.subarray(1 + NONCE_LEN);
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ct);
  } catch (cause) {
    throw new CryptoError("TAG_MISMATCH", "authentication tag mismatch", { cause });
  }
}

/** Convenience: encrypt UTF-8 text as a data blob (spec §5.5). */
export function encryptData(
  dek: Uint8Array,
  plaintext: Uint8Array,
  userId: string,
  recordType: string,
  dekVersion: number,
): string {
  return encryptBlob(dek, plaintext, dataAAD(userId, recordType, dekVersion));
}

/** Convenience: decrypt a data blob (spec §5.5). Throws TAG_MISMATCH on failure. */
export function decryptData(
  dek: Uint8Array,
  blobB64: string,
  userId: string,
  recordType: string,
  dekVersion: number,
): Uint8Array {
  return decryptBlob(dek, blobB64, dataAAD(userId, recordType, dekVersion));
}
