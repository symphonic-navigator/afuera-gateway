/**
 * Key generation, derivation and DEK wrapping (spec §3, §5.1).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { decryptBlob, encryptBlob, wrapAAD, type WrapPurpose } from "./aead.js";
import { CryptoError } from "./errors.js";
import { deriveAuthSeed, deriveMasterKek } from "./hkdf.js";
import { randomBytes } from "./utils.js";

export const ROOT_SECRET_LEN = 32;
export const DEK_LEN = 32;
export const API_KEY_LEN = 32;

export interface AuthKeypair {
  publicKey: Uint8Array; // 32 B Ed25519 public key
  secretKey: Uint8Array; // 32 B Ed25519 seed (expanded on demand by noble)
}

/** Fresh 256-bit root secret from the CSPRNG (spec §5.1 step 1). */
export function generateRootSecret(): Uint8Array {
  return randomBytes(ROOT_SECRET_LEN);
}

/** Fresh 256-bit DEK from the CSPRNG (spec §5.1 step 8). */
export function generateDek(): Uint8Array {
  return randomBytes(DEK_LEN);
}

/** BIP-39 encode a root secret → 24 words (spec §5.1 step 2). */
export function rootSecretToMnemonic(rootSecret: Uint8Array): string {
  if (rootSecret.length !== ROOT_SECRET_LEN) {
    throw new CryptoError(
      "INVALID_FORMAT",
      `root secret must be ${ROOT_SECRET_LEN} bytes, got ${rootSecret.length}`,
    );
  }
  return entropyToMnemonic(rootSecret, wordlist);
}

/**
 * BIP-39 decode a 24-word mnemonic → root secret.
 * Throws `INVALID_FORMAT` on bad checksum or wrong word count.
 */
export function mnemonicToRootSecret(mnemonic: string): Uint8Array {
  const normalized = mnemonic.trim().split(/\s+/).join(" ");
  if (!validateMnemonic(normalized, wordlist)) {
    throw new CryptoError("INVALID_FORMAT", "invalid BIP-39 mnemonic");
  }
  const entropy = mnemonicToEntropy(normalized, wordlist);
  if (entropy.length !== ROOT_SECRET_LEN) {
    throw new CryptoError(
      "INVALID_FORMAT",
      `mnemonic must encode ${ROOT_SECRET_LEN} bytes (24 words)`,
    );
  }
  return entropy;
}

/** Derive the Ed25519 auth key pair from the root secret (spec §5.1 steps 4–6). */
export function deriveAuthKeypair(rootSecret: Uint8Array): AuthKeypair {
  const seed = deriveAuthSeed(rootSecret);
  return { publicKey: ed25519.getPublicKey(seed), secretKey: seed };
}

/**
 * Wrap a DEK under a KEK (spec §4.1 wrap format).
 * `purpose` is "master" or `api:<key_id>`; bound into the AAD together
 * with the DEK version.
 */
export function wrapDek(
  kek: Uint8Array,
  dek: Uint8Array,
  purpose: WrapPurpose,
  dekVersion: number,
): string {
  return encryptBlob(kek, dek, wrapAAD(purpose, dekVersion));
}

/**
 * Unwrap a DEK. Throws `TAG_MISMATCH` on key/AAD mismatch or corruption
 * (spec §9.2 — the AEAD layer cannot distinguish the two).
 */
export function unwrapDek(
  kek: Uint8Array,
  wrappedDekB64: string,
  purpose: WrapPurpose,
  dekVersion: number,
): Uint8Array {
  const dek = decryptBlob(kek, wrappedDekB64, wrapAAD(purpose, dekVersion));
  if (dek.length !== DEK_LEN) {
    throw new CryptoError("TAG_MISMATCH", `unwrapped DEK has ${dek.length} bytes, expected ${DEK_LEN}`);
  }
  return dek;
}

/** Master-path convenience wrappers (spec §5.1 step 9 / §5.2 step 7). */
export function wrapDekMaster(rootSecret: Uint8Array, dek: Uint8Array, dekVersion: number): string {
  return wrapDek(deriveMasterKek(rootSecret), dek, "master", dekVersion);
}

export function unwrapDekMaster(
  rootSecret: Uint8Array,
  wrappedDekMasterB64: string,
  dekVersion: number,
): Uint8Array {
  return unwrapDek(deriveMasterKek(rootSecret), wrappedDekMasterB64, "master", dekVersion);
}
