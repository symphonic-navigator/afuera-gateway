/**
 * Shared test fixtures (spec §9). The HKDF vector below was computed once
 * with @noble/hashes 2.3.0 and is pinned so any regression in derivation
 * (or a library swap) fails loudly.
 */

export function fixtureIkm(): Uint8Array {
  // 0x000102...1f — spec §9.1
  return new Uint8Array(32).map((_, i) => i);
}

/** HKDF-SHA256(ikm=0x0001..1f, salt="ag-root-v1", info="master-kek-v1", 32) */
export const EXPECTED_MASTER_KEK_HEX =
  "16be15d5e2e15bcd10389583e5072f08cf3c58864a809016459d66a8f83ebee8";

/** HKDF-SHA256(ikm=0x0001..1f, salt="ag-root-v1", info="auth-ed25519-seed-v1", 32) */
export const EXPECTED_AUTH_SEED_HEX =
  "c1f00567ce8688078b0caaf2c7436a8bc2cfb9ea9192c0fec8f1a5a408e60b1f";

/** BIP-39 mnemonic for entropy 0x0001..1f (English wordlist). */
export const EXPECTED_MNEMONIC_0001_1F =
  "abandon amount liar amount expire adjust cage candy arch gather drum bullet " +
  "absurd math era live bid rhythm alien crouch range attend journey unaware";
