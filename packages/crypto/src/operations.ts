/**
 * Operation-level crypto from spec §5 — the pure-crypto halves only.
 * Anything touching the network/server is returned as a payload for the
 * caller to transmit.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { decryptData, encryptData } from "./aead.js";
import {
  deriveAuthKeypair,
  generateDek,
  generateRootSecret,
  rootSecretToMnemonic,
  unwrapDekMaster,
  wrapDekMaster,
  type AuthKeypair,
} from "./keys.js";
import { deriveMasterKek } from "./hkdf.js";
import { base64urlEncode as b64url, concatBytes, utf8, uuidv4 } from "./utils.js";

export const LOGIN_DOMAIN = "ag-login-v1";
export const ROTATE_MASTER_DOMAIN = "ag-rotate-master-v1";

// ---------------------------------------------------------------------------
// §5.1 Initialization
// ---------------------------------------------------------------------------

/** Fields the client must send to the server to register (spec §5.1 step 10). */
export interface RegistrationPayload {
  userId: string;
  /** base64url Ed25519 public key */
  authPublicKey: string;
  /** base64url blob: DEK wrapped under the master KEK */
  wrappedDekMaster: string;
  dekVersion: number;
  masterVersion: number;
}

export interface InitializedUser {
  /** 24-word BIP-39 backup of the root secret — display ONCE. */
  mnemonic: string;
  rootSecret: Uint8Array;
  dek: Uint8Array;
  masterKek: Uint8Array;
  authKeypair: AuthKeypair;
  registration: RegistrationPayload;
}

/**
 * User onboarding (spec §5.1, crypto steps 1–9).
 * Step 3 (mnemonic confirmation) and step 10 (server registration) are
 * the caller's job; `registration` carries exactly what the server needs.
 */
export function initializeUser(): InitializedUser {
  const rootSecret = generateRootSecret();
  const mnemonic = rootSecretToMnemonic(rootSecret);
  const authKeypair = deriveAuthKeypair(rootSecret);
  const masterKek = deriveMasterKek(rootSecret);
  const dek = generateDek();
  const dekVersion = 1;
  const wrappedDekMaster = wrapDekMaster(rootSecret, dek, dekVersion);
  const userId = uuidv4();
  return {
    mnemonic,
    rootSecret,
    dek,
    masterKek,
    authKeypair,
    registration: {
      userId,
      authPublicKey: b64url(authKeypair.publicKey),
      wrappedDekMaster,
      dekVersion,
      masterVersion: 1,
    },
  };
}

// ---------------------------------------------------------------------------
// §5.2 Login (challenge-response) — crypto halves
// ---------------------------------------------------------------------------

export interface LoginKeyMaterial {
  authKeypair: AuthKeypair;
  masterKek: Uint8Array;
}

/** Re-derive auth keypair + master KEK from the root secret (spec §5.2 step 1). */
export function deriveLoginKeyMaterial(rootSecret: Uint8Array): LoginKeyMaterial {
  return { authKeypair: deriveAuthKeypair(rootSecret), masterKek: deriveMasterKek(rootSecret) };
}

/**
 * Challenge message (spec §5.2 step 3):
 *   utf8("ag-login-v1") || 0x00 || nonce || 0x00 || utf8(expires_at)
 * `nonce` is the raw 32-byte server challenge nonce; `expiresAt` is the
 * server-supplied ISO 8601 string, signed verbatim.
 */
export function buildLoginMessage(nonce: Uint8Array, expiresAt: string): Uint8Array {
  return concatBytes(
    utf8(LOGIN_DOMAIN),
    utf8("\0"),
    nonce,
    utf8("\0"),
    utf8(expiresAt),
  );
}

/** Sign the login challenge with the derived auth key (spec §5.2 step 4). */
export function signLoginChallenge(
  secretKey: Uint8Array,
  nonce: Uint8Array,
  expiresAt: string,
): Uint8Array {
  return ed25519.sign(buildLoginMessage(nonce, expiresAt), secretKey);
}

/** Verify a login challenge signature (used by the server side / tests). */
export function verifyLoginChallenge(
  publicKey: Uint8Array,
  nonce: Uint8Array,
  expiresAt: string,
  signature: Uint8Array,
): boolean {
  return ed25519.verify(signature, buildLoginMessage(nonce, expiresAt), publicKey);
}

// ---------------------------------------------------------------------------
// §5.6 Master key rotation — crypto half
// ---------------------------------------------------------------------------

/**
 * Rotation signature message (spec §5.6 step 6):
 *   utf8("ag-rotate-master-v1") || new_auth_public_key
 */
export function buildMasterRotationMessage(newAuthPublicKey: Uint8Array): Uint8Array {
  return concatBytes(utf8(ROTATE_MASTER_DOMAIN), newAuthPublicKey);
}

export interface MasterRotationResult {
  /** Backup for the NEW root secret — display ONCE. */
  newMnemonic: string;
  newRootSecret: Uint8Array;
  /** The unchanged DEK, recovered via the old master KEK. */
  dek: Uint8Array;
  /** Payload for Server.updateMasterKeys (spec §5.6 step 6). */
  update: {
    /** base64url Ed25519 public key derived from the new root secret */
    newAuthPublicKey: string;
    /** base64url blob: same DEK wrapped under the NEW master KEK */
    newWrappedDekMaster: string;
    /**
     * base64url signature from the OLD auth key over
     * "ag-rotate-master-v1" || new_auth_public_key — proves possession
     * of the old root secret.
     */
    rotationSignature: string;
  };
}

/**
 * Master rotation (spec §5.6 steps 1–6, crypto only).
 * Unwraps the DEK with the old root secret, generates a new root secret,
 * re-wraps, and signs the new public key with the OLD auth key.
 * `dek_version` is unchanged by design.
 */
export function rotateMaster(
  oldRootSecret: Uint8Array,
  wrappedDekMasterB64: string,
  dekVersion: number,
): MasterRotationResult {
  const dek = unwrapDekMaster(oldRootSecret, wrappedDekMasterB64, dekVersion);
  const oldKeypair = deriveAuthKeypair(oldRootSecret);
  const newRootSecret = generateRootSecret();
  const newMnemonic = rootSecretToMnemonic(newRootSecret);
  const newKeypair = deriveAuthKeypair(newRootSecret);
  const newWrappedDekMaster = wrapDekMaster(newRootSecret, dek, dekVersion);
  const rotationSignature = ed25519.sign(
    buildMasterRotationMessage(newKeypair.publicKey),
    oldKeypair.secretKey,
  );
  return {
    newMnemonic,
    newRootSecret,
    dek,
    update: {
      newAuthPublicKey: b64url(newKeypair.publicKey),
      newWrappedDekMaster,
      rotationSignature: b64url(rotationSignature),
    },
  };
}

/** Verify a master-rotation signature against the OLD public key (server side / tests). */
export function verifyMasterRotationSignature(
  oldAuthPublicKey: Uint8Array,
  newAuthPublicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  return ed25519.verify(signature, buildMasterRotationMessage(newAuthPublicKey), oldAuthPublicKey);
}

// ---------------------------------------------------------------------------
// §5.7 DEK rotation — crypto helpers
// ---------------------------------------------------------------------------

/**
 * Re-encrypt one data blob under a new DEK / new dek_version
 * (spec §5.7 step 4). Throws TAG_MISMATCH if the blob does not
 * authenticate under the old context.
 */
export function reEncryptDataBlob(
  oldDek: Uint8Array,
  newDek: Uint8Array,
  blobB64: string,
  userId: string,
  recordType: string,
  oldDekVersion: number,
  newDekVersion: number,
): string {
  const plaintext = decryptData(oldDek, blobB64, userId, recordType, oldDekVersion);
  return encryptData(newDek, plaintext, userId, recordType, newDekVersion);
}

/** Re-wrap a fresh DEK for the master path (spec §5.7 step 5). */
export function rewrapDekForMaster(
  rootSecret: Uint8Array,
  newDek: Uint8Array,
  newDekVersion: number,
): string {
  return wrapDekMaster(rootSecret, newDek, newDekVersion);
}
