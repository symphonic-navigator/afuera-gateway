/**
 * Session crypto for the Ollama uplink tunnel — ported byte-compatibly from
 * the ollama-uplink project (packages/protocol/src/crypto.ts).
 *
 * Session keys: HKDF-SHA256(ikm = SHA-256(PSK), salt = nonce_s || nonce_r,
 * info = "s2r" | "r2s"). Frames: XChaCha20-Poly1305 with a random 192-bit
 * nonce prepended, AAD = utf8(`${sessionId}:${direction}:${seq}`).
 */

import { randomBytes, randomUUID } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

export type Direction = "s2r" | "r2s";

export interface SessionKeys {
  s2r: Uint8Array;
  r2s: Uint8Array;
}

export interface FrameAad {
  sessionId: string;
  direction: Direction;
  seq: number;
}

export function sha256Hex(input: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(input))).toString("hex");
}

export function hashPsk(psk: string): Uint8Array {
  return sha256(new TextEncoder().encode(psk));
}

export function generateNonce(): Uint8Array {
  return randomBytes(16);
}

export function generateSessionId(): string {
  return randomUUID();
}

export function deriveSessionKeys(
  pskHash: Uint8Array,
  nonceS: Uint8Array,
  nonceR: Uint8Array,
): SessionKeys {
  const salt = new Uint8Array(nonceS.length + nonceR.length);
  salt.set(nonceS, 0);
  salt.set(nonceR, nonceS.length);
  return {
    s2r: hkdf(sha256, pskHash, salt, new TextEncoder().encode("s2r"), 32),
    r2s: hkdf(sha256, pskHash, salt, new TextEncoder().encode("r2s"), 32),
  };
}

function aadBytes(aad: FrameAad): Uint8Array {
  return new TextEncoder().encode(`${aad.sessionId}:${aad.direction}:${aad.seq}`);
}

export function encryptFrame(
  key: Uint8Array,
  aad: FrameAad,
  plaintext: Uint8Array,
): Uint8Array {
  const nonce = randomBytes(24);
  const ciphertext = xchacha20poly1305(key, nonce, aadBytes(aad)).encrypt(plaintext);
  const out = new Uint8Array(24 + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, 24);
  return out;
}

export function decryptFrame(key: Uint8Array, aad: FrameAad, frame: Uint8Array): Uint8Array {
  if (frame.length < 24 + 16) {
    throw new Error("frame too short");
  }
  const nonce = frame.subarray(0, 24);
  return xchacha20poly1305(key, nonce, aadBytes(aad)).decrypt(frame.subarray(24));
}
