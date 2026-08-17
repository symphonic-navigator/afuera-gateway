/**
 * Small platform-neutral utilities: encoding, CSPRNG, memory hygiene.
 *
 * No Node-only APIs anywhere in this package — randomness comes from
 * `globalThis.crypto.getRandomValues`, which exists in browsers and in
 * Node >= 19 (WebCrypto global).
 */

import { CryptoError } from "./errors.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function utf8Decode(b: Uint8Array): string {
  return textDecoder.decode(b);
}

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_RE = /^[A-Za-z0-9\-_]*$/;

/** base64url (RFC 4648 §5), no padding. */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : undefined;
    out += B64URL_ALPHABET[b0 >> 2]!;
    out += B64URL_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)]!;
    if (b1 !== undefined) out += B64URL_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)]!;
    if (b2 !== undefined) out += B64URL_ALPHABET[b2 & 0x3f]!;
  }
  return out;
}

export function base64urlDecode(s: string): Uint8Array {
  if (!B64URL_RE.test(s) || s.length % 4 === 1) {
    throw new CryptoError("INVALID_FORMAT", "invalid base64url string");
  }
  const lookup = new Map<string, number>([...B64URL_ALPHABET].map((c, i) => [c, i]));
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 4) {
    const c0 = lookup.get(s[i]!)!;
    const c1 = i + 1 < s.length ? lookup.get(s[i + 1]!)! : 0;
    const c2 = i + 2 < s.length ? lookup.get(s[i + 2]!)! : 0;
    const c3 = i + 3 < s.length ? lookup.get(s[i + 3]!)! : 0;
    out.push((c0 << 2) | (c1 >> 4));
    if (i + 2 < s.length) out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
    if (i + 3 < s.length) out.push(((c2 & 0x03) << 6) | c3);
  }
  return new Uint8Array(out);
}

export function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexDecode(hex: string): Uint8Array {
  if (!/^([0-9a-fA-F]{2})*$/.test(hex)) {
    throw new CryptoError("INVALID_FORMAT", "invalid hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** CSPRNG bytes via WebCrypto (browser + Node 22). */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Best-effort erasure of sensitive material (spec §4.3). */
export function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}

/**
 * Constant-time-ish equality for same-length secrets (key hashes, tokens).
 * Not a hard guarantee under JIT, but avoids early-exit comparisons.
 * Lengths are treated as public.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Generate a random UUIDv4 string. */
export function uuidv4(): string {
  const b = randomBytes(16);
  b[6] = (b[6]! & 0x0f) | 0x40; // version 4
  b[8] = (b[8]! & 0x3f) | 0x80; // variant 10
  const h = hexEncode(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * Encode a UUID as its 16 raw bytes (network order, dashes stripped).
 * Used as the HKDF salt for API-KEK derivation (spec §3 / §5.3) — the
 * spec says "salt = key_id bytes"; we fix "bytes" to mean the canonical
 * 16-byte binary form of the UUID, not its ASCII representation.
 */
export function uuidToBytes(uuid: string): Uint8Array {
  if (!UUID_RE.test(uuid)) {
    throw new CryptoError("INVALID_FORMAT", `not a UUID: ${uuid}`);
  }
  return hexDecode(uuid.replaceAll("-", ""));
}

/** Inverse of {@link uuidToBytes}. */
export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new CryptoError("INVALID_FORMAT", "UUID must be 16 bytes");
  }
  const h = hexEncode(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
