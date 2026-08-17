/**
 * Typed errors for @afuera/crypto.
 *
 * Codes mirror spec §8 where the crypto layer can produce them.
 * `AUTH_FAILED`, `WRONG_API_KEY`, `CHALLENGE_EXPIRED` and
 * `ROTATION_INCOMPLETE` are server-side conditions listed here so that
 * client code can share one error vocabulary; the crypto core itself
 * throws `TAG_MISMATCH`, `UNSUPPORTED_VERSION` and `INVALID_FORMAT`.
 *
 * Note (spec §9.2): a failed DEK unwrap surfaces as `TAG_MISMATCH` —
 * the AEAD layer cannot distinguish "corrupt wrapper" from "wrong key",
 * and the spec's test vectors require TAG_MISMATCH on AAD mismatch even
 * for wrapping. `DEK_UNWRAP_FAILED` is reserved for the server/audit
 * layer which has the context to make that distinction.
 */
export const CRYPTO_ERROR_CODES = [
  "AUTH_FAILED",
  "WRONG_API_KEY",
  "DEK_UNWRAP_FAILED",
  "TAG_MISMATCH",
  "CHALLENGE_EXPIRED",
  "ROTATION_INCOMPLETE",
  "INVALID_FORMAT",
  "UNSUPPORTED_VERSION",
] as const;

export type CryptoErrorCode = (typeof CRYPTO_ERROR_CODES)[number];

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CryptoError";
    this.code = code;
  }
}

export function isCryptoError(err: unknown, code?: CryptoErrorCode): err is CryptoError {
  return err instanceof CryptoError && (code === undefined || err.code === code);
}
