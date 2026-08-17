/**
 * @afuera/crypto — cryptographic foundation layer for afuera-gateway.
 *
 * Implements docs/specs/auth-crypto.md v0.2.0:
 *  - HKDF-SHA-256 key hierarchy (§3)
 *  - XChaCha20-Poly1305 blob format + AAD context binding (§4.1, §5.5)
 *  - BIP-39 mnemonic backup of the root secret (§5.1)
 *  - Ed25519 challenge-response login and rotation signatures (§5.2, §5.6)
 *  - API-key creation / DEK unwrap (§5.3, §5.4)
 *  - Master and DEK rotation crypto helpers (§5.6, §5.7)
 *
 * Pure crypto only — no network, no storage, no Node-only APIs.
 */

export { CryptoError, isCryptoError, CRYPTO_ERROR_CODES } from "./errors.js";
export type { CryptoErrorCode } from "./errors.js";

export {
  utf8,
  utf8Decode,
  base64urlEncode,
  base64urlDecode,
  hexEncode,
  hexDecode,
  randomBytes,
  zeroize,
  constantTimeEqual,
  concatBytes,
  uuidv4,
  uuidToBytes,
  bytesToUuid,
} from "./utils.js";

export {
  HKDF_SALT_ROOT,
  HKDF_INFO_AUTH_ED25519_SEED,
  HKDF_INFO_MASTER_KEK,
  HKDF_INFO_API_KEK,
  deriveRootPrk,
  deriveAuthSeed,
  deriveMasterKek,
  deriveApiKek,
} from "./hkdf.js";

export {
  BLOB_VERSION,
  NONCE_LEN,
  TAG_LEN,
  BLOB_OVERHEAD,
  dataAAD,
  wrapAAD,
  encryptBlob,
  decryptBlob,
  encryptData,
  decryptData,
} from "./aead.js";
export type { WrapPurpose } from "./aead.js";

export {
  ROOT_SECRET_LEN,
  DEK_LEN,
  API_KEY_LEN,
  generateRootSecret,
  generateDek,
  rootSecretToMnemonic,
  mnemonicToRootSecret,
  deriveAuthKeypair,
  wrapDek,
  unwrapDek,
  wrapDekMaster,
  unwrapDekMaster,
} from "./keys.js";
export type { AuthKeypair } from "./keys.js";

export {
  API_KEY_TOKEN_PREFIX,
  createApiKey,
  parseApiKeyToken,
  unwrapDekWithApiKey,
} from "./apikey.js";
export type { CreatedApiKey, ParsedApiKeyToken } from "./apikey.js";

export {
  LOGIN_DOMAIN,
  ROTATE_MASTER_DOMAIN,
  initializeUser,
  deriveLoginKeyMaterial,
  buildLoginMessage,
  signLoginChallenge,
  verifyLoginChallenge,
  buildMasterRotationMessage,
  rotateMaster,
  verifyMasterRotationSignature,
  reEncryptDataBlob,
  rewrapDekForMaster,
} from "./operations.js";
export type {
  RegistrationPayload,
  InitializedUser,
  LoginKeyMaterial,
  MasterRotationResult,
} from "./operations.js";
