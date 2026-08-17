# Auth & Crypto Layer Specification — E2EE with Multi-Key Access

> Version: 0.2.0
> Status: Accepted (foundation layer — to be fully implemented and tested before any business logic)
> Scope: Cryptographic foundation for client-side end-to-end encryption with server-side key wrapping, API-key-based access delegation, and key rotation.
> Stack: TypeScript / Vite / React (client), Node (backend), SQLite (storage)

---

## 1. Design Goals

| Goal | Description |
|------|-------------|
| **E2EE** | The server never sees user data or keys in plaintext. |
| **Multi-Key Access** | Multiple API keys can independently unlock the same DEK. |
| **Master Key Rotation** | The root secret can be rotated without re-encrypting data or re-issuing API keys. |
| **DEK Rotation** | The DEK itself can be rotated (data re-encryption) to heal compromise. |
| **Zero-Knowledge Server** | The server stores only public keys, key hashes, and wrapped keys. |
| **Deterministic Key Derivation, Randomized Encryption** | Key derivation from the same inputs is reproducible (testability); all encryption uses fresh random nonces. Determinism MUST NEVER extend to nonces. |
| **Single AEAD Primitive** | XChaCha20-Poly1305 is used for data encryption AND key wrapping. No AES, no WebCrypto dependency. |
| **Human-Readable Backup** | The root secret is encodable as a BIP-39 mnemonic for backup and onboarding. |

---

## 2. Cryptographic Primitives

### 2.1 Algorithms

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| **KDF** | HKDF-SHA-256 | RFC 5869, extract-then-expand; single extract per secret, domain separation via `info` labels |
| **Data encryption** | XChaCha20-Poly1305 | 192-bit (24-byte) random nonce, 128-bit Poly1305 tag |
| **Key wrapping** | XChaCha20-Poly1305 | Same primitive as data encryption — one AEAD everywhere |
| **API key lookup hash** | SHA-256 | Hex-encoded; safe because keys carry 256 bits of entropy |
| **Authentication signature** | Ed25519 | Key pair derived deterministically from root secret |
| **Mnemonic encoding** | BIP-39 | 24 words (256 bits entropy) ↔ root secret |
| **CSPRNG** | `crypto.getRandomValues` (browser) / `crypto.randomBytes` (Node) | — |

> **Note on the AES-256-KW → XChaCha20-Poly1305 change (v0.2.0):** RFC 3394 AES-KW was dropped deliberately. Using one AEAD for both data and key wrapping removes the entire AES/WebCrypto dependency, and random 192-bit nonces make nonce-reuse concerns negligible. AEAD wrapping provides the same confidentiality plus stronger integrity (Poly1305 tag vs. AIV).

### 2.2 Recommended Libraries

| Package | Purpose | Runs on |
|---------|---------|---------|
| `@noble/ciphers` | XChaCha20-Poly1305 | Browser + Node |
| `@noble/hashes` | HKDF-SHA-256, SHA-256 | Browser + Node |
| `@noble/curves` | Ed25519 | Browser + Node |
| `@scure/bip39` | Mnemonic encoding/decoding | Browser + Node |

All are audited, dependency-free, pure TypeScript. The SAME stack is used client- and server-side, so test vectors and implementations are shared.

### 2.3 Key Sizes

| Key | Size | Description |
|-----|------|-------------|
| Root Secret | 256 bit (32 B) | Never leaves the client; encodable as 24-word mnemonic |
| Master KEK | 256 bit (32 B) | Derived from root secret via HKDF |
| API Key | 256 bit (32 B) | Randomly generated; server stores only its hash |
| API KEK | 256 bit (32 B) | Derived from API key via HKDF |
| DEK | 256 bit (32 B) | Random per user; encrypts all user data |
| Auth key pair | Ed25519 | Seed derived from root secret |

---

## 3. Key Hierarchy

```
┌──────────────────────────────────────────┐
│        Root Secret (256 bit)             │  ← client only, never transmitted
│   CSPRNG-generated, BIP-39-encodable     │
└──────────────────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  HKDF-Extract        │
        │  salt = "ag-root-v1" │
        └──────────────────────┘
                   │ PRK
        ┌──────────┴──────────┐
        ▼                     ▼
  HKDF-Expand             HKDF-Expand
  info="auth-ed25519-     info="master-kek-v1"
       seed-v1"
        │                     │
        ▼                     ▼
┌──────────────┐      ┌──────────────┐
│ Auth seed    │      │ Master KEK   │
│ (Ed25519)    │      │ (32 B)       │
└──────────────┘      └──────────────┘
        │                     │
        ▼                     ▼
   Signature             DEK wrapping
   (login)               (XChaCha20-Poly1305)
```

```
┌──────────────────────────────────────────┐
│          API Key (256 bit, random)       │  ← one per API key, shown once
└──────────────────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  HKDF-Extract        │
        │  salt = key_id bytes │
        └──────────────────────┘
                   │
                   ▼
        HKDF-Expand
        info = "api-kek-v1"
                   │
                   ▼
            ┌──────────────┐
            │   API KEK    │
            │   (32 B)     │
            └──────────────┘
                   │
                   ▼
             DEK wrapping
       (XChaCha20-Poly1305)
```

**Domain separation rules:**
- HKDF salts are fixed protocol constants (versioned, e.g. `"ag-root-v1"`). They are NOT secrets.
- All context separation happens via `info` labels. Every derived key has its own versioned `info` string.
- Bumping a protocol version (e.g. `"-v1"` → `"-v2"`) produces an entirely new key space.

---

## 4. Data Structures

### 4.1 Blob Format (all encrypted payloads)

```
version  (1 byte)   — 0x01 = XChaCha20-Poly1305
nonce    (24 bytes) — random per encryption
ciphertext (n bytes)
tag      (16 bytes) — Poly1305

blob = version || nonce || ciphertext || tag
encoded as base64url for storage/transport
```

The version byte makes future algorithm or format migration possible without guessing.

**AAD (Additional Authenticated Data)** — every encryption binds context:

```
AAD = utf8(user_id) || 0x00 || utf8(record_type) || 0x00 || utf8(dek_version)
```

This prevents the server (or an attacker with DB access) from swapping ciphertexts between users, fields, or key versions — decryption fails if the context doesn't match.

For key wrapping, the AAD is:

```
AAD_wrap = utf8("dek-wrap") || 0x00 || utf8(purpose) || 0x00 || utf8(dek_version)
-- purpose ∈ { "master", "api:<key_id>" }
```

### 4.2 Server-Side Storage (per user)

```typescript
interface UserCryptoRecord {
  user_id: string;                 // UUIDv4

  // Authentication
  auth_public_key: string;         // Ed25519 public key (base64url)

  // Encrypted data
  encrypted_data_blob: string;     // blob format §4.1, encrypted under DEK

  // DEK wrappers
  wrapped_dek_master: string;      // blob format §4.1, encrypted under Master KEK

  // Versioning
  dek_version: number;             // monotonically increasing, bump on DEK rotation
  master_version: number;          // monotonically increasing, bump on master rotation
  created_at: string;              // ISO 8601
  updated_at: string;              // ISO 8601
}

interface ApiKeyRecord {
  key_id: string;                  // UUIDv4
  user_id: string;                 // FK → UserCryptoRecord
  key_hash: string;                // SHA-256(api_key) hex — lookup index
  wrapped_dek: string;             // blob format §4.1, encrypted under API KEK
  expires_at: string | null;       // ISO 8601, null = no expiry
  created_at: string;
  last_used_at: string | null;
  revoked: boolean;                // soft delete
}

// Separate permissions table — controls what an API key may do,
// both cryptographically (can it get the DEK?) and at application level.
interface ApiKeyPermission {
  key_id: string;                  // FK → ApiKeyRecord
  scope: string;                   // e.g. "data:read", "data:write", "keys:manage"
  granted_at: string;              // ISO 8601
}
```

Scope naming scheme: `<resource>:<action>`. The set of valid scopes is defined by the application layer (separate spec); the crypto layer only enforces the two scopes it owns:

| Scope | Meaning |
|-------|---------|
| `data:read` | Server may hand out `wrapped_dek` for this key |
| `data:write` | Key may write/replace `encrypted_data_blob` |
| `keys:manage` | Key may create/revoke other API keys (reserved, not issued in v1) |

A key without `data:read` can authenticate but never receives a wrapped DEK.

### 4.3 Client-Side State

```typescript
interface ClientCryptoState {
  root_secret: Uint8Array;         // 32 B
  master_kek: Uint8Array;          // 32 B, derived — re-derivable, no need to persist
  dek: Uint8Array | null;          // 32 B, only after unwrap
  auth_keypair: {                  // Ed25519
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };
}
```

**Persistence decision (accepted risk):** The root secret MAY be cached base64url-encoded in `sessionStorage` (per-tab, cleared on tab close) so that page reloads don't require re-entering the mnemonic. Client-side compromise is an accepted risk (see §7 Threat Model). The root secret MUST NOT be written to `localStorage`, cookies, IndexedDB, or any server endpoint.

Sensitive material SHOULD be zeroed from memory on logout (`TypedArray.fill(0)`).

---

## 5. Operations

### 5.1 Initialization (User Onboarding)

```
function initializeUser():
Input:  —
Output: { mnemonic, user_id }

Steps:
1. root_secret        ← CSPRNG(32)
2. mnemonic           ← BIP39.encode(root_secret)      // 24 words
3. Display mnemonic to user ONCE; require confirmation (re-entry or word quiz)
4. prk                ← HKDF-Extract(salt="ag-root-v1", ikm=root_secret)
5. auth_seed          ← HKDF-Expand(prk, info="auth-ed25519-seed-v1", 32)
6. auth_keypair       ← Ed25519.fromSeed(auth_seed)
7. master_kek         ← HKDF-Expand(prk, info="master-kek-v1", 32)
8. dek                ← CSPRNG(32)
9. wrapped_dek_master ← XChaCha20-Poly1305.encrypt(master_kek, dek, aad=wrapAAD("master", 1))
10. Register on server:
    user_id (new UUIDv4), auth_public_key, wrapped_dek_master,
    dek_version=1, master_version=1
11. Cache root_secret in sessionStorage (optional, §4.3)
```

### 5.2 Login (Challenge-Response)

```
function login(user_id, root_secret):
Input:  user_id, root_secret (from mnemonic entry or sessionStorage)
Output: { session, dek }

Steps:
1. Re-derive auth_keypair and master_kek as in §5.1 steps 4–7
2. { nonce, expires_at } ← Server.getChallenge(user_id)
   // server: nonce = CSPRNG(32), single-use, TTL ≤ 60 s
3. message  ← utf8("ag-login-v1") || 0x00 || nonce || 0x00 || utf8(expires_at)
4. signature ← Ed25519.sign(secretKey, message)
5. session ← Server.verifyChallenge(user_id, signature, nonce)
   // server: marks nonce consumed atomically BEFORE verifying;
   // verifies signature against stored auth_public_key;
   // issues tokens on success (§5.9)
6. wrapped_dek_master ← Server.getWrappedDekMaster(user_id, session)
7. dek ← XChaCha20-Poly1305.decrypt(master_kek, wrapped_dek_master,
                                    aad=wrapAAD("master", dek_version))
8. return { session, dek }
```

Failure at step 5 or 7 is indistinguishable from "user does not exist" to the caller.

### 5.3 Create API Key

```
function createApiKey(session, dek, scopes[], expires_at):
Input:  session, dek, requested scopes, optional expiry
Output: { api_key_plaintext, key_id }

Steps:
1. api_key_plaintext ← CSPRNG(32)
2. key_id            ← UUIDv4()
3. prk               ← HKDF-Extract(salt=bytes(key_id), ikm=api_key_plaintext)
4. api_kek           ← HKDF-Expand(prk, info="api-kek-v1", 32)
5. wrapped_dek_api   ← XChaCha20-Poly1305.encrypt(api_kek, dek,
                          aad=wrapAAD("api:"+key_id, dek_version))
6. key_hash          ← SHA-256(api_key_plaintext) hex
7. Server.storeApiKey(user_id, key_id, key_hash, wrapped_dek_api,
                      scopes, expires_at)
   // server validates requested scopes against the caller's own scopes
8. return { api_key_plaintext, key_id }
   → api_key_plaintext is displayed EXACTLY ONCE. Format for display:
     "agk_" + base64url(key_id) + "." + base64url(api_key_plaintext)
```

### 5.4 API Key Access (Data Read)

```
function decryptWithApiKey(api_key_token):     // the full "agk_..." string
Input:  api_key_token
Output: { dek, scopes }

Steps:
1. Parse token → key_id, api_key_plaintext
2. api_kek  ← HKDF as in §5.3 steps 3–4
3. key_hash ← SHA-256(api_key_plaintext) hex
4. record   ← Server.getWrappedDekByHash(key_hash)
   // server checks: hash exists, not revoked, not expired,
   // scope "data:read" present — otherwise uniform 401
   // server updates last_used_at, enforces rate limit
5. dek ← XChaCha20-Poly1305.decrypt(api_kek, record.wrapped_dek,
                                    aad=wrapAAD("api:"+key_id, record.dek_version))
6. return { dek, scopes: record.scopes }
```

### 5.5 Encrypt / Decrypt Data

```
function encryptData(dek, plaintext, user_id, record_type, dek_version):
1. aad  ← utf8(user_id) || 0x00 || utf8(record_type) || 0x00 || utf8(dek_version)
2. nonce ← CSPRNG(24)
3. ct   ← XChaCha20-Poly1305.encrypt(dek, nonce, plaintext, aad)
4. return base64url(0x01 || nonce || ct)        // blob format §4.1

function decryptData(dek, blob_b64, user_id, record_type, dek_version):
1. blob ← base64url.decode(blob_b64)
2. require blob[0] == 0x01
3. nonce ← blob[1:25]; ct ← blob[25:]
4. aad  ← (as above; MUST match encryption context)
5. return XChaCha20-Poly1305.decrypt(dek, nonce, ct, aad)
   // throws AUTH_FAILED on tag mismatch
```

### 5.6 Master Key Rotation

Rotates the root secret. Data and API keys stay untouched — only the master wrapper and auth key change.

```
function rotateMasterKey(session, old_root_secret):
Output: { new_mnemonic }

Steps:
1. dek ← unwrap via old master KEK (as in §5.2 steps 6–7)
2. new_root_secret ← CSPRNG(32)
3. new_mnemonic    ← BIP39.encode(new_root_secret)
4. Derive new auth_keypair, new master_kek (as in §5.1)
5. new_wrapped_dek_master ← encrypt(new_master_kek, dek,
                                    aad=wrapAAD("master", dek_version))
6. Server.updateMasterKeys(user_id,
       new_auth_public_key, new_wrapped_dek_master,
       master_version += 1)
   // MUST be authenticated by a signature from the OLD auth key
   // over the new public key: sign("ag-rotate-master-v1" || new_auth_public_key)
7. Invalidate all sessions and refresh tokens for the user
8. Display new_mnemonic ONCE; require confirmation
9. return { new_mnemonic }
```

**Important:** `dek_version` does NOT change. API keys and `encrypted_data_blob` are unaffected.

### 5.7 DEK Rotation (Compromise Healing)

Rotates the DEK itself: all data is re-encrypted and all wrappers are re-created. Requires the master path (root secret), not an API key.

```
function rotateDek(session, root_secret):
Output: { new_dek_version }

Steps:
1. old_dek ← unwrap via master KEK
2. new_dek ← CSPRNG(32)
3. new_version ← dek_version + 1

   // Re-encrypt all user data
4. for each encrypted_data_blob owned by the user:
     plaintext ← decryptData(old_dek, blob, user_id, type, dek_version)
     new_blob  ← encryptData(new_dek, plaintext, user_id, type, new_version)
     stage(new_blob)
   // processed in batches server-side via upload/download;
   // MUST be transactional or resumable per blob

   // Re-wrap for master
5. new_wrapped_dek_master ← encrypt(master_kek, new_dek,
                                    aad=wrapAAD("master", new_version))

   // Re-wrap for every active API key — requires each API KEK,
   // which the client does NOT have. Therefore:
6. The server CANNOT re-wrap for API keys itself (zero-knowledge).
   → DEK rotation INVALIDATES all existing API keys.
   → Mark all ApiKeyRecords revoked; re-issue keys as needed (§5.3).

7. Server.commitDekRotation(user_id, new_wrapped_dek_master,
       new_version, staged_blobs, revoke_all_api_keys)
   // single transaction: bump dek_version, swap blobs, revoke keys
8. return { new_dek_version }
```

**Design note:** invalidating API keys on DEK rotation is deliberate — the server is zero-knowledge and cannot re-wrap without the API KEKs, and a rotation typically happens precisely because key material may have leaked. Callers re-provision keys afterwards.

### 5.8 Revoke API Key

```
function revokeApiKey(session, key_id):
1. Server.revokeApiKey(user_id, key_id)   // sets revoked = true
2. Revoked keys fail uniformly at §5.4 step 4 (401, no detail)
```

### 5.9 Session Tokens

- Access token: opaque random 256-bit, 15 min TTL, held in memory only.
- Refresh token: opaque random 256-bit, 30 days, rotating on use, delivered as `httpOnly; Secure; SameSite=Strict` cookie.
- Token store server-side: hashed (SHA-256) tokens, never plaintext.
- Master rotation invalidates all tokens (§5.6 step 7).

---

## 6. Security Requirements

### 6.1 Must-Have

- [ ] Root secret never leaves the client; only derived material is used for auth.
- [ ] API keys are displayed exactly once in plaintext; server stores only the SHA-256 hash.
- [ ] DEK is never transmitted or stored unwrapped.
- [ ] Every encryption uses a fresh random 192-bit nonce (never construct nonces deterministically).
- [ ] Every decryption verifies the Poly1305 tag AND the expected AAD context.
- [ ] Challenge nonces are single-use, consumed atomically, TTL ≤ 60 s.
- [ ] Rate limiting on login challenge verification and API key validation (per IP and per user/key). **Must-have** — hash-lookup enumeration is the only server-side attack surface for keys.
- [ ] Uniform error responses: wrong key / revoked key / unknown user / expired key are indistinguishable (401).
- [ ] All transport over TLS 1.3.
- [ ] Strict CSP, no third-party scripts on authenticated pages (see §7, XSS).

### 6.2 Should-Have

- [ ] Audit log (append-only) for: login, key creation, key revocation, master rotation, DEK rotation, failed auth attempts.
- [ ] Hardware-backed storage of root secret where available (future).
- [ ] Anomaly alerting on `DEK_UNWRAP_FAILED` / `AUTH_FAILED` spikes.

### 6.3 Must-NOT

- [ ] No fallback/recovery mechanism that gives the server access to the DEK.
- [ ] No key derivation from human-chosen passwords (only full-entropy 256-bit secrets).
- [ ] Root secret never in `localStorage`, cookies, logs, error reports, or analytics.
- [ ] No deterministic nonces anywhere.

---

## 7. Threat Model

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| Server database leak | Zero-knowledge: only public keys, hashes, wrapped keys stored | Offline brute-force of API keys infeasible (256-bit entropy) |
| Passive network observer | TLS 1.3, all payloads ciphertext | — |
| Stolen API key | Scoped permissions, expiry, revocation, `last_used_at` audit | Full `data:read` keys still grant read access — prefer narrow scopes |
| Lost root secret | 24-word mnemonic IS the backup | If lost with no mnemonic: unrecoverable **by design** |
| Compromised DEK | DEK rotation (§5.7) re-encrypts all data, revokes all API keys | Data exfiltrated before rotation stays exposed |
| **Malicious server serving backdoored client code** | — | **Accepted** (classic web-E2EE limitation). Future: reproducible builds, code signing, native app |
| **XSS in client** | Strict CSP, no third-party scripts, tokens in memory, `sessionStorage` only | **Accepted** per project decision: client-side security is prioritized below server-side; sessionStorage caching of the root secret is a deliberate trade-off |
| Timing/enumeration via hash lookup | Uniform 401s, rate limiting | Low |

---

## 8. Error Handling

| Error | Cause | Response |
|-------|-------|----------|
| `AUTH_FAILED` | Wrong root secret, bad signature, or unknown user | Uniform 401, no user-existence signal |
| `WRONG_API_KEY` | Hash mismatch / revoked / expired / missing scope | Uniform 401, rate-limited |
| `DEK_UNWRAP_FAILED` | Corrupt wrapper or key mismatch | 500, admin alert, audit entry |
| `TAG_MISMATCH` | Data corrupted in storage/transport OR wrong DEK OR manipulated ciphertext | Surface integrity error to user; distinguish "corruption" (single blob) from "tampering pattern" (multiple blobs → alert) |
| `CHALLENGE_EXPIRED` | Nonce TTL exceeded | Retry login flow |
| `ROTATION_INCOMPLETE` | DEK rotation interrupted mid-batch | Resume from per-blob state; never half-commit |

---

## 9. Test Vectors

All vectors are deterministic and shared between client and server tests.

### 9.1 HKDF Derivation

```
ikm   = 0x000102...1f  (32 bytes)
salt  = "ag-root-v1"
info  = "master-kek-v1"
out   = HKDF-SHA256(ikm, salt, info, 32)
→ expected value: constant in test fixtures, must reproduce identically
   in browser and Node implementations
```

### 9.2 Wrapping Roundtrip

```
kek     = 0xaabbcc...  (32 bytes)
dek     = 0x010203...  (32 bytes)
wrapped = encrypt(kek, dek, aad=wrapAAD("master", 1))
decrypt(kek, wrapped, same aad) === dek          // must hold
decrypt(kek, wrapped, aad with dek_version=2)    // must throw TAG_MISMATCH
```

### 9.3 Mnemonic Roundtrip

```
root_secret = 0x000102...1f
mnemonic    = BIP39.encode(root_secret)     // 24 words
BIP39.decode(mnemonic) === root_secret      // must hold
```

### 9.4 Tamper Detection

```
blob = encryptData(dek, "hello", user, "record", 1)
flip any byte in ciphertext → decryptData must throw TAG_MISMATCH
swap AAD user_id           → decryptData must throw TAG_MISMATCH
```

---

## 10. Resolved & Open Questions

**Resolved in v0.2.0:**
- ~~Cipher choice~~ → XChaCha20-Poly1305 everywhere (incl. wrapping), no AES.
- ~~DEK rotation~~ → specified in §5.7, invalidates API keys by design.
- ~~API key scoping~~ → `ApiKeyPermission` table + `expires_at` (§4.2).
- ~~Backup/recovery~~ → BIP-39 mnemonic IS the recovery mechanism; no server-side fallback.
- ~~Reload behavior~~ → root secret cached in `sessionStorage` (accepted risk, §4.3).
- ~~Forward secrecy of old wraps~~ → non-issue since master rotation keeps the same DEK; DEK rotation (the real healing path) revokes everything.

**Open (deferred to application layer):**
1. **Full scope vocabulary** — the complete `<resource>:<action>` catalogue is owned by the business-logic spec; the crypto layer only enforces `data:read` / `data:write` / `keys:manage`.
2. **Multi-device** — solved trivially by mnemonic entry per device; no device-linking protocol for now.
3. **`keys:manage` delegation** — reserved, not issued in v1.

---

## 11. Change History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-08-16 | Initial draft |
| 0.2.0 | 2026-08-16 | Security review: XChaCha20-Poly1305 replaces AES-GCM/AES-KW (single AEAD, 192-bit nonces); HKDF restructured (single extract, info-label separation); AAD context binding; blob version byte; DEK rotation operation (§5.7); API key scopes + expiry via permissions table; BIP-39 mnemonic backup; hardened challenge-response (domain separation, single-use nonces); sessionStorage decision + threat model; uniform auth errors; rate limiting promoted to must-have |
