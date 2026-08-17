# Auth REST API Reference

> Server-side counterpart of `auth-crypto.md` (§5 operations, §6 security, §8 errors).
> Implemented by `apps/server`. The server is **zero-knowledge**: it verifies
> Ed25519 signatures and stores hashes/wrapped blobs only. Plaintext keys and
> unwrapped DEKs never cross the wire.

Base path: `/v1`. All bodies are JSON. Binary values (public keys, nonces,
signatures, encrypted blobs) are base64url-encoded strings.

---

## Error contract

| Status | Body | Meaning |
|--------|------|---------|
| 400 | `{ "error": "bad_request" }` | Malformed body (missing/invalid fields) |
| 400 | `{ "error": "invalid_scope" }` | Unknown or reserved scope requested (incl. `keys:manage`) |
| 400 | `{ "error": "incomplete_rotation" }` | DEK rotation did not stage exactly the existing gateway-credential set (gateway.md §7) or the existing HF credential (hfif.md §7) |
| 401 | `{ "error": "unauthorized" }` | **Uniform** — unknown user, bad signature, revoked/expired key, missing scope are indistinguishable |
| 404 | `{ "error": "not_found" }` | Unknown or foreign resource (e.g. revoking another user's key) |
| 409 | `{ "error": "conflict" }` | Duplicate registration / duplicate `key_id` or `key_hash` |
| 409 | `{ "error": "version_conflict" }` | DEK rotation version gap (`new_dek_version` ≠ current + 1) |
| 429 | rate-limit exceeded | Per-IP limit hit (see Rate limits) |

No response ever reveals whether a `user_id` or key exists.

## Auth paths

Authenticated endpoints accept `Authorization: Bearer <token>` with two token
kinds, selected by a preHandler:

1. **Session path** — opaque access token from `POST /v1/auth/verify` or
   `/v1/auth/refresh`. Implicit full scopes.
2. **API key path** — display token `agk_<b64url(key_id)>.<b64url(api_key)>`.
   Looked up by SHA-256 hash; revoked/expired → uniform 401; scopes loaded
   from `api_key_permissions`; `last_used_at` updated on success.

Each endpoint below declares which path(s) it allows.

---

## Registration & login

### `POST /v1/users/register` (spec §5.1) — public
```json
{ "user_id": "uuidv4", "auth_public_key": "b64url Ed25519 pk (32B)", "wrapped_dek_master": "b64url §4.1 blob" }
```
→ `201 { "user_id", "dek_version": 1, "master_version": 1 }`. Duplicate → 409.
Audits `register`.

### `POST /v1/auth/challenge` (spec §5.2) — public, strict rate limit
```json
{ "user_id": "uuidv4" }
```
→ `200 { "nonce": "b64url, 32B", "expires_at": "ISO 8601" }` (TTL 60 s).
**Anti-enumeration:** unknown users get a syntactically valid fake nonce
(`HMAC-SHA256(server_secret, user_id)`) that is never stored, so verification
fails uniformly.

### `POST /v1/auth/verify` (spec §5.2, §5.9) — public, strict rate limit
```json
{ "user_id": "...", "nonce": "b64url", "signature": "b64url Ed25519 sig (64B)" }
```
The nonce is consumed atomically **before** verification (single-use). The
signature covers `utf8("ag-login-v1") || 0x00 || nonce || 0x00 || utf8(expires_at)`.

Success → `200 { "access_token", "token_type": "Bearer", "expires_at" }` plus
refresh cookie `ag_refresh` (`HttpOnly; Secure; SameSite=Strict; Path=/v1/auth`).
Any failure → uniform 401. Audits `login_success` / `login_failure`.

### `POST /v1/auth/refresh` (spec §5.9) — refresh cookie
Rotates atomically: old refresh token invalidated, new pair issued in the same
token family. → `200` like `/verify`. Reuse of an already-rotated refresh token
revokes the **whole family** (theft detection) and audits
`refresh_reuse_detected`. Failures → uniform 401 + cookie cleared.

### `POST /v1/auth/logout` — refresh cookie
Invalidates the token family, clears the cookie → `200 { "ok": true }`.

---

## Crypto endpoints

### `GET /v1/crypto/wrapped-dek-master` — session only
→ `200 { "wrapped_dek_master", "dek_version" }`.

### `GET /v1/crypto/wrapped-dek` (spec §5.4) — API key only, scope `data:read`, strict rate limit
→ `200 { "wrapped_dek", "dek_version", "scopes": [...] }` for the presented key.

### `POST /v1/crypto/rotate-master` (spec §5.6) — session only
```json
{ "new_auth_public_key": "b64url", "new_wrapped_dek_master": "b64url blob", "rotation_signature": "b64url" }
```
`rotation_signature` is the OLD auth key's Ed25519 signature over
`utf8("ag-rotate-master-v1") || new_auth_public_key`. One transaction: swap
auth key + master wrapper, `master_version + 1`, delete **all** user tokens.
→ `200 { "master_version" }`. Bad signature → 401. Audits `master_rotated`.

### `POST /v1/crypto/rotate-dek` (spec §5.7) — session only
```json
{ "new_wrapped_dek_master": "b64url blob", "new_dek_version": 2, "encrypted_data_blob": "b64url blob", "revoke_all_api_keys": true, "gateway_credentials": [{ "api_name": "nano-gpt", "blob": "b64url blob" }] }
```
`new_dek_version` must equal current `dek_version + 1` (else 409);
`revoke_all_api_keys` must be `true`. One transaction: bump `dek_version`,
swap blob + master wrapper, revoke ALL API keys. → `200 { "dek_version" }`.
Audits `dek_rotated`.

**Gateway extension (gateway.md §7):** `gateway_credentials` is optional.
If the user HAS gateway credentials, the array MUST cover exactly the
existing `api_name` set (blobs re-encrypted client-side under the new
DEK/version) — else 400 `incomplete_rotation`. On commit, credential blobs
are replaced in the same transaction.

**HF extension (hfif.md §7):** `hf_credential: { "blob" }` is optional. If
the user HAS an HF credential, the field MUST be present; if they have
none, it MUST be absent — else 400 `incomplete_rotation`. On commit, the
blob is replaced in the same transaction.

---

## Data blob

### `GET /v1/data/blob` — session, or API key with `data:read`
→ `200 { "encrypted_data_blob": string | null, "dek_version" }`.

### `PUT /v1/data/blob` — session, or API key with `data:write`
```json
{ "encrypted_data_blob": "b64url §4.1 blob" }
```
Ciphertext stored verbatim. → `200 { "ok": true, "dek_version" }`.

---

## API key management (session only)

### `POST /v1/api-keys` (spec §5.3 step 7)
```json
{ "key_id": "uuidv4", "key_hash": "SHA-256 hex (64 chars)", "wrapped_dek": "b64url blob", "scopes": ["data:read", "data:write"], "expires_at": "ISO 8601 | null (optional)" }
```
Allowed scopes: `data:read`, `data:write`, `gateway:use`, `gateway:manage`,
`ollama:use`, `ollama:manage`, `hfif:use`, `hfif:manage` (the gateway scopes
are defined by gateway.md §6, the ollama scopes by ollama-relay.md §7, the
hfif scopes by hfif.md §6). `keys:manage` and unknown
scopes → 400 `invalid_scope`. Duplicate `key_id`/`key_hash` → 409.
→ `201 { "key_id" }`. Audits `api_key_created`.

### `GET /v1/api-keys`
→ `200 { "keys": [{ "key_id", "scopes", "created_at", "last_used_at", "expires_at", "revoked" }] }`.
Never includes `key_hash` or `wrapped_dek`.

### `POST /v1/api-keys/:keyId/revoke` (spec §5.8)
Soft delete. → `200 { "ok": true }`; unknown/foreign key → 404. Audits
`api_key_revoked`.

---

## Token model (spec §5.9)

| Token | Form | TTL | Storage |
|-------|------|-----|---------|
| Access | opaque 256-bit random, response body | 15 min | SHA-256 hash only |
| Refresh | opaque 256-bit random, `ag_refresh` cookie (`HttpOnly; Secure; SameSite=Strict`) | 30 days, rotating | SHA-256 hash only |

One login = one **token family** (`family_id`). Refresh rotation keeps the
family; reuse of a rotated token or logout revokes the whole family; master
rotation deletes all of the user's tokens.

## Rate limits (@fastify/rate-limit, per IP)

- Strict (~10/min): `POST /v1/auth/challenge`, `POST /v1/auth/verify`,
  `GET /v1/crypto/wrapped-dek`.
- Moderate global default (~300/min) on everything else.
- Over limit → 429.

## Audit log (spec §6.2)

Append-only `audit_log` (user_id, event, JSON metadata, ip, created_at).
Events: `register`, `login_success`, `login_failure`, `api_key_created`,
`api_key_revoked`, `api_key_access_denied`, `master_rotated`, `dek_rotated`,
`refresh_reuse_detected`. The gateway layer adds `gateway_api_defined`,
`gateway_api_removed`, `gateway_credential_set`, `gateway_credential_deleted`,
`gateway_proxy_call`, `gateway_credential_decrypt_failed` (gateway.md §9).
The Ollama relay layer adds `ollama_uplink_created`, `ollama_uplink_deleted`,
`ollama_sidecar_connect`, `ollama_sidecar_disconnect`, `ollama_proxy_call`
(ollama-relay.md §8) — operational metadata only, never payload data.
The hfif layer adds `hfif_token_set`, `hfif_token_deleted`,
`hfif_proxy_call`, `hfif_endpoint_resumed`, `hfif_endpoint_paused`
(hfif.md §9) — never HF tokens, prompts, or completions.

## Configuration (env)

| Var | Default | Purpose |
|-----|---------|---------|
| `DATABASE_PATH` | `afuera.db` | SQLite file (`:memory:` in tests) |
| `AG_SERVER_SECRET` | random per boot | anti-enumeration HMAC key |
| `AG_CHALLENGE_TTL_MS` | `60000` | challenge TTL (spec: ≤ 60 s) |
| `AG_ACCESS_TOKEN_TTL_MS` | `900000` | access token TTL |
| `AG_REFRESH_TOKEN_TTL_MS` | `2592000000` | refresh token TTL (30 d) |
| `AG_RATE_LIMIT_MAX` | `300` | global per-IP limit per minute |
| `AG_RATE_LIMIT_STRICT_MAX` | `10` | strict per-IP limit per minute |
| `AG_PUBLIC_BASE_URL` | unset | public base URL for Ollama sidecar `relay_url` (ollama-relay.md §9) |
| `AG_RATE_LIMIT_OLLAMA_MAX` | `60` | per-token Ollama proxy limit per minute |
| `AG_OLLAMA_PROXY_TIMEOUT_MS` | `120000` | overall timeout for one tunnelled Ollama request |
| `AG_HF_API_BASE` | HF endpoints API | hfif control-plane base URL (hfif.md §8) |
| `AG_HF_WHOAMI_URL` | HF whoami-v2 | hfif namespace/token check URL |
| `AG_HFIF_RESUME_TIMEOUT_MS` | `180000` | resume/pause wait bound |
| `AG_HFIF_RESUME_POLL_MS` | `5000` | describe-poll interval while waiting |
| `AG_HFIF_UPSTREAM_TIMEOUT_MS` | `600000` | per-call inference timeout (cold starts) |
| `AG_RATE_LIMIT_HFIF_MAX` | `60` | per-API-key hfif limit per minute |
| `AG_HFIF_ALLOW_HTTP` | off | dev/test: allow `http://` endpoint invocation URLs |
| `PORT` / `HOST` | `3000` / `0.0.0.0` | listen address |
