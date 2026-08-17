# Gateway Specification — Business Logic #1: API Gateway ("Upstream Key Translation")

> Version: 0.1.0
> Status: Accepted (implemented by `apps/server`, migration `003_gateway.sql`)
> Builds on: `auth-crypto.md` v0.2.0 (key hierarchy, blob format, API keys), `auth-api.md` (auth paths, error contract)

---

## 1. Concept

An admin defines named **upstream APIs** (e.g. `nano-gpt` →
`https://api.nano-gpt.com`). Each user stores **their own upstream API key**
per defined API, encrypted **client-side** under their DEK. Clients then call

```
ANY /gateway/:apiName/*
Authorization: Bearer agk_<key_id>.<api_key>
```

and the server **translates**: it derives the API-KEK from the presented
token, unwraps the user's DEK (from `api_keys.wrapped_dek`), decrypts the
stored upstream credential, and proxies the request to the upstream with the
real upstream key injected. To the upstream, the call looks like a direct
call from the user; to the client, the upstream key never leaves its
encrypted at-rest form.

## 2. Threat-model note (IMPORTANT)

The server remains **zero-knowledge AT REST**: upstream keys exist only as
§4.1 blobs under the user's DEK, and the DEK exists only wrapped. However, a
request bearing an `agk_` token **transiently arms the server with the user's
DEK** for the duration of that request. Consequences, all enforced by the
implementation:

- **The proxy path accepts `agk_` tokens ONLY.** Session tokens are opaque
  and carry no key material — proxying with a session is *impossible by
  design*, not merely disallowed. A session Bearer token on a proxy route
  gets the uniform 401.
- **Memory hygiene:** the unwrapped DEK and the decrypted upstream key are
  `zeroize()`d in a `finally` immediately after the upstream call. (Caveat:
  the upstream key is briefly converted to a JS string for header injection;
  JS strings cannot be reliably zeroed. This is an accepted, documented
  limitation — the Buffer copies are zeroed.)
- **No logging:** keys, tokens, and credential blobs are never written to
  logs or the audit log. Audit metadata contains only `api_name` and
  `upstream_status`.
- Transient decryption means a **fully compromised server process** could
  exfiltrate a DEK/upstream key *during* a proxy call. This is inherent to
  server-side key translation and is the documented price of the feature;
  at rest, a database leak still reveals nothing.

## 3. Schema (migration `003_gateway.sql`)

```sql
gateway_apis (
  name         TEXT PRIMARY KEY,            -- slug: [a-z0-9-]{2,64}
  base_url     TEXT NOT NULL,               -- https:// origin (+ optional path prefix)
  description  TEXT,
  auth_header  TEXT NOT NULL DEFAULT 'Authorization',
  auth_scheme  TEXT NOT NULL DEFAULT 'Bearer',   -- '' → header value is the raw key
  created_by   TEXT NOT NULL REFERENCES user_crypto(user_id),
  created_at   TEXT NOT NULL
)

gateway_credentials (
  user_id    TEXT NOT NULL REFERENCES user_crypto(user_id) ON DELETE CASCADE,
  api_name   TEXT NOT NULL REFERENCES gateway_apis(name)   ON DELETE CASCADE,
  blob       TEXT NOT NULL,                 -- §4.1 blob
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, api_name)
)
```

`base_url` is validated on write: `https://` only (see `AG_GATEWAY_ALLOW_HTTP`
dev escape hatch), no userinfo, no query/hash, no `..` path traversal;
normalized to `origin + path-prefix` without trailing slash.

## 4. AAD / encryption contract (client-side, `@afuera/crypto`)

```ts
blob = encryptBlob(dek, utf8(upstream_api_key),
                   dataAAD(user_id, "gateway-credential:" + api_name, dek_version))
```

- The `api_name` is bound into the AAD — blobs **cannot be swapped between
  upstreams** (or users, or DEK versions): decryption fails on any mismatch.
- Server-side decryption at proxy time uses the same AAD with the **current**
  `dek_version` from `user_crypto`. This is why DEK rotation must re-encrypt
  credential blobs (§7).

## 5. Endpoints

All `/v1/gateway/*` endpoints use the `auth-api.md` error contract. Additional
error bodies:

| Status | Body | Meaning |
|--------|------|---------|
| 400 | `{ "error": "invalid_base_url" }` | base_url failed validation (§3) |
| 400 | `{ "error": "incomplete_rotation" }` | rotate-dek did not stage exactly the existing credential set (§7) |
| 403 | `{ "error": "forbidden" }` | authenticated but not a gateway admin |
| 404 | `{ "error": "unknown_api" }` | no upstream API defined under that name |
| 404 | `{ "error": "credential_not_found" }` | user has no credential for that API |
| 500 | `{ "error": "credential_decrypt_failed" }` | stored blob fails integrity under the current DEK/version (audited as `gateway_credential_decrypt_failed`) |
| 502 | `{ "error": "upstream_error" }` | upstream unreachable / timeout |

### 5.1 Upstream API catalog

**`POST /v1/gateway/apis`** — admin only (session path; `user_id` must be
listed in env `AG_ADMIN_USERS`, comma-separated; empty list = no admins).
`agk_` tokens get the uniform 401; non-admin sessions get 403.

```json
{ "name": "nano-gpt", "base_url": "https://api.nano-gpt.com",
  "description": null, "auth_header": "Authorization", "auth_scheme": "Bearer" }
```

→ `201 { "name", "base_url" }`. Duplicate name → 409 `conflict`.
Audits `gateway_api_defined`.

**`GET /v1/gateway/apis`** — any authenticated path (session or any valid
`agk_`, no scope). Public catalog:
→ `200 { "apis": [{ "name", "base_url", "description" }] }`.

**`DELETE /v1/gateway/apis/:name`** — admin only. Deleting an API cascades
its `gateway_credentials`. → `200 { "ok": true }`; unknown → 404
`unknown_api`. Audits `gateway_api_removed`.

### 5.2 Per-user credentials

Session path **or** `agk_` with scope `gateway:manage`.

**`PUT /v1/gateway/credentials/:apiName`** — upsert.
`{ "blob": "b64url §4.1 blob" }` → `200 { "ok": true }`. Undefined apiName →
404 `unknown_api`. Audits `gateway_credential_set` (no blob logging).

**`GET /v1/gateway/credentials`** — list own, metadata only:
→ `200 { "credentials": [{ "api_name", "created_at", "updated_at" }] }`.

**`GET /v1/gateway/credentials/:apiName`** — fetch one blob (client may want
to rotate/inspect it): → `200 { "api_name", "blob", "created_at", "updated_at" }`;
404 `credential_not_found`.

**`DELETE /v1/gateway/credentials/:apiName`** — → `200 { "ok": true }`;
404 `credential_not_found`. Audits `gateway_credential_deleted`.

### 5.3 The proxy (core)

**`ALL /gateway/:apiName` and `/gateway/:apiName/*`** (GET, POST, PUT, PATCH,
DELETE, HEAD, OPTIONS) — `agk_` token ONLY, scope `gateway:use`, rate-limited
per API key (~60/min, `AG_RATE_LIMIT_GATEWAY_MAX`).

Flow (all auth failures → uniform 401):

1. Parse token → `key_hash` lookup (exists, not revoked, not expired, scope
   present) — uniform 401 otherwise. (`authGuard`, `auth-api.md`.)
2. Derive the API-KEK via `deriveApiKek(keyId, apiKey)`; unwrap the DEK from
   `api_keys.wrapped_dek` with `wrapAAD("api:"+key_id, current dek_version)`
   — on failure uniform 401.
3. Look up `gateway_apis` by name → 404 `unknown_api`; look up the credential
   `(user_id, api_name)` → 404 `credential_not_found`. (These are post-auth
   states; they intentionally reveal nothing about auth.)
4. Decrypt the blob with the DEK + AAD (§4) → upstream key (utf8).
5. Forward to upstream (Node global `fetch`/undici):
   - same method; URL = `base_url` + raw wildcard suffix + original query
     string (the suffix is taken from the **raw** request URL so
     percent-encoding is forwarded verbatim);
   - request body forwarded as raw bytes (the proxy routes use scoped
     raw-buffer content type parsers that shadow JSON parsing only within the
     proxy plugin; Fastify's default 1 MB body limit applies);
   - headers forwarded EXCEPT `host`, `authorization`, `connection`,
     `content-length`, `transfer-encoding`, and the hop-by-hop set
     (`keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`,
     `trailer`, `upgrade`);
   - injects `<auth_header>: <auth_scheme> <key>` (empty scheme → raw key);
   - sets a `User-Agent` if the client sent none;
   - `redirect: "manual"`, timeout ≈ 60 s (`AG_GATEWAY_UPSTREAM_TIMEOUT_MS`).
6. Streams the upstream response back (`reply.send(Readable.fromWeb(...))`):
   status, headers minus hop-by-hop, minus `set-cookie`, and minus
   `content-encoding`/`content-length` (undici transparently decompresses, so
   upstream framing no longer describes the streamed body).
7. Upstream unreachable/timeout → 502 `upstream_error`.
8. `finally`: `zeroize` the DEK and upstream-key buffers (§2).
9. Audits `gateway_proxy_call` with `{ api_name, upstream_status }`
   (`upstream_status: null` on unreachable upstream). Never logs keys.

## 6. Scopes

The API-key scope vocabulary (`auth-api.md`) is extended to:

| Scope | Issued | Meaning |
|-------|--------|---------|
| `data:read` | ✓ | `GET /v1/crypto/wrapped-dek`, `GET /v1/data/blob` |
| `data:write` | ✓ | `PUT /v1/data/blob` |
| `gateway:use` | ✓ | `ANY /gateway/:apiName/*` (proxy) |
| `gateway:manage` | ✓ | `/v1/gateway/credentials*` CRUD |
| `keys:manage` | ✗ reserved | still rejected with 400 `invalid_scope` |

`gateway:use` and `gateway:manage` are deliberately separate: a key that may
proxy cannot read back credential blobs, and vice versa.

## 7. Interaction with DEK rotation (`rotate-dek`)

`POST /v1/crypto/rotate-dek` gains an optional field:

```json
{ "gateway_credentials": [{ "api_name": "nano-gpt", "blob": "b64url" }] }
```

Blobs are re-encrypted **client-side** under the new DEK/version via the
existing `reEncryptDataBlob(oldDek, newDek, blob, user_id,
"gateway-credential:"+api_name, oldVersion, newVersion)` (§4 AAD is
version-bound).

Rules (enforced in the same single transaction as §5.7 step 7):

- If the user HAS gateway credentials, the array MUST cover **exactly** the
  existing `api_name` set — otherwise 400 `incomplete_rotation` and nothing
  commits. (Credential blobs cannot be recovered after rotation: the old DEK
  is gone and the server cannot re-encrypt them.)
- On commit, all credential blobs are replaced alongside the data blob swap,
  master wrapper swap, version bump, and API-key revocation.
- After rotation the client re-issues API keys (§5.3); a new `agk_` key
  proxies immediately because credential AADs now match the new
  `dek_version`.
- If the user has no gateway credentials, the field is optional (and must be
  empty/absent).

## 8. Limits & configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `AG_ADMIN_USERS` | `""` (no admins) | comma-separated admin user_ids for catalog write routes |
| `AG_RATE_LIMIT_GATEWAY_MAX` | `60` | per-API-key proxy limit per minute |
| `AG_GATEWAY_UPSTREAM_TIMEOUT_MS` | `60000` | per-call upstream timeout → 502 |
| `AG_GATEWAY_ALLOW_HTTP` | off | dev/test only: allow `http://` base_urls. MUST stay off in production — upstream keys are injected into these requests. |

Proxy request bodies are buffered raw up to Fastify's default 1 MB
`bodyLimit`; larger uploads are out of scope for v1.

## 9. Audit events

`gateway_api_defined`, `gateway_api_removed`, `gateway_credential_set`,
`gateway_credential_deleted`, `gateway_proxy_call`
(`{ api_name, upstream_status }`), `gateway_credential_decrypt_failed`.
None of them ever contain keys, tokens, or blobs.
