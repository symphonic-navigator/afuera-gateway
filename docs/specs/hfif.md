# HFIF Specification — Business Logic #3: Per-User Hugging Face Inference Endpoints Proxy

> Version: 0.1.0
> Status: Accepted (implemented by `apps/server`, migration `005_hfif.sql`)
> Builds on: `auth-crypto.md` v0.2.0 (key hierarchy, blob format, API keys), `auth-api.md` (auth paths, error contract), `gateway.md` (transient-decryption threat model)
> Ported from: the single-user Python reference `hf-inference-proxy`
> (`src/hf_inference_proxy/hf.py`, `proxy.py`) — made per-user and moved
> behind the zero-knowledge credential model.

---

## 1. Concept

A user stores **one Hugging Face access token**, encrypted **client-side**
under their DEK. Clients then call an OpenAI-compatible API:

```
GET  /hfif/v1/models
POST /hfif/v1/chat/completions
POST /hfif/v1/completions
POST /hfif/v1/embeddings
Authorization: Bearer agk_<key_id>.<api_key>
```

The server resolves the user's HF namespace (whoami-v2), lists their HF
Inference Endpoints, maps `model` → endpoint (by `model.repository`, fallback
endpoint name), **auto-resumes** paused endpoints, and forwards the request
to the endpoint's `status.url` with the user's decrypted HF token as Bearer.
Manual resume/pause control is exposed as well — pausing an endpoint stops
its GPU cost.

## 2. Threat-model note (IMPORTANT)

Identical to the gateway (gateway.md §2). The server is **zero-knowledge AT
REST**: the HF token exists only as a §4.1 blob under the user's DEK. A
request bearing an `agk_` token **transiently arms the server with the
user's DEK** for the duration of that request. Consequences, all enforced by
the implementation:

- **Client-facing `/hfif/*` routes accept `agk_` tokens ONLY.** Session
  tokens carry no key material — proxying with a session is impossible by
  design. A session Bearer token on `/hfif/*` gets the uniform 401. (Token
  *management* under `/v1/hfif/token` also allows sessions, like the
  gateway's credential CRUD.)
- **Uniform 401 for missing/undecryptable credentials**: no stored token,
  or a blob that fails integrity under the current DEK/version, is
  indistinguishable from any other auth failure.
- **Memory hygiene:** the unwrapped DEK is zeroized immediately after the
  credential decrypt; the decrypted HF token buffer is `zeroize()`d in a
  `finally` after the request. (Caveat, same as the gateway: the token is
  briefly converted to a JS string for the Authorization header; JS strings
  cannot be reliably zeroed. The Buffer copies are zeroed.)
- **No logging:** the HF token, credential blobs, prompts and completions
  are never written to logs or the audit log. Audit metadata contains only
  model names, endpoint names and upstream statuses (§9).
- **No cross-request caching:** the namespace, endpoint list and all HF API
  data are fetched fresh within each request's lifecycle; nothing HF-related
  is kept in memory between requests. (The Python reference cached the
  namespace process-wide; we deliberately do not.)

## 3. Schema (migration `005_hfif.sql`)

```sql
hf_credentials (
  user_id    TEXT PRIMARY KEY
             REFERENCES user_crypto(user_id) ON DELETE CASCADE,
  blob       TEXT NOT NULL,     -- §4.1 blob, AAD "hfif-credential"
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)
```

One HF token per user (PK `user_id`), cascade-deleted with the user.

## 4. AAD / encryption contract (client-side, `@afuera/crypto`)

```ts
blob = encryptBlob(dek, utf8(hf_token),
                   dataAAD(user_id, "hfif-credential", dek_version))
```

- The record type `"hfif-credential"` is bound into the AAD — blobs cannot
  be swapped between users or DEK versions, and are domain-separated from
  `gateway-credential:<api_name>` blobs.
- Server-side decryption uses the **current** `dek_version` from
  `user_crypto` — hence the rotate-dek interaction (§7).

## 5. Endpoints

Error contract per `auth-api.md`. Additional error bodies:

| Status | Body | Meaning |
|--------|------|---------|
| 400 | `{ "error": "incomplete_rotation" }` | rotate-dek did not stage the existing HF credential (§7) |
| 404 | `{ "error": "credential_not_found" }` | DELETE with no stored token |
| 502 | `{ "error": "upstream_error" }` | HF control plane unreachable (management/check routes) |
| 503 | `{ "error": "endpoint_unavailable" }` | manual resume/pause failed or timed out |

The OpenAI-compatible routes (`/hfif/v1/*`) use the reference's OpenAI-style
error shape instead: `{ "error": { "message": "..." } }`.

### 5.1 Token management — session OR `agk_` with scope `hfif:manage`

**`PUT /v1/hfif/token`** — upsert. `{ "blob": "b64url §4.1 blob" }` →
`200 { "ok": true }`. Audits `hfif_token_set` (never the blob).

**`GET /v1/hfif/token`** — → `200 { "exists", "created_at", "updated_at", "blob"? }`.
The blob is returned verbatim (client may re-wrap/inspect it); the server
never attempts decryption here. Without a stored token:
`{ "exists": false, "created_at": null, "updated_at": null }`.

**`DELETE /v1/hfif/token`** — → `200 { "ok": true }`; none stored → 404
`credential_not_found`. Audits `hfif_token_deleted`.

**`POST /v1/hfif/token/check`** — `agk_` ONLY, scope `hfif:use` **or**
`hfif:manage` (the check needs the DEK → key material required). Decrypts
the token, calls whoami-v2, returns the ported TokenCheckResult:

```json
{ "ok": true, "namespace": "user", "username": "user", "role": "fineGrained",
  "scopes": ["inference.endpoints.write"], "has_write": true, "reason": null }
```

`has_write` is true when the role is `write`/`admin`/`owner` or the
fine-grained scopes include `inference.endpoints.write`; otherwise `reason`
explains what is missing. No credential / undecryptable → uniform 401;
control plane unreachable → 502 `upstream_error`.

### 5.2 OpenAI-compatible API — `agk_` ONLY, scope `hfif:use`, per-key rate limit (~60/min)

**`GET /hfif/v1/models`** — always a FRESH endpoint list (uncached, no
background polling). OpenAI list shape:

```json
{ "object": "list", "data": [
  { "id": "meta/llama-3", "object": "model", "created": 1755000000,
    "owned_by": "huggingface",
    "meta": { "endpoint_name": "llama", "state": "running", "task": "text-generation",
              "framework": "vllm", "instance": "intel-cpu", "vendor": "aws",
              "region": "us-east-1" } } ] }
```

`id` = `model.repository`, falling back to the endpoint name. `created` is
the list time (the reference used its store's last-refresh timestamp; we
have no store — every call refreshes). Empty account → empty `data`.

**`POST /hfif/v1/chat/completions`, `/hfif/v1/completions`, `/hfif/v1/embeddings`**

Flow:

1. Parse the JSON body → 400 `{"error":{"message":"invalid json body"}}` /
   `missing 'model' field`.
2. Fresh endpoint list; find by `repository`, fallback endpoint name.
   Unknown → 404 `{"error":{"message":"model '<model>' not found"}}`.
3. **Auto-resume:** if the endpoint's state ≠ `running` or it has no URL →
   `POST {api_base}/{ns}/{name}/resume` (400 "already running" is fine),
   then poll describe every `AG_HFIF_RESUME_POLL_MS` until
   `state=running` + `status.url` present, `failed`/`error`/`cancelled`, or
   `AG_HFIF_RESUME_TIMEOUT_MS` expires → 503
   `{"error":{"message":"endpoint '<model>' could not be started"}}`.
4. Forward to `status.url` (trailing slashes stripped) + the original
   `/v1/<suffix>` path + query string, body re-serialized JSON, headers
   `Authorization: Bearer <hf_token>`, `Content-Type: application/json`,
   `Accept: text/event-stream` when `stream: true` (else `application/json`).
   Long timeout (`AG_HFIF_UPSTREAM_TIMEOUT_MS`, default 600 s) for cold
   starts.
5. **Stream:** SSE passthrough, chunks forwarded 1:1 on a 200
   `text/event-stream` response; upstream connection/read failures (before
   or during the stream) are emitted as SSE error frames
   (`data: {"error":{"message":"upstream error: ..."}}`).
   **Non-stream:** upstream status + content-type + body passthrough;
   unreachable → 502 `{"error":{"message":"upstream error: ..."}}`.
6. Audits `hfif_proxy_call` with `{ model, status }` (`status: null` on
   unreachable upstream). Never prompts/completions/tokens.

Endpoint invocation URLs come from HF's `status.url` and are passed through
as-is, except the scheme check: `https:` required in production, `http:`
only via the `AG_HFIF_ALLOW_HTTP` dev/test escape hatch — the user's HF
token is injected into these requests.

### 5.3 Endpoint control — `agk_` ONLY, scope `hfif:use`, per-key rate limit

**`GET /hfif/endpoints`** — fresh list of all endpoints, normalized
(`normalize_endpoint` fields minus `raw`): name, repository, url, state,
message, task, framework, revision, vendor, region, instance, instance_size,
accelerator, min/max_replica, scale_to_zero_timeout, ready/target_replica,
created/updated/last_used_at, health_route, type, image_model_path,
image_ctx_size, image_n_parallel. For a future dashboard.

**`POST /hfif/endpoints/:name/resume`** / **`POST /hfif/endpoints/:name/pause`**
— manual control. Resume is a control-plane call and does not itself incur
GPU cost (cost starts once the endpoint runs); **pause stops the GPU and
thus the cost**. Both wait for the target state (same timeout/poll env as
auto-resume) and return the normalized endpoint; failure/timeout → 503
`endpoint_unavailable`. Audit `hfif_endpoint_resumed` /
`hfif_endpoint_paused`.

## 6. Scopes

The API-key scope vocabulary (`auth-api.md`) is extended to:

| Scope | Issued | Meaning |
|-------|--------|---------|
| `hfif:use` | ✓ | `/hfif/*` (OpenAI API, endpoint list, resume/pause) + `token/check` |
| `hfif:manage` | ✓ | `/v1/hfif/token` CRUD + `token/check` |

Deliberately separate (like the gateway): a key that may proxy cannot read
back the token blob, and vice versa. `keys:manage` stays rejected.

## 7. Interaction with DEK rotation (`rotate-dek`)

`POST /v1/crypto/rotate-dek` gains an optional field alongside
`gateway_credentials`:

```json
{ "hf_credential": { "blob": "b64url" } }
```

The blob is re-encrypted **client-side** under the new DEK/version via
`reEncryptDataBlob(oldDek, newDek, blob, user_id, "hfif-credential",
oldVersion, newVersion)` (§4 AAD is version-bound).

Rules (enforced in the same single transaction as the data blob swap):

- If the user HAS an HF credential, `hf_credential` MUST be present; if
  they have none, it MUST be absent — otherwise 400 `incomplete_rotation`
  and nothing commits. (The blob cannot be recovered after rotation.)
- On commit, the credential blob is replaced alongside everything else and
  all API keys are revoked; a newly issued `agk_` key proxies immediately.
- The `dek_rotated` audit metadata gains `hf_credential: boolean`.

## 8. Refresh strategy & configuration

No background polling and no caching of HF API data: every client request
fetches a fresh endpoint list (whoami-v2 + list endpoints, both free
control-plane calls). The only wait loop is resume/pause polling, bounded
by env.

| Env var | Default | Purpose |
|---------|---------|---------|
| `AG_HF_API_BASE` | `https://api.endpoints.huggingface.cloud/v2/endpoint` | HF control-plane base URL |
| `AG_HF_WHOAMI_URL` | `https://huggingface.co/api/whoami-v2` | namespace + token scope check |
| `AG_HFIF_RESUME_TIMEOUT_MS` | `180000` | upper bound for resume/pause waits |
| `AG_HFIF_RESUME_POLL_MS` | `5000` | describe-poll interval while waiting |
| `AG_HFIF_UPSTREAM_TIMEOUT_MS` | `600000` | per-call inference timeout (cold starts) |
| `AG_RATE_LIMIT_HFIF_MAX` | `60` | per-API-key limit per minute on `/hfif/*` |
| `AG_HFIF_ALLOW_HTTP` | off | dev/test only: allow `http://` endpoint invocation URLs. MUST stay off in production. |

Control-plane calls (whoami/list/describe/resume/pause) use a fixed 30 s
timeout, as in the reference.

## 9. Audit events

`hfif_token_set`, `hfif_token_deleted`, `hfif_proxy_call`
(`{ model, status }`), `hfif_endpoint_resumed`, `hfif_endpoint_paused`
(`{ endpoint_name }`). None of them ever contain the HF token, blobs,
prompts, or completions.

## 10. Deviations from the Python reference

- Namespace memoized only per request (reference: process-wide cache) — see §2.
- `/v1/models` `created` = list time (reference: store's last-refresh).
- `pause` wait-timeout returns failure (the reference had a dead-code
  fallback returning the last poll result).
- The 401-token `reason` string no longer suggests `hf auth login`.
- Control-plane failures on `/hfif/v1/*` map to 502 with the OpenAI error
  shape (reference: unhandled 500).
