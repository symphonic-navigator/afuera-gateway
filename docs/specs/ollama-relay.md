# Ollama Relay Specification — Business Logic #2: Per-User Ollama Uplinks

> Version: 0.1.0
> Status: Accepted (implemented by `apps/server`, migration `004_ollama.sql`, protocol package `packages/ollama-protocol`)
> Builds on: `auth-crypto.md` v0.2.0, `auth-api.md` (auth paths, error contract)
> Wire protocol: ported byte-compatibly from the author's `ollama-uplink` project — an **unmodified** existing sidecar can connect.

---

## 1. Concept

Each user manages 0..n named **ollama uplinks**. The user's existing sidecar
(homelab, next to their Ollama, **unchanged**) dials OUT via WebSocket to our
server; the existing `RELAY_URL` env var carries the uplink identity, so the
sidecar binary works as-is. External clients then reach the user's Ollama
through

```
ANY /ollama/<name>/api/*     (Ollama-compatible)
ANY /ollama/<name>/v1/*      (OpenAI-compatible)
Authorization: Bearer agk_<key_id>.<api_key>   (or a session access token)
```

and the server tunnels the request over the encrypted WebSocket to the user's
sidecar, which forwards it to the local Ollama and streams the response back.

## 2. Two identity planes

**Client-facing identity = (user_id, name).** The `agk_` token (or session)
identifies the user BEFORE routing, so uplink name collisions across users
are fine: user A's `strixhalo` and user B's `strixhalo` are distinct uplinks,
and each user's token reaches only their own sidecar. Names are slugs
(`[a-z0-9-]{2,64}`), unique per user (`UNIQUE(user_id, name)`).

**Sidecar-facing identity = server-assigned uplink UUID + PSK.** The sidecar
connects to `wss://host/uplink/<uuid>`; the UUID in the URL selects the
uplink row, and the PSK proves possession of the shared secret (§4). The PSK
is 32 random bytes (base64url), generated server-side at creation, displayed
EXACTLY ONCE in the creation response, and stored only as
`SHA-256(utf8(psk))` hex.

## 3. Threat model

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| Server database leak | Only the PSK **hash** is stored (256-bit entropy → offline brute-force infeasible). Nothing DEK-encrypted on this path. | — |
| Passive network observer | TLS (wss/https) plus the tunnel's own XChaCha20-Poly1305 session encryption inside the WebSocket | — |
| Stolen `agk_` key | Scoped (`ollama:use` ≠ `ollama:manage`), revocable, rate-limited | A `ollama:use` key drives the user's Ollama until revoked |
| Stolen uplink UUID alone | Useless without the PSK: the first encrypted frame fails AEAD and the connection is closed (uniform, no oracle) | — |
| Connection hijack / slot theft | A new connection replaces an established one ONLY after proving the PSK (first successfully decrypted frame) | — |
| **Relay sees plaintext in transit** | — | **Accepted**: the relay (this server) terminates the tunnel encryption, so prompt/response plaintext passes through its memory in flight. It is NEVER stored or logged, in any mode. |
| Payload leakage via logs/audit | Hard rule (from ollama-uplink): prompts/responses are never logged or stored. Audit metadata contains operational fields only (uplink id/name, status) | — |

**No DEK involvement → no rotate-dek interaction.** Uplink session keys
derive from `SHA-256(PSK)` — not from the user's DEK — so uplinks keep
working while the user is logged out, and `POST /v1/crypto/rotate-dek` (which
revokes all API keys and re-encrypts DEK-bound blobs) has NO effect on this
feature. Consequently the client-facing proxy accepts session tokens too:
unlike the gateway proxy, no server-side decryption is needed here, so a
session Bearer token (opaque, no key material) is sufficient.

## 4. Tunnel protocol (compatibility note)

`packages/ollama-protocol` is a line-by-line TypeScript port of
ollama-uplink's `packages/protocol` — same HKDF labels, same AAD format, same
JSON message shapes. Unit tests pin the exact HKDF outputs the original
implementation derives.

- Handshake: sidecar → `hello { name, nonce_s, models }`; server →
  `hello_ack { nonce_r, session_id }`. The hello `name` MUST equal the stored
  uplink name (mismatch → close).
- Session keys: `HKDF-SHA256(ikm = SHA-256(PSK), salt = nonce_s || nonce_r,
  info = "s2r" | "r2s")`.
- Frames: XChaCha20-Poly1305, random 24-byte nonce prepended, AAD =
  `utf8("<sessionId>:<direction>:<seq>")`, per-direction sequence numbers. A
  frame that fails AEAD closes the connection — this is how a wrong PSK
  manifests (uniform close, no detail).
- Multiplexing: `request_open { request_id, method, path, headers, body }`
  (body base64 or null) → `response_head { status, headers }`,
  `response_chunk { data /* base64 */ }`, `response_end { usage }`; `cancel`,
  `error`, `model_update`, `ping`/`pong`.
- The sidecar's first encrypted frame (`model_update`) doubles as PSK proof.

**Server-side deviation from the original relay (deliberate hardening):**
the original registered a connecting sidecar immediately after the handshake;
we register (and take over any previous connection) only after the first
successfully decrypted frame, so a wrong-PSK connection can never boot a
healthy sidecar off its slot.

## 5. Schema (migration `004_ollama.sql`)

```sql
ollama_uplinks (
  id         TEXT PRIMARY KEY,                -- UUIDv4, server-assigned; in the sidecar's WS URL
  user_id    TEXT NOT NULL REFERENCES user_crypto(user_id) ON DELETE CASCADE,
  name       TEXT NOT NULL,                   -- slug [a-z0-9-]{2,64}
  psk_hash   TEXT NOT NULL UNIQUE,            -- SHA-256(utf8(psk)) hex
  models     TEXT NOT NULL DEFAULT '[]',      -- JSON array, from hello / model_update
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (user_id, name)
)
```

Active sidecar connections live in an in-memory registry only — never in the
DB. 0..1 connection per uplink; a new PROVEN connection takes over (the old
one is closed) — reconnect semantics for flaky networks.

## 6. Endpoints

Error contract per `auth-api.md`, plus:

| Status | Body | Meaning |
|--------|------|---------|
| 404 | `{ "error": "unknown_uplink" }` | no uplink under (authenticated user, name) |
| 404 | `{ "error": "not_found" }` | delete of unknown OR foreign uplink id (uniform) |
| 409 | `{ "error": "conflict" }` | duplicate (user_id, name) |
| 502 | `{ "error": "uplink_error" }` | sidecar reported an error frame mid-request |
| 503 | `{ "error": "uplink_offline" }` | uplink exists but no sidecar is connected |
| 504 | `{ "error": "uplink_timeout" }` | overall request timeout; the tunnel request is cancelled |

### 6.1 Uplink management — session OR `agk_` with scope `ollama:manage`

**`POST /v1/ollama/uplinks`** — `{ "name": "strixhalo" }` →
`201 { "id", "name", "psk", "relay_url" }`. `psk` is shown EXACTLY ONCE;
`relay_url` is `wss://…/uplink/<id>`, built from `AG_PUBLIC_BASE_URL` if set,
else from the request's Host/protocol. Audits `ollama_uplink_created`.

**`GET /v1/ollama/uplinks`** →
`200 { "uplinks": [{ "id", "name", "models", "online", "created_at" }] }`.
Never includes `psk_hash`.

**`DELETE /v1/ollama/uplinks/:id`** — deletes the row and drops the active
connection. → `200 { "ok": true }`; unknown/foreign id → uniform 404.
Audits `ollama_uplink_deleted`.

### 6.2 Sidecar-facing WebSocket — `GET /uplink/:uplinkId`

No HTTP auth: the uplink UUID + PSK ARE the credential. Unknown UUID → close.
Handshake per §4; wrong PSK → uniform close on the first encrypted frame;
uplink stays offline (never registered). On registration:
`ollama_sidecar_connect` audited (metadata: uplink id + name + user_id); on
close: `ollama_sidecar_disconnect`. `models` column updated on hello and on
`model_update`. Liveness: server pings every 30 s and closes the session
after 90 s without any inbound frame. Max WS payload 16 MB.

### 6.3 Client-facing proxy — session OR `agk_` with scope `ollama:use`

`ALL /ollama/:name/api/*`, `/ollama/:name/v1/*` (plus the bare `/api` / `/v1`
forms), methods GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS. Rate-limited per
presented token (`AG_RATE_LIMIT_OLLAMA_MAX`, ~60/min).

Flow (all auth failures → uniform 401 via `authGuard`):

1. Resolve `(user_id, name)` → uplink row; unknown → 404 `unknown_uplink`;
   no active connection → 503 `uplink_offline`.
2. `request_open` with the method, the path suffix after `/ollama/:name`
   INCLUDING the query string (taken from the raw URL, percent-encoding
   verbatim), headers minus `authorization`/`host`/`connection`/
   `content-length`/hop-by-hop, and the raw body (base64 in the message).
3. `response_head`/`response_chunk`/`response_end` are streamed back to the
   HTTP client — status and headers preserved (minus hop-by-hop,
   `set-cookie`, framing), chunking preserved (SSE/NDJSON stream, never
   buffered). Request bodies are buffered raw up to Fastify's 1 MB
   `bodyLimit` (scoped content type parsers, same approach as the gateway).
4. Client disconnect → `cancel` to the sidecar. Sidecar `error` frame → 502
   `uplink_error`. Overall timeout `AG_OLLAMA_PROXY_TIMEOUT_MS` (~120 s) →
   `cancel` + 504 `uplink_timeout`.
5. Audits `ollama_proxy_call` with `{ uplink: name, status }` — never the
   path suffix (it may carry payload-adjacent data), never bodies.

## 7. Scopes

The API-key scope vocabulary (`auth-api.md`) is extended to:

| Scope | Issued | Meaning |
|-------|--------|---------|
| `data:read` | ✓ | `GET /v1/crypto/wrapped-dek`, `GET /v1/data/blob` |
| `data:write` | ✓ | `PUT /v1/data/blob` |
| `gateway:use` | ✓ | `ANY /gateway/:apiName/*` |
| `gateway:manage` | ✓ | `/v1/gateway/credentials*` CRUD |
| `ollama:use` | ✓ | `ANY /ollama/:name/(api|v1)/*` (proxy) |
| `ollama:manage` | ✓ | `/v1/ollama/uplinks*` CRUD |
| `keys:manage` | ✗ reserved | still rejected with 400 `invalid_scope` |

`ollama:use` and `ollama:manage` are deliberately separate: a key that may
drive the Ollama cannot create/delete uplinks (which would reveal a PSK).

## 8. Audit events

`ollama_uplink_created`, `ollama_uplink_deleted`, `ollama_sidecar_connect`,
`ollama_sidecar_disconnect` (metadata: uplink id + name + user_id),
`ollama_proxy_call` (`{ uplink, status }`). None of them ever contain the
PSK, `psk_hash`, request/response bodies, or the path suffix.

## 9. Limits & configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `AG_PUBLIC_BASE_URL` | unset | public base URL for building `relay_url` (e.g. `https://gateway.example.com`); falls back to request Host/protocol |
| `AG_RATE_LIMIT_OLLAMA_MAX` | `60` | per-token client-proxy limit per minute |
| `AG_OLLAMA_PROXY_TIMEOUT_MS` | `120000` | overall timeout for one tunnelled request → cancel + 504 |

Connection constants (not env-configurable): handshake timeout 10 s, ping
interval 30 s, pong/liveness timeout 90 s, max WS payload 16 MB.
