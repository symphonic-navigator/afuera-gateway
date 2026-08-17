-- Migration 004: per-user Ollama relay — business logic #2.
-- See docs/specs/ollama-relay.md.
--
-- Each user manages 0..n named "ollama uplinks". A sidecar on the user's
-- homelab dials OUT via WebSocket to /uplink/<id> and proves possession of
-- the uplink's PSK; external clients reach the user's Ollama through
-- /ollama/<name>/api/* and /ollama/<name>/v1/*, authenticated with an agk_
-- API key (or a session) — the effective routing key is (user_id, name).
--
-- The server stores ONLY the SHA-256 hash of the PSK (session keys derive
-- from SHA-256(PSK), so the PSK itself never needs to be stored, and nothing
-- here is DEK-encrypted: uplinks work without user login and rotate-dek has
-- NO interaction with this table).

CREATE TABLE ollama_uplinks (
  id         TEXT PRIMARY KEY,                    -- UUIDv4, server-assigned; appears in the sidecar's WS URL
  user_id    TEXT NOT NULL
             REFERENCES user_crypto (user_id) ON DELETE CASCADE,
  name       TEXT NOT NULL,                       -- slug: [a-z0-9-]{2,64} (validated on write)
  psk_hash   TEXT NOT NULL UNIQUE,                -- SHA-256(utf8(psk)) hex; the PSK itself is shown once at creation
  models     TEXT NOT NULL DEFAULT '[]',          -- JSON array of model names (from hello / model_update)
  created_at TEXT NOT NULL,                       -- ISO 8601
  updated_at TEXT NOT NULL,                       -- ISO 8601
  UNIQUE (user_id, name)                          -- client-facing names are per-user
);

-- Active sidecar connections live in memory only (the registry), never here.
