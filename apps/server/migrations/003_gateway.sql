-- Migration 003: API gateway ("upstream key translation") — business logic #1.
-- See docs/specs/gateway.md.
--
-- The server stays zero-knowledge AT REST: upstream API keys are stored only
-- as §4.1 blobs encrypted client-side under the user's DEK, with the AAD
-- dataAAD(user_id, "gateway-credential:<api_name>", dek_version). The server
-- can decrypt a credential ONLY transiently, during a proxy call that
-- presents an agk_ API key (which carries the key material).

-- Admin-defined catalog of upstream APIs.
CREATE TABLE gateway_apis (
  name         TEXT PRIMARY KEY,                  -- slug: [a-z0-9-]{2,64} (validated on write)
  base_url     TEXT NOT NULL,                     -- https:// origin (+ optional path prefix), validated on write
  description  TEXT,
  auth_header  TEXT NOT NULL DEFAULT 'Authorization',
  auth_scheme  TEXT NOT NULL DEFAULT 'Bearer',    -- '' → header value is the raw key
  created_by   TEXT NOT NULL
               REFERENCES user_crypto (user_id),
  created_at   TEXT NOT NULL                      -- ISO 8601
);

-- Per-user upstream credentials, one per (user, api). Blob format §4.1.
CREATE TABLE gateway_credentials (
  user_id    TEXT NOT NULL
             REFERENCES user_crypto (user_id) ON DELETE CASCADE,
  api_name   TEXT NOT NULL
             REFERENCES gateway_apis (name) ON DELETE CASCADE,
  blob       TEXT NOT NULL,                       -- §4.1 blob, AAD "gateway-credential:<api_name>"
  created_at TEXT NOT NULL,                       -- ISO 8601
  updated_at TEXT NOT NULL,                       -- ISO 8601
  PRIMARY KEY (user_id, api_name)
);
