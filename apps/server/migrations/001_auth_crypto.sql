-- Migration 001: crypto foundation storage (spec §4.2)
--
-- The server is zero-knowledge: it stores only public keys, key hashes,
-- and wrapped (encrypted) keys. All blobs use the §4.1 format
-- (base64url version||nonce||ct||tag).

CREATE TABLE user_crypto (
  user_id             TEXT PRIMARY KEY,              -- UUIDv4
  -- Authentication
  auth_public_key     TEXT NOT NULL,                 -- Ed25519 public key (base64url)
  -- Encrypted data
  encrypted_data_blob TEXT,                          -- §4.1 blob under DEK; NULL until first write
  -- DEK wrappers
  wrapped_dek_master  TEXT NOT NULL,                 -- §4.1 blob under Master KEK
  -- Versioning
  dek_version         INTEGER NOT NULL DEFAULT 1
                      CHECK (dek_version >= 1),      -- bump on DEK rotation (§5.7)
  master_version      INTEGER NOT NULL DEFAULT 1
                      CHECK (master_version >= 1),   -- bump on master rotation (§5.6)
  created_at          TEXT NOT NULL,                 -- ISO 8601
  updated_at          TEXT NOT NULL                  -- ISO 8601
);

CREATE TABLE api_keys (
  key_id        TEXT PRIMARY KEY,                    -- UUIDv4
  user_id       TEXT NOT NULL
                REFERENCES user_crypto (user_id) ON DELETE CASCADE,
  key_hash      TEXT NOT NULL UNIQUE,                -- SHA-256(api_key) hex — lookup index
  wrapped_dek   TEXT NOT NULL,                       -- §4.1 blob under API KEK
  expires_at    TEXT,                                -- ISO 8601, NULL = no expiry
  created_at    TEXT NOT NULL,
  last_used_at  TEXT,
  revoked       INTEGER NOT NULL DEFAULT 0           -- soft delete (SQLite boolean)
                CHECK (revoked IN (0, 1))
);

-- Lookup index for §5.4 step 4 (UNIQUE above already enforces
-- one-record-per-hash; this keeps the lookup path explicit).
CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);

-- Separate permissions table (spec §4.2): what an API key may do.
CREATE TABLE api_key_permissions (
  key_id     TEXT NOT NULL
             REFERENCES api_keys (key_id) ON DELETE CASCADE,
  scope      TEXT NOT NULL,                          -- "<resource>:<action>", e.g. "data:read"
  granted_at TEXT NOT NULL,                          -- ISO 8601
  PRIMARY KEY (key_id, scope)
);
