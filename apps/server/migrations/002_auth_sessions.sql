-- Migration 002: auth sessions, login challenges, audit log (spec §5.2, §5.9, §6.2)
--
-- The server stays zero-knowledge: challenges and session tokens are stored
-- as opaque values / SHA-256 hashes only, never plaintext secrets.

-- Single-use login challenges (spec §5.2). nonce is the base64url-encoded
-- 32-byte CSPRNG value sent to the client; it is signed verbatim by the
-- client together with expires_at.
CREATE TABLE challenges (
  nonce      TEXT PRIMARY KEY,                     -- base64url, 32-byte CSPRNG
  user_id    TEXT NOT NULL
             REFERENCES user_crypto (user_id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,                        -- ISO 8601, TTL ≤ 60 s
  consumed   INTEGER NOT NULL DEFAULT 0            -- single-use, set atomically BEFORE verify
             CHECK (consumed IN (0, 1))
);

CREATE INDEX idx_challenges_expires_at ON challenges (expires_at);

-- Session tokens (spec §5.9). Only SHA-256(token) hex is stored.
--   kind      — 'access' (15 min, response body) | 'refresh' (30 days, cookie)
--   family_id — one login session; refresh rotation keeps the family,
--               reuse of a rotated refresh token revokes the WHOLE family.
CREATE TABLE auth_tokens (
  token_hash TEXT PRIMARY KEY,                     -- SHA-256(token) hex
  user_id    TEXT NOT NULL
             REFERENCES user_crypto (user_id) ON DELETE CASCADE,
  kind       TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
  family_id  TEXT NOT NULL,                        -- UUIDv4 per login
  expires_at TEXT NOT NULL,                        -- ISO 8601
  created_at TEXT NOT NULL,                        -- ISO 8601
  revoked    INTEGER NOT NULL DEFAULT 0
             CHECK (revoked IN (0, 1))
);

CREATE INDEX idx_auth_tokens_family ON auth_tokens (family_id);
CREATE INDEX idx_auth_tokens_user ON auth_tokens (user_id);

-- Append-only audit log (spec §6.2). metadata is a JSON object string.
CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    TEXT,                                 -- NULL when no user context (e.g. unknown-user login)
  event      TEXT NOT NULL,                        -- e.g. "login_success", "refresh_reuse_detected"
  metadata   TEXT,                                 -- JSON object, NULL when empty
  ip         TEXT,
  created_at TEXT NOT NULL                         -- ISO 8601
);

CREATE INDEX idx_audit_log_user ON audit_log (user_id);
CREATE INDEX idx_audit_log_event ON audit_log (event);
