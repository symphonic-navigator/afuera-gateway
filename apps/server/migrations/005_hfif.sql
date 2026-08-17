-- Migration 005: per-user Hugging Face Inference Endpoints proxy ("hfif") —
-- business logic #3. See docs/specs/hfif.md.
--
-- Same threat model as the gateway (003): the server is zero-knowledge AT
-- REST. Each user stores ONE HF access token as a §4.1 blob encrypted
-- client-side under their DEK, AAD dataAAD(user_id, "hfif-credential",
-- dek_version). The server can decrypt it ONLY transiently, during a request
-- that presents an agk_ API key (which carries the key material).

-- Per-user HF token (one per user).
CREATE TABLE hf_credentials (
  user_id    TEXT PRIMARY KEY
             REFERENCES user_crypto (user_id) ON DELETE CASCADE,
  blob       TEXT NOT NULL,                       -- §4.1 blob, AAD "hfif-credential"
  created_at TEXT NOT NULL,                       -- ISO 8601
  updated_at TEXT NOT NULL                        -- ISO 8601
);
