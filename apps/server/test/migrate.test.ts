import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { migrate } from "../src/db/migrate.js";

function freshDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("foreign_keys = ON");
  return db;
}

function tableNames(db: Database.Database): string[] {
  const rows = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .all() as { name: string }[];
  return rows.map((r) => r.name);
}

function columns(db: Database.Database, table: string): string[] {
  return (db.pragma(`table_info(${table})`) as { name: string }[]).map((c) => c.name);
}

describe("migration 001 (spec §4.2 schema)", () => {
  it("applies cleanly to a fresh in-memory database", () => {
    const db = freshDb();
    const applied = migrate(db);
    expect(applied).toEqual([
      "001_auth_crypto.sql",
      "002_auth_sessions.sql",
      "003_gateway.sql",
      "004_ollama.sql",
      "005_hfif.sql",
    ]);
    expect(tableNames(db)).toEqual([
      "api_key_permissions",
      "api_keys",
      "audit_log",
      "auth_tokens",
      "challenges",
      "gateway_apis",
      "gateway_credentials",
      "hf_credentials",
      "ollama_uplinks",
      "schema_migrations",
      "user_crypto",
    ]);
  });

  it("is idempotent — running twice applies nothing the second time", () => {
    const db = freshDb();
    migrate(db);
    expect(migrate(db)).toEqual([]);
  });

  it("user_crypto has the UserCryptoRecord columns incl. dek_version/master_version", () => {
    const db = freshDb();
    migrate(db);
    expect(columns(db, "user_crypto")).toEqual([
      "user_id",
      "auth_public_key",
      "encrypted_data_blob",
      "wrapped_dek_master",
      "dek_version",
      "master_version",
      "created_at",
      "updated_at",
    ]);
  });

  it("api_keys has the ApiKeyRecord columns, a key_hash index, and FK to user_crypto", () => {
    const db = freshDb();
    migrate(db);
    expect(columns(db, "api_keys")).toEqual([
      "key_id",
      "user_id",
      "key_hash",
      "wrapped_dek",
      "expires_at",
      "created_at",
      "last_used_at",
      "revoked",
    ]);
    const indexes = db.pragma("index_list(api_keys)") as { name: string }[];
    expect(indexes.map((i) => i.name)).toContain("idx_api_keys_key_hash");
  });

  it("api_key_permissions has composite PK (key_id, scope)", () => {
    const db = freshDb();
    migrate(db);
    const info = db.pragma("table_info(api_key_permissions)") as {
      name: string;
      pk: number;
    }[];
    const pkCols = info.filter((c) => c.pk > 0).map((c) => c.name);
    expect(pkCols).toEqual(["key_id", "scope"]);
  });

  it("migration 002 tables: challenges, auth_tokens, audit_log (spec §5.2, §5.9, §6.2)", () => {
    const db = freshDb();
    migrate(db);
    expect(columns(db, "challenges")).toEqual(["nonce", "user_id", "expires_at", "consumed"]);
    expect(columns(db, "auth_tokens")).toEqual([
      "token_hash",
      "user_id",
      "kind",
      "family_id",
      "expires_at",
      "created_at",
      "revoked",
    ]);
    expect(columns(db, "audit_log")).toEqual([
      "id",
      "user_id",
      "event",
      "metadata",
      "ip",
      "created_at",
    ]);
    // auth_tokens.kind constrained to access|refresh
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO user_crypto
         (user_id, auth_public_key, encrypted_data_blob, wrapped_dek_master,
          dek_version, master_version, created_at, updated_at)
       VALUES ('user-1', 'pk', NULL, 'w', 1, 1, ?, ?)`,
    ).run(now, now);
    expect(() =>
      db
        .prepare(
          `INSERT INTO auth_tokens (token_hash, user_id, kind, family_id, expires_at, created_at, revoked)
           VALUES ('h', 'user-1', 'bogus', 'fam', ?, ?, 0)`,
        )
        .run(now, now),
    ).toThrowError();
  });

  it("migration 003 tables: gateway_apis, gateway_credentials (gateway.md schema)", () => {
    const db = freshDb();
    migrate(db);
    expect(columns(db, "gateway_apis")).toEqual([
      "name",
      "base_url",
      "description",
      "auth_header",
      "auth_scheme",
      "created_by",
      "created_at",
    ]);
    expect(columns(db, "gateway_credentials")).toEqual([
      "user_id",
      "api_name",
      "blob",
      "created_at",
      "updated_at",
    ]);

    // composite PK (user_id, api_name) + cascade from gateway_apis
    const info = db.pragma("table_info(gateway_credentials)") as { name: string; pk: number }[];
    expect(info.filter((c) => c.pk > 0).map((c) => c.name)).toEqual(["user_id", "api_name"]);

    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO user_crypto
         (user_id, auth_public_key, encrypted_data_blob, wrapped_dek_master,
          dek_version, master_version, created_at, updated_at)
       VALUES ('user-1', 'pk', NULL, 'w', 1, 1, ?, ?)`,
    ).run(now, now);
    db.prepare(
      `INSERT INTO gateway_apis (name, base_url, description, auth_header, auth_scheme, created_by, created_at)
       VALUES ('nano-gpt', 'https://api.nano-gpt.com', NULL, 'Authorization', 'Bearer', 'user-1', ?)`,
    ).run(now);
    db.prepare(
      `INSERT INTO gateway_credentials (user_id, api_name, blob, created_at, updated_at)
       VALUES ('user-1', 'nano-gpt', 'blob', ?, ?)`,
    ).run(now, now);
    // deleting the API cascades its credentials
    db.prepare("DELETE FROM gateway_apis WHERE name = 'nano-gpt'").run();
    expect(db.prepare("SELECT COUNT(*) AS n FROM gateway_credentials").get()).toEqual({ n: 0 });
  });

  it("migration 004 table: ollama_uplinks (ollama-relay.md schema)", () => {
    const db = freshDb();
    migrate(db);
    expect(columns(db, "ollama_uplinks")).toEqual([
      "id",
      "user_id",
      "name",
      "psk_hash",
      "models",
      "created_at",
      "updated_at",
    ]);

    const now = new Date().toISOString();
    const insertUser = db.prepare(
      `INSERT INTO user_crypto
         (user_id, auth_public_key, encrypted_data_blob, wrapped_dek_master,
          dek_version, master_version, created_at, updated_at)
       VALUES (?, 'pk', NULL, 'w', 1, 1, ?, ?)`,
    );
    insertUser.run("user-1", now, now);
    insertUser.run("user-2", now, now);
    const insertUplink = db.prepare(
      `INSERT INTO ollama_uplinks (id, user_id, name, psk_hash, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    insertUplink.run("uplink-1", "user-1", "strixhalo", "hash-1", now, now);

    // UNIQUE(user_id, name): same name for the same user rejected…
    expect(() => insertUplink.run("uplink-2", "user-1", "strixhalo", "hash-2", now, now)).toThrowError();
    // …but the same name for a DIFFERENT user is fine (per-user namespace).
    insertUplink.run("uplink-3", "user-2", "strixhalo", "hash-3", now, now);
    // psk_hash is globally UNIQUE.
    expect(() => insertUplink.run("uplink-4", "user-2", "other", "hash-1", now, now)).toThrowError();
    // FK: unknown user rejected.
    expect(() => insertUplink.run("uplink-5", "nobody", "x1", "hash-5", now, now)).toThrowError();
    // models defaults to an empty JSON array.
    expect(db.prepare("SELECT models FROM ollama_uplinks WHERE id = 'uplink-1'").get()).toEqual({
      models: "[]",
    });
    // deleting the user cascades their uplinks.
    db.prepare("DELETE FROM user_crypto WHERE user_id = 'user-1'").run();
    expect(
      db.prepare("SELECT COUNT(*) AS n FROM ollama_uplinks WHERE user_id = 'user-1'").get(),
    ).toEqual({ n: 0 });
    expect(
      db.prepare("SELECT COUNT(*) AS n FROM ollama_uplinks WHERE user_id = 'user-2'").get(),
    ).toEqual({ n: 1 });
  });

  it("migration 005 table: hf_credentials (hfif.md schema)", () => {
    const db = freshDb();
    migrate(db);
    expect(columns(db, "hf_credentials")).toEqual([
      "user_id",
      "blob",
      "created_at",
      "updated_at",
    ]);

    // PK is user_id (one HF token per user) + cascade from user_crypto
    const info = db.pragma("table_info(hf_credentials)") as { name: string; pk: number }[];
    expect(info.filter((c) => c.pk > 0).map((c) => c.name)).toEqual(["user_id"]);

    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO user_crypto
         (user_id, auth_public_key, encrypted_data_blob, wrapped_dek_master,
          dek_version, master_version, created_at, updated_at)
       VALUES ('user-1', 'pk', NULL, 'w', 1, 1, ?, ?)`,
    ).run(now, now);
    db.prepare(
      `INSERT INTO hf_credentials (user_id, blob, created_at, updated_at)
       VALUES ('user-1', 'blob', ?, ?)`,
    ).run(now, now);
    // one credential per user
    expect(() =>
      db
        .prepare(
          `INSERT INTO hf_credentials (user_id, blob, created_at, updated_at)
           VALUES ('user-1', 'blob2', ?, ?)`,
        )
        .run(now, now),
    ).toThrowError();
    // FK: unknown user rejected
    expect(() =>
      db
        .prepare(
          `INSERT INTO hf_credentials (user_id, blob, created_at, updated_at)
           VALUES ('nobody', 'blob', ?, ?)`,
        )
        .run(now, now),
    ).toThrowError();
    // deleting the user cascades the credential
    db.prepare("DELETE FROM user_crypto WHERE user_id = 'user-1'").run();
    expect(db.prepare("SELECT COUNT(*) AS n FROM hf_credentials").get()).toEqual({ n: 0 });
  });

  it("roundtrip: insert a user, an API key, and permissions; FK + uniqueness enforced", () => {
    const db = freshDb();
    migrate(db);
    const now = new Date().toISOString();

    db.prepare(
      `INSERT INTO user_crypto
         (user_id, auth_public_key, encrypted_data_blob, wrapped_dek_master,
          dek_version, master_version, created_at, updated_at)
       VALUES (?, ?, ?, ?, 1, 1, ?, ?)`,
    ).run("user-1", "pubkey-b64url", null, "wrapped-blob", now, now);

    db.prepare(
      `INSERT INTO api_keys
         (key_id, user_id, key_hash, wrapped_dek, expires_at, created_at, last_used_at, revoked)
       VALUES (?, ?, ?, ?, NULL, ?, NULL, 0)`,
    ).run("key-1", "user-1", "deadbeef", "wrapped-api-blob", now);

    db.prepare(
      "INSERT INTO api_key_permissions (key_id, scope, granted_at) VALUES (?, ?, ?)",
    ).run("key-1", "data:read", now);

    const key = db.prepare("SELECT * FROM api_keys WHERE key_hash = ?").get("deadbeef") as {
      key_id: string;
      revoked: number;
    };
    expect(key.key_id).toBe("key-1");
    expect(key.revoked).toBe(0);

    // duplicate (key_id, scope) rejected
    expect(() =>
      db
        .prepare("INSERT INTO api_key_permissions (key_id, scope, granted_at) VALUES (?, ?, ?)")
        .run("key-1", "data:read", now),
    ).toThrowError();

    // FK violation: key for unknown user rejected
    expect(() =>
      db
        .prepare(
          `INSERT INTO api_keys
             (key_id, user_id, key_hash, wrapped_dek, expires_at, created_at, last_used_at, revoked)
           VALUES ('key-2', 'nobody', 'cafe', 'x', NULL, ?, NULL, 0)`,
        )
        .run(now),
    ).toThrowError();
  });
});
