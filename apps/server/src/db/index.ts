import Database from "better-sqlite3";
import { migrate } from "./migrate.js";

export type AppDatabase = Database.Database;

/**
 * Open (or create) the application database and apply pending migrations.
 * Pass ":memory:" for tests.
 */
export function openDatabase(file = process.env["DATABASE_PATH"] ?? "afuera.db"): AppDatabase {
  const db = new Database(file);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migrate(db);
  return db;
}
