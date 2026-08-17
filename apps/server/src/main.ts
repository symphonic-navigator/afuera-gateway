import { buildApp } from "./app.js";
import { openDatabase } from "./db/index.js";

const port = Number(process.env["PORT"] ?? 3000);
const host = process.env["HOST"] ?? "0.0.0.0";

// Open (and migrate) the database at startup so migration errors fail fast.
const db = openDatabase();

const app = buildApp({ db, logger: true });

try {
  await app.listen({ port, host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
