/**
 * Encrypted data blob read/write (spec §5.5 storage side).
 * The server stores ciphertext verbatim — it never sees plaintext.
 */

import type { FastifyInstance } from "fastify";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import { asBody, authGuard, unauthorized } from "../security.js";

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
}

export function dataRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db } = ctx;

  // Session OR api key with data:read.
  app.get(
    "/v1/data/blob",
    { preHandler: [authGuard(db, { session: true, apiKey: true, scope: "data:read" })] },
    async (req, reply) => {
      const auth = req.auth!;
      const row = db
        .prepare("SELECT encrypted_data_blob, dek_version FROM user_crypto WHERE user_id = ?")
        .get(auth.userId) as
        | { encrypted_data_blob: string | null; dek_version: number }
        | undefined;
      if (!row) return unauthorized(reply);
      return reply.send({
        encrypted_data_blob: row.encrypted_data_blob,
        dek_version: row.dek_version,
      });
    },
  );

  // Session OR api key with data:write. Ciphertext stored verbatim.
  app.put(
    "/v1/data/blob",
    { preHandler: [authGuard(db, { session: true, apiKey: true, scope: "data:write" })] },
    async (req, reply) => {
      const auth = req.auth!;
      const body = asBody(req);
      const blob = body["encrypted_data_blob"];
      if (typeof blob !== "string" || blob.length === 0) {
        return reply.code(400).send({ error: "bad_request" });
      }
      const result = db
        .prepare("UPDATE user_crypto SET encrypted_data_blob = ?, updated_at = ? WHERE user_id = ?")
        .run(blob, new Date().toISOString(), auth.userId);
      if (result.changes === 0) return unauthorized(reply);
      const row = db
        .prepare("SELECT dek_version FROM user_crypto WHERE user_id = ?")
        .get(auth.userId) as { dek_version: number };
      return reply.send({ ok: true, dek_version: row.dek_version });
    },
  );
}
