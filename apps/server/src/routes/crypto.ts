/**
 * Wrapped-DEK retrieval and key rotation endpoints (spec §5.4, §5.6, §5.7).
 */

import type { FastifyInstance } from "fastify";
import { verifyMasterRotationSignature } from "@afuera/crypto";
import { audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { AppDatabase } from "../db/index.js";
import {
  asBody,
  authGuard,
  decodeB64url,
  deleteUserTokens,
  isNonEmptyString,
  isValidBlob,
  unauthorized,
} from "../security.js";

interface RouteContext {
  db: AppDatabase;
  config: AppConfig;
}

interface UserCryptoRow {
  user_id: string;
  auth_public_key: string;
  encrypted_data_blob: string | null;
  wrapped_dek_master: string;
  dek_version: number;
  master_version: number;
}

export function cryptoRoutes(app: FastifyInstance, ctx: RouteContext): void {
  const { db, config } = ctx;

  // -- §5.2 step 6: master wrapper, session path ONLY -------------------------
  app.get(
    "/v1/crypto/wrapped-dek-master",
    { preHandler: [authGuard(db, { session: true })] },
    async (req, reply) => {
      const auth = req.auth!;
      const row = db
        .prepare("SELECT wrapped_dek_master, dek_version FROM user_crypto WHERE user_id = ?")
        .get(auth.userId) as Pick<UserCryptoRow, "wrapped_dek_master" | "dek_version"> | undefined;
      if (!row) return unauthorized(reply);
      return reply.send({
        wrapped_dek_master: row.wrapped_dek_master,
        dek_version: row.dek_version,
      });
    },
  );

  // -- §5.4 step 4: per-API-key wrapper, API key path ONLY --------------------
  app.get(
    "/v1/crypto/wrapped-dek",
    {
      config: { rateLimit: config.rateLimitStrict },
      preHandler: [authGuard(db, { apiKey: true, scope: "data:read" })],
    },
    async (req, reply) => {
      const auth = req.auth!;
      if (auth.type !== "apikey") return unauthorized(reply);
      const row = db
        .prepare(
          `SELECT k.wrapped_dek, u.dek_version
           FROM api_keys k JOIN user_crypto u ON u.user_id = k.user_id
           WHERE k.key_id = ?`,
        )
        .get(auth.keyId) as { wrapped_dek: string; dek_version: number } | undefined;
      if (!row) return unauthorized(reply);
      return reply.send({
        wrapped_dek: row.wrapped_dek,
        dek_version: row.dek_version,
        scopes: [...auth.scopes],
      });
    },
  );

  // -- §5.6: master rotation ---------------------------------------------------
  app.post(
    "/v1/crypto/rotate-master",
    { preHandler: [authGuard(db, { session: true })] },
    async (req, reply) => {
      const auth = req.auth!;
      const body = asBody(req);
      const newAuthPublicKey = body["new_auth_public_key"];
      const newWrappedDekMaster = body["new_wrapped_dek_master"];
      const rotationSignature = body["rotation_signature"];
      if (
        !decodeB64url(newAuthPublicKey, 32) ||
        !isValidBlob(newWrappedDekMaster) ||
        !isNonEmptyString(rotationSignature)
      ) {
        return reply.code(400).send({ error: "bad_request" });
      }
      const user = db
        .prepare("SELECT * FROM user_crypto WHERE user_id = ?")
        .get(auth.userId) as UserCryptoRow | undefined;
      if (!user) return unauthorized(reply);

      // Signature from the OLD auth key over
      // "ag-rotate-master-v1" || new_auth_public_key (§5.6 step 6).
      const oldPub = decodeB64url(user.auth_public_key, 32);
      const newPub = decodeB64url(newAuthPublicKey, 32);
      const sig = decodeB64url(rotationSignature, 64);
      let ok = false;
      if (oldPub && newPub && sig) {
        try {
          ok = verifyMasterRotationSignature(oldPub, newPub, sig);
        } catch {
          ok = false;
        }
      }
      if (!ok) return unauthorized(reply);

      // ONE transaction: swap auth key + master wrapper, bump version,
      // invalidate ALL tokens of the user (§5.6 step 7).
      const now = new Date().toISOString();
      db.transaction(() => {
        db.prepare(
          `UPDATE user_crypto
           SET auth_public_key = ?, wrapped_dek_master = ?,
               master_version = master_version + 1, updated_at = ?
           WHERE user_id = ?`,
        ).run(newAuthPublicKey, newWrappedDekMaster, now, user.user_id);
        deleteUserTokens(db, user.user_id);
        audit(db, "master_rotated", { userId: user.user_id, ip: req.ip });
      })();

      const updated = db
        .prepare("SELECT master_version FROM user_crypto WHERE user_id = ?")
        .get(user.user_id) as { master_version: number };
      return reply.send({ master_version: updated.master_version });
    },
  );

  // -- §5.7: DEK rotation -------------------------------------------------------
  app.post(
    "/v1/crypto/rotate-dek",
    { preHandler: [authGuard(db, { session: true })] },
    async (req, reply) => {
      const auth = req.auth!;
      const body = asBody(req);
      const newWrappedDekMaster = body["new_wrapped_dek_master"];
      const newDekVersion = body["new_dek_version"];
      const encryptedDataBlob = body["encrypted_data_blob"];
      const revokeAllApiKeys = body["revoke_all_api_keys"];
      // Gateway extension (docs/specs/gateway.md §rotation): optional array of
      // credential blobs already re-encrypted client-side under the new
      // DEK/version.
      const gatewayCredentials = body["gateway_credentials"];
      // HF extension (docs/specs/hfif.md §rotation): optional single
      // credential blob already re-encrypted client-side under the new
      // DEK/version.
      const hfCredential = body["hf_credential"];
      if (
        !isValidBlob(newWrappedDekMaster) ||
        typeof newDekVersion !== "number" ||
        !Number.isInteger(newDekVersion) ||
        !isValidBlob(encryptedDataBlob) ||
        revokeAllApiKeys !== true
      ) {
        return reply.code(400).send({ error: "bad_request" });
      }
      let stagedCredentials: { api_name: string; blob: string }[] | null = null;
      if (gatewayCredentials !== undefined) {
        if (
          !Array.isArray(gatewayCredentials) ||
          gatewayCredentials.some(
            (c) =>
              typeof c !== "object" ||
              c === null ||
              !isNonEmptyString((c as Record<string, unknown>)["api_name"]) ||
              !isValidBlob((c as Record<string, unknown>)["blob"]),
          )
        ) {
          return reply.code(400).send({ error: "bad_request" });
        }
        stagedCredentials = gatewayCredentials as { api_name: string; blob: string }[];
        if (new Set(stagedCredentials.map((c) => c.api_name)).size !== stagedCredentials.length) {
          return reply.code(400).send({ error: "bad_request" });
        }
      }
      let stagedHfCredential: string | null = null;
      if (hfCredential !== undefined) {
        if (
          typeof hfCredential !== "object" ||
          hfCredential === null ||
          !isValidBlob((hfCredential as Record<string, unknown>)["blob"])
        ) {
          return reply.code(400).send({ error: "bad_request" });
        }
        stagedHfCredential = (hfCredential as { blob: string }).blob;
      }
      const user = db
        .prepare("SELECT * FROM user_crypto WHERE user_id = ?")
        .get(auth.userId) as UserCryptoRow | undefined;
      if (!user) return unauthorized(reply);

      // The client must prove it knows the current version (§5.7 step 3).
      if (newDekVersion !== user.dek_version + 1) {
        return reply.code(409).send({ error: "version_conflict" });
      }

      // If the user has gateway credentials, the staged array MUST cover
      // exactly the existing api_names — blobs are re-encrypted under the new
      // DEK/version and cannot be recovered after rotation.
      const existingNames = new Set(
        (
          db
            .prepare("SELECT api_name FROM gateway_credentials WHERE user_id = ?")
            .all(user.user_id) as { api_name: string }[]
        ).map((r) => r.api_name),
      );
      const stagedNames = new Set((stagedCredentials ?? []).map((c) => c.api_name));
      if (
        existingNames.size !== stagedNames.size ||
        ![...existingNames].every((n) => stagedNames.has(n))
      ) {
        return reply.code(400).send({ error: "incomplete_rotation" });
      }

      // Same rule for the HF credential (hfif.md): if the user HAS one, the
      // field MUST be present; if they have none, it must be absent — the
      // blob cannot be recovered after rotation.
      const hasHfCredential =
        db.prepare("SELECT 1 AS x FROM hf_credentials WHERE user_id = ?").get(user.user_id) !==
        undefined;
      if (hasHfCredential !== (stagedHfCredential !== null)) {
        return reply.code(400).send({ error: "incomplete_rotation" });
      }

      // ONE transaction (§5.7 step 7): bump dek_version, swap blob and
      // master wrapper, replace all gateway credential blobs, revoke ALL
      // api keys.
      const now = new Date().toISOString();
      db.transaction(() => {
        db.prepare(
          `UPDATE user_crypto
           SET wrapped_dek_master = ?, encrypted_data_blob = ?,
               dek_version = ?, updated_at = ?
           WHERE user_id = ? AND dek_version = ?`,
        ).run(newWrappedDekMaster, encryptedDataBlob, newDekVersion, now, user.user_id, user.dek_version);
        if (stagedCredentials !== null) {
          const updateCred = db.prepare(
            `UPDATE gateway_credentials SET blob = ?, updated_at = ?
             WHERE user_id = ? AND api_name = ?`,
          );
          for (const c of stagedCredentials) {
            updateCred.run(c.blob, now, user.user_id, c.api_name);
          }
        }
        if (stagedHfCredential !== null) {
          db.prepare(
            `UPDATE hf_credentials SET blob = ?, updated_at = ? WHERE user_id = ?`,
          ).run(stagedHfCredential, now, user.user_id);
        }
        db.prepare("UPDATE api_keys SET revoked = 1 WHERE user_id = ?").run(user.user_id);
        audit(db, "dek_rotated", {
          userId: user.user_id,
          metadata: {
            new_dek_version: newDekVersion,
            gateway_credentials: stagedCredentials?.length ?? 0,
            hf_credential: stagedHfCredential !== null,
          },
          ip: req.ip,
        });
      })();

      return reply.send({ dek_version: newDekVersion });
    },
  );
}
