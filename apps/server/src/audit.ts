import type { AppDatabase } from "./db/index.js";

/**
 * Append-only audit log (spec §6.2). Events used by the auth layer:
 *   register, login_success, login_failure, api_key_created,
 *   api_key_revoked, api_key_access_denied, master_rotated, dek_rotated,
 *   refresh_reuse_detected
 */
export function audit(
  db: AppDatabase,
  event: string,
  opts: { userId?: string | null; metadata?: Record<string, unknown>; ip?: string | null } = {},
): void {
  db.prepare(
    "INSERT INTO audit_log (user_id, event, metadata, ip, created_at) VALUES (?, ?, ?, ?, ?)",
  ).run(
    opts.userId ?? null,
    event,
    opts.metadata ? JSON.stringify(opts.metadata) : null,
    opts.ip ?? null,
    new Date().toISOString(),
  );
}
