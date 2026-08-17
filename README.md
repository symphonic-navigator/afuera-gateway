# afuera-gateway

api multiplexer, for ZKP / E2EE use to break "regulation" and geofencing

## Layout

pnpm-workspaces monorepo (Node ≥ 22, pnpm 11):

- `packages/crypto` — `@afuera/crypto`: client-side E2EE crypto core
  (HKDF key hierarchy, XChaCha20-Poly1305 blobs + key wrapping, BIP-39
  mnemonic, Ed25519 login/rotation signatures, API-key tokens).
  Spec: `docs/specs/auth-crypto.md`.
- `apps/server` — `@afuera/server`: zero-knowledge Fastify 5 + SQLite
  (better-sqlite3) backend implementing the auth layer (registration,
  challenge-response login, session tokens, API keys, rotations, audit log).
  REST reference: `docs/specs/auth-api.md`.
- `apps/client` — Vite + React scaffold.
- `docs/specs` — authoritative specs.

## Commands

```sh
pnpm install          # install workspace deps
pnpm -r typecheck     # TypeScript checks, all packages
pnpm -r test          # Vitest, all packages (server tests use in-memory SQLite)
pnpm -r build         # build all packages
pnpm dev              # run all dev servers in parallel
pnpm --filter @afuera/server dev    # server only (tsx watch)
```

Server configuration is via env vars — see `docs/specs/auth-api.md`
("Configuration"). Migrations in `apps/server/migrations/*.sql` are applied
automatically at startup.
