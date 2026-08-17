import Fastify, { type FastifyInstance } from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifyRateLimit from "@fastify/rate-limit";
import fastifyWebsocket from "@fastify/websocket";
import { loadConfig, type AppConfig } from "./config.js";
import { openDatabase, type AppDatabase } from "./db/index.js";
import { UplinkRegistry } from "./ollama/registry.js";
import { ollamaUplinkRoutes } from "./ollama/uplink.js";
import { authRoutes } from "./routes/auth.js";
import { cryptoRoutes } from "./routes/crypto.js";
import { apiKeyRoutes } from "./routes/apikeys.js";
import { dataRoutes } from "./routes/data.js";
import { gatewayRoutes } from "./routes/gateway.js";
import { hfifRoutes } from "./routes/hfif.js";
import { ollamaRoutes } from "./routes/ollama.js";

export interface BuildAppOptions {
  /** Defaults to openDatabase() (file DB from DATABASE_PATH). Pass an in-memory DB in tests. */
  db?: AppDatabase;
  /** Shallow overrides on top of loadConfig() (env-derived defaults). */
  config?: Partial<AppConfig>;
  logger?: boolean;
}

/**
 * Build the HTTP app: /health plus the full auth layer (spec §5/§6/§8).
 * The server is zero-knowledge — it verifies Ed25519 signatures and stores
 * hashes/wrapped blobs only.
 */
export function buildApp(opts: BuildAppOptions = {}): FastifyInstance {
  const db = opts.db ?? openDatabase();
  const config: AppConfig = { ...loadConfig(), ...opts.config };
  const app = Fastify({ logger: opts.logger ?? false });
  // Active sidecar connections: in-memory only, never in the DB.
  const ollamaRegistry = new UplinkRegistry();

  void app.register(fastifyCookie);
  void app.register(fastifyRateLimit, {
    global: true,
    max: config.rateLimitGlobal.max,
    timeWindow: config.rateLimitGlobal.timeWindow,
  });
  // Sidecar-facing WebSocket endpoint (GET /uplink/:uplinkId).
  void app.register(fastifyWebsocket, { options: { maxPayload: 16 * 1024 * 1024 } });

  // Routes are registered in a follow-up plugin so avvio guarantees the
  // rate-limit plugin is fully loaded first — its onRoute hook (which picks
  // up per-route `config.rateLimit` overrides) only sees routes registered
  // after it has loaded.
  void app.register((instance, _opts, done) => {
    instance.get("/health", async () => ({ status: "ok" }));

    const ctx = { db, config, ollamaRegistry };
    authRoutes(instance, ctx);
    cryptoRoutes(instance, ctx);
    apiKeyRoutes(instance, ctx);
    dataRoutes(instance, ctx);
    gatewayRoutes(instance, ctx);
    hfifRoutes(instance, ctx);
    ollamaUplinkRoutes(instance, ctx);
    ollamaRoutes(instance, ctx);
    done();
  });

  return app;
}
