import { randomBytes } from "node:crypto";

export interface RateLimitConfig {
  max: number;
  timeWindow: string;
}

export interface AppConfig {
  /**
   * Secret for the anti-enumeration HMAC (fake challenges for unknown
   * users, spec §5.2). From AG_SERVER_SECRET; if unset, a random secret is
   * generated per boot (fine for tests and single-process deployments —
   * fake challenges only need to be syntactically valid).
   */
  serverSecret: string;
  /** Challenge nonce TTL — spec §5.2 requires ≤ 60 s. */
  challengeTtlMs: number;
  /** Access token TTL — spec §5.9: 15 min. */
  accessTokenTtlMs: number;
  /** Refresh token TTL — spec §5.9: 30 days. */
  refreshTokenTtlMs: number;
  /** Moderate global default rate limit (per IP). */
  rateLimitGlobal: RateLimitConfig;
  /** Strict limit for login challenge/verify and API-key DEK retrieval (spec §6.1). */
  rateLimitStrict: RateLimitConfig;
  /**
   * Gateway admin user_ids (AG_ADMIN_USERS, comma-separated). Empty = no
   * admins: no one can define/remove upstream APIs (docs/specs/gateway.md).
   */
  adminUsers: string[];
  /** Per-API-key rate limit for the gateway proxy route (~60/min). */
  rateLimitGateway: RateLimitConfig;
  /** Timeout for a single upstream call made by the gateway proxy. */
  gatewayUpstreamTimeoutMs: number;
  /**
   * Dev/test escape hatch (AG_GATEWAY_ALLOW_HTTP=1): allow http:// base_urls
   * when defining upstream APIs. Production MUST keep this off — upstream
   * keys are injected into these requests.
   */
  gatewayAllowHttp: boolean;
  /**
   * Public base URL of this server (AG_PUBLIC_BASE_URL, e.g.
   * "https://gateway.example.com"). Used to build the sidecar relay_url
   * (wss://…/uplink/<id>) returned by POST /v1/ollama/uplinks. If unset, the
   * relay_url is derived from the request's Host header / protocol.
   */
  publicBaseUrl: string | null;
  /** Per-key/user rate limit for the Ollama client proxy (~60/min). */
  rateLimitOllama: RateLimitConfig;
  /**
   * Overall timeout for one tunnelled Ollama request (~120 s,
   * AG_OLLAMA_PROXY_TIMEOUT_MS) → cancel + 504.
   */
  ollamaProxyTimeoutMs: number;
  /**
   * HF Inference Endpoints control-plane base URL (AG_HF_API_BASE,
   * docs/specs/hfif.md). No trailing slash.
   */
  hfApiBase: string;
  /** HF whoami-v2 URL (AG_HF_WHOAMI_URL) — namespace + token scope check. */
  hfWhoamiUrl: string;
  /** Per-API-key rate limit for the hfif proxy/control routes (~60/min). */
  rateLimitHfif: RateLimitConfig;
  /** Upper bound for resume/pause wait loops (AG_HFIF_RESUME_TIMEOUT_MS). */
  hfifResumeTimeoutMs: number;
  /** Poll interval while waiting for an endpoint state change. */
  hfifResumePollMs: number;
  /**
   * Timeout for a single inference-upstream call (~600 s,
   * AG_HFIF_UPSTREAM_TIMEOUT_MS) — cold-start tolerance.
   */
  hfifUpstreamTimeoutMs: number;
  /**
   * Dev/test escape hatch (AG_HFIF_ALLOW_HTTP=1): allow http:// endpoint
   * invocation URLs (status.url). Production MUST keep this off — the
   * user's HF token is injected into these requests.
   */
  hfifAllowHttp: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return {
    serverSecret: env["AG_SERVER_SECRET"] ?? randomBytes(32).toString("hex"),
    challengeTtlMs: Number(env["AG_CHALLENGE_TTL_MS"] ?? 60_000),
    accessTokenTtlMs: Number(env["AG_ACCESS_TOKEN_TTL_MS"] ?? 15 * 60_000),
    refreshTokenTtlMs: Number(env["AG_REFRESH_TOKEN_TTL_MS"] ?? 30 * 24 * 60 * 60_000),
    rateLimitGlobal: { max: Number(env["AG_RATE_LIMIT_MAX"] ?? 300), timeWindow: "1 minute" },
    rateLimitStrict: {
      max: Number(env["AG_RATE_LIMIT_STRICT_MAX"] ?? 10),
      timeWindow: "1 minute",
    },
    adminUsers: (env["AG_ADMIN_USERS"] ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
    rateLimitGateway: {
      max: Number(env["AG_RATE_LIMIT_GATEWAY_MAX"] ?? 60),
      timeWindow: "1 minute",
    },
    gatewayUpstreamTimeoutMs: Number(env["AG_GATEWAY_UPSTREAM_TIMEOUT_MS"] ?? 60_000),
    gatewayAllowHttp: env["AG_GATEWAY_ALLOW_HTTP"] === "1",
    publicBaseUrl: env["AG_PUBLIC_BASE_URL"] ?? null,
    rateLimitOllama: {
      max: Number(env["AG_RATE_LIMIT_OLLAMA_MAX"] ?? 60),
      timeWindow: "1 minute",
    },
    ollamaProxyTimeoutMs: Number(env["AG_OLLAMA_PROXY_TIMEOUT_MS"] ?? 120_000),
    hfApiBase: (
      env["AG_HF_API_BASE"] ?? "https://api.endpoints.huggingface.cloud/v2/endpoint"
    ).replace(/\/+$/, ""),
    hfWhoamiUrl: env["AG_HF_WHOAMI_URL"] ?? "https://huggingface.co/api/whoami-v2",
    rateLimitHfif: {
      max: Number(env["AG_RATE_LIMIT_HFIF_MAX"] ?? 60),
      timeWindow: "1 minute",
    },
    hfifResumeTimeoutMs: Number(env["AG_HFIF_RESUME_TIMEOUT_MS"] ?? 180_000),
    hfifResumePollMs: Number(env["AG_HFIF_RESUME_POLL_MS"] ?? 5_000),
    hfifUpstreamTimeoutMs: Number(env["AG_HFIF_UPSTREAM_TIMEOUT_MS"] ?? 600_000),
    hfifAllowHttp: env["AG_HFIF_ALLOW_HTTP"] === "1",
  };
}
