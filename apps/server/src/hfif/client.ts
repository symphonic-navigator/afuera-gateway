/**
 * Hugging Face Inference Endpoints API client — business logic #3 ("hfif"),
 * docs/specs/hfif.md.
 *
 * TypeScript port of the reference Python client
 * (hf-inference-proxy: src/hf_inference_proxy/hf.py). All calls go directly
 * to the HF HTTP API with the user's HF token as Bearer:
 *
 *   whoami-v2                    -> namespace + token role/scopes (free)
 *   GET  {api_base}/{ns}         -> list endpoints (free)
 *   GET  {api_base}/{ns}/{name}  -> describe one endpoint (free)
 *   POST {api_base}/{ns}/{name}/resume -> resume a paused endpoint
 *   POST {api_base}/{ns}/{name}/pause  -> pause a running endpoint (stops GPU cost)
 *
 * Differences from the Python original (documented in hfif.md):
 *  - no cross-request caching: the client is constructed per request with
 *    the transiently decrypted token; the namespace is resolved lazily and
 *    memoized only for the lifetime of the instance (one request);
 *  - `pause` returns null on wait-timeout (the Python original had a
 *    dead-code fallback returning the last poll result);
 *  - the 401-token reason string no longer references the `hf` CLI.
 */

// Scopes that the proxy needs. `inference.endpoints.write` is the important
// one — without it we can list/describe but not resume paused endpoints.
export const HF_REQUIRED_SCOPES = ["inference.endpoints.write"] as const;

// Token roles that implicitly have write access (classic user tokens used
// to, fine-grained tokens need explicit scope). We check both.
const WRITE_ROLES = new Set(["write", "admin", "owner"]);

/** Timeout for control-plane calls (whoami/list/describe/resume/pause). */
const CONTROL_TIMEOUT_MS = 30_000;

export interface HfClientConfig {
  /** e.g. https://api.endpoints.huggingface.cloud/v2/endpoint */
  apiBase: string;
  /** e.g. https://huggingface.co/api/whoami-v2 */
  whoamiUrl: string;
  resumeTimeoutMs: number;
  resumePollMs: number;
}

/** Result of a token capability check (ported TokenCheckResult shape). */
export interface TokenCheckResult {
  ok: boolean;
  namespace: string | null;
  username: string | null;
  role: string | null;
  scopes: string[];
  has_write: boolean;
  reason: string | null;
}

/** Raw endpoint object as returned by the HF API (nested, loosely typed). */
export type RawEndpoint = Record<string, unknown>;

/** Control-plane returned a non-2xx status. */
export class HfApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`HF API returned HTTP ${String(status)}`);
    this.name = "HfApiError";
  }
}

/** Control-plane unreachable / timeout. */
export class HfNetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HfNetworkError";
  }
}

function asObj(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
}

function asStr(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function asNum(v: unknown): number | null {
  return typeof v === "number" ? v : null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class HfClient {
  /** Namespace memoized for the lifetime of this (per-request) client. */
  private namespace: string | null = null;

  constructor(
    private readonly token: string,
    private readonly cfg: HfClientConfig,
  ) {}

  private async request(method: string, url: string): Promise<Response> {
    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: { authorization: `Bearer ${this.token}` },
        signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
      });
    } catch (err) {
      throw new HfNetworkError(err instanceof Error ? err.message : String(err));
    }
    return res;
  }

  private async requestJson(method: string, url: string): Promise<unknown> {
    const res = await this.request(method, url);
    if (!res.ok) {
      throw new HfApiError(res.status, await res.text());
    }
    return res.json();
  }

  // --- namespace -----------------------------------------------------------

  async resolveNamespace(): Promise<string> {
    if (this.namespace !== null) return this.namespace;
    const data = asObj(await this.requestJson("GET", this.cfg.whoamiUrl));
    let name = asStr(data["name"]);
    if (!name) {
      const orgs = Array.isArray(data["orgs"]) ? data["orgs"] : [];
      name = orgs.length > 0 ? asStr(asObj(orgs[0])["name"]) : null;
    }
    if (!name) throw new HfApiError(200, "could not resolve namespace from whoami");
    this.namespace = name;
    return name;
  }

  // --- token check (free) ---------------------------------------------------

  /**
   * Check whether the token can do what we need (ported `check_token`).
   * `networkError` flags control-plane unreachability so the route layer can
   * answer 502 instead of a capability report.
   */
  async checkToken(): Promise<{ check: TokenCheckResult; networkError: boolean }> {
    const fail = (reason: string): { check: TokenCheckResult; networkError: boolean } => ({
      networkError: false,
      check: {
        ok: false,
        namespace: null,
        username: null,
        role: null,
        scopes: [],
        has_write: false,
        reason,
      },
    });

    let res: Response;
    try {
      res = await this.request("GET", this.cfg.whoamiUrl);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ...fail(`network error: ${message}`), networkError: true };
    }
    if (res.status === 401) {
      return fail("token is invalid or expired");
    }
    if (res.status !== 200) {
      return fail(`whoami-v2 returned HTTP ${String(res.status)}`);
    }
    const data = asObj(await res.json());
    const username = asStr(data["name"]);
    const orgs = Array.isArray(data["orgs"]) ? data["orgs"] : [];
    const namespace = username ?? (orgs.length > 0 ? asStr(asObj(orgs[0])["name"]) : null);
    const accessToken = asObj(asObj(data["auth"])["accessToken"]);
    const role = asStr(accessToken["role"]);
    const fineGrained = asObj(accessToken["fineGrained"]);
    // collect all scopes: global + scoped per entity
    const scopes: string[] = Array.isArray(fineGrained["global"])
      ? (fineGrained["global"] as unknown[]).filter((s): s is string => typeof s === "string")
      : [];
    const scoped = Array.isArray(fineGrained["scoped"]) ? fineGrained["scoped"] : [];
    for (const entry of scoped) {
      const permissions = asObj(entry)["permissions"];
      if (!Array.isArray(permissions)) continue;
      for (const perm of permissions) {
        if (typeof perm === "string" && !scopes.includes(perm)) scopes.push(perm);
      }
    }
    const scopeSet = new Set(scopes);
    const hasWrite =
      (role !== null && WRITE_ROLES.has(role)) ||
      HF_REQUIRED_SCOPES.every((s) => scopeSet.has(s));
    const missing = HF_REQUIRED_SCOPES.filter((s) => !scopeSet.has(s));
    let reason: string | null = null;
    if (!hasWrite) {
      if (role === "read") {
        reason =
          "token is read-only (role 'read'). Create a fine-grained " +
          "token with 'inference.endpoints.write' scope at " +
          "https://huggingface.co/settings/tokens";
      } else if (missing.length > 0) {
        reason =
          `token is missing scope(s): ${missing.join(", ")}. ` +
          "Create a fine-grained token with these scopes at " +
          "https://huggingface.co/settings/tokens";
      } else {
        reason = "token role or scopes are insufficient for resume";
      }
    }
    return {
      networkError: false,
      check: {
        ok: hasWrite,
        namespace,
        username,
        role,
        scopes,
        has_write: hasWrite,
        reason,
      },
    };
  }

  // --- list + describe (free) ------------------------------------------------

  async listEndpoints(): Promise<RawEndpoint[]> {
    const ns = await this.resolveNamespace();
    const data = asObj(await this.requestJson("GET", `${this.cfg.apiBase}/${ns}`));
    const items = data["items"];
    return Array.isArray(items) ? (items as RawEndpoint[]) : [];
  }

  async describeEndpoint(name: string): Promise<RawEndpoint> {
    const ns = await this.resolveNamespace();
    return asObj(await this.requestJson("GET", `${this.cfg.apiBase}/${ns}/${name}`));
  }

  // --- resume (control plane, no inference cost) -----------------------------

  /**
   * Resume a paused/scaled-to-zero endpoint and (optionally) wait for
   * running. Returns the described endpoint once running, or null on
   * failure/timeout. Resume is a control-plane call — it does not itself
   * incur GPU cost; cost starts when the endpoint is actually running.
   */
  async resumeEndpoint(name: string, wait = true): Promise<RawEndpoint | null> {
    return this.stateChange(name, "resume", wait);
  }

  // --- pause (control plane, stops GPU cost) ---------------------------------

  /**
   * Pause a running endpoint (stops the GPU and thus the cost). Returns the
   * described endpoint once paused, or null on failure/timeout.
   */
  async pauseEndpoint(name: string, wait = true): Promise<RawEndpoint | null> {
    return this.stateChange(name, "pause", wait);
  }

  private async stateChange(
    name: string,
    action: "resume" | "pause",
    wait: boolean,
  ): Promise<RawEndpoint | null> {
    const ns = await this.resolveNamespace();
    let res: Response;
    try {
      res = await this.request("POST", `${this.cfg.apiBase}/${ns}/${name}/${action}`);
    } catch {
      return null;
    }
    if (!res.ok) {
      const text = await res.text();
      // 400 "already running"/"already paused" is fine — target state reached.
      const already = action === "resume" ? "already running" : "already paused";
      if (!(res.status === 400 && text.includes(already))) {
        return null;
      }
    }

    if (!wait) {
      try {
        return await this.describeEndpoint(name);
      } catch {
        return null;
      }
    }

    // Pause is usually fast (~5-15 s), but we reuse the resume timeout as
    // upper bound for both (as the reference does).
    const deadline = Date.now() + this.cfg.resumeTimeoutMs;
    while (Date.now() < deadline) {
      await sleep(this.cfg.resumePollMs);
      let data: RawEndpoint;
      try {
        data = await this.describeEndpoint(name);
      } catch {
        continue;
      }
      const status = asObj(data["status"]);
      const state = asStr(status["state"]) ?? "unknown";
      if (action === "resume") {
        if (state === "running" && asStr(status["url"]) !== null) return data;
      } else if (state === "paused") {
        return data;
      }
      if (state === "failed" || state === "error" || state === "cancelled") {
        return null;
      }
    }
    return null;
  }
}

/** Flattened endpoint shape (ported `normalize_endpoint`, minus `raw`). */
export interface NormalizedEndpoint {
  name: string | null;
  repository: string | null;
  url: string | null;
  state: string;
  message: string | null;
  task: string | null;
  framework: string | null;
  revision: string | null;
  vendor: string | null;
  region: string | null;
  instance: string | null;
  instance_size: string | null;
  accelerator: string | null;
  min_replica: number | null;
  max_replica: number | null;
  scale_to_zero_timeout: number | null;
  ready_replica: number | null;
  target_replica: number | null;
  created_at: string | null;
  updated_at: string | null;
  last_used_at: string | null;
  health_route: string | null;
  type: string | null;
  image_model_path: string | null;
  image_ctx_size: number | null;
  image_n_parallel: number | null;
}

/** Flatten an endpoint's nested HF API shape into a flat object. */
export function normalizeEndpoint(ep: RawEndpoint): NormalizedEndpoint {
  const model = asObj(ep["model"]);
  const status = asObj(ep["status"]);
  const compute = asObj(ep["compute"]);
  const provider = asObj(ep["provider"]);
  const scaling = asObj(compute["scaling"]);
  const image = asObj(model["image"]);
  const framework = asStr(model["framework"]);
  // llamacpp / vllm / etc. image config
  const imageCfg = framework !== null ? asObj(image[framework]) : {};
  return {
    name: asStr(ep["name"]),
    repository: asStr(model["repository"]),
    url: asStr(status["url"]),
    state: asStr(status["state"]) ?? "unknown",
    message: asStr(status["message"]),
    task: asStr(model["task"]),
    framework,
    revision: asStr(model["revision"]),
    vendor: asStr(provider["vendor"]),
    region: asStr(provider["region"]),
    instance: asStr(compute["instanceType"]),
    instance_size: asStr(compute["instanceSize"]),
    accelerator: asStr(compute["accelerator"]),
    min_replica: asNum(scaling["minReplica"]),
    max_replica: asNum(scaling["maxReplica"]),
    scale_to_zero_timeout: asNum(scaling["scaleToZeroTimeout"]),
    ready_replica: asNum(status["readyReplica"]),
    target_replica: asNum(status["targetReplica"]),
    created_at: asStr(status["createdAt"]),
    updated_at: asStr(status["updatedAt"]),
    last_used_at: asStr(status["lastUsedAt"]),
    health_route: asStr(ep["healthRoute"]) ?? asStr(model["healthRoute"]),
    type: asStr(ep["type"]),
    image_model_path: asStr(imageCfg["modelPath"]),
    image_ctx_size: asNum(imageCfg["ctxSize"]),
    image_n_parallel: asNum(imageCfg["nParallel"]),
  };
}
