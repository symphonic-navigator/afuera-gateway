/**
 * HTTP integration: the per-user HF Inference Endpoints proxy ("hfif",
 * docs/specs/hfif.md) — token management, token check, OpenAI-compatible
 * proxy with auto-resume, manual resume/pause, and the rotate-dek
 * interaction, end-to-end against a fake HF control plane and a fake
 * inference endpoint.
 */

import { createServer } from "node:net";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createApiKey,
  dataAAD,
  encryptBlob,
  encryptData,
  generateDek,
  reEncryptDataBlob,
  rewrapDekForMaster,
  utf8,
  type CreatedApiKey,
  type InitializedUser,
} from "@afuera/crypto";
import type { AppConfig } from "../src/config.js";
import type { AppDatabase } from "../src/db/index.js";
import {
  auditEvents,
  bearer,
  buildTestApp,
  loginSession,
  registerUser,
  type Session,
} from "./helpers.js";

// ---------------------------------------------------------------------------
// fake HF control plane (whoami-v2 + /v2/endpoint/*) with mutable state
// ---------------------------------------------------------------------------

const HF_TOKEN = "hf_USER-SECRET-TOKEN";
const NAMESPACE = "test-user";

interface FakeEndpointState {
  name: string;
  repository: string | null;
  state: string;
  url: string | null;
  task: string | null;
  framework: string | null;
  /** describe polls remaining before a pending transition completes. */
  pollsRemaining: number;
  /** "running" | "paused" — where the current transition lands. */
  pendingTarget: string | null;
  /** url assigned when a resume completes. */
  runningUrl: string | null;
}

interface ControlPlaneOptions {
  /** whoami-v2 role ("read" | "write" | "fineGrained" | ...). */
  role?: string;
  /** fine-grained global scopes. */
  scopes?: string[];
  /** token the fake accepts; others get 401. */
  validToken?: string;
}

interface FakeControlPlane {
  baseUrl: string;
  endpoints: Map<string, FakeEndpointState>;
  resumeCalls: string[];
  pauseCalls: string[];
  authorizations: (string | undefined)[];
  addEndpoint(ep: Partial<FakeEndpointState> & { name: string }): void;
  close(): Promise<void>;
}

function rawEndpoint(ep: FakeEndpointState): Record<string, unknown> {
  return {
    name: ep.name,
    type: "inference",
    model: {
      repository: ep.repository,
      task: ep.task,
      framework: ep.framework,
      revision: "main",
      image: ep.framework ? { [ep.framework]: { modelPath: ep.repository } } : {},
    },
    status: {
      state: ep.state,
      url: ep.url,
      message: null,
      readyReplica: ep.state === "running" ? 1 : 0,
      targetReplica: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      lastUsedAt: null,
    },
    compute: {
      instanceType: "intel-cpu",
      instanceSize: "x2",
      accelerator: "cpu",
      scaling: { minReplica: 0, maxReplica: 1, scaleToZeroTimeout: 900 },
    },
    provider: { vendor: "aws", region: "us-east-1" },
  };
}

async function startFakeControlPlane(opts: ControlPlaneOptions = {}): Promise<FakeControlPlane> {
  const role = opts.role ?? "write";
  const scopes = opts.scopes ?? [];
  const validToken = opts.validToken ?? HF_TOKEN;
  const endpoints = new Map<string, FakeEndpointState>();
  const resumeCalls: string[] = [];
  const pauseCalls: string[] = [];
  const authorizations: (string | undefined)[] = [];

  const app = Fastify();

  app.get("/api/whoami-v2", async (req, reply) => {
    authorizations.push(req.headers.authorization);
    if (req.headers.authorization !== `Bearer ${validToken}`) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    return reply.send({
      type: "user",
      name: NAMESPACE,
      orgs: [],
      auth: {
        accessToken: {
          role,
          fineGrained: { global: scopes, scoped: [] },
        },
      },
    });
  });

  app.get("/v2/endpoint/:ns", async (req, reply) => {
    authorizations.push(req.headers.authorization);
    return reply.send({ items: [...endpoints.values()].map(rawEndpoint) });
  });

  app.get("/v2/endpoint/:ns/:name", async (req, reply) => {
    authorizations.push(req.headers.authorization);
    const { name } = req.params as { name: string };
    const ep = endpoints.get(name);
    if (!ep) return reply.code(404).send({ error: "not found" });
    // advance a pending transition (the client polls describe)
    if (ep.pendingTarget !== null && ep.pollsRemaining > 0) {
      ep.pollsRemaining -= 1;
      if (ep.pollsRemaining === 0) {
        ep.state = ep.pendingTarget;
        ep.url = ep.pendingTarget === "running" ? ep.runningUrl : null;
        ep.pendingTarget = null;
      }
    }
    return reply.send(rawEndpoint(ep));
  });

  app.post("/v2/endpoint/:ns/:name/resume", async (req, reply) => {
    authorizations.push(req.headers.authorization);
    const { name } = req.params as { name: string };
    const ep = endpoints.get(name);
    if (!ep) return reply.code(404).send({ error: "not found" });
    resumeCalls.push(name);
    if (ep.state === "running") {
      return reply.code(400).send({ error: "endpoint already running" });
    }
    if (ep.state === "failed") {
      // stays failed — the client's first poll sees the terminal state
      return reply.send({});
    }
    ep.state = "pending";
    ep.pendingTarget = "running";
    ep.pollsRemaining = ep.pollsRemaining || 2;
    return reply.send({});
  });

  app.post("/v2/endpoint/:ns/:name/pause", async (req, reply) => {
    authorizations.push(req.headers.authorization);
    const { name } = req.params as { name: string };
    const ep = endpoints.get(name);
    if (!ep) return reply.code(404).send({ error: "not found" });
    pauseCalls.push(name);
    if (ep.state === "paused") {
      return reply.code(400).send({ error: "endpoint already paused" });
    }
    ep.state = "pending";
    ep.pendingTarget = "paused";
    ep.pollsRemaining = ep.pollsRemaining || 2;
    return reply.send({});
  });

  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  if (address === null || typeof address === "string") throw new Error("no control-plane address");
  return {
    baseUrl: `http://127.0.0.1:${String(address.port)}`,
    endpoints,
    resumeCalls,
    pauseCalls,
    authorizations,
    addEndpoint(ep) {
      endpoints.set(ep.name, {
        repository: null,
        state: "paused",
        url: null,
        task: "text-generation",
        framework: "vllm",
        pollsRemaining: 2,
        pendingTarget: null,
        runningUrl: null,
        ...ep,
      });
    },
    close: () => app.close(),
  };
}

// ---------------------------------------------------------------------------
// fake inference endpoint (OpenAI-style canned JSON + SSE streaming)
// ---------------------------------------------------------------------------

interface FakeInference {
  baseUrl: string;
  requests: { url: string; authorization: string | undefined; body: string }[];
  close(): Promise<void>;
}

const SSE_CHUNKS = [
  `data: ${JSON.stringify({ id: "chatcmpl-1", choices: [{ delta: { content: "Hello" } }] })}\n\n`,
  `data: ${JSON.stringify({ id: "chatcmpl-1", choices: [{ delta: { content: " world" } }] })}\n\n`,
  "data: [DONE]\n\n",
];

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function startFakeInference(): Promise<FakeInference> {
  const requests: FakeInference["requests"] = [];
  const app = Fastify();
  const rawBody = { parseAs: "buffer" as const };
  const bufferParser = (_req: unknown, body: unknown, done: (e: null, b?: unknown) => void) =>
    done(null, body);
  app.addContentTypeParser("application/json", rawBody, bufferParser);
  app.addContentTypeParser("*", rawBody, bufferParser);

  const record = (req: {
    url: string;
    headers: { authorization?: string | undefined };
    body: unknown;
  }) => {
    requests.push({
      url: req.url,
      authorization: req.headers.authorization,
      body: Buffer.isBuffer(req.body) ? Buffer.from(req.body).toString("utf8") : "",
    });
  };

  app.post("/v1/chat/completions", async (req, reply) => {
    record(req);
    const body = JSON.parse(
      Buffer.isBuffer(req.body) ? req.body.toString("utf8") : "{}",
    ) as { stream?: boolean };
    if (body.stream) {
      await reply.hijack();
      reply.raw.writeHead(200, { "content-type": "text/event-stream" });
      for (const chunk of SSE_CHUNKS) {
        reply.raw.write(chunk);
        await sleep(5);
      }
      reply.raw.end();
      return reply;
    }
    return reply
      .code(200)
      .header("content-type", "application/json")
      .send(
        JSON.stringify({
          id: "chatcmpl-1",
          object: "chat.completion",
          choices: [{ message: { role: "assistant", content: "CANNED-COMPLETION" } }],
        }),
      );
  });

  app.post("/v1/completions", async (req, reply) => {
    record(req);
    return reply.send({ id: "cmpl-1", object: "text_completion", choices: [{ text: "done" }] });
  });

  app.post("/v1/embeddings", async (req, reply) => {
    record(req);
    return reply.send({ object: "list", data: [{ object: "embedding", embedding: [0.1, 0.2] }] });
  });

  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  if (address === null || typeof address === "string") throw new Error("no inference address");
  return {
    baseUrl: `http://127.0.0.1:${String(address.port)}`,
    requests,
    close: () => app.close(),
  };
}

/** A port that is guaranteed closed (bound, released, reused here). */
async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

// ---------------------------------------------------------------------------
// client-side drivers
// ---------------------------------------------------------------------------

interface HfifFixture {
  app: FastifyInstance;
  db: AppDatabase;
  user: InitializedUser;
  session: Session;
}

async function setupHfifApp(
  control: FakeControlPlane,
  extra: Partial<AppConfig> = {},
): Promise<HfifFixture> {
  const { app, db } = buildTestApp({
    hfApiBase: `${control.baseUrl}/v2/endpoint`,
    hfWhoamiUrl: `${control.baseUrl}/api/whoami-v2`,
    hfifResumeTimeoutMs: 5_000,
    hfifResumePollMs: 10,
    hfifUpstreamTimeoutMs: 5_000,
    hfifAllowHttp: true,
    rateLimitHfif: { max: 10_000, timeWindow: "1 minute" },
    ...extra,
  });
  const user = await registerUser(app);
  const session = await loginSession(app, user.registration.userId, user.rootSecret);
  return { app, db, user, session };
}

/** Client-side HF token blob (hfif.md §AAD contract). */
function hfBlob(
  dek: Uint8Array,
  userId: string,
  dekVersion: number,
  token = HF_TOKEN,
): string {
  return encryptBlob(dek, utf8(token), dataAAD(userId, "hfif-credential", dekVersion));
}

async function storeToken(
  app: FastifyInstance,
  session: Session,
  blob: string,
): Promise<number> {
  const res = await app.inject({
    method: "PUT",
    url: "/v1/hfif/token",
    headers: bearer(session.accessToken),
    payload: { blob },
  });
  return res.statusCode;
}

async function issueApiKey(
  app: FastifyInstance,
  session: Session,
  dek: Uint8Array,
  dekVersion: number,
  scopes: string[],
): Promise<CreatedApiKey> {
  const key = createApiKey(dek, dekVersion);
  const res = await app.inject({
    method: "POST",
    url: "/v1/api-keys",
    headers: bearer(session.accessToken),
    payload: {
      key_id: key.keyId,
      key_hash: key.keyHash,
      wrapped_dek: key.wrappedDek,
      scopes,
    },
  });
  if (res.statusCode !== 201) {
    throw new Error(`create api key failed: ${res.statusCode} ${res.body}`);
  }
  return key;
}

// ---------------------------------------------------------------------------

describe("hfif (docs/specs/hfif.md)", () => {
  let control: FakeControlPlane;
  let inference: FakeInference;

  beforeAll(async () => {
    control = await startFakeControlPlane();
    inference = await startFakeInference();
  });
  afterAll(async () => {
    await control.close();
    await inference.close();
  });

  it("token CRUD: session + hfif:manage, scope enforcement, uniform 401s, audit", async () => {
    const { app, db, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    const blob = hfBlob(user.dek, userId, 1);

    // not set yet
    const empty = await app.inject({
      method: "GET",
      url: "/v1/hfif/token",
      headers: bearer(session.accessToken),
    });
    expect(empty.statusCode).toBe(200);
    expect(empty.json()).toEqual({ exists: false, created_at: null, updated_at: null });

    // upsert via session; read back the blob
    expect(await storeToken(app, session, blob)).toBe(200);
    const manageKey = await issueApiKey(app, session, user.dek, 1, ["hfif:manage"]);
    const useOnlyKey = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);
    const dataKey = await issueApiKey(app, session, user.dek, 1, ["data:read"]);

    const fetched = await app.inject({
      method: "GET",
      url: "/v1/hfif/token",
      headers: bearer(manageKey.token),
    });
    expect(fetched.statusCode).toBe(200);
    const fetchedBody = fetched.json() as { exists: boolean; blob: string; created_at: string };
    expect(fetchedBody.exists).toBe(true);
    expect(fetchedBody.blob).toBe(blob);

    // hfif:use key cannot manage; data:read key cannot either
    for (const key of [useOnlyKey, dataKey]) {
      const denied = await app.inject({
        method: "PUT",
        url: "/v1/hfif/token",
        headers: bearer(key.token),
        payload: { blob },
      });
      expect(denied.statusCode).toBe(401);
      expect(denied.json()).toEqual({ error: "unauthorized" });
    }
    // hfif:manage key CAN upsert
    const viaManage = await app.inject({
      method: "PUT",
      url: "/v1/hfif/token",
      headers: bearer(manageKey.token),
      payload: { blob: hfBlob(user.dek, userId, 1) },
    });
    expect(viaManage.statusCode).toBe(200);

    // bad blob → 400
    const bad = await app.inject({
      method: "PUT",
      url: "/v1/hfif/token",
      headers: bearer(session.accessToken),
      payload: { blob: "not-a-blob" },
    });
    expect(bad.statusCode).toBe(400);

    // delete + 404 on re-delete
    const del = await app.inject({
      method: "DELETE",
      url: "/v1/hfif/token",
      headers: bearer(session.accessToken),
    });
    expect(del.statusCode).toBe(200);
    const delAgain = await app.inject({
      method: "DELETE",
      url: "/v1/hfif/token",
      headers: bearer(session.accessToken),
    });
    expect(delAgain.statusCode).toBe(404);
    expect(delAgain.json()).toEqual({ error: "credential_not_found" });

    expect(auditEvents(db)).toContain("hfif_token_set");
    expect(auditEvents(db)).toContain("hfif_token_deleted");
    // the blob (and of course the token) never appear in the audit log
    const everything = JSON.stringify(db.prepare("SELECT * FROM audit_log").all());
    expect(everything).not.toContain(blob);
    expect(everything).not.toContain(HF_TOKEN);
    await app.close();
  });

  it("token/check: fine-grained ok, read-only reason, invalid token, no credential → 401", async () => {
    // fine-grained token WITH the required scope
    const fg = await startFakeControlPlane({
      role: "fineGrained",
      scopes: ["inference.endpoints.write"],
    });
    const { app, user, session } = await setupHfifApp(fg);
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const useKey = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);
    const manageKey = await issueApiKey(app, session, user.dek, 1, ["hfif:manage"]);

    const ok = await app.inject({
      method: "POST",
      url: "/v1/hfif/token/check",
      headers: bearer(useKey.token),
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toEqual({
      ok: true,
      namespace: NAMESPACE,
      username: NAMESPACE,
      role: "fineGrained",
      scopes: ["inference.endpoints.write"],
      has_write: true,
      reason: null,
    });

    // hfif:manage works too
    const viaManage = await app.inject({
      method: "POST",
      url: "/v1/hfif/token/check",
      headers: bearer(manageKey.token),
    });
    expect(viaManage.statusCode).toBe(200);
    // session → uniform 401 (no key material)
    const viaSession = await app.inject({
      method: "POST",
      url: "/v1/hfif/token/check",
      headers: bearer(session.accessToken),
    });
    expect(viaSession.statusCode).toBe(401);
    await app.close();
    await fg.close();

    // read-only role → has_write=false with reason
    const ro = await startFakeControlPlane({ role: "read" });
    const roFx = await setupHfifApp(ro);
    await storeToken(roFx.app, roFx.session, hfBlob(roFx.user.dek, roFx.user.registration.userId, 1));
    const roKey = await issueApiKey(roFx.app, roFx.session, roFx.user.dek, 1, ["hfif:use"]);
    const readOnly = await roFx.app.inject({
      method: "POST",
      url: "/v1/hfif/token/check",
      headers: bearer(roKey.token),
    });
    expect(readOnly.statusCode).toBe(200);
    const roBody = readOnly.json() as { ok: boolean; has_write: boolean; reason: string };
    expect(roBody.ok).toBe(false);
    expect(roBody.has_write).toBe(false);
    expect(roBody.reason).toContain("read-only");
    await roFx.app.close();
    await ro.close();

    // HF API rejects the token → reason; and no credential → uniform 401
    const picky = await startFakeControlPlane({ validToken: "hf_SOMEONE_ELSE" });
    const pFx = await setupHfifApp(picky);
    await storeToken(pFx.app, pFx.session, hfBlob(pFx.user.dek, pFx.user.registration.userId, 1));
    const pKey = await issueApiKey(pFx.app, pFx.session, pFx.user.dek, 1, ["hfif:use"]);
    const invalid = await pFx.app.inject({
      method: "POST",
      url: "/v1/hfif/token/check",
      headers: bearer(pKey.token),
    });
    expect(invalid.statusCode).toBe(200);
    expect((invalid.json() as { ok: boolean; reason: string }).ok).toBe(false);
    expect((invalid.json() as { reason: string }).reason).toContain("invalid or expired");

    const other = await registerUser(pFx.app);
    const otherSession = await loginSession(pFx.app, other.registration.userId, other.rootSecret);
    const otherKey = await issueApiKey(pFx.app, otherSession, other.dek, 1, ["hfif:use"]);
    const noCred = await pFx.app.inject({
      method: "POST",
      url: "/v1/hfif/token/check",
      headers: bearer(otherKey.token),
    });
    expect(noCred.statusCode).toBe(401);
    expect(noCred.json()).toEqual({ error: "unauthorized" });
    await pFx.app.close();
    await picky.close();

    // control plane unreachable → 502
    const dead = await closedPort();
    const dFx = await setupHfifApp(control, {
      hfWhoamiUrl: `http://127.0.0.1:${String(dead)}/api/whoami-v2`,
    });
    await storeToken(dFx.app, dFx.session, hfBlob(dFx.user.dek, dFx.user.registration.userId, 1));
    const dKey = await issueApiKey(dFx.app, dFx.session, dFx.user.dek, 1, ["hfif:use"]);
    const down = await dFx.app.inject({
      method: "POST",
      url: "/v1/hfif/token/check",
      headers: bearer(dKey.token),
    });
    expect(down.statusCode).toBe(502);
    expect(down.json()).toEqual({ error: "upstream_error" });
    await dFx.app.close();
  });

  it("GET /hfif/v1/models: fresh OpenAI-shaped list with meta; empty account → empty", async () => {
    const { app, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    // empty account
    const empty = await app.inject({
      method: "GET",
      url: "/hfif/v1/models",
      headers: bearer(key.token),
    });
    expect(empty.statusCode).toBe(200);
    expect(empty.json()).toEqual({ object: "list", data: [] });

    control.addEndpoint({
      name: "llama",
      repository: "meta/llama-3",
      state: "running",
      url: `${inference.baseUrl}`,
    });
    control.addEndpoint({ name: "no-repo", repository: null, state: "paused" });

    const res = await app.inject({
      method: "GET",
      url: "/hfif/v1/models",
      headers: bearer(key.token),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      object: string;
      data: { id: string; object: string; owned_by: string; meta: Record<string, unknown> }[];
    };
    expect(body.object).toBe("list");
    expect(body.data).toHaveLength(2);
    const llama = body.data.find((m) => m.id === "meta/llama-3")!;
    expect(llama.object).toBe("model");
    expect(llama.owned_by).toBe("huggingface");
    expect(llama.meta).toEqual({
      endpoint_name: "llama",
      state: "running",
      task: "text-generation",
      framework: "vllm",
      instance: "intel-cpu",
      vendor: "aws",
      region: "us-east-1",
    });
    // fallback: no repository → id is the endpoint name
    expect(body.data.some((m) => m.id === "no-repo")).toBe(true);
    // control plane was called with the decrypted HF token
    expect(control.authorizations.every((a) => a === `Bearer ${HF_TOKEN}`)).toBe(true);
    await app.close();
  });

  it("full E2E proxy: paused endpoint auto-resumes, decrypted Bearer forwarded, non-stream + SSE", async () => {
    const { app, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    control.addEndpoint({
      name: "chatty",
      repository: "org/chatty-7b",
      state: "paused",
      runningUrl: inference.baseUrl,
      pollsRemaining: 2,
    });

    // --- non-stream: auto-resume → poll → proxy
    const res = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(key.token), "content-type": "application/json" },
      payload: { model: "org/chatty-7b", messages: [{ role: "user", content: "hi" }] },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { choices: { message: { content: string } }[] }).choices[0]!.message.content).toBe(
      "CANNED-COMPLETION",
    );
    expect(control.resumeCalls).toContain("chatty");
    const ep = control.endpoints.get("chatty")!;
    expect(ep.state).toBe("running");
    expect(ep.url).toBe(inference.baseUrl);

    const forwarded = inference.requests[inference.requests.length - 1]!;
    expect(forwarded.url).toBe("/v1/chat/completions");
    expect(forwarded.authorization).toBe(`Bearer ${HF_TOKEN}`);
    expect(JSON.parse(forwarded.body)).toEqual({
      model: "org/chatty-7b",
      messages: [{ role: "user", content: "hi" }],
    });

    // --- now running: no second resume call
    const resumeCount = control.resumeCalls.length;
    const again = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(key.token), "content-type": "application/json" },
      payload: { model: "org/chatty-7b", messages: [] },
    });
    expect(again.statusCode).toBe(200);
    expect(control.resumeCalls.length).toBe(resumeCount);

    // --- SSE stream: chunks arrive in order, 1:1
    const stream = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(key.token), "content-type": "application/json" },
      payload: { model: "org/chatty-7b", messages: [], stream: true },
    });
    expect(stream.statusCode).toBe(200);
    expect(stream.headers["content-type"]).toContain("text/event-stream");
    expect(stream.body).toBe(SSE_CHUNKS.join(""));
    const streamed = inference.requests[inference.requests.length - 1]!;
    expect(streamed.authorization).toBe(`Bearer ${HF_TOKEN}`);
    expect(JSON.parse(streamed.body)).toMatchObject({ stream: true });
    // upstream saw the SSE accept header
    await app.close();
  });

  it("proxy errors: unknown model → 404, resume timeout → 503, failed endpoint → 503, upstream down → 502", async () => {
    control.addEndpoint({
      name: "slow-boot",
      repository: "org/slow",
      state: "paused",
      runningUrl: inference.baseUrl,
      pollsRemaining: 1_000_000, // never finishes in time
    });
    control.addEndpoint({ name: "broken", repository: "org/broken", state: "failed" });
    const dead = await closedPort();
    control.addEndpoint({
      name: "dead",
      repository: "org/dead",
      state: "running",
      url: `http://127.0.0.1:${String(dead)}`,
    });

    const { app, user, session } = await setupHfifApp(control, {
      hfifResumeTimeoutMs: 50,
      hfifResumePollMs: 10,
    });
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    const call = (model: string) =>
      app.inject({
        method: "POST",
        url: "/hfif/v1/chat/completions",
        headers: { ...bearer(key.token), "content-type": "application/json" },
        payload: { model, messages: [] },
      });

    const unknown = await call("org/no-such-model");
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json()).toEqual({ error: { message: "model 'org/no-such-model' not found" } });

    const timeout = await call("org/slow");
    expect(timeout.statusCode).toBe(503);
    expect(timeout.json()).toEqual({
      error: { message: "endpoint 'org/slow' could not be started" },
    });

    const failed = await call("org/broken");
    expect(failed.statusCode).toBe(503);

    const down = await call("org/dead");
    expect(down.statusCode).toBe(502);
    expect((down.json() as { error: { message: string } }).error.message).toContain(
      "upstream error",
    );

    // missing model field → 400
    const noModel = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(key.token), "content-type": "application/json" },
      payload: { messages: [] },
    });
    expect(noModel.statusCode).toBe(400);
    expect(noModel.json()).toEqual({ error: { message: "missing 'model' field" } });
    await app.close();
  });

  it("SSE upstream failure is emitted as an SSE error frame", async () => {
    const dead = await closedPort();
    control.addEndpoint({
      name: "dead-stream",
      repository: "org/dead-stream",
      state: "running",
      url: `http://127.0.0.1:${String(dead)}`,
    });
    const { app, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    const res = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(key.token), "content-type": "application/json" },
      payload: { model: "org/dead-stream", messages: [], stream: true },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toContain("text/event-stream");
    expect(res.body).toMatch(/^data: \{"error":\{"message":"upstream error: .*\}\}\n\n$/);
    await app.close();
  });

  it("manual resume/pause with state transitions; unknown endpoint → 503; audit", async () => {
    const { app, db, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    control.addEndpoint({
      name: "manual",
      repository: "org/manual",
      state: "paused",
      runningUrl: inference.baseUrl,
      pollsRemaining: 1,
    });

    const resumed = await app.inject({
      method: "POST",
      url: "/hfif/endpoints/manual/resume",
      headers: bearer(key.token),
    });
    expect(resumed.statusCode).toBe(200);
    const resumedBody = resumed.json() as { name: string; state: string; url: string };
    expect(resumedBody.state).toBe("running");
    expect(resumedBody.url).toBe(inference.baseUrl);
    expect(resumedBody).not.toHaveProperty("raw");
    expect(control.resumeCalls).toContain("manual");

    const paused = await app.inject({
      method: "POST",
      url: "/hfif/endpoints/manual/pause",
      headers: bearer(key.token),
    });
    expect(paused.statusCode).toBe(200);
    expect((paused.json() as { state: string; url: string | null }).state).toBe("paused");
    expect((paused.json() as { url: string | null }).url).toBeNull();
    expect(control.pauseCalls).toContain("manual");

    const unknown = await app.inject({
      method: "POST",
      url: "/hfif/endpoints/no-such/resume",
      headers: bearer(key.token),
    });
    expect(unknown.statusCode).toBe(503);
    expect(unknown.json()).toEqual({ error: "endpoint_unavailable" });

    // normalized list for a future dashboard
    const list = await app.inject({
      method: "GET",
      url: "/hfif/endpoints",
      headers: bearer(key.token),
    });
    expect(list.statusCode).toBe(200);
    const listed = (list.json() as { endpoints: Record<string, unknown>[] }).endpoints;
    const manual = listed.find((e) => e["name"] === "manual")!;
    expect(manual["repository"]).toBe("org/manual");
    expect(manual["instance_size"]).toBe("x2");
    expect(manual).not.toHaveProperty("raw");

    expect(auditEvents(db)).toContain("hfif_endpoint_resumed");
    expect(auditEvents(db)).toContain("hfif_endpoint_paused");
    await app.close();
  });

  it("auth matrix on /hfif/*: session → 401, missing scope → 401, revoked → 401", async () => {
    const { app, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const useKey = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);
    const manageOnly = await issueApiKey(app, session, user.dek, 1, ["hfif:manage"]);
    const dataKey = await issueApiKey(app, session, user.dek, 1, ["data:read"]);

    const viaSession = await app.inject({
      method: "GET",
      url: "/hfif/v1/models",
      headers: bearer(session.accessToken),
    });
    expect(viaSession.statusCode).toBe(401);
    expect(viaSession.json()).toEqual({ error: "unauthorized" });

    for (const k of [manageOnly, dataKey]) {
      const denied = await app.inject({
        method: "GET",
        url: "/hfif/v1/models",
        headers: bearer(k.token),
      });
      expect(denied.statusCode).toBe(401);
    }

    const revoked = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);
    await app.inject({
      method: "POST",
      url: `/v1/api-keys/${revoked.keyId}/revoke`,
      headers: bearer(session.accessToken),
    });
    const viaRevoked = await app.inject({
      method: "GET",
      url: "/hfif/v1/models",
      headers: bearer(revoked.token),
    });
    expect(viaRevoked.statusCode).toBe(401);

    // sanity: the hfif:use key works
    const ok = await app.inject({
      method: "GET",
      url: "/hfif/v1/models",
      headers: bearer(useKey.token),
    });
    expect(ok.statusCode).toBe(200);
    await app.close();
  });

  it("rotate-dek with hf_credential: re-issued key still proxies; missing field → 400, nothing commits", async () => {
    const { app, db, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    const oldBlob = hfBlob(user.dek, userId, 1);
    await storeToken(app, session, oldBlob);
    const oldKey = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    control.addEndpoint({
      name: "rotator",
      repository: "org/rotator",
      state: "running",
      url: inference.baseUrl,
    });

    const dataV1 = encryptData(user.dek, utf8("payload"), userId, "record", 1);
    await app.inject({
      method: "PUT",
      url: "/v1/data/blob",
      headers: bearer(session.accessToken),
      payload: { encrypted_data_blob: dataV1 },
    });
    const newDek = generateDek();
    const newDataBlob = reEncryptDataBlob(user.dek, newDek, dataV1, userId, "record", 1, 2);

    // --- missing hf_credential while one exists → 400, nothing committed
    const incomplete = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-dek",
      headers: bearer(session.accessToken),
      payload: {
        new_wrapped_dek_master: rewrapDekForMaster(user.rootSecret, newDek, 2),
        new_dek_version: 2,
        encrypted_data_blob: newDataBlob,
        revoke_all_api_keys: true,
      },
    });
    expect(incomplete.statusCode).toBe(400);
    expect(incomplete.json()).toEqual({ error: "incomplete_rotation" });
    // nothing committed: version still 1, old key still proxies
    const version = await app.inject({
      method: "GET",
      url: "/v1/crypto/wrapped-dek-master",
      headers: bearer(session.accessToken),
    });
    expect((version.json() as { dek_version: number }).dek_version).toBe(1);
    const stillWorks = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(oldKey.token), "content-type": "application/json" },
      payload: { model: "org/rotator", messages: [] },
    });
    expect(stillWorks.statusCode).toBe(200);

    // --- complete rotation commits
    const rotated = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-dek",
      headers: bearer(session.accessToken),
      payload: {
        new_wrapped_dek_master: rewrapDekForMaster(user.rootSecret, newDek, 2),
        new_dek_version: 2,
        encrypted_data_blob: newDataBlob,
        revoke_all_api_keys: true,
        hf_credential: {
          blob: reEncryptDataBlob(user.dek, newDek, oldBlob, userId, "hfif-credential", 1, 2),
        },
      },
    });
    expect(rotated.statusCode).toBe(200);
    expect(rotated.json()).toEqual({ dek_version: 2 });

    // old key revoked → 401
    const oldAttempt = await app.inject({
      method: "GET",
      url: "/hfif/v1/models",
      headers: bearer(oldKey.token),
    });
    expect(oldAttempt.statusCode).toBe(401);

    // NEW key (dek_version 2) still proxies: the re-encrypted blob decrypts
    // under the new DEK/version.
    const newKey = await issueApiKey(app, session, newDek, 2, ["hfif:use"]);
    const before = inference.requests.length;
    const res = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(newKey.token), "content-type": "application/json" },
      payload: { model: "org/rotator", messages: [] },
    });
    expect(res.statusCode).toBe(200);
    expect(inference.requests.slice(before)[0]!.authorization).toBe(`Bearer ${HF_TOKEN}`);

    // the stored blob really is the rotated one
    const row = db
      .prepare("SELECT blob FROM hf_credentials WHERE user_id = ?")
      .get(userId) as { blob: string };
    expect(row.blob).not.toBe(oldBlob);
    await app.close();
  });

  it("rate-limits the client API per API key (429)", async () => {
    const { app, user, session } = await setupHfifApp(control, {
      rateLimitHfif: { max: 2, timeWindow: "1 minute" },
    });
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    const call = () =>
      app.inject({ method: "GET", url: "/hfif/v1/models", headers: bearer(key.token) });
    expect((await call()).statusCode).toBe(200);
    expect((await call()).statusCode).toBe(200);
    expect((await call()).statusCode).toBe(429);
    await app.close();
  });

  it("audits hfif_proxy_call with model+status only — never token/prompt/completion", async () => {
    const { app, db, user, session } = await setupHfifApp(control);
    const userId = user.registration.userId;
    await storeToken(app, session, hfBlob(user.dek, userId, 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["hfif:use"]);

    control.addEndpoint({
      name: "audited",
      repository: "org/audited",
      state: "running",
      url: inference.baseUrl,
    });
    const res = await app.inject({
      method: "POST",
      url: "/hfif/v1/chat/completions",
      headers: { ...bearer(key.token), "content-type": "application/json" },
      payload: { model: "org/audited", messages: [{ role: "user", content: "PROMPT-SECRET" }] },
    });
    expect(res.statusCode).toBe(200);

    const rows = db
      .prepare("SELECT event, metadata FROM audit_log WHERE event = 'hfif_proxy_call'")
      .all() as { event: string; metadata: string }[];
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0]!.metadata)).toEqual({ model: "org/audited", status: 200 });

    const everything = JSON.stringify(db.prepare("SELECT * FROM audit_log").all());
    expect(everything).not.toContain(HF_TOKEN);
    expect(everything).not.toContain("PROMPT-SECRET");
    expect(everything).not.toContain("CANNED-COMPLETION");
    expect(everything).not.toContain("agk_");
    await app.close();
  });
});
