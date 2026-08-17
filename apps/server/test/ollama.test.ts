/**
 * HTTP + WebSocket integration: the per-user Ollama relay
 * (docs/specs/ollama-relay.md) — uplink CRUD, the sidecar handshake over a
 * real WebSocket (via the TestSidecar, which speaks the ported protocol),
 * the client-facing proxy incl. cross-user name collisions, takeover,
 * cancel, rate limits, and audit hygiene.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { describe, expect, it } from "vitest";
import { createApiKey, type CreatedApiKey, type InitializedUser } from "@afuera/crypto";
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
import { connectExpectClose, TestSidecar, waitFor } from "./ollama-sidecar.js";

const enc = new TextEncoder();

interface RunningApp {
  app: FastifyInstance;
  db: AppDatabase;
  baseUrl: string;
  wsUrl: (uplinkId: string) => string;
}

async function listen(config: Partial<AppConfig> = {}): Promise<RunningApp> {
  const { app, db } = buildTestApp(config);
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address() as AddressInfo;
  return {
    app,
    db,
    baseUrl: `http://127.0.0.1:${String(address.port)}`,
    wsUrl: (uplinkId) => `ws://127.0.0.1:${String(address.port)}/uplink/${uplinkId}`,
  };
}

interface UserCtx {
  user: InitializedUser;
  session: Session;
}

async function setupUser(app: FastifyInstance): Promise<UserCtx> {
  const user = await registerUser(app);
  const session = await loginSession(app, user.registration.userId, user.rootSecret);
  return { user, session };
}

async function issueKey(
  app: FastifyInstance,
  ctx: UserCtx,
  scopes: string[],
): Promise<CreatedApiKey> {
  const key = createApiKey(ctx.user.dek, 1);
  const res = await app.inject({
    method: "POST",
    url: "/v1/api-keys",
    headers: bearer(ctx.session.accessToken),
    payload: {
      key_id: key.keyId,
      key_hash: key.keyHash,
      wrapped_dek: key.wrappedDek,
      scopes,
    },
  });
  if (res.statusCode !== 201) throw new Error(`create api key failed: ${res.statusCode} ${res.body}`);
  return key;
}

interface CreatedUplink {
  id: string;
  name: string;
  psk: string;
  relay_url: string;
}

async function createUplink(
  app: FastifyInstance,
  token: string,
  name: string,
): Promise<LightMyRequestResponse & { uplink: CreatedUplink }> {
  const res = await app.inject({
    method: "POST",
    url: "/v1/ollama/uplinks",
    headers: bearer(token),
    payload: { name },
  });
  return Object.assign(res, { uplink: res.json() as CreatedUplink });
}

interface ListedUplink {
  id: string;
  name: string;
  models: string[];
  online: boolean;
  created_at: string;
}

async function listUplinks(app: FastifyInstance, token: string): Promise<ListedUplink[]> {
  const res = await app.inject({
    method: "GET",
    url: "/v1/ollama/uplinks",
    headers: bearer(token),
  });
  if (res.statusCode !== 200) throw new Error(`list failed: ${res.statusCode} ${res.body}`);
  return (res.json() as { uplinks: ListedUplink[] }).uplinks;
}

async function waitOnline(
  app: FastifyInstance,
  token: string,
  uplinkId: string,
  online: boolean,
): Promise<void> {
  await waitFor(async () => {
    const rows = await listUplinks(app, token);
    return rows.some((r) => r.id === uplinkId && r.online === online);
  });
}

/** Canned Ollama-ish responses; `marker` proves WHICH sidecar answered. */
function cannedHandler(marker: string) {
  return (
    msg: { path: string },
    responder: {
      sendHead(status: number, headers: Record<string, string>): void;
      sendChunk(data: Uint8Array): void;
      sendEnd(usage: null): void;
      sendError(message: string): void;
    },
  ): void => {
    if (msg.path.startsWith("/api/tags")) {
      responder.sendHead(200, { "content-type": "application/json" });
      responder.sendChunk(enc.encode(JSON.stringify({ models: [{ name: "qwen3:8b" }], marker })));
      responder.sendEnd(null);
      return;
    }
    if (msg.path.startsWith("/api/generate")) {
      responder.sendHead(200, { "content-type": "application/x-ndjson" });
      const lines = [
        `{"response":"part-1:${marker}"}\n`,
        '{"response":"part-2"}\n',
        '{"response":"part-3","done":true}\n',
      ];
      let i = 0;
      const timer = setInterval(() => {
        const line = lines[i];
        if (line === undefined) {
          clearInterval(timer);
          responder.sendEnd(null);
          return;
        }
        responder.sendChunk(enc.encode(line));
        i++;
      }, 15);
      timer.unref();
      return;
    }
    responder.sendHead(404, { "content-type": "application/json" });
    responder.sendChunk(enc.encode('{"error":"no such route"}'));
    responder.sendEnd(null);
  };
}

// ---------------------------------------------------------------------------

describe("ollama relay (docs/specs/ollama-relay.md)", () => {
  it("uplink CRUD: create shows the PSK once, list never leaks it, delete is uniform 404", async () => {
    const { app, db } = await listen({ publicBaseUrl: "https://gateway.example.com" });
    const ctx = await setupUser(app);

    // slug validation
    for (const bad of ["A", "x", "has space", "UPPER", "a".repeat(65)]) {
      const res = await createUplink(app, ctx.session.accessToken, bad);
      expect(res.statusCode).toBe(400);
    }

    const created = await createUplink(app, ctx.session.accessToken, "strixhalo");
    expect(created.statusCode).toBe(201);
    const { uplink } = created;
    expect(uplink.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(uplink.name).toBe("strixhalo");
    expect(uplink.psk.length).toBeGreaterThanOrEqual(43); // 32 B base64url, shown once
    expect(uplink.relay_url).toBe(`wss://gateway.example.com/uplink/${uplink.id}`);
    // duplicate name for the SAME user → 409
    const dup = await createUplink(app, ctx.session.accessToken, "strixhalo");
    expect(dup.statusCode).toBe(409);

    // list: metadata only — no psk, no psk_hash, offline, empty models
    const rows = await listUplinks(app, ctx.session.accessToken);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: uplink.id, name: "strixhalo", online: false, models: [] });
    expect(JSON.stringify(rows)).not.toContain(uplink.psk);
    expect(JSON.stringify(rows)).not.toContain("psk");

    // agk_ WITHOUT ollama:manage → 401; with ollama:manage → works
    const dataKey = await issueKey(app, ctx, ["data:read"]);
    const denied = await createUplink(app, dataKey.token, "other");
    expect(denied.statusCode).toBe(401);
    const manageKey = await issueKey(app, ctx, ["ollama:manage"]);
    const viaKey = await createUplink(app, manageKey.token, "other");
    expect(viaKey.statusCode).toBe(201);

    // delete: uniform 404 for unknown AND foreign ids
    const stranger = await setupUser(app);
    const foreign = await app.inject({
      method: "DELETE",
      url: `/v1/ollama/uplinks/${uplink.id}`,
      headers: bearer(stranger.session.accessToken),
    });
    expect(foreign.statusCode).toBe(404);
    const unknown = await app.inject({
      method: "DELETE",
      url: "/v1/ollama/uplinks/00000000-0000-4000-8000-000000000000",
      headers: bearer(ctx.session.accessToken),
    });
    expect(unknown.statusCode).toBe(404);
    const del = await app.inject({
      method: "DELETE",
      url: `/v1/ollama/uplinks/${uplink.id}`,
      headers: bearer(ctx.session.accessToken),
    });
    expect(del.statusCode).toBe(200);
    expect(await listUplinks(app, ctx.session.accessToken)).toHaveLength(1);

    expect(auditEvents(db)).toContain("ollama_uplink_created");
    expect(auditEvents(db)).toContain("ollama_uplink_deleted");
    await app.close();
  }, 15_000);

  it("full E2E: sidecar handshake → online → canned + streaming proxy calls (agk_ and session)", async () => {
    const { app, db, baseUrl, wsUrl } = await listen();
    const ctx = await setupUser(app);
    const { uplink } = await createUplink(app, ctx.session.accessToken, "strixhalo");
    const useKey = await issueKey(app, ctx, ["ollama:use"]);

    const sidecar = await TestSidecar.connect({
      relayUrl: wsUrl(uplink.id),
      name: "strixhalo",
      psk: uplink.psk,
      models: ["qwen3:8b"],
      onRequest: cannedHandler("PAYLOAD-RESPONSE-9b21c"),
    });
    await waitOnline(app, ctx.session.accessToken, uplink.id, true);
    // models from the hello are listed
    const rows = await listUplinks(app, ctx.session.accessToken);
    expect(rows[0]?.models).toEqual(["qwen3:8b"]);

    // canned GET via agk_ (query string forwarded verbatim)
    const tags = await fetch(`${baseUrl}/ollama/strixhalo/api/tags?limit=1`, {
      headers: bearer(useKey.token),
    });
    expect(tags.status).toBe(200);
    const tagsBody = (await tags.json()) as { marker: string };
    expect(tagsBody.marker).toBe("PAYLOAD-RESPONSE-9b21c");
    expect(sidecar.requests[0]?.msg.method).toBe("GET");
    expect(sidecar.requests[0]?.msg.path).toBe("/api/tags?limit=1");
    // authorization/host must NOT be tunnelled
    expect(sidecar.requests[0]?.msg.headers["authorization"]).toBeUndefined();
    expect(sidecar.requests[0]?.msg.headers["host"]).toBeUndefined();

    // streaming POST (NDJSON) via agk_ — chunks arrive in order
    const prompt = "PAYLOAD-SECRET-PROMPT-7f3a9";
    const res = await fetch(`${baseUrl}/ollama/strixhalo/api/generate`, {
      method: "POST",
      headers: { ...bearer(useKey.token), "content-type": "application/json" },
      body: JSON.stringify({ model: "qwen3:8b", prompt }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/x-ndjson");
    const reader = res.body!.getReader();
    const chunks: string[] = [];
    const dec = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(dec.decode(value, { stream: true }));
    }
    const body = chunks.join("");
    expect(body).toBe(
      '{"response":"part-1:PAYLOAD-RESPONSE-9b21c"}\n{"response":"part-2"}\n{"response":"part-3","done":true}\n',
    );
    expect(chunks.length).toBeGreaterThan(1); // genuinely chunked, not buffered
    const genReq = sidecar.requests[1]!;
    expect(genReq.msg.method).toBe("POST");
    expect(genReq.msg.path).toBe("/api/generate");
    expect(JSON.parse(Buffer.from(genReq.msg.body ?? "", "base64").toString())).toEqual({
      model: "qwen3:8b",
      prompt,
    });

    // session-token client call also works (no DEK needed on this path)
    const viaSession = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
      headers: bearer(ctx.session.accessToken),
    });
    expect(viaSession.status).toBe(200);

    // audit: operational events only — payload strings appear NOWHERE
    const auditRows = db
      .prepare("SELECT event, metadata FROM audit_log")
      .all() as { event: string; metadata: string | null }[];
    expect(auditRows.map((r) => r.event)).toContain("ollama_sidecar_connect");
    expect(auditRows.map((r) => r.event)).toContain("ollama_proxy_call");
    const everything = JSON.stringify(auditRows);
    expect(everything).not.toContain(prompt);
    expect(everything).not.toContain("PAYLOAD-RESPONSE-9b21c");
    const proxyAudit = auditRows.find((r) => r.event === "ollama_proxy_call");
    expect(JSON.parse(proxyAudit!.metadata!)).toMatchObject({ uplink: "strixhalo", status: 200 });

    sidecar.close();
    await waitOnline(app, ctx.session.accessToken, uplink.id, false);
    expect(auditEvents(db)).toContain("ollama_sidecar_disconnect");
    await app.close();
  }, 15_000);

  it("collision resolution: same uplink name for two users routes per authenticated user", async () => {
    const { app, baseUrl, wsUrl } = await listen();
    const a = await setupUser(app);
    const b = await setupUser(app);
    const uplinkA = (await createUplink(app, a.session.accessToken, "strixhalo")).uplink;
    const uplinkB = (await createUplink(app, b.session.accessToken, "strixhalo")).uplink;
    expect(uplinkA.id).not.toBe(uplinkB.id);
    const keyA = await issueKey(app, a, ["ollama:use"]);
    const keyB = await issueKey(app, b, ["ollama:use"]);

    const sidecarA = await TestSidecar.connect({
      relayUrl: wsUrl(uplinkA.id),
      name: "strixhalo",
      psk: uplinkA.psk,
      models: ["model-a"],
      onRequest: cannedHandler("sidecar-A"),
    });
    const sidecarB = await TestSidecar.connect({
      relayUrl: wsUrl(uplinkB.id),
      name: "strixhalo",
      psk: uplinkB.psk,
      models: ["model-b"],
      onRequest: cannedHandler("sidecar-B"),
    });
    await waitOnline(app, a.session.accessToken, uplinkA.id, true);
    await waitOnline(app, b.session.accessToken, uplinkB.id, true);

    const resA = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
      headers: bearer(keyA.token),
    });
    expect(((await resA.json()) as { marker: string }).marker).toBe("sidecar-A");
    const resB = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
      headers: bearer(keyB.token),
    });
    expect(((await resB.json()) as { marker: string }).marker).toBe("sidecar-B");
    // A's key can never reach B's sidecar (different user_id → unknown_uplink
    // would be the answer if B hadn't defined the name — here each simply
    // reaches ONLY their own).
    expect(sidecarA.requests).toHaveLength(1);
    expect(sidecarB.requests).toHaveLength(1);

    sidecarA.close();
    sidecarB.close();
    await app.close();
  }, 15_000);

  it("handshake failures: wrong PSK / name mismatch / unknown uuid all close, uplink stays offline", async () => {
    const { app, db, wsUrl } = await listen();
    const ctx = await setupUser(app);
    const { uplink } = await createUplink(app, ctx.session.accessToken, "strixhalo");

    // unknown uplink UUID
    await connectExpectClose({ relayUrl: wsUrl(crypto.randomUUID()) });

    // name mismatch in hello
    await connectExpectClose({ relayUrl: wsUrl(uplink.id), name: "not-strixhalo" });

    // wrong PSK: the hello_ack arrives, but the first encrypted frame cannot
    // be decrypted → uniform close, never online.
    const wrong = await TestSidecar.connect({
      relayUrl: wsUrl(uplink.id),
      name: "strixhalo",
      psk: "definitely-the-wrong-psk",
    });
    await wrong.closed;
    await waitFor(async () =>
      (await listUplinks(app, ctx.session.accessToken)).every((r) => !r.online),
    );
    expect(auditEvents(db)).not.toContain("ollama_sidecar_connect");
    await app.close();
  }, 15_000);

  it("takeover: a second proven sidecar replaces the first", async () => {
    const { app, baseUrl, wsUrl } = await listen();
    const ctx = await setupUser(app);
    const { uplink } = await createUplink(app, ctx.session.accessToken, "strixhalo");
    const useKey = await issueKey(app, ctx, ["ollama:use"]);

    let firstClosed = false;
    const first = await TestSidecar.connect({
      relayUrl: wsUrl(uplink.id),
      name: "strixhalo",
      psk: uplink.psk,
      onRequest: cannedHandler("first"),
    });
    void first.closed.then(() => {
      firstClosed = true;
    });
    await waitOnline(app, ctx.session.accessToken, uplink.id, true);

    const second = await TestSidecar.connect({
      relayUrl: wsUrl(uplink.id),
      name: "strixhalo",
      psk: uplink.psk,
      onRequest: cannedHandler("second"),
    });
    await waitFor(() => firstClosed);
    const res = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
      headers: bearer(useKey.token),
    });
    expect(((await res.json()) as { marker: string }).marker).toBe("second");
    expect(first.requests).toHaveLength(0);
    expect(second.requests).toHaveLength(1);

    second.close();
    await app.close();
  }, 15_000);

  it("proxy guards: 404 unknown name, 503 offline, 401 missing scope / revoked key", async () => {
    const { app, baseUrl } = await listen();
    const ctx = await setupUser(app);
    const { uplink } = await createUplink(app, ctx.session.accessToken, "strixhalo");
    const useKey = await issueKey(app, ctx, ["ollama:use"]);
    const wrongScope = await issueKey(app, ctx, ["gateway:use"]);

    // unknown name (post-auth) → 404 unknown_uplink
    const unknown = await fetch(`${baseUrl}/ollama/nope/api/tags`, {
      headers: bearer(useKey.token),
    });
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toEqual({ error: "unknown_uplink" });

    // offline uplink → 503 uplink_offline
    const offline = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
      headers: bearer(useKey.token),
    });
    expect(offline.status).toBe(503);
    expect(await offline.json()).toEqual({ error: "uplink_offline" });

    // agk_ without ollama:use → uniform 401
    const denied = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
      headers: bearer(wrongScope.token),
    });
    expect(denied.status).toBe(401);

    // revoked agk_ → uniform 401
    const revoke = await app.inject({
      method: "POST",
      url: `/v1/api-keys/${useKey.keyId}/revoke`,
      headers: bearer(ctx.session.accessToken),
    });
    expect(revoke.statusCode).toBe(200);
    const revoked = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
      headers: bearer(useKey.token),
    });
    expect(revoked.status).toBe(401);
    void uplink;
    await app.close();
  }, 15_000);

  it("client disconnect mid-stream cancels the tunnel request at the sidecar", async () => {
    const { app, baseUrl, wsUrl } = await listen();
    const ctx = await setupUser(app);
    const { uplink } = await createUplink(app, ctx.session.accessToken, "strixhalo");
    const useKey = await issueKey(app, ctx, ["ollama:use"]);

    const sidecar = await TestSidecar.connect({
      relayUrl: wsUrl(uplink.id),
      name: "strixhalo",
      psk: uplink.psk,
      onRequest: (_msg, responder) => {
        responder.sendHead(200, { "content-type": "application/x-ndjson" });
        responder.sendChunk(enc.encode('{"tick":0}\n'));
        let n = 1;
        const timer = setInterval(() => {
          responder.sendChunk(enc.encode(`{"tick":${String(n)}}\n`));
          n++;
        }, 20);
        timer.unref();
        responder.onCancel(() => {
          clearInterval(timer);
        });
      },
    });
    await waitOnline(app, ctx.session.accessToken, uplink.id, true);

    await new Promise<void>((resolve, reject) => {
      const req = http.get(
        `${baseUrl}/ollama/strixhalo/api/generate`,
        { headers: bearer(useKey.token) },
        (res) => {
          res.once("data", () => {
            res.destroy(); // client goes away mid-stream
            resolve();
          });
        },
      );
      req.once("error", reject);
    });
    await waitFor(() => sidecar.cancels.length > 0);
    sidecar.close();
    await app.close();
  }, 15_000);

  it("overall request timeout cancels and answers 504", async () => {
    const { app, baseUrl, wsUrl } = await listen({ ollamaProxyTimeoutMs: 150 });
    const ctx = await setupUser(app);
    const { uplink } = await createUplink(app, ctx.session.accessToken, "strixhalo");
    const useKey = await issueKey(app, ctx, ["ollama:use"]);
    const sidecar = await TestSidecar.connect({
      relayUrl: wsUrl(uplink.id),
      name: "strixhalo",
      psk: uplink.psk,
      onRequest: () => {
        // never responds
      },
    });
    await waitOnline(app, ctx.session.accessToken, uplink.id, true);
    const res = await fetch(`${baseUrl}/ollama/strixhalo/api/generate`, {
      method: "POST",
      headers: { ...bearer(useKey.token), "content-type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(504);
    expect(await res.json()).toEqual({ error: "uplink_timeout" });
    await waitFor(() => sidecar.cancels.length > 0);
    sidecar.close();
    await app.close();
  }, 15_000);

  it("rate limit: client-facing proxy answers 429 over the per-key limit", async () => {
    const { app, baseUrl, wsUrl } = await listen({
      rateLimitOllama: { max: 2, timeWindow: "1 minute" },
    });
    const ctx = await setupUser(app);
    const { uplink } = await createUplink(app, ctx.session.accessToken, "strixhalo");
    const useKey = await issueKey(app, ctx, ["ollama:use"]);
    const sidecar = await TestSidecar.connect({
      relayUrl: wsUrl(uplink.id),
      name: "strixhalo",
      psk: uplink.psk,
      onRequest: cannedHandler("rl"),
    });
    await waitOnline(app, ctx.session.accessToken, uplink.id, true);

    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${baseUrl}/ollama/strixhalo/api/tags`, {
        headers: bearer(useKey.token),
      });
      statuses.push(res.status);
      await res.arrayBuffer(); // drain
    }
    expect(statuses).toEqual([200, 200, 429]);
    sidecar.close();
    await app.close();
  }, 15_000);
});
