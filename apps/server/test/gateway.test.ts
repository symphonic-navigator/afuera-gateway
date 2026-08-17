/**
 * HTTP integration: the API gateway (docs/specs/gateway.md) —
 * admin catalog, per-user upstream credentials, and the proxy
 * ("upstream key translation") end-to-end against a fake upstream.
 */

import { createServer } from "node:net";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createApiKey,
  dataAAD,
  decryptBlob,
  encryptBlob,
  encryptData,
  generateDek,
  initializeUser,
  reEncryptDataBlob,
  rewrapDekForMaster,
  utf8,
  utf8Decode,
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
// fake upstream: records what it receives, returns canned responses
// ---------------------------------------------------------------------------

interface RecordedRequest {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

interface FakeUpstream {
  baseUrl: string;
  requests: RecordedRequest[];
  close(): Promise<void>;
}

const MODELS_BODY = JSON.stringify({ data: [{ id: "gpt-nano-1" }] });

async function startFakeUpstream(): Promise<FakeUpstream> {
  const requests: RecordedRequest[] = [];
  const upstream: FastifyInstance = Fastify();
  // raw bytes for everything (exact match beats the catch-all, so the
  // default JSON parser must be shadowed explicitly)
  const rawBody = { parseAs: "buffer" as const };
  const bufferParser = (_req: unknown, body: unknown, done: (e: null, b?: unknown) => void) =>
    done(null, body);
  upstream.addContentTypeParser("application/json", rawBody, bufferParser);
  upstream.addContentTypeParser("*", rawBody, bufferParser);
  upstream.all("/*", async (req, reply) => {
    requests.push({
      method: req.method,
      url: req.raw.url ?? "",
      headers: req.headers,
      // copy: the parser's buffer is pool-backed and reused after the reply
      body: Buffer.isBuffer(req.body) ? Buffer.from(req.body) : Buffer.alloc(0),
    });
    if (req.url.startsWith("/api/v1/models")) {
      return reply
        .code(200)
        .header("content-type", "application/json")
        .header("set-cookie", "upstream_session=should-be-stripped")
        .header("x-upstream", "fake")
        .send(MODELS_BODY);
    }
    if (req.url.startsWith("/echo")) {
      return reply
        .code(200)
        .header("content-type", String(req.headers["content-type"] ?? "application/octet-stream"))
        .send(req.body);
    }
    return reply.code(404).send({ error: "no such upstream route" });
  });
  await upstream.listen({ port: 0, host: "127.0.0.1" });
  const address = upstream.server.address();
  if (address === null || typeof address === "string") throw new Error("no upstream address");
  return {
    baseUrl: `http://127.0.0.1:${String(address.port)}`,
    requests,
    close: () => upstream.close(),
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
// client-side drivers (the client half of the gateway flows)
// ---------------------------------------------------------------------------

const UPSTREAM_KEY = "sk-nano-gpt-USER-SECRET";

interface GatewayFixture {
  app: FastifyInstance;
  db: AppDatabase;
  admin: InitializedUser;
  adminSession: Session;
}

/** App with a pre-registered admin user (user_id must be known pre-boot). */
async function setupGatewayApp(extra: Partial<AppConfig> = {}): Promise<GatewayFixture> {
  const admin = initializeUser();
  const { app, db } = buildTestApp({
    adminUsers: [admin.registration.userId],
    gatewayAllowHttp: true,
    gatewayUpstreamTimeoutMs: 5_000,
    rateLimitGateway: { max: 10_000, timeWindow: "1 minute" },
    ...extra,
  });
  const res = await app.inject({
    method: "POST",
    url: "/v1/users/register",
    payload: {
      user_id: admin.registration.userId,
      auth_public_key: admin.registration.authPublicKey,
      wrapped_dek_master: admin.registration.wrappedDekMaster,
    },
  });
  if (res.statusCode !== 201) throw new Error(`admin register failed: ${res.statusCode}`);
  const adminSession = await loginSession(app, admin.registration.userId, admin.rootSecret);
  return { app, db, admin, adminSession };
}

async function defineApi(
  app: FastifyInstance,
  session: Session,
  api: { name: string; base_url: string; description?: string; auth_header?: string; auth_scheme?: string },
): Promise<number> {
  const res = await app.inject({
    method: "POST",
    url: "/v1/gateway/apis",
    headers: bearer(session.accessToken),
    payload: api,
  });
  return res.statusCode;
}

/** Client-side credential blob (gateway.md §AAD contract). */
function credentialBlob(
  dek: Uint8Array,
  userId: string,
  apiName: string,
  dekVersion: number,
  key = UPSTREAM_KEY,
): string {
  return encryptBlob(dek, utf8(key), dataAAD(userId, `gateway-credential:${apiName}`, dekVersion));
}

/** Store a credential through the server (session path). */
async function storeCredential(
  app: FastifyInstance,
  session: Session,
  apiName: string,
  blob: string,
): Promise<void> {
  const res = await app.inject({
    method: "PUT",
    url: `/v1/gateway/credentials/${apiName}`,
    headers: bearer(session.accessToken),
    payload: { blob },
  });
  if (res.statusCode !== 200) {
    throw new Error(`store credential failed: ${res.statusCode} ${res.body}`);
  }
}

/** Create + register an API key with the given scopes. */
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

describe("gateway (docs/specs/gateway.md)", () => {
  let upstream: FakeUpstream;

  beforeAll(async () => {
    upstream = await startFakeUpstream();
  });
  afterAll(async () => {
    await upstream.close();
  });

  it("admin defines/removes APIs; non-admin forbidden; catalog via session and agk_", async () => {
    const { app, db, adminSession } = await setupGatewayApp();
    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);

    // non-admin session cannot define
    const forbidden = await defineApi(app, session, { name: "nano-gpt", base_url: upstream.baseUrl });
    expect(forbidden).toBe(403);
    // agk_ token cannot reach admin routes at all (session path only)
    const agk = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);
    const viaKey = await app.inject({
      method: "POST",
      url: "/v1/gateway/apis",
      headers: bearer(agk.token),
      payload: { name: "nano-gpt", base_url: upstream.baseUrl },
    });
    expect(viaKey.statusCode).toBe(401);

    // validation: bad slug, non-https scheme, path traversal, duplicate
    expect(
      await defineApi(app, adminSession, { name: "Bad Slug!", base_url: upstream.baseUrl }),
    ).toBe(400);
    expect(
      await defineApi(app, adminSession, { name: "nano-gpt", base_url: "ftp://example.com" }),
    ).toBe(400);
    expect(
      await defineApi(app, adminSession, { name: "nano-gpt", base_url: "https://example.com/../etc" }),
    ).toBe(400);

    // admin defines; duplicate → 409
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(201);
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(409);

    // catalog via session
    const catalogSession = await app.inject({
      method: "GET",
      url: "/v1/gateway/apis",
      headers: bearer(session.accessToken),
    });
    expect(catalogSession.statusCode).toBe(200);
    expect(catalogSession.json()).toEqual({
      apis: [{ name: "nano-gpt", base_url: upstream.baseUrl, description: null }],
    });
    // catalog via agk_ (any valid key)
    const catalogKey = await app.inject({
      method: "GET",
      url: "/v1/gateway/apis",
      headers: bearer(agk.token),
    });
    expect(catalogKey.statusCode).toBe(200);
    expect((catalogKey.json() as { apis: unknown[] }).apis).toHaveLength(1);

    // http base_url rejected when the escape hatch is off
    const admin2 = initializeUser();
    const strict = buildTestApp({ adminUsers: [admin2.registration.userId] });
    await strict.app.inject({
      method: "POST",
      url: "/v1/users/register",
      payload: {
        user_id: admin2.registration.userId,
        auth_public_key: admin2.registration.authPublicKey,
        wrapped_dek_master: admin2.registration.wrappedDekMaster,
      },
    });
    const strictSession = await loginSession(strict.app, admin2.registration.userId, admin2.rootSecret);
    expect(
      await defineApi(strict.app, strictSession, { name: "nano-gpt", base_url: upstream.baseUrl }),
    ).toBe(400);
    await strict.app.close();

    // admin removes; credentials cascade; second delete → 404
    const del = await app.inject({
      method: "DELETE",
      url: "/v1/gateway/apis/nano-gpt",
      headers: bearer(adminSession.accessToken),
    });
    expect(del.statusCode).toBe(200);
    const delAgain = await app.inject({
      method: "DELETE",
      url: "/v1/gateway/apis/nano-gpt",
      headers: bearer(adminSession.accessToken),
    });
    expect(delAgain.statusCode).toBe(404);

    expect(auditEvents(db)).toContain("gateway_api_defined");
    expect(auditEvents(db)).toContain("gateway_api_removed");
    await app.close();
  });

  it("full E2E: credential → agk_ key → proxy GET (path+query+key injection) and POST (raw body)", async () => {
    const { app, adminSession } = await setupGatewayApp();
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(201);

    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);
    await storeCredential(app, session, "nano-gpt", credentialBlob(user.dek, user.registration.userId, "nano-gpt", 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);

    // --- GET with query string
    const before = upstream.requests.length;
    const res = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models?limit=5&filter=all",
      headers: { ...bearer(key.token), "x-custom": "kept" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(MODELS_BODY); // byte-identical
    expect(res.headers["x-upstream"]).toBe("fake");
    expect(res.headers["content-type"]).toContain("application/json");

    const recorded = upstream.requests.slice(before);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]!.method).toBe("GET");
    expect(recorded[0]!.url).toBe("/api/v1/models?limit=5&filter=all");
    // the DECRYPTED upstream key was injected — the agk_ token never left the server
    expect(recorded[0]!.headers["authorization"]).toBe(`Bearer ${UPSTREAM_KEY}`);
    expect(recorded[0]!.headers["x-custom"]).toBe("kept");
    expect(JSON.stringify(recorded[0]!.headers)).not.toContain("agk_");

    // --- POST with a JSON body, proxied byte-identical
    const payload = JSON.stringify({ prompt: "hello", n: 1 });
    const echo = await app.inject({
      method: "POST",
      url: "/gateway/nano-gpt/echo",
      headers: { ...bearer(key.token), "content-type": "application/json" },
      payload,
    });
    expect(echo.statusCode).toBe(200);
    expect(echo.body).toBe(payload);
    const echoed = upstream.requests[upstream.requests.length - 1]!;
    expect(echoed.method).toBe("POST");
    expect(echoed.url).toBe("/echo");
    expect(echoed.body.toString("utf8")).toBe(payload);
    expect(echoed.headers["authorization"]).toBe(`Bearer ${UPSTREAM_KEY}`);

    await app.close();
  });

  it("proxy auth matrix: session → 401, missing scope → 401, revoked → 401, unknown api → 404, missing credential → 404, upstream down → 502", async () => {
    const { app, adminSession } = await setupGatewayApp();
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(201);
    const dead = await closedPort();
    expect(await defineApi(app, adminSession, { name: "dead-api", base_url: `http://127.0.0.1:${String(dead)}` })).toBe(201);

    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);
    await storeCredential(app, session, "nano-gpt", credentialBlob(user.dek, user.registration.userId, "nano-gpt", 1));
    await storeCredential(app, session, "dead-api", credentialBlob(user.dek, user.registration.userId, "dead-api", 1));
    const useKey = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);
    const dataKey = await issueApiKey(app, session, user.dek, 1, ["data:read"]);

    // session token → uniform 401 (sessions carry no key material, by design)
    const viaSession = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(session.accessToken),
    });
    expect(viaSession.statusCode).toBe(401);
    expect(viaSession.json()).toEqual({ error: "unauthorized" });

    // agk_ without gateway:use → 401
    const wrongScope = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(dataKey.token),
    });
    expect(wrongScope.statusCode).toBe(401);

    // revoked key → 401
    const revokedKey = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);
    await app.inject({
      method: "POST",
      url: `/v1/api-keys/${revokedKey.keyId}/revoke`,
      headers: bearer(session.accessToken),
    });
    const viaRevoked = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(revokedKey.token),
    });
    expect(viaRevoked.statusCode).toBe(401);

    // unknown api → 404 unknown_api
    const unknownApi = await app.inject({
      method: "GET",
      url: "/gateway/no-such-api/x",
      headers: bearer(useKey.token),
    });
    expect(unknownApi.statusCode).toBe(404);
    expect(unknownApi.json()).toEqual({ error: "unknown_api" });

    // sanity: this user HAS the credential → proxies fine
    const sanity = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(useKey.token),
    });
    expect(sanity.statusCode).toBe(200);

    const other = await registerUser(app);
    const otherSession = await loginSession(app, other.registration.userId, other.rootSecret);
    const otherKey = await issueApiKey(app, otherSession, other.dek, 1, ["gateway:use"]);
    const noCredential = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(otherKey.token),
    });
    expect(noCredential.statusCode).toBe(404);
    expect(noCredential.json()).toEqual({ error: "credential_not_found" });

    // upstream unreachable → 502 upstream_error
    const down = await app.inject({
      method: "GET",
      url: "/gateway/dead-api/anything",
      headers: bearer(useKey.token),
    });
    expect(down.statusCode).toBe(502);
    expect(down.json()).toEqual({ error: "upstream_error" });

    await app.close();
  });

  it("custom auth_header / empty auth_scheme honored (raw key header)", async () => {
    const { app, adminSession } = await setupGatewayApp();
    expect(
      await defineApi(app, adminSession, {
        name: "raw-key-api",
        base_url: upstream.baseUrl,
        auth_header: "x-api-key",
        auth_scheme: "",
      }),
    ).toBe(201);

    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);
    await storeCredential(app, session, "raw-key-api", credentialBlob(user.dek, user.registration.userId, "raw-key-api", 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);

    const before = upstream.requests.length;
    const res = await app.inject({
      method: "GET",
      url: "/gateway/raw-key-api/api/v1/models",
      headers: bearer(key.token),
    });
    expect(res.statusCode).toBe(200);
    const recorded = upstream.requests.slice(before);
    expect(recorded[0]!.headers["x-api-key"]).toBe(UPSTREAM_KEY); // raw key, no scheme
    expect(recorded[0]!.headers["authorization"]).toBeUndefined();
    await app.close();
  });

  it("response header hygiene: upstream set-cookie stripped, hop-by-hop not forwarded", async () => {
    const { app, adminSession } = await setupGatewayApp();
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(201);
    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);
    await storeCredential(app, session, "nano-gpt", credentialBlob(user.dek, user.registration.userId, "nano-gpt", 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);

    const before = upstream.requests.length;
    const res = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: {
        ...bearer(key.token),
        connection: "keep-alive",
        "keep-alive": "timeout=5",
        te: "trailers",
        "transfer-encoding": "chunked",
        host: "spoofed.example.com",
      },
    });
    expect(res.statusCode).toBe(200);
    // response side: set-cookie stripped, real content kept
    expect(res.headers["set-cookie"]).toBeUndefined();
    expect(res.headers["x-upstream"]).toBe("fake");
    expect(res.headers["connection"]).not.toBe("keep-alive-from-upstream");
    // request side: hop-by-hop + host + the agk_ authorization never reached upstream
    const recorded = upstream.requests.slice(before)[0]!;
    expect(recorded.headers["host"]).not.toBe("spoofed.example.com");
    expect(recorded.headers["keep-alive"]).toBeUndefined();
    expect(recorded.headers["te"]).toBeUndefined();
    expect(recorded.headers["transfer-encoding"]).toBeUndefined();
    expect(recorded.headers["authorization"]).toBe(`Bearer ${UPSTREAM_KEY}`);
    await app.close();
  });

  it("credential CRUD incl. AAD binding across upstreams", async () => {
    const { app, db, adminSession } = await setupGatewayApp();
    expect(await defineApi(app, adminSession, { name: "api-a", base_url: upstream.baseUrl })).toBe(201);
    expect(await defineApi(app, adminSession, { name: "api-b", base_url: upstream.baseUrl })).toBe(201);

    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);
    const manageKey = await issueApiKey(app, session, user.dek, 1, ["gateway:manage"]);

    // PUT to an undefined api → 404 unknown_api
    const unknownApi = await app.inject({
      method: "PUT",
      url: "/v1/gateway/credentials/nope",
      headers: bearer(session.accessToken),
      payload: { blob: credentialBlob(user.dek, user.registration.userId, "nope", 1) },
    });
    expect(unknownApi.statusCode).toBe(404);
    expect(unknownApi.json()).toEqual({ error: "unknown_api" });

    // upsert via session, list + read via agk_ with gateway:manage
    const blobA = credentialBlob(user.dek, user.registration.userId, "api-a", 1);
    await storeCredential(app, session, "api-a", blobA);
    const list = await app.inject({
      method: "GET",
      url: "/v1/gateway/credentials",
      headers: bearer(manageKey.token),
    });
    expect(list.statusCode).toBe(200);
    const creds = (list.json() as { credentials: { api_name: string; created_at: string; updated_at: string }[] }).credentials;
    expect(creds).toHaveLength(1);
    expect(creds[0]!.api_name).toBe("api-a");
    expect(JSON.stringify(list.json())).not.toContain("blob"); // metadata only

    const one = await app.inject({
      method: "GET",
      url: "/v1/gateway/credentials/api-a",
      headers: bearer(manageKey.token),
    });
    expect(one.statusCode).toBe(200);
    expect((one.json() as { blob: string }).blob).toBe(blobA);

    // AAD binding: the blob for api-a does NOT decrypt against api-b's AAD
    const roundtrip = decryptBlob(
      user.dek,
      blobA,
      dataAAD(user.registration.userId, "gateway-credential:api-a", 1),
    );
    expect(utf8Decode(roundtrip)).toBe(UPSTREAM_KEY);
    expect(() =>
      decryptBlob(user.dek, blobA, dataAAD(user.registration.userId, "gateway-credential:api-b", 1)),
    ).toThrow();

    // gateway:manage key cannot proxy (no gateway:use), and vice versa
    const useKey = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);
    const manageViaUse = await app.inject({
      method: "GET",
      url: "/v1/gateway/credentials/api-a",
      headers: bearer(useKey.token),
    });
    expect(manageViaUse.statusCode).toBe(401);
    const proxyViaManage = await app.inject({
      method: "GET",
      url: "/gateway/api-a/api/v1/models",
      headers: bearer(manageKey.token),
    });
    expect(proxyViaManage.statusCode).toBe(401);

    // delete + 404 on re-delete; audit trail
    const del = await app.inject({
      method: "DELETE",
      url: "/v1/gateway/credentials/api-a",
      headers: bearer(manageKey.token),
    });
    expect(del.statusCode).toBe(200);
    const delAgain = await app.inject({
      method: "DELETE",
      url: "/v1/gateway/credentials/api-a",
      headers: bearer(session.accessToken),
    });
    expect(delAgain.statusCode).toBe(404);
    expect(delAgain.json()).toEqual({ error: "credential_not_found" });

    expect(auditEvents(db)).toContain("gateway_credential_set");
    expect(auditEvents(db)).toContain("gateway_credential_deleted");
    await app.close();
  });

  it("rotate-dek with gateway credentials: re-issued key still proxies; incomplete list → 400", async () => {
    const { app, adminSession } = await setupGatewayApp();
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(201);
    expect(await defineApi(app, adminSession, { name: "other-api", base_url: upstream.baseUrl })).toBe(201);

    const user = await registerUser(app);
    const userId = user.registration.userId;
    const session = await loginSession(app, userId, user.rootSecret);
    await storeCredential(app, session, "nano-gpt", credentialBlob(user.dek, userId, "nano-gpt", 1));
    await storeCredential(app, session, "other-api", credentialBlob(user.dek, userId, "other-api", 1));
    const oldKey = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);

    // data blob v1 (required by rotate-dek)
    const dataV1 = encryptData(user.dek, utf8("payload"), userId, "record", 1);
    await app.inject({
      method: "PUT",
      url: "/v1/data/blob",
      headers: bearer(session.accessToken),
      payload: { encrypted_data_blob: dataV1 },
    });

    const newDek = generateDek();
    const newDataBlob = reEncryptDataBlob(user.dek, newDek, dataV1, userId, "record", 1, 2);

    // --- incomplete: only one of the two credentials staged → 400
    const incomplete = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-dek",
      headers: bearer(session.accessToken),
      payload: {
        new_wrapped_dek_master: rewrapDekForMaster(user.rootSecret, newDek, 2),
        new_dek_version: 2,
        encrypted_data_blob: newDataBlob,
        revoke_all_api_keys: true,
        gateway_credentials: [
          {
            api_name: "nano-gpt",
            blob: reEncryptDataBlob(user.dek, newDek, credentialBlob(user.dek, userId, "nano-gpt", 1), userId, "gateway-credential:nano-gpt", 1, 2),
          },
        ],
      },
    });
    expect(incomplete.statusCode).toBe(400);
    expect(incomplete.json()).toEqual({ error: "incomplete_rotation" });

    // --- complete rotation commits
    const credRow = (apiName: string) =>
      credentialBlob(user.dek, userId, apiName, 1);
    const rotated = await app.inject({
      method: "POST",
      url: "/v1/crypto/rotate-dek",
      headers: bearer(session.accessToken),
      payload: {
        new_wrapped_dek_master: rewrapDekForMaster(user.rootSecret, newDek, 2),
        new_dek_version: 2,
        encrypted_data_blob: newDataBlob,
        revoke_all_api_keys: true,
        gateway_credentials: [
          { api_name: "nano-gpt", blob: reEncryptDataBlob(user.dek, newDek, credRow("nano-gpt"), userId, "gateway-credential:nano-gpt", 1, 2) },
          { api_name: "other-api", blob: reEncryptDataBlob(user.dek, newDek, credRow("other-api"), userId, "gateway-credential:other-api", 1, 2) },
        ],
      },
    });
    expect(rotated.statusCode).toBe(200);
    expect(rotated.json()).toEqual({ dek_version: 2 });

    // old key revoked → 401
    const oldAttempt = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(oldKey.token),
    });
    expect(oldAttempt.statusCode).toBe(401);

    // NEW key (issued post-rotation under dek_version 2) still proxies:
    // the server decrypts the re-encrypted credential with the NEW DEK/version.
    const newKey = await issueApiKey(app, session, newDek, 2, ["gateway:use"]);
    const before = upstream.requests.length;
    const res = await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(newKey.token),
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(MODELS_BODY);
    expect(upstream.requests.slice(before)[0]!.headers["authorization"]).toBe(`Bearer ${UPSTREAM_KEY}`);

    await app.close();
  });

  it("rate-limits the proxy per API key (429)", async () => {
    const { app, adminSession } = await setupGatewayApp({
      rateLimitGateway: { max: 2, timeWindow: "1 minute" },
    });
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(201);
    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);
    await storeCredential(app, session, "nano-gpt", credentialBlob(user.dek, user.registration.userId, "nano-gpt", 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);

    const call = () =>
      app.inject({ method: "GET", url: "/gateway/nano-gpt/api/v1/models", headers: bearer(key.token) });
    expect((await call()).statusCode).toBe(200);
    expect((await call()).statusCode).toBe(200);
    expect((await call()).statusCode).toBe(429);
    await app.close();
  });

  it("audits gateway_proxy_call with upstream status (never keys/blobs)", async () => {
    const { app, db, adminSession } = await setupGatewayApp();
    expect(await defineApi(app, adminSession, { name: "nano-gpt", base_url: upstream.baseUrl })).toBe(201);
    const user = await registerUser(app);
    const session = await loginSession(app, user.registration.userId, user.rootSecret);
    await storeCredential(app, session, "nano-gpt", credentialBlob(user.dek, user.registration.userId, "nano-gpt", 1));
    const key = await issueApiKey(app, session, user.dek, 1, ["gateway:use"]);
    await app.inject({
      method: "GET",
      url: "/gateway/nano-gpt/api/v1/models",
      headers: bearer(key.token),
    });

    const rows = db
      .prepare("SELECT event, metadata FROM audit_log WHERE event = 'gateway_proxy_call'")
      .all() as { event: string; metadata: string }[];
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0]!.metadata)).toEqual({ api_name: "nano-gpt", upstream_status: 200 });
    // no key material or blobs anywhere in the audit log
    const everything = db.prepare("SELECT * FROM audit_log").all();
    expect(JSON.stringify(everything)).not.toContain(UPSTREAM_KEY);
    expect(JSON.stringify(everything)).not.toContain("agk_");
    await app.close();
  });
});
