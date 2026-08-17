/**
 * Ported from ollama-uplink packages/protocol/test/session.test.ts —
 * multiplexer request/response/chunk/cancel flows over a memory transport.
 */

import { describe, expect, it, vi } from "vitest";
import {
  createMemoryTransportPair,
  deriveSessionKeys,
  hashPsk,
  type Message,
  TunnelSession,
} from "../src/index.js";

function makePair(sessionId = "session-1") {
  const keys = deriveSessionKeys(
    hashPsk("test-psk"),
    new Uint8Array(16).fill(7),
    new Uint8Array(16).fill(9),
  );
  const [a, b] = createMemoryTransportPair();
  return {
    keys,
    relay: new TunnelSession(a, keys, sessionId, "relay"),
    sidecar: new TunnelSession(b, keys, sessionId, "sidecar"),
  };
}

describe("TunnelSession", () => {
  it("opens a request and streams head, chunks and end with usage", () => {
    const { relay, sidecar } = makePair();
    sidecar.onRequestOpen((msg, responder) => {
      expect(msg.kind).toBe("request_open");
      expect(msg.method).toBe("POST");
      expect(msg.path).toBe("/api/chat");
      expect(JSON.parse(Buffer.from(msg.body ?? "", "base64").toString())).toEqual({ model: "m" });
      responder.sendHead(200, { "content-type": "application/x-ndjson" });
      responder.sendChunk(new TextEncoder().encode("chunk-1\n"));
      responder.sendChunk(new TextEncoder().encode("chunk-2\n"));
      responder.sendEnd({ prompt_tokens: 3, completion_tokens: 5 });
    });
    const pending = relay.openRequest({
      method: "POST",
      path: "/api/chat",
      headers: { "content-type": "application/json" },
      body: new TextEncoder().encode(JSON.stringify({ model: "m" })),
    });
    const head = vi.fn();
    const chunks: string[] = [];
    const end = vi.fn();
    pending.onHead(head);
    pending.onChunk((d) => chunks.push(new TextDecoder().decode(d)));
    pending.onEnd(end);
    // Memory transport is synchronous: everything has already happened.
    expect(head).toHaveBeenCalledWith(200, { "content-type": "application/x-ndjson" });
    expect(chunks).toEqual(["chunk-1\n", "chunk-2\n"]);
    expect(end).toHaveBeenCalledWith({ prompt_tokens: 3, completion_tokens: 5 });
    expect(pending.settled).toBe(true);
  });

  it("multiplexes concurrent request_ids", () => {
    const { relay, sidecar } = makePair();
    sidecar.onRequestOpen((msg, responder) => {
      responder.sendEnd({ prompt_tokens: msg.request_id === "r-1" ? 1 : 2, completion_tokens: 0 });
    });
    const one = relay.openRequest({
      requestId: "r-1",
      method: "POST",
      path: "/a",
      headers: {},
      body: null,
    });
    const two = relay.openRequest({
      requestId: "r-2",
      method: "POST",
      path: "/b",
      headers: {},
      body: null,
    });
    const ends: Array<[string, number | undefined]> = [];
    one.onEnd((u) => ends.push(["r-1", u?.prompt_tokens]));
    two.onEnd((u) => ends.push(["r-2", u?.prompt_tokens]));
    expect(ends).toEqual([
      ["r-1", 1],
      ["r-2", 2],
    ]);
  });

  it("propagates cancel from the opener to the responder", () => {
    const { relay, sidecar } = makePair();
    const cancelled = vi.fn();
    sidecar.onRequestOpen((_msg, responder) => responder.onCancel(cancelled));
    const pending = relay.openRequest({ method: "POST", path: "/x", headers: {}, body: null });
    pending.cancel();
    expect(cancelled).toHaveBeenCalledOnce();
    expect(pending.settled).toBe(true);
  });

  it("delivers responder errors to the pending request", () => {
    const { relay, sidecar } = makePair();
    sidecar.onRequestOpen((_msg, responder) => responder.sendError("upstream exploded"));
    const pending = relay.openRequest({ method: "POST", path: "/x", headers: {}, body: null });
    const error = vi.fn();
    pending.onError(error);
    expect(error).toHaveBeenCalledWith("upstream exploded");
    expect(pending.settled).toBe(true);
  });

  it("auto-answers ping with pong and does not deliver ping to listeners", () => {
    const { relay, sidecar } = makePair();
    const sidecarMessages: Message[] = [];
    sidecar.onMessage((m) => sidecarMessages.push(m));
    const relayMessages: Message[] = [];
    relay.onMessage((m) => relayMessages.push(m));
    relay.send({ kind: "ping", ts: 123 });
    expect(sidecarMessages).toEqual([]);
    expect(relayMessages).toEqual([{ kind: "pong", ts: 123 }]);
  });

  it("closes the session when a frame cannot be decrypted", () => {
    const wrongKeys = deriveSessionKeys(
      hashPsk("wrong"),
      new Uint8Array(16).fill(7),
      new Uint8Array(16).fill(9),
    );
    const [a, b] = createMemoryTransportPair();
    const victim = new TunnelSession(a, wrongKeys, "s2", "relay");
    const attacker = new TunnelSession(
      b,
      deriveSessionKeys(hashPsk("nope"), new Uint8Array(16).fill(7), new Uint8Array(16).fill(9)),
      "s2",
      "sidecar",
    );
    const victimClosed = vi.fn();
    victim.onClose(victimClosed);
    attacker.send({ kind: "model_update", models: [] });
    expect(victimClosed).toHaveBeenCalledOnce();
  });

  it("fails pending requests and cancels responders when the session closes", () => {
    const { relay, sidecar } = makePair();
    const cancelled = vi.fn();
    sidecar.onRequestOpen((_msg, responder) => responder.onCancel(cancelled));
    const pending = relay.openRequest({ method: "POST", path: "/x", headers: {}, body: null });
    const error = vi.fn();
    pending.onError(error);
    sidecar.close();
    expect(error).toHaveBeenCalledWith("session closed");
    expect(cancelled).toHaveBeenCalledOnce();
  });
});
