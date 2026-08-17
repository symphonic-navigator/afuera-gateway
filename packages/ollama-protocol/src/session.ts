/**
 * TunnelSession multiplexer — ported byte-compatibly from the ollama-uplink
 * project (packages/protocol/src/session.ts).
 *
 * One encrypted session carries any number of concurrent requests
 * (request_open → response_head/response_chunk/response_end, cancel, error),
 * plus ping/pong keepalive and model_update. Frames are sequenced per
 * direction; a frame that fails AEAD verification closes the session.
 */

import {
  type Direction,
  decryptFrame,
  encryptFrame,
  generateSessionId,
  type SessionKeys,
} from "./crypto.js";
import { decodeMessage, encodeMessage, type Message, type Usage } from "./messages.js";

export interface FrameTransport {
  send(data: Uint8Array): void;
  onMessage(cb: (data: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  close(): void;
}

export type Role = "relay" | "sidecar";

export type RequestOpenMessage = Extract<Message, { kind: "request_open" }>;

export interface PendingRequest {
  readonly requestId: string;
  readonly settled: boolean;
  onHead(cb: (status: number, headers: Record<string, string>) => void): void;
  onChunk(cb: (data: Uint8Array) => void): void;
  onEnd(cb: (usage: Usage | null) => void): void;
  onError(cb: (message: string) => void): void;
  cancel(): void;
}

export interface Responder {
  sendHead(status: number, headers: Record<string, string>): void;
  sendChunk(data: Uint8Array): void;
  sendEnd(usage: Usage | null): void;
  sendError(message: string): void;
  onCancel(cb: () => void): void;
}

type PendingEvent =
  | { type: "head"; status: number; headers: Record<string, string> }
  | { type: "chunk"; data: Uint8Array }
  | { type: "end"; usage: Usage | null }
  | { type: "error"; message: string };

class PendingRequestImpl implements PendingRequest {
  settled = false;
  // Events are buffered so callbacks registered after a synchronous
  // response still observe them, in order.
  private readonly events: PendingEvent[] = [];
  private readonly headCbs: Array<(status: number, headers: Record<string, string>) => void> = [];
  private readonly chunkCbs: Array<(data: Uint8Array) => void> = [];
  private readonly endCbs: Array<(usage: Usage | null) => void> = [];
  private readonly errorCbs: Array<(message: string) => void> = [];

  constructor(
    readonly requestId: string,
    private readonly doCancel: () => void,
  ) {}

  onHead(cb: (status: number, headers: Record<string, string>) => void): void {
    for (const event of this.events) if (event.type === "head") cb(event.status, event.headers);
    this.headCbs.push(cb);
  }

  onChunk(cb: (data: Uint8Array) => void): void {
    for (const event of this.events) if (event.type === "chunk") cb(event.data);
    this.chunkCbs.push(cb);
  }

  onEnd(cb: (usage: Usage | null) => void): void {
    for (const event of this.events) if (event.type === "end") cb(event.usage);
    this.endCbs.push(cb);
  }

  onError(cb: (message: string) => void): void {
    for (const event of this.events) if (event.type === "error") cb(event.message);
    this.errorCbs.push(cb);
  }

  cancel(): void {
    if (this.settled) return;
    this.settled = true;
    this.doCancel();
  }

  fireHead(status: number, headers: Record<string, string>): void {
    if (this.settled) return;
    this.events.push({ type: "head", status, headers });
    for (const cb of this.headCbs) cb(status, headers);
  }

  fireChunk(data: Uint8Array): void {
    if (this.settled) return;
    this.events.push({ type: "chunk", data });
    for (const cb of this.chunkCbs) cb(data);
  }

  fireEnd(usage: Usage | null): void {
    if (this.settled) return;
    this.settled = true;
    this.events.push({ type: "end", usage });
    for (const cb of this.endCbs) cb(usage);
  }

  fireError(message: string): void {
    if (this.settled) return;
    this.settled = true;
    this.events.push({ type: "error", message });
    for (const cb of this.errorCbs) cb(message);
  }
}

class ResponderImpl implements Responder {
  private cancelCbs: Array<() => void> = [];
  private done = false;

  constructor(
    private readonly session: TunnelSession,
    private readonly requestId: string,
  ) {}

  sendHead(status: number, headers: Record<string, string>): void {
    if (this.done) return;
    this.session.send({ kind: "response_head", request_id: this.requestId, status, headers });
  }

  sendChunk(data: Uint8Array): void {
    if (this.done) return;
    this.session.send({
      kind: "response_chunk",
      request_id: this.requestId,
      data: Buffer.from(data).toString("base64"),
    });
  }

  sendEnd(usage: Usage | null): void {
    if (this.done) return;
    this.done = true;
    this.session.send({ kind: "response_end", request_id: this.requestId, usage });
    this.session.clearResponder(this.requestId);
  }

  sendError(message: string): void {
    if (this.done) return;
    this.done = true;
    this.session.send({ kind: "error", request_id: this.requestId, message });
    this.session.clearResponder(this.requestId);
  }

  onCancel(cb: () => void): void {
    this.cancelCbs.push(cb);
  }

  fireCancel(): void {
    if (this.done) return;
    this.done = true;
    for (const cb of this.cancelCbs) cb();
    this.session.clearResponder(this.requestId);
  }
}

export class TunnelSession {
  private sendSeq = 0;
  private recvSeq = 0;
  private closed = false;
  private readonly messageCbs: Array<(msg: Message) => void> = [];
  private readonly closeCbs: Array<() => void> = [];
  private readonly openCbs: Array<(msg: RequestOpenMessage, responder: Responder) => void> = [];
  private readonly pending = new Map<string, PendingRequestImpl>();
  private readonly responders = new Map<string, ResponderImpl>();

  constructor(
    private readonly transport: FrameTransport,
    private readonly keys: SessionKeys,
    private readonly sessionId: string,
    private readonly role: Role,
  ) {
    transport.onMessage((data) => this.handleFrame(data));
    transport.onClose(() => this.handleClose());
  }

  send(msg: Message): void {
    if (this.closed) throw new Error("session closed");
    const direction = this.sendDirection();
    const frame = encryptFrame(
      this.keys[direction],
      { sessionId: this.sessionId, direction, seq: this.sendSeq++ },
      encodeMessage(msg),
    );
    this.transport.send(frame);
  }

  onMessage(cb: (msg: Message) => void): void {
    this.messageCbs.push(cb);
  }

  onRequestOpen(cb: (msg: RequestOpenMessage, responder: Responder) => void): void {
    this.openCbs.push(cb);
  }

  onClose(cb: () => void): void {
    if (this.closed) cb();
    else this.closeCbs.push(cb);
  }

  close(): void {
    if (!this.closed) this.transport.close();
    this.handleClose();
  }

  openRequest(init: {
    requestId?: string;
    method: string;
    path: string;
    headers: Record<string, string>;
    body: Uint8Array | null;
  }): PendingRequest {
    const requestId = init.requestId ?? generateSessionId();
    const impl = new PendingRequestImpl(requestId, () => {
      this.pending.delete(requestId);
      this.sendCancelFrame(requestId);
    });
    this.pending.set(requestId, impl);
    this.send({
      kind: "request_open",
      request_id: requestId,
      method: init.method,
      path: init.path,
      headers: init.headers,
      body: init.body ? Buffer.from(init.body).toString("base64") : null,
    });
    return impl;
  }

  cancel(requestId: string): void {
    const impl = this.pending.get(requestId);
    if (impl) impl.cancel();
    else this.sendCancelFrame(requestId);
  }

  clearResponder(requestId: string): void {
    this.responders.delete(requestId);
  }

  private sendCancelFrame(requestId: string): void {
    if (this.closed) return;
    this.send({ kind: "cancel", request_id: requestId });
  }

  private sendDirection(): Direction {
    return this.role === "sidecar" ? "s2r" : "r2s";
  }

  private recvDirection(): Direction {
    return this.role === "sidecar" ? "r2s" : "s2r";
  }

  private handleFrame(data: Uint8Array): void {
    if (this.closed) return;
    let msg: Message;
    try {
      const direction = this.recvDirection();
      const plaintext = decryptFrame(
        this.keys[direction],
        { sessionId: this.sessionId, direction, seq: this.recvSeq },
        data,
      );
      this.recvSeq++;
      msg = decodeMessage(plaintext);
    } catch {
      this.transport.close();
      this.handleClose();
      return;
    }
    if (msg.kind === "ping") {
      this.send({ kind: "pong", ts: msg.ts });
      return;
    }
    this.dispatch(msg);
  }

  private dispatch(msg: Message): void {
    switch (msg.kind) {
      case "request_open": {
        const responder = new ResponderImpl(this, msg.request_id);
        this.responders.set(msg.request_id, responder);
        for (const cb of this.openCbs) cb(msg, responder);
        return;
      }
      case "response_head":
        this.pending.get(msg.request_id)?.fireHead(msg.status, msg.headers);
        return;
      case "response_chunk":
        this.pending.get(msg.request_id)?.fireChunk(Buffer.from(msg.data, "base64"));
        return;
      case "response_end": {
        const impl = this.pending.get(msg.request_id);
        this.pending.delete(msg.request_id);
        impl?.fireEnd(msg.usage);
        return;
      }
      case "error": {
        const impl = this.pending.get(msg.request_id);
        this.pending.delete(msg.request_id);
        impl?.fireError(msg.message);
        return;
      }
      case "cancel":
        this.responders.get(msg.request_id)?.fireCancel();
        return;
      default:
        for (const cb of this.messageCbs) cb(msg);
    }
  }

  private handleClose(): void {
    if (this.closed) return;
    this.closed = true;
    for (const impl of this.pending.values()) impl.fireError("session closed");
    this.pending.clear();
    for (const responder of this.responders.values()) responder.fireCancel();
    this.responders.clear();
    for (const cb of this.closeCbs) cb();
  }
}

export function createMemoryTransportPair(): [FrameTransport, FrameTransport] {
  interface State {
    messageCbs: Array<(data: Uint8Array) => void>;
    closeCbs: Array<() => void>;
    closed: boolean;
  }
  const a: State = { messageCbs: [], closeCbs: [], closed: false };
  const b: State = { messageCbs: [], closeCbs: [], closed: false };
  const makeClose = (self: State, peer: State) => () => {
    if (!self.closed) {
      self.closed = true;
      for (const cb of self.closeCbs) cb();
    }
    if (!peer.closed) {
      peer.closed = true;
      for (const cb of peer.closeCbs) cb();
    }
  };
  const make = (self: State, peer: State): FrameTransport => ({
    send: (data) => {
      if (self.closed) throw new Error("transport closed");
      for (const cb of [...peer.messageCbs]) cb(data);
    },
    onMessage: (cb) => {
      self.messageCbs.push(cb);
    },
    onClose: (cb) => {
      self.closeCbs.push(cb);
    },
    close: makeClose(self, peer),
  });
  return [make(a, b), make(b, a)];
}
