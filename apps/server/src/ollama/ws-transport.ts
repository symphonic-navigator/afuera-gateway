/**
 * Adapt a ws WebSocket to the protocol package's FrameTransport
 * (ported from ollama-uplink apps/relay/server/src/ws-transport.ts).
 */

import type { FrameTransport } from "@afuera/ollama-protocol";
import type { WebSocket } from "ws";

type RawData = Buffer | ArrayBuffer | Buffer[];

function toBytes(data: RawData): Uint8Array {
  if (Buffer.isBuffer(data)) return new Uint8Array(data);
  if (Array.isArray(data)) return new Uint8Array(Buffer.concat(data));
  return new Uint8Array(data);
}

export function wsTransport(ws: WebSocket): FrameTransport {
  return {
    send: (data) => {
      ws.send(data);
    },
    onMessage: (cb) => ws.on("message", (data: RawData) => cb(toBytes(data))),
    onClose: (cb) => ws.on("close", cb),
    close: () => {
      ws.close();
    },
  };
}
