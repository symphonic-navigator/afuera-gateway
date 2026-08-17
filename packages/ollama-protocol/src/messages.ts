/**
 * Wire message shapes for the Ollama uplink tunnel — ported byte-compatibly
 * from the ollama-uplink project (packages/protocol/src/messages.ts).
 *
 * Messages are JSON, UTF-8 encoded. Binary bodies/chunks are base64 strings.
 */

export interface Usage {
  prompt_tokens: number;
  completion_tokens: number;
}

export type Message =
  | { kind: "hello"; name: string; nonce_s: string; models: string[] }
  | { kind: "hello_ack"; nonce_r: string; session_id: string }
  | {
      kind: "request_open";
      request_id: string;
      method: string;
      path: string;
      headers: Record<string, string>;
      body: string | null;
    }
  | { kind: "response_head"; request_id: string; status: number; headers: Record<string, string> }
  | { kind: "response_chunk"; request_id: string; data: string }
  | { kind: "response_end"; request_id: string; usage: Usage | null }
  | { kind: "cancel"; request_id: string }
  | { kind: "error"; request_id: string; message: string }
  | { kind: "model_update"; models: string[] }
  | { kind: "ping"; ts: number }
  | { kind: "pong"; ts: number };

export function encodeMessage(msg: Message): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(msg));
}

export function decodeMessage(data: Uint8Array): Message {
  const parsed: unknown = JSON.parse(new TextDecoder().decode(data));
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    typeof (parsed as { kind?: unknown }).kind !== "string"
  ) {
    throw new Error("invalid frame");
  }
  return parsed as Message;
}
