/**
 * In-memory registry of online Ollama sidecar connections
 * (docs/specs/ollama-relay.md). Active connections are process-local state —
 * never written to the database. Keyed by uplink UUID (the sidecar-facing
 * identity); 0..1 connection per uplink.
 */

import type { TunnelSession } from "@afuera/ollama-protocol";

export interface OnlineUplink {
  uplinkId: string;
  userId: string;
  name: string;
  connectedAt: string;
  models: string[];
  session: TunnelSession;
}

export class UplinkRegistry {
  private readonly online = new Map<string, OnlineUplink>();

  register(uplink: OnlineUplink): void {
    this.online.set(uplink.uplinkId, uplink);
  }

  unregister(uplinkId: string): void {
    this.online.delete(uplinkId);
  }

  get(uplinkId: string): OnlineUplink | undefined {
    return this.online.get(uplinkId);
  }

  updateModels(uplinkId: string, models: string[]): void {
    const uplink = this.online.get(uplinkId);
    if (uplink) uplink.models = models;
  }
}
