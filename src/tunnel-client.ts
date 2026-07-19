/**
 * The CONSUMING end of the subscription tunnel, daemon side
 * (`docs/features/sub-tunnel-and-chat-sessions.md` §1). When the walker
 * hits a subscription hop this box has no credential for, and the
 * bootstrap's `fleet_subscriptions` names an online peer serving that
 * provider, the request tunnels to the peer over THIS daemon's existing
 * relay socket and streams the peer's response back.
 *
 * Mirrors the browser's `tunnelFetch` (lib/stores/daemon-store.ts): open +
 * buffered request chunks + EOF out; head-frame → streaming `Response` in.
 * Any failure (nack, close pre-head, socket drop) rejects — the walker
 * treats it as a failed hop and continues the walk (degradation preserved).
 */

import type {
  TRelayFrame,
  TRelayTunnelCloseFrame,
  TRelayTunnelDataFrame,
  TRelayTunnelEndFrame,
  TRelayTunnelOpenAckFrame,
  TTunnelSurface,
} from "@openllmsh/protocol";
import { TUNNEL_CHUNK_MAX } from "@openllmsh/protocol";
import { logInfo } from "./logger";

const OPEN_TIMEOUT_MS = 15_000;

/**
 * The relay frame sender, REGISTERED by the control channel at startup
 * (not imported — walker → control-channel would close an import cycle
 * through tunnel-server → listener → walker). Null until the channel
 * starts; `tunnelToPeer` then rejects immediately.
 */
let relaySender: ((frame: TRelayFrame) => void) | null = null;
export const registerTunnelSender = (
  send: ((frame: TRelayFrame) => void) | null,
): void => {
  relaySender = send;
};

type TPendingTunnel = {
  resolveHead: (res: Response) => void;
  rejectHead: (e: Error) => void;
  headTimer: ReturnType<typeof setTimeout>;
  headDone: boolean;
  controller: ReadableStreamDefaultController<Uint8Array> | null;
  early: Uint8Array[];
  ended: boolean;
};

const pending = new Map<string, TPendingTunnel>();

/** Does this consuming daemon own `tunnelId`? Routes inbound tunnel frames:
 *  client-owned ids come here; everything else is the serving end's. */
export const ownsTunnel = (tunnelId: string): boolean => pending.has(tunnelId);

/** Error every pending consumed tunnel — called on socket reconnect (the
 *  relay swept them; their frames can never route again). */
export const failAllConsumedTunnels = (): void => {
  for (const [, t] of pending) {
    clearTimeout(t.headTimer);
    if (!t.headDone) t.rejectHead(new Error("relay socket closed"));
    t.controller?.error(new Error("relay socket closed"));
  }
  pending.clear();
};

const finish = (tunnelId: string, error: Error | null): void => {
  const t = pending.get(tunnelId);
  if (t === undefined) return;
  pending.delete(tunnelId);
  clearTimeout(t.headTimer);
  if (error !== null) {
    if (!t.headDone) t.rejectHead(error);
    if (!t.ended) t.controller?.error(error);
  } else if (!t.ended) {
    t.controller?.close();
  }
};

/** Handle an inbound frame for a tunnel this daemon CONSUMES. */
export const handleConsumedTunnelFrame = (
  frame:
    | TRelayTunnelOpenAckFrame
    | TRelayTunnelDataFrame
    | TRelayTunnelEndFrame
    | TRelayTunnelCloseFrame,
): void => {
  switch (frame.type) {
    case "tunnel_open_ack": {
      if (frame.ok) return; // wait for the head data frame
      finish(frame.tunnel_id, new Error(frame.error ?? "tunnel refused"));
      return;
    }
    case "tunnel_data": {
      if (frame.dir !== "res") return;
      const t = pending.get(frame.tunnel_id);
      if (t === undefined || t.ended) return;
      const bytes = new Uint8Array(Buffer.from(frame.data_b64, "base64"));
      if (!t.headDone) {
        t.headDone = true;
        clearTimeout(t.headTimer);
        if (bytes.length > 0) t.early.push(bytes);
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            t.controller = controller;
            for (const chunk of t.early) controller.enqueue(chunk);
            t.early.length = 0;
          },
        });
        const headers = new Headers();
        if (frame.res_headers?.content_type !== undefined)
          headers.set("content-type", frame.res_headers.content_type);
        t.resolveHead(
          new Response(stream, { status: frame.status ?? 200, headers }),
        );
        return;
      }
      if (bytes.length === 0) return;
      if (t.controller !== null) t.controller.enqueue(bytes);
      else t.early.push(bytes);
      return;
    }
    case "tunnel_end": {
      if (frame.dir !== "res") return;
      const t = pending.get(frame.tunnel_id);
      if (t === undefined) return;
      t.controller?.close();
      t.ended = true;
      return;
    }
    case "tunnel_close": {
      const t = pending.get(frame.tunnel_id);
      if (t === undefined) return;
      finish(
        frame.tunnel_id,
        frame.reason === "done" || t.ended
          ? null
          : new Error(`tunnel closed (${frame.reason ?? "unknown"})`),
      );
      return;
    }
  }
};

/**
 * Tunnel one request to the fleet peer serving `keyId`. Resolves once the
 * response head arrives (body streams thereafter); rejects on any failure
 * (including no registered relay sender — control channel not started).
 */
export const tunnelToPeer = (args: {
  keyId: string;
  surface: TTunnelSurface;
  body: Uint8Array;
  accept: "application/json" | "text/event-stream";
  anthropicVersion?: string | null;
  anthropicBeta?: string | null;
  signal: AbortSignal;
}): Promise<Response> => {
  const sender = relaySender;
  if (sender === null) {
    return Promise.reject(new Error("relay channel not started"));
  }
  const send = sender;
  const tunnelId = crypto.randomUUID();
  logInfo("tunnel-client", "tunneling hop to fleet peer", {
    key: args.keyId,
    surface: args.surface,
  });
  return new Promise<Response>((resolve, reject) => {
    const headTimer = setTimeout(() => {
      pending.delete(tunnelId);
      send({
        type: "tunnel_close",
        tunnel_id: tunnelId,
        reason: "timeout",
      });
      reject(new Error("tunnel open timed out"));
    }, OPEN_TIMEOUT_MS);
    pending.set(tunnelId, {
      resolveHead: resolve,
      rejectHead: reject,
      headTimer,
      headDone: false,
      controller: null,
      early: [],
      ended: false,
    });
    args.signal.addEventListener("abort", () => {
      send({
        type: "tunnel_close",
        tunnel_id: tunnelId,
        reason: "consumer_gone",
      });
      finish(tunnelId, new Error("aborted"));
    });
    send({
      type: "tunnel_open",
      tunnel_id: tunnelId,
      key_id: args.keyId,
      method: "POST",
      surface: args.surface,
      headers: {
        content_type: "application/json",
        accept: args.accept,
        ...(args.anthropicVersion != null
          ? { anthropic_version: args.anthropicVersion.slice(0, 32) }
          : {}),
        ...(args.anthropicBeta != null
          ? { anthropic_beta: args.anthropicBeta.slice(0, 256) }
          : {}),
      },
      consumer: "daemon",
    });
    let seq = 0;
    for (let i = 0; i < args.body.length; i += TUNNEL_CHUNK_MAX) {
      send({
        type: "tunnel_data",
        tunnel_id: tunnelId,
        seq,
        dir: "req",
        data_b64: Buffer.from(
          args.body.subarray(i, i + TUNNEL_CHUNK_MAX),
        ).toString("base64"),
      });
      seq += 1;
    }
    send({ type: "tunnel_end", tunnel_id: tunnelId, dir: "req" });
  });
};
