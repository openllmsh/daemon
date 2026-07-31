/**
 * The SERVING end of the subscription tunnel
 * (`docs/features/sub-tunnel-and-chat-sessions.md` §1). A consumer (a
 * browser tab, or a fleet-peer daemon) opens a `tunnel_*` channel over the
 * relay; this module accepts it, buffers the request bytes, dispatches the
 * request IN-PROCESS against the daemon's own `/v1/*` surface
 * (`handleInference` — same path a loopback client takes, including the
 * daemon-fetched signed plan), and streams the response back as
 * `tunnel_data` frames.
 *
 * Isolation: tunnels run on their own async tasks — they NEVER ride the
 * control channel's `commandTail` FIFO (a streaming response would block
 * every other command). The vendor subscription credential is injected by
 * the walker locally, exactly as for a loopback request; only OpenLLM-wire
 * request/response bytes cross the relay.
 */

import type {
  TRelayFrame,
  TRelayTunnelCloseFrame,
  TRelayTunnelDataFrame,
  TRelayTunnelEndFrame,
  TRelayTunnelOpenFrame,
  TTunnelSurface,
} from "@openllmsh/protocol";
import {
  TUNNEL_CHUNK_MAX,
  TUNNELED_REQUEST_HEADER,
  TUNNELED_REQUEST_VALUE,
} from "@openllmsh/protocol";
import type { TServeTunnel } from "@openllmsh/tunnel/streams";
import { enforceSeedGate } from "./device-access-verify";
import { daemonApiKeyId } from "./env";
import { daemonPublicKey } from "./keypair";
import { handleInference } from "./listener";
import { logInfo, logWarn } from "./logger";
import { beginRequest, endRequest } from "./self-update";

/** Max concurrently-served tunnels — beyond it, opens are nacked
 *  `tunnel_busy`. Concurrent tunnels behave like concurrent loopback
 *  clients (the walker already serves several CLIs at once). */
const MAX_SERVED_TUNNELS = 8;
/** Hard cap on buffered request body before dispatch (JSON inference). */
const MAX_TUNNEL_REQ_BYTES = 8 * 1024 * 1024;

/** The local endpoint each closed-vocabulary surface maps to. No free URL
 *  path ever crosses the relay — the serving daemon owns this mapping. */
const surfacePath = (surface: TTunnelSurface): string => {
  switch (surface) {
    case "chat_completions":
      return "/v1/chat/completions";
    case "messages":
      return "/v1/messages";
    case "responses":
      return "/v1/responses";
    case "responses_compact":
      return "/v1/responses/compact";
  }
};

type TServedTunnel = {
  readonly tunnelId: string;
  readonly open: TRelayTunnelOpenFrame;
  /** Request chunks buffered until `tunnel_end dir:"req"` (request bodies
   *  are small JSON; responses stream). */
  readonly reqChunks: Uint8Array[];
  reqBytes: number;
  readonly abort: AbortController;
  dispatched: boolean;
};

const served = new Map<string, TServedTunnel>();
let muxServedCount = 0;

const forwardedHeaders = (open: {
  readonly headers?: {
    readonly content_type?: "application/json";
    readonly accept?: "application/json" | "text/event-stream";
    readonly anthropic_version?: string;
    readonly anthropic_beta?: string;
  };
}): Headers => {
  const headers = new Headers();
  headers.set("content-type", open.headers?.content_type ?? "application/json");
  if (open.headers?.accept !== undefined)
    headers.set("accept", open.headers.accept);
  if (open.headers?.anthropic_version !== undefined)
    headers.set("anthropic-version", open.headers.anthropic_version);
  if (open.headers?.anthropic_beta !== undefined)
    headers.set("anthropic-beta", open.headers.anthropic_beta);
  headers.set(TUNNELED_REQUEST_HEADER, TUNNELED_REQUEST_VALUE);
  return headers;
};

type TTunneledOpen = {
  readonly surface: TTunnelSurface;
  readonly headers?: {
    readonly content_type?: "application/json";
    readonly accept?: "application/json" | "text/event-stream";
    readonly anthropic_version?: string;
    readonly anthropic_beta?: string;
  };
};

function tunneledRequest(
  open: TTunneledOpen,
  body: Uint8Array,
  signal: AbortSignal,
): Request;
function tunneledRequest(
  open: TTunneledOpen,
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
): Request;
/** Construct the in-process request while preserving Bun's stream duplex requirement. */
function tunneledRequest(
  open: TTunneledOpen,
  body: ReadableStream<Uint8Array> | Uint8Array,
  signal: AbortSignal,
): Request {
  const url = `http://127.0.0.1${surfacePath(open.surface)}`;
  const headers = forwardedHeaders(open);
  if (body instanceof Uint8Array) {
    return new Request(url, {
      method: "POST",
      headers,
      body: body as unknown as BodyInit,
      signal,
    });
  }
  return new Request(url, {
    method: "POST",
    headers,
    body,
    duplex: "half",
    signal,
  } as RequestInit);
}

/** The request dispatcher — `handleInference` in production; injectable so
 *  tests exercise the tunnel state machine without a walker/cloud. */
type TDispatch = (req: Request) => Promise<Response>;
let dispatch: TDispatch = handleInference;
export const setTunnelDispatcher = (fn: TDispatch | null): void => {
  dispatch = fn ?? handleInference;
};

/** Is this frame one the tunnel server owns? (Keeps the control channel's
 *  switch clean.) */
export const isTunnelFrame = (
  frame: TRelayFrame,
): frame is
  | TRelayTunnelOpenFrame
  | TRelayTunnelDataFrame
  | TRelayTunnelEndFrame
  | TRelayTunnelCloseFrame =>
  frame.type === "tunnel_open" ||
  frame.type === "tunnel_data" ||
  frame.type === "tunnel_end" ||
  frame.type === "tunnel_close";

/** Abort every live tunnel — called on control-channel reconnect (the relay
 *  swept the old socket's tunnels; their frames can never route again). */
export const abortAllTunnels = (): void => {
  for (const t of served.values()) t.abort.abort();
  served.clear();
};

const b64encode = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64");

const b64decode = (data: string): Uint8Array =>
  new Uint8Array(Buffer.from(data, "base64"));

/** Handle one inbound tunnel frame from the relay. `send` is the control
 *  channel's frame sender (drops silently when the socket is down — the
 *  relay's death sweep tells the consumer). */
export const handleTunnelFrame = (
  frame:
    | TRelayTunnelOpenFrame
    | TRelayTunnelDataFrame
    | TRelayTunnelEndFrame
    | TRelayTunnelCloseFrame,
  send: (frame: TRelayFrame) => void,
): void => {
  switch (frame.type) {
    case "tunnel_open": {
      if (served.size + muxServedCount >= MAX_SERVED_TUNNELS) {
        send({
          type: "tunnel_open_ack",
          tunnel_id: frame.tunnel_id,
          ok: false,
          error: "tunnel_busy",
        });
        return;
      }
      if (served.has(frame.tunnel_id)) {
        send({
          type: "tunnel_open_ack",
          tunnel_id: frame.tunnel_id,
          ok: false,
          error: "invalid_tunnel",
        });
        return;
      }
      // Seed-gate: browser consumers must present a vault-signed grant when
      // provisioned. Fleet daemon→daemon hops set consumer:"daemon" and have no
      // vault DEK on the consumer side — skip enforcement for those (product
      // rule: seedgate is browser-only until a peer-grant path lands).
      // Trust boundary: the relay stamps `consumer` from the authenticated
      // socket role before forward, so a watcher cannot claim "daemon" to
      // skip the gate. Direct (non-relay) sockets must not self-assert.
      if (frame.consumer !== "daemon") {
        const gate = enforceSeedGate(frame.grant, {
          keyId: daemonApiKeyId(),
          cid: frame.tunnel_id,
          aud: daemonPublicKey(),
        });
        if (gate.mode === "reject") {
          logWarn("tunnel", "tunnel_open rejected: seedgate", {
            id: frame.tunnel_id,
            reason: gate.reason,
          });
          send({
            type: "tunnel_open_ack",
            tunnel_id: frame.tunnel_id,
            ok: false,
            error: "unauthorized",
          });
          return;
        }
      }
      served.set(frame.tunnel_id, {
        tunnelId: frame.tunnel_id,
        open: frame,
        reqChunks: [],
        reqBytes: 0,
        abort: new AbortController(),
        dispatched: false,
      });
      logInfo("tunnel", "tunnel opened", {
        id: frame.tunnel_id,
        surface: frame.surface,
        consumer: frame.consumer ?? "unknown",
      });
      send({ type: "tunnel_open_ack", tunnel_id: frame.tunnel_id, ok: true });
      return;
    }
    case "tunnel_data": {
      const t = served.get(frame.tunnel_id);
      if (t === undefined || frame.dir !== "req" || t.dispatched) return;
      const chunk = b64decode(frame.data_b64);
      const nextBytes = t.reqBytes + chunk.byteLength;
      if (nextBytes > MAX_TUNNEL_REQ_BYTES) {
        served.delete(frame.tunnel_id);
        t.abort.abort();
        send({
          type: "tunnel_close",
          tunnel_id: frame.tunnel_id,
          reason: "protocol_error",
        });
        logWarn(
          "tunnel",
          `tunnel ${frame.tunnel_id} request body exceeds ${MAX_TUNNEL_REQ_BYTES} bytes`,
        );
        return;
      }
      t.reqBytes = nextBytes;
      t.reqChunks.push(chunk);
      return;
    }
    case "tunnel_end": {
      const t = served.get(frame.tunnel_id);
      if (t === undefined || frame.dir !== "req" || t.dispatched) return;
      t.dispatched = true;
      // Own async task — never the commandTail.
      void serveTunnel(t, send).catch((err: unknown) => {
        logWarn(
          "tunnel",
          `tunnel ${t.tunnelId} failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      });
      return;
    }
    case "tunnel_close": {
      const t = served.get(frame.tunnel_id);
      if (t === undefined) return;
      served.delete(frame.tunnel_id);
      t.abort.abort();
      return;
    }
  }
};

/** Dispatch the buffered request and stream the response back. */
const serveTunnel = async (
  t: TServedTunnel,
  send: (frame: TRelayFrame) => void,
): Promise<void> => {
  const body = concatChunks(t.reqChunks);
  t.reqChunks.length = 0;
  const req = tunneledRequest(t.open, body, t.abort.signal);

  // Mirror the listener's in-flight tracking so self-update waits for
  // streaming tunnels exactly as it waits for loopback streams.
  beginRequest();
  let seq = 0;
  try {
    const res = await dispatch(req);
    const contentType = res.headers.get("content-type") ?? "application/json";
    const isSse = contentType.includes("text/event-stream");
    const head = {
      status: res.status,
      res_headers: { content_type: contentType, is_sse: isSse },
    };
    if (res.body === null) {
      send({
        type: "tunnel_data",
        tunnel_id: t.tunnelId,
        seq,
        dir: "res",
        data_b64: "",
        ...head,
      });
    } else {
      const reader = res.body.getReader();
      let sentHead = false;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (t.abort.signal.aborted) {
          await reader.cancel().catch(() => {});
          break;
        }
        // Split at the chunk cap so no frame outgrows the wire bound.
        for (let i = 0; i < value.length; i += TUNNEL_CHUNK_MAX) {
          send({
            type: "tunnel_data",
            tunnel_id: t.tunnelId,
            seq,
            dir: "res",
            data_b64: b64encode(value.subarray(i, i + TUNNEL_CHUNK_MAX)),
            ...(sentHead ? {} : head),
          });
          sentHead = true;
          seq += 1;
        }
      }
      if (!sentHead) {
        // Empty body — the head still has to reach the consumer.
        send({
          type: "tunnel_data",
          tunnel_id: t.tunnelId,
          seq,
          dir: "res",
          data_b64: "",
          ...head,
        });
      }
    }
    if (!t.abort.signal.aborted) {
      send({ type: "tunnel_end", tunnel_id: t.tunnelId, dir: "res" });
      send({ type: "tunnel_close", tunnel_id: t.tunnelId, reason: "done" });
    }
  } catch (err) {
    if (!t.abort.signal.aborted) {
      logWarn(
        "tunnel",
        `dispatch failed for ${t.tunnelId}: ${err instanceof Error ? err.message : String(err)}`,
      );
      send({
        type: "tunnel_close",
        tunnel_id: t.tunnelId,
        reason: "protocol_error",
      });
    }
  } finally {
    endRequest();
    served.delete(t.tunnelId);
  }
};

/** Admission remains daemon-owned so JSON and mux tunnels share one capacity cap. */
export const admitMuxTunnel = (): "tunnel_busy" | null =>
  served.size + muxServedCount >= MAX_SERVED_TUNNELS ? "tunnel_busy" : null;

/** Daemon adapter for the generic mux serving seam. */
export const serveMuxTunnel: TServeTunnel = async (open, body, signal) => {
  muxServedCount += 1;
  beginRequest();
  let completed = false;
  const complete = (): void => {
    if (completed) return;
    completed = true;
    signal.removeEventListener("abort", complete);
    muxServedCount -= 1;
    endRequest();
  };
  // Dispatch can still be awaiting a provider when the relay dies. Release
  // daemon-owned admission and self-update fencing immediately; completion is
  // idempotent if a late response subsequently reaches the generic streamer.
  signal.addEventListener("abort", complete, { once: true });
  try {
    const response = await dispatch(tunneledRequest(open, body, signal));
    const contentType =
      response.headers.get("content-type") ?? "application/json";
    return {
      status: response.status,
      headers: {
        content_type: contentType,
        is_sse: contentType.includes("text/event-stream"),
      },
      body: response.body,
      onComplete: complete,
    };
  } catch (error) {
    complete();
    if (!signal.aborted) {
      logWarn(
        "tunnel",
        `mux dispatch failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    throw error;
  }
};

const concatChunks = (chunks: Uint8Array[]): Uint8Array<ArrayBuffer> => {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
};
