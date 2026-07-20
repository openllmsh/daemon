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
  TStreamResetCode,
  TTunnelSurface,
} from "@openllmsh/protocol";
import { parseStreamOpenPayload, TUNNEL_CHUNK_MAX } from "@openllmsh/protocol";
import {
  decodeJsonPayload,
  encodeJsonPayload,
  MAX_PAYLOAD_BYTES,
} from "@openllmsh/tunnel/codec";
import type { TMuxStream } from "@openllmsh/tunnel/mux";
import { handleInference } from "./listener";
import { logInfo, logWarn } from "./logger";
import { beginRequest, endRequest } from "./self-update";

/** Max concurrently-served tunnels — beyond it, opens are nacked
 *  `tunnel_busy`. Concurrent tunnels behave like concurrent loopback
 *  clients (the walker already serves several CLIs at once). */
const MAX_SERVED_TUNNELS = 8;

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
  headers.set("x-openllm-tunneled", "1");
  return headers;
};

const muxReset = (stream: TMuxStream, code: TStreamResetCode): void => {
  stream.reset(encodeJsonPayload({ code }));
};

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
      served.set(frame.tunnel_id, {
        tunnelId: frame.tunnel_id,
        open: frame,
        reqChunks: [],
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
      t.reqChunks.push(b64decode(frame.data_b64));
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
  const headers = forwardedHeaders(t.open);
  const req = new Request(`http://127.0.0.1${surfacePath(t.open.surface)}`, {
    method: "POST",
    headers,
    body,
    signal: t.abort.signal,
  });

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

/**
 * Serve a binary mux tunnel. Unlike the legacy splice, dispatch begins at OPEN
 * and the in-process handler consumes request bytes as DATA arrives.
 */
export const serveMuxTunnelStream = (
  stream: TMuxStream,
  openPayload: Uint8Array,
): void => {
  const open = parseStreamOpenPayload(decodeJsonPayload(openPayload));
  if (open === null || open.kind !== "tunnel") {
    muxReset(stream, "invalid_tunnel");
    return;
  }
  if (served.size + muxServedCount >= MAX_SERVED_TUNNELS) {
    muxReset(stream, "tunnel_busy");
    return;
  }
  muxServedCount += 1;
  const abort = new AbortController();
  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  const body = new ReadableStream<Uint8Array>({
    start(nextController) {
      controller = nextController;
    },
    cancel() {
      abort.abort();
    },
  });
  const offData = stream.onData((bytes) => controller?.enqueue(bytes));
  const offEnd = stream.onEnd(() => controller?.close());
  const offReset = stream.onReset(() => {
    abort.abort();
    try {
      controller?.error(new Error("consumer reset"));
    } catch {
      // The request body may already have reached its terminal state.
    }
    void reader?.cancel().catch(() => {});
  });
  const run = async (): Promise<void> => {
    beginRequest();
    try {
      const req = new Request(`http://127.0.0.1${surfacePath(open.surface)}`, {
        method: "POST",
        headers: forwardedHeaders(open),
        body,
        duplex: "half",
        signal: abort.signal,
      } as RequestInit);
      const res = await dispatch(req);
      const contentType = res.headers.get("content-type") ?? "application/json";
      stream.sendCtrl(
        encodeJsonPayload({
          t: "res_head",
          status: res.status,
          res_headers: {
            content_type: contentType,
            is_sse: contentType.includes("text/event-stream"),
          },
        }),
      );
      if (res.body !== null) {
        reader = res.body.getReader();
        for (;;) {
          const result = await reader.read();
          if (result.done || abort.signal.aborted) break;
          for (
            let offset = 0;
            offset < result.value.byteLength;
            offset += MAX_PAYLOAD_BYTES
          ) {
            await stream.write(
              result.value.subarray(offset, offset + MAX_PAYLOAD_BYTES),
            );
          }
        }
      }
      if (!abort.signal.aborted) stream.end();
    } catch (error) {
      if (!abort.signal.aborted) {
        logWarn(
          "tunnel",
          `mux dispatch failed: ${error instanceof Error ? error.message : String(error)}`,
        );
        muxReset(stream, "dispatch_failed");
      }
    } finally {
      offData();
      offEnd();
      offReset();
      muxServedCount -= 1;
      endRequest();
    }
  };
  void run();
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
