/**
 * The CONSUMING end of the subscription tunnel, daemon side
 * (`docs/features/sub-tunnel-and-chat-sessions.md` §1). When the walker
 * hits a subscription hop this box has no credential for, and the
 * bootstrap's `fleet_subscriptions` names an online peer serving that
 * provider, the request tunnels to the peer. Fleet hops prefer an
 * already-open direct RTC mux, then relay binary mux. There is no JSON
 * `tunnel_*` splice — if neither RTC nor mux is available the hop fails and
 * the walker continues.
 *
 * Mirrors the browser's `tunnelFetch` (lib/stores/daemon-store.ts).
 * Any failure rejects — the walker treats it as a failed hop and continues
 * the walk (degradation preserved).
 */

import type { TTunnelSurface } from "@openllmsh/protocol";
import { RTC_CAP, SEEDGATE_CAP } from "@openllmsh/protocol";
import { tunnelStream } from "@openllmsh/tunnel/streams";
import { fleetSubscriptionPubkeyFor } from "./config";
import { logInfo } from "./logger";
import { getMuxPeerCaps, muxChannelTo } from "./mux-host";
import { ensureRtcTo, getRtcMuxChannel, markRtcFailure } from "./rtc-client";

/**
 * Local mux errors that fire before FRAME_TYPE.open leaves the consumer —
 * the only safe window to re-dispatch the same request over relay mux.
 * Parity with browser `isPreDispatchTunnelError` in daemon-store.
 */
const isPreDispatchTunnelError = (error: unknown): boolean => {
  if (!(error instanceof Error)) return false;
  return (
    error.message === "channel is closed" ||
    error.message === "stream ids exhausted"
  );
};

/**
 * Tunnel one request to the fleet peer serving `keyId`. Resolves once the
 * response head arrives (body streams thereafter); rejects when neither RTC
 * nor mux is available, or when the stream fails.
 */
export const tunnelToPeer = async (args: {
  keyId: string;
  surface: TTunnelSurface;
  body: Uint8Array;
  accept: "application/json" | "text/event-stream";
  anthropicVersion?: string | null;
  anthropicBeta?: string | null;
  signal: AbortSignal;
}): Promise<Response> => {
  const headers = {
    content_type: "application/json" as const,
    accept: args.accept,
    ...(args.anthropicVersion != null
      ? { anthropic_version: args.anthropicVersion.slice(0, 32) }
      : {}),
    ...(args.anthropicBeta != null
      ? { anthropic_beta: args.anthropicBeta.slice(0, 256) }
      : {}),
  };

  const peerCaps = getMuxPeerCaps(args.keyId);
  const peerPubkey = fleetSubscriptionPubkeyFor(args.keyId);
  logInfo("tunnel-client", "resolving fleet hop transport", {
    key: args.keyId,
    surface: args.surface,
    hasRtc1: peerCaps?.has(RTC_CAP) ?? false,
    hasSeedgate1: peerCaps?.has(SEEDGATE_CAP) ?? false,
  });
  // Eager RTC: best-effort, never blocks the hop. If the channel is already
  // open we use it; otherwise ensureRtcTo races setup while we try mux.
  ensureRtcTo(args.keyId, {
    pubkey: peerPubkey ?? "",
    hasRtc1: peerCaps?.has(RTC_CAP) ?? false,
    // Fleet daemons cannot mint a browser vault grant; a seed-gated peer must
    // use relay mux (whose authenticated `consumer:"daemon"` is admitted).
    hasSeedgate1: peerCaps?.has(SEEDGATE_CAP) ?? false,
  });

  const rtc = getRtcMuxChannel(args.keyId);
  if (rtc !== null) {
    try {
      const result = await tunnelStream(rtc, {
        surface: args.surface,
        headers,
        body: args.body,
        signal: args.signal,
      });
      return new Response(result.body, {
        status: result.status,
        headers: result.headers,
      });
    } catch (error: unknown) {
      // Caller abort is not an RTC path failure — do not cache or fall through.
      if (args.signal.aborted) {
        throw error instanceof Error
          ? error
          : new DOMException("Aborted", "AbortError");
      }
      // openStream sends FRAME_TYPE.open synchronously — once that returns the
      // peer may already be dispatching. Only re-dispatch on known pre-dispatch
      // local failures (parity with browser tunnelFetch).
      markRtcFailure(args.keyId);
      if (!isPreDispatchTunnelError(error)) throw error;
      // Pre-dispatch RTC failure falls through to relay mux on this request.
    }
  }

  const mux = await muxChannelTo(args.keyId);
  if (mux === null) {
    throw new Error(
      "Device transport unavailable. Peer has neither RTC nor mux — update OpenLLM on the peer.",
    );
  }
  logInfo("tunnel-client", "tunneling hop to fleet peer", {
    key: args.keyId,
    surface: args.surface,
    path: "mux",
  });
  try {
    const result = await tunnelStream(mux, {
      surface: args.surface,
      headers,
      body: args.body,
      signal: args.signal,
    });
    return new Response(result.body, {
      status: result.status,
      headers: result.headers,
    });
  } catch (error: unknown) {
    if (args.signal.aborted) {
      throw error instanceof Error
        ? error
        : new DOMException("Aborted", "AbortError");
    }
    throw error instanceof Error ? error : new Error(String(error));
  }
};
