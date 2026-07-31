import type { TRelayFrame } from "@openllmsh/protocol";
import type { TDuplex, TMuxChannel } from "@openllmsh/tunnel/mux";
import { createChannel } from "@openllmsh/tunnel/mux";
import { serveStream } from "@openllmsh/tunnel/streams";
import {
  checkDeviceGrant,
  getDeviceAccessPubkey,
} from "./device-access-verify";
import { daemonApiKeyId } from "./env";
import { daemonPublicKey } from "./keypair";
import { logWarn } from "./logger";
import { admitMuxTunnel, serveMuxTunnel } from "./tunnel-server";

/**
 * Base capabilities advertised on hello/status.
 * `mux1` = binary mux over the relay WS; `rtc1` = WebRTC data-channel mux host.
 * `seedgate1` is layered on when a device-access pubkey is pinned — see
 * {@link currentDaemonCaps}.
 */
export const DAEMON_MUX_CAPS = ["mux1", "rtc1"] as const;

/** Live capability list — includes `seedgate1` when device access is provisioned. */
export const currentDaemonCaps = (): string[] => {
  const caps: string[] = [...DAEMON_MUX_CAPS];
  if (getDeviceAccessPubkey() !== null) caps.push("seedgate1");
  return caps;
};

let active: TMuxChannel | null = null;
let sink: ((bytes: Uint8Array | null) => void) | null = null;
let sendFrame: ((frame: TRelayFrame) => void) | null = null;
let sendBinary: ((bytes: Uint8Array) => void) | null = null;
const peerCaps = new Map<string, ReadonlySet<string>>();
const opening = new Map<
  string,
  {
    resolve: (channel: TMuxChannel | null) => void;
    readonly timer: ReturnType<typeof setTimeout>;
    readonly channelId: string;
  }
>();
const failedUntil = new Map<string, number>();
let activeKeyId: string | null = null;
const MUX_ACK_TIMEOUT_MS = 5_000;
const MUX_FAILURE_CACHE_MS = 60_000;
let muxAckTimeoutMs = MUX_ACK_TIMEOUT_MS;

/** Test-only timeout override for deterministic channel-negotiation coverage. */
export const setMuxAckTimeoutForTest = (timeoutMs: number | null): void => {
  muxAckTimeoutMs = timeoutMs ?? MUX_ACK_TIMEOUT_MS;
};

/** Test-only cache reset; production invalidation follows presence replacement. */
export const resetMuxFailureCacheForTest = (): void => {
  failedUntil.clear();
};

export const updateMuxPeerCaps = (
  keyId: string,
  caps: readonly string[] | undefined,
): void => {
  if (caps === undefined) peerCaps.delete(keyId);
  else peerCaps.set(keyId, new Set(caps));
  failedUntil.delete(keyId);
};

export const replaceMuxPeerCaps = (
  caps: Readonly<Record<string, readonly string[]>> | undefined,
): void => {
  peerCaps.clear();
  if (caps === undefined) return;
  for (const [keyId, values] of Object.entries(caps))
    updateMuxPeerCaps(keyId, values);
};

const failOpen = (keyId: string): void => {
  const pending = opening.get(keyId);
  if (pending === undefined) return;
  opening.delete(keyId);
  clearTimeout(pending.timer);
  failedUntil.set(keyId, Date.now() + MUX_FAILURE_CACHE_MS);
  pending.resolve(null);
};

/** Consumer-side negotiation. One mux channel may exist on this relay socket. */
export const muxChannelTo = async (
  keyId: string,
): Promise<TMuxChannel | null> => {
  if (process.env.OPENLLM_MUX_DISABLE === "1") return null;
  if (!peerCaps.get(keyId)?.has("mux1")) return null;
  if (
    failedUntil.get(keyId) !== undefined &&
    (failedUntil.get(keyId) ?? 0) > Date.now()
  )
    return null;
  if (active !== null) return activeKeyId === keyId ? active : null;
  const pending = opening.get(keyId);
  if (pending !== undefined)
    return new Promise((resolve) => {
      const previousResolve = pending.resolve;
      pending.resolve = (channel) => {
        previousResolve(channel);
        resolve(channel);
      };
    });
  const send = sendFrame;
  const binary = sendBinary;
  if (send === null || binary === null) return null;
  const channelId = crypto.randomUUID();
  return new Promise<TMuxChannel | null>((resolve) => {
    const timer = setTimeout(() => failOpen(keyId), muxAckTimeoutMs);
    opening.set(keyId, { resolve, timer, channelId });
    send({ type: "channel_open", channel_id: channelId, key_id: keyId });
  });
};

export const handleChannelOpenAck = (frame: {
  readonly channel_id: string;
  readonly ok: boolean;
}): void => {
  const entry = [...opening.entries()].find(
    ([, pending]) => pending.channelId === frame.channel_id,
  );
  if (entry === undefined) return;
  const [keyId] = entry;
  if (!frame.ok) {
    failOpen(keyId);
    return;
  }
  const pending = opening.get(keyId);
  if (pending === undefined || sendBinary === null) return;
  opening.delete(keyId);
  clearTimeout(pending.timer);
  const duplex = relayDuplex(sendBinary, (callback) => {
    sink = callback;
  });
  active = createChannel({
    duplex,
    side: "consumer",
    onClose: () => {
      active = null;
      activeKeyId = null;
      sink = null;
    },
  });
  activeKeyId = keyId;
  pending.resolve(active);
};

/** Host transport seam: control-channel owns the WebSocket, this module owns mux state. */
export const relayDuplex = (
  sendBytes: (bytes: Uint8Array) => void,
  registerOnBytes: (callback: (bytes: Uint8Array | null) => void) => void,
): TDuplex => ({
  send: sendBytes,
  onBytes: registerOnBytes,
  close: () => registerOnBytes(() => {}),
});

export const configureMuxHost = (options: {
  readonly send: (frame: TRelayFrame) => void;
  readonly sendBytes: (bytes: Uint8Array) => void;
}): void => {
  sendFrame = options.send;
  sendBinary = options.sendBytes;
};

/**
 * Shared OPEN dispatcher for every daemon-side mux channel (relay WS + RTC).
 * Keep tunnel-server reachable through this single closure so rtc-host does
 * not re-implement admit/serve.
 */
export const serveMuxOnStream = serveStream({
  // Keep the tunnel-server import lazy: its production dispatcher reaches the
  // control channel, which imports this host during daemon initialization.
  tunnel: (open, body, signal) => serveMuxTunnel(open, body, signal),
  admitTunnel: () => admitMuxTunnel(),
  invalidOpenCode: "invalid_tunnel",
});

/** Accept the relay-authorized channel. D2 allows only one active channel/socket. */
export const acceptChannel = (frame: {
  readonly channel_id: string;
  readonly grant?: string;
}): void => {
  const send = sendFrame;
  const binary = sendBinary;
  if (send === null || binary === null) return;
  if (process.env.OPENLLM_MUX_DISABLE === "1") {
    send({
      type: "channel_open_ack",
      channel_id: frame.channel_id,
      ok: false,
      error: "not_capable",
    });
    return;
  }
  // Seed-gate: when provisioned, every channel_open must carry a valid grant.
  // Gates ALL mux streams (including sessions) that ride this channel.
  if (getDeviceAccessPubkey() !== null) {
    const keyId = daemonApiKeyId();
    const grant = frame.grant;
    if (keyId === null) {
      // Match handleRtcOffer: cause-specific log so ops can tell a missing
      // OPENLLM_API_KEY from a client that simply omitted the grant.
      logWarn("mux-host", "channel_open rejected: no api key id", {
        channelId: frame.channel_id,
      });
      send({
        type: "channel_open_ack",
        channel_id: frame.channel_id,
        ok: false,
        error: "unauthorized",
      });
      return;
    }
    if (grant === undefined || grant.length === 0) {
      logWarn("mux-host", "channel_open rejected: missing grant", {
        channelId: frame.channel_id,
      });
      send({
        type: "channel_open_ack",
        channel_id: frame.channel_id,
        ok: false,
        error: "unauthorized",
      });
      return;
    }
    const checked = checkDeviceGrant(grant, {
      keyId,
      cid: frame.channel_id,
      aud: daemonPublicKey(),
    });
    if (!checked.ok) {
      logWarn("mux-host", "channel_open rejected: grant failed", {
        channelId: frame.channel_id,
        reason: checked.reason,
      });
      send({
        type: "channel_open_ack",
        channel_id: frame.channel_id,
        ok: false,
        error: "unauthorized",
      });
      return;
    }
  }
  if (active !== null) {
    send({
      type: "channel_open_ack",
      channel_id: frame.channel_id,
      ok: false,
      error: "channel_exists",
    });
    return;
  }
  const duplex = relayDuplex(binary, (callback) => {
    sink = callback;
  });
  active = createChannel({
    duplex,
    side: "daemon",
    onStream: serveMuxOnStream,
    onClose: () => {
      active = null;
      sink = null;
    },
  });
  send({ type: "channel_open_ack", channel_id: frame.channel_id, ok: true });
};

/** Feed a complete binary websocket message to the active mux channel. */
export const muxHostOnBytes = (bytes: Uint8Array): void => {
  sink?.(bytes);
};

/** A dead relay socket tears down all stream state. */
export const resetAllChannels = (): void => {
  for (const keyId of [...opening.keys()]) failOpen(keyId);
  const channel = active;
  active = null;
  activeKeyId = null;
  sink = null;
  channel?.close("relay_restart");
};
