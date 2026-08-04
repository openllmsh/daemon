import type { TChannelCloseReason, TRelayFrame } from "@openllmsh/protocol";
import { MUX_CAP, MUX2_CAP, RTC_CAP, SEEDGATE_CAP } from "@openllmsh/protocol";
import {
  decodeChannelEnvelope,
  encodeChannelEnvelope,
} from "@openllmsh/tunnel/channel-envelope";
import { encodeJsonPayload } from "@openllmsh/tunnel/codec";
import type { TDuplex, TMuxChannel } from "@openllmsh/tunnel/mux";
import { createChannel } from "@openllmsh/tunnel/mux";
import { serveStream } from "@openllmsh/tunnel/streams";
import { enforceSeedGate, getDeviceAccessPubkey } from "./device-access-verify";
import { daemonApiKeyId } from "./env";
import { daemonPublicKey } from "./keypair";
import { logInfo, logWarn } from "./logger";
import { ptySessionsEnabled } from "./pty-sessions-pref";
import type { TSessionStream } from "./session-core";
import {
  attachSessionHostViaCli,
  discoverSessionHosts,
  spawnSessionHostProc,
} from "./session-host-proc";
import { admitMuxTunnel, serveMuxTunnel } from "./tunnel-server";

/**
 * Base capabilities advertised on hello/status.
 * `mux1` = binary mux over the relay WS; `mux2` = the channel-id envelope on
 * each relay-WS binary message, which lets ONE relay socket carry several
 * concurrent channels (the daemon always envelopes its relay-WS channels — the
 * relay bridges to a legacy `mux1`-only peer, so no peer-cap knowledge is
 * needed); `rtc1` = WebRTC data-channel mux host and fleet consumer offerer
 * (RTC → relay mux → JSON splice). RTC data channels are NEVER enveloped —
 * they carry a single mux directly, with no relay hop. `seedgate1` is layered
 * on when a device-access pubkey is pinned — see {@link currentDaemonCaps}.
 */
export const DAEMON_MUX_CAPS = [MUX_CAP, MUX2_CAP, RTC_CAP] as const;

/**
 * `OPENLLM_RTC_DISABLE=1` withdraws `rtc1` only.
 *
 * The escape hatch for a host where the peer-to-peer path is a liability: on a
 * network that answers unreachable ICE candidates with ICMP, WebRTC produced a
 * stream of socket errors with nothing to show for it. Withdrawing the
 * capability means the browser never offers, so no ICE agent is built and no
 * UDP is sent — and everything still works over relay mux, one hop slower.
 *
 * Deliberately separate from `OPENLLM_MUX_DISABLE`, which withdraws the mux
 * transport wholesale and takes terminal sessions down with it. That was the
 * only lever available the first time this was needed, and it was too blunt.
 */
const rtcDisabled = (): boolean => process.env.OPENLLM_RTC_DISABLE === "1";

/** Live capability list — includes `seedgate1` when device access is provisioned. */
export const currentDaemonCaps = (): string[] => {
  const caps: string[] = DAEMON_MUX_CAPS.filter(
    (cap) => cap !== RTC_CAP || !rtcDisabled(),
  );
  if (getDeviceAccessPubkey() !== null) caps.push(SEEDGATE_CAP);
  return caps;
};

/**
 * One live relay-WS mux channel. Several may coexist (`mux2`): a serving
 * channel the daemon accepted (`side: "daemon"`), or a consumer channel it
 * opened to a fleet peer (`side: "consumer"`, keyed by that peer's `keyId`).
 */
type TRelayChannel = {
  readonly channelId: string;
  readonly keyId: string | null;
  readonly channel: TMuxChannel;
  sink: ((bytes: Uint8Array | null) => void) | null;
};

let sendFrame: ((frame: TRelayFrame) => void) | null = null;
let sendBinary: ((bytes: Uint8Array) => void) | null = null;
/** Live channels by relay-assigned channel id. */
const channels = new Map<string, TRelayChannel>();
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

/** Latest relay-advertised peer caps, used by the fleet RTC path. */
export const getMuxPeerCaps = (
  keyId: string,
): ReadonlySet<string> | undefined => peerCaps.get(keyId);

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

/** The consumer channel already open to `keyId`, if any. */
const consumerChannelFor = (keyId: string): TRelayChannel | undefined => {
  for (const channel of channels.values())
    if (channel.keyId === keyId) return channel;
  return undefined;
};

const failOpen = (keyId: string, reason?: TChannelCloseReason): void => {
  const pending = opening.get(keyId);
  if (pending === undefined) return;
  opening.delete(keyId);
  clearTimeout(pending.timer);
  failedUntil.set(keyId, Date.now() + MUX_FAILURE_CACHE_MS);
  sendFrame?.({
    type: "channel_close",
    channel_id: pending.channelId,
    ...(reason === undefined ? {} : { reason }),
  });
  pending.resolve(null);
};

/** Consumer-side negotiation. `mux2` permits one channel per fleet peer. */
export const muxChannelTo = async (
  keyId: string,
): Promise<TMuxChannel | null> => {
  if (process.env.OPENLLM_MUX_DISABLE === "1") return null;
  const caps = peerCaps.get(keyId);
  if (caps === undefined || !caps.has(MUX_CAP)) return null;
  const failedAt = failedUntil.get(keyId);
  if (failedAt !== undefined && failedAt > Date.now()) return null;
  const existing = consumerChannelFor(keyId);
  if (existing !== undefined) return existing.channel;
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
    const timer = setTimeout(
      () => failOpen(keyId, "consumer_gone"),
      muxAckTimeoutMs,
    );
    opening.set(keyId, { resolve, timer, channelId });
    // Fleet peer hop: mark consumer so the serving daemon can skip browser-only
    // seedgate (this process has no vault DEK to mint a grant).
    send({
      type: "channel_open",
      channel_id: channelId,
      key_id: keyId,
      consumer: "daemon",
    });
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
  if (pending === undefined) return;
  const binary = sendBinary;
  if (binary === null) {
    opening.delete(keyId);
    clearTimeout(pending.timer);
    failedUntil.set(keyId, Date.now() + MUX_FAILURE_CACHE_MS);
    sendFrame?.({
      type: "channel_close",
      channel_id: pending.channelId,
      reason: "channel_exists",
    });
    pending.resolve(null);
    return;
  }
  opening.delete(keyId);
  clearTimeout(pending.timer);
  const record = registerChannel(pending.channelId, keyId, "consumer");
  pending.resolve(record.channel);
};

/**
 * Register a relay-WS channel (both consumer + serving sides). The duplex
 * envelopes every outbound message with the channel id and reads its inbound
 * bytes from the shared {@link muxHostOnBytes} demux — so several channels can
 * share the one relay socket.
 */
const registerChannel = (
  channelId: string,
  keyId: string | null,
  side: "consumer" | "daemon",
): TRelayChannel => {
  const record: TRelayChannel = {
    channelId,
    keyId,
    channel: null as unknown as TMuxChannel,
    sink: null,
  };
  const duplex = relayDuplex(
    (bytes) => sendBinary?.(encodeChannelEnvelope(channelId, bytes)),
    (callback) => {
      record.sink = callback;
    },
  );
  (record as { channel: TMuxChannel }).channel = createChannel({
    duplex,
    side,
    ...(side === "daemon" ? { onStream: serveMuxOnStream } : {}),
    onClose: () => {
      if (channels.get(channelId) === record) channels.delete(channelId);
      record.sink = null;
    },
  });
  channels.set(channelId, record);
  return record;
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
 * not re-implement admit/serve. Session OPEN binds a PTY via session-host.
 */
const pipeSessionStreams = (
  relay: TSessionStream,
  host: TSessionStream,
): void => {
  let closed = false;
  const closeHost = (): void => {
    if (closed) return;
    closed = true;
    host.end();
  };
  relay.onData((bytes) => {
    void host.write(bytes).catch(() => {
      closed = true;
      host.reset();
      relay.reset();
    });
  });
  relay.onCtrl((payload) => host.sendCtrl(payload));
  relay.onReset((payload) => {
    host.reset(payload);
    closed = true;
  });
  relay.onEnd(closeHost);
  host.onData((bytes) => {
    void relay.write(bytes).catch(closeHost);
  });
  host.onCtrl((payload) => relay.sendCtrl(payload));
  host.onReset((payload) => {
    closed = true;
    relay.reset(payload);
  });
  host.onEnd(() => {
    if (closed) return;
    closed = true;
    relay.end();
  });
};

/** Browser mux streams are attach clients; durable hosts own every PTY. */
export const serveMuxOnStream = serveStream({
  // Keep the tunnel-server import lazy: its production dispatcher reaches the
  // control channel, which imports this host during daemon initialization.
  tunnel: (open, body, signal) => serveMuxTunnel(open, body, signal),
  session: async (stream, open) => {
    if (!ptySessionsEnabled()) {
      logInfo("session", "remote session open refused: sessions disabled", {
        id: open.session_id,
      });
      stream.reset(
        encodeJsonPayload({
          code: "sessions_disabled",
          message:
            "remote terminal sessions are disabled on this device — run: openllmd sessions on",
        }),
      );
      return;
    }
    // Spawn (if needed) then attach via a CLI pipe child. The CLI owns the
    // unix-socket dial; the daemon never opens a session socket itself.
    if (open.mode !== "attach") {
      const socketPath = await spawnSessionHostProc({
        id: open.session_id,
        cli: open.cli,
        cols: open.cols,
        rows: open.rows,
        ...(open.cwd === undefined ? {} : { cwd: open.cwd }),
        ...(open.title === undefined ? {} : { title: open.title }),
        ...(open.dangerous === undefined ? {} : { dangerous: open.dangerous }),
        ...(open.resume_session_id === undefined
          ? {}
          : { resume: open.resume_session_id }),
      });
      if (socketPath === null) {
        stream.reset(encodeJsonPayload({ code: "spawn_failed" }));
        return;
      }
    } else if (
      discoverSessionHosts().every((host) => host.id !== open.session_id)
    ) {
      stream.reset(encodeJsonPayload({ code: "session_not_found" }));
      return;
    }
    const host = attachSessionHostViaCli({ ...open, mode: "attach" });
    if (host === null) {
      stream.reset(
        encodeJsonPayload({
          code: open.mode === "attach" ? "session_not_found" : "spawn_failed",
        }),
      );
      return;
    }
    pipeSessionStreams(stream, host);
  },
  admitTunnel: () => admitMuxTunnel(),
  invalidOpenCode: "invalid_tunnel",
});

/** Accept the relay-authorized channel. `mux2` allows several concurrent. */
export const acceptChannel = (frame: {
  readonly channel_id: string;
  readonly grant?: string;
  readonly consumer?: "browser" | "daemon";
}): void => {
  const send = sendFrame;
  const binary = sendBinary;
  if (send === null || binary === null) return;
  if (process.env.OPENLLM_MUX_DISABLE === "1") {
    // Every reject is logged. A silently-refused channel_open is invisible on
    // the daemon and indistinguishable, from the browser, from a device that
    // never answered — which is exactly the shape of the hardest transport
    // bugs to diagnose.
    logWarn("mux-host", "channel_open rejected: mux disabled", {
      channelId: frame.channel_id,
    });
    send({
      type: "channel_open_ack",
      channel_id: frame.channel_id,
      ok: false,
      error: "not_capable",
    });
    return;
  }
  if (channels.has(frame.channel_id)) {
    logWarn("mux-host", "channel_open rejected: duplicate id", {
      channelId: frame.channel_id,
    });
    send({
      type: "channel_open_ack",
      channel_id: frame.channel_id,
      ok: false,
      error: "channel_exists",
    });
    return;
  }
  // Seed-gate: browser consumers must present a vault-signed grant when
  // provisioned. Fleet daemon→daemon hops set consumer:"daemon" and have no
  // vault DEK — skip enforcement for those (parity with tunnel-server).
  // Trust boundary: the relay stamps `consumer` from the authenticated
  // socket role before forward, so a watcher cannot claim "daemon" to
  // skip the gate. Direct (non-relay) sockets must not self-assert.
  if (frame.consumer !== "daemon") {
    const gate = enforceSeedGate(frame.grant, {
      keyId: daemonApiKeyId(),
      cid: frame.channel_id,
      aud: daemonPublicKey(),
    });
    if (gate.mode === "reject") {
      logWarn("mux-host", "channel_open rejected: seedgate", {
        channelId: frame.channel_id,
        reason: gate.reason,
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
  registerChannel(frame.channel_id, null, "daemon");
  logInfo("mux-host", "channel_open accepted", {
    channelId: frame.channel_id,
    consumer: frame.consumer ?? "browser",
  });
  send({ type: "channel_open_ack", channel_id: frame.channel_id, ok: true });
};

/**
 * The relay says this channel's peer is gone (`consumer_gone` when a browser
 * socket dies, `daemon_gone` for a serving peer). Tear the local half down so
 * its streams RESET — which detaches any device PTY bound to them — and so the
 * next `channel_open` is not refused `channel_exists` by a channel whose other
 * end no longer exists. Previously this frame had no handler at all: the stale
 * channel survived until the daemon's OWN relay socket cycled, stranding every
 * session on it in the meantime.
 */
export const closeChannelFromRelay = (frame: {
  readonly channel_id: string;
  readonly reason?: TChannelCloseReason;
}): void => {
  // A close for a channel still being negotiated settles that open instead.
  for (const [keyId, pending] of [...opening.entries()]) {
    if (pending.channelId === frame.channel_id) failOpen(keyId, frame.reason);
  }
  const record = channels.get(frame.channel_id);
  if (record === undefined) return;
  channels.delete(frame.channel_id);
  record.sink = null;
  record.channel.close(frame.reason ?? "peer_gone");
};

/** Feed a complete binary websocket message to the channel its envelope tags. */
export const muxHostOnBytes = (bytes: Uint8Array | null): void => {
  if (bytes === null) {
    // Transport died — fan the null through every channel so each resets.
    for (const record of [...channels.values()]) record.sink?.(null);
    return;
  }
  const envelope = decodeChannelEnvelope(bytes);
  if (!envelope.ok) return;
  channels.get(envelope.channelId)?.sink?.(envelope.payload);
};

/** A dead relay socket tears down all stream state without killing PTYs. */
export const resetAllChannels = (): void => {
  for (const keyId of [...opening.keys()]) failOpen(keyId);
  for (const record of [...channels.values()]) {
    channels.delete(record.channelId);
    record.sink = null;
    record.channel.close("relay_restart");
  }
};
