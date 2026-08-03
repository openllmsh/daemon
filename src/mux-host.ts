import type { TChannelCloseReason, TRelayFrame } from "@openllmsh/protocol";
import { MUX_CAP, RTC_CAP, SEEDGATE_CAP } from "@openllmsh/protocol";
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
 * `mux1` = binary mux over the relay WS; `rtc1` = WebRTC data-channel mux host
 * and fleet consumer offerer (RTC → relay mux → JSON splice).
 * `seedgate1` is layered on when a device-access pubkey is pinned — see
 * {@link currentDaemonCaps}.
 */
export const DAEMON_MUX_CAPS = [MUX_CAP, RTC_CAP] as const;

/** Live capability list — includes `seedgate1` when device access is provisioned. */
export const currentDaemonCaps = (): string[] => {
  const caps: string[] = [...DAEMON_MUX_CAPS];
  if (getDeviceAccessPubkey() !== null) caps.push(SEEDGATE_CAP);
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
/** Relay-assigned id of {@link active}, so an inbound `channel_close` can be
 *  matched to the channel it refers to. */
let activeChannelId: string | null = null;
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

/** Consumer-side negotiation. One mux channel may exist on this relay socket. */
export const muxChannelTo = async (
  keyId: string,
): Promise<TMuxChannel | null> => {
  if (process.env.OPENLLM_MUX_DISABLE === "1") return null;
  const caps = peerCaps.get(keyId);
  if (caps === undefined || !caps.has(MUX_CAP)) return null;
  const failedAt = failedUntil.get(keyId);
  if (failedAt !== undefined && failedAt > Date.now()) return null;
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
  if (sendBinary === null || active !== null) {
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
  const duplex = relayDuplex(sendBinary, (callback) => {
    sink = callback;
  });
  active = createChannel({
    duplex,
    side: "consumer",
    onClose: () => {
      active = null;
      activeKeyId = null;
      activeChannelId = null;
      sink = null;
    },
  });
  activeKeyId = keyId;
  activeChannelId = pending.channelId;
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

/** Accept the relay-authorized channel. D2 allows only one active channel/socket. */
export const acceptChannel = (frame: {
  readonly channel_id: string;
  readonly grant?: string;
  readonly consumer?: "browser" | "daemon";
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
  if (active !== null || opening.size > 0) {
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
      activeChannelId = null;
      sink = null;
    },
  });
  activeChannelId = frame.channel_id;
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
  if (activeChannelId !== frame.channel_id) return;
  const channel = active;
  active = null;
  activeKeyId = null;
  activeChannelId = null;
  sink = null;
  channel?.close(frame.reason ?? "peer_gone");
};

/** Feed a complete binary websocket message to the active mux channel. */
export const muxHostOnBytes = (bytes: Uint8Array): void => {
  sink?.(bytes);
};

/** A dead relay socket tears down all stream state without killing PTYs. */
export const resetAllChannels = (): void => {
  for (const keyId of [...opening.keys()]) failOpen(keyId);
  const channel = active;
  active = null;
  activeKeyId = null;
  activeChannelId = null;
  sink = null;
  channel?.close("relay_restart");
};
