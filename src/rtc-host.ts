/**
 * Daemon-side WebRTC data-channel host (werift responder).
 *
 * Browser creates the offer + data channel; this module answers, seals a
 * DTLS-fingerprint proof under the daemon's long-lived X25519 key, trickles
 * ICE, and once the data channel opens mounts the same mux OPEN dispatcher
 * that the relay-WS path uses ({@link serveMuxOnStream}).
 *
 * Signaling frames (`rtc_offer` / `rtc_answer` / `rtc_ice`) ride the control
 * channel through the relay; payload bytes never touch the relay after the
 * data channel is up.
 */
import type { TRelayFrame } from "@openllmsh/protocol";
import { MAX_PAYLOAD_BYTES } from "@openllmsh/tunnel/codec";
import type { TMuxChannel } from "@openllmsh/tunnel/mux";
import { createChannel } from "@openllmsh/tunnel/mux";
import {
  decodeOfferInner,
  encodeAnswerInner,
  fingerprintFromSdp,
  maxMessageSizeFromSdp,
  negotiateRtcPayloadCap,
} from "@openllmsh/tunnel/rtc-auth";
import type { TRtcDataChannelLike } from "@openllmsh/tunnel/rtc-duplex";
import { rtcDuplex } from "@openllmsh/tunnel/rtc-duplex";
import type { RTCDataChannel, RTCIceCandidate } from "werift";
import { RTCPeerConnection } from "werift";
import { openSealed, sealTo } from "./keypair";
import { logDebug, logWarn } from "./logger";
import { serveMuxOnStream } from "./mux-host";

/** Bound concurrent RTC sessions per daemon process. */
const MAX_CONCURRENT_RTC = 8;

/** Default STUN; override with comma-separated `OPENLLM_RTC_STUN`. */
const DEFAULT_STUN = "stun:stun.l.google.com:19302";

type TRtcSession = {
  readonly channelId: string;
  readonly pc: RTCPeerConnection;
  mux: TMuxChannel | null;
  closed: boolean;
};

let sendFrame: ((frame: TRelayFrame) => void) | null = null;
const sessions = new Map<string, TRtcSession>();

/** Wire the control-channel sender (idempotent; re-called on reconnect). */
export const configureRtcHost = (options: {
  readonly send: (frame: TRelayFrame) => void;
}): void => {
  sendFrame = options.send;
};

const iceServers = (): ReadonlyArray<{ urls: string }> => {
  const raw = process.env.OPENLLM_RTC_STUN?.trim();
  if (raw === undefined || raw.length === 0) return [{ urls: DEFAULT_STUN }];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((urls) => ({ urls }));
};

/**
 * Adapt werift's channel to the thin {@link TRtcDataChannelLike} surface.
 * werift's `send` only accepts `Buffer | string` (not `ArrayBuffer`); the mux
 * always hands a `Uint8Array`, which is a Buffer-view under Bun/Node.
 */
const asRtcDataChannelLike = (dc: RTCDataChannel): TRtcDataChannelLike => ({
  get readyState() {
    return dc.readyState;
  },
  get bufferedAmount() {
    return dc.bufferedAmount;
  },
  send: (data) => {
    if (typeof data === "string") {
      dc.send(data);
      return;
    }
    if (Buffer.isBuffer(data)) {
      dc.send(data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      dc.send(Buffer.from(data));
      return;
    }
    // ArrayBufferView (Uint8Array, …) — copy into a Buffer for werift.
    dc.send(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
  },
  close: () => dc.close(),
  get onmessage() {
    return dc.onmessage as TRtcDataChannelLike["onmessage"];
  },
  set onmessage(value) {
    dc.onmessage = value as RTCDataChannel["onmessage"];
  },
  get onclose() {
    return dc.onclose as TRtcDataChannelLike["onclose"];
  },
  set onclose(value) {
    dc.onclose = value as RTCDataChannel["onclose"];
  },
  get onerror() {
    return dc.onerror as TRtcDataChannelLike["onerror"];
  },
  set onerror(value) {
    dc.onerror = value as RTCDataChannel["onerror"];
  },
});

const localFingerprint = (pc: RTCPeerConnection): string | null => {
  const sdp = pc.localDescription?.sdp;
  if (typeof sdp === "string" && sdp.length > 0) {
    const fromSdp = fingerprintFromSdp(sdp);
    if (fromSdp !== null) return fromSdp;
  }
  // Fallback: werift transport API (same value, different shape).
  const fps = pc.dtlsTransports[0]?.localParameters.fingerprints;
  if (fps !== undefined && fps.length > 0) {
    const first = fps[0];
    return `${first.algorithm} ${first.value}`;
  }
  return null;
};

const closeSession = (channelId: string, reason: string): void => {
  const session = sessions.get(channelId);
  if (session === undefined || session.closed) return;
  session.closed = true;
  sessions.delete(channelId);
  try {
    session.mux?.close(reason);
  } catch {
    // mux already closed
  }
  session.mux = null;
  void session.pc.close().catch(() => {});
  logDebug("rtc-host", "session closed", { channelId, reason });
};

/** Tear down every RTC session — called on control-channel reconnect. */
export const resetAllRtcSessions = (): void => {
  for (const channelId of [...sessions.keys()]) {
    closeSession(channelId, "relay_restart");
  }
};

const attachDataChannel = (
  session: TRtcSession,
  dc: RTCDataChannel,
  maxPayloadBytes: number,
): void => {
  const mount = (): void => {
    if (session.closed || session.mux !== null) return;
    const duplex = rtcDuplex(asRtcDataChannelLike(dc));
    session.mux = createChannel({
      duplex,
      side: "daemon",
      maxPayloadBytes,
      onStream: serveMuxOnStream,
      onClose: () => {
        session.mux = null;
        closeSession(session.channelId, "mux_closed");
      },
    });
    logDebug("rtc-host", "mux mounted on data channel", {
      channelId: session.channelId,
      maxPayloadBytes,
    });
  };

  if (dc.readyState === "open") {
    mount();
    return;
  }
  const previous = dc.onopen;
  dc.onopen = () => {
    previous?.();
    mount();
  };
};

/**
 * Handle an inbound `rtc_offer`. Rejects silently (no answer) on bad proof /
 * at-cap / duplicate channel_id so a MITM cannot probe.
 */
export const handleRtcOffer = async (frame: {
  readonly channel_id: string;
  readonly key_id: string;
  readonly sdp: string;
  readonly fingerprint_proof: string;
}): Promise<void> => {
  const send = sendFrame;
  if (send === null) return;
  if (sessions.has(frame.channel_id)) {
    logWarn("rtc-host", "duplicate rtc_offer", {
      channelId: frame.channel_id,
    });
    return;
  }
  if (sessions.size >= MAX_CONCURRENT_RTC) {
    logWarn("rtc-host", "rtc session cap reached", {
      channelId: frame.channel_id,
      cap: MAX_CONCURRENT_RTC,
    });
    return;
  }

  const opened = openSealed(frame.fingerprint_proof);
  if (opened === null) {
    logWarn("rtc-host", "bad fingerprint_proof (open failed)", {
      channelId: frame.channel_id,
    });
    return;
  }
  const inner = decodeOfferInner(opened);
  if (inner === null) {
    logWarn("rtc-host", "bad fingerprint_proof (shape)", {
      channelId: frame.channel_id,
    });
    return;
  }

  const offerSdpMax = maxMessageSizeFromSdp(frame.sdp);
  const maxPayloadBytes = negotiateRtcPayloadCap(
    offerSdpMax,
    MAX_PAYLOAD_BYTES,
  );

  let pc: RTCPeerConnection;
  try {
    pc = new RTCPeerConnection({ iceServers: [...iceServers()] });
  } catch (err) {
    logWarn("rtc-host", "RTCPeerConnection construct failed", {
      err: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  const session: TRtcSession = {
    channelId: frame.channel_id,
    pc,
    mux: null,
    closed: false,
  };
  sessions.set(frame.channel_id, session);

  pc.ondatachannel = (ev) => {
    if (session.closed) return;
    attachDataChannel(session, ev.channel, maxPayloadBytes);
  };

  pc.onicecandidate = (ev) => {
    if (session.closed || sendFrame === null) return;
    const candidate = ev.candidate;
    if (candidate === undefined || candidate === null) return;
    // Serialize as RTCIceCandidateInit JSON (protocol contract).
    const init =
      typeof (candidate as RTCIceCandidate).toJSON === "function"
        ? (candidate as RTCIceCandidate).toJSON()
        : candidate;
    try {
      sendFrame({
        type: "rtc_ice",
        channel_id: frame.channel_id,
        candidate: JSON.stringify(init),
      });
    } catch {
      // socket racing a close
    }
  };

  pc.onconnectionstatechange = () => {
    const state = pc.connectionState;
    if (state === "failed" || state === "closed" || state === "disconnected") {
      closeSession(frame.channel_id, `pc_${state}`);
    }
  };

  try {
    await pc.setRemoteDescription({ type: "offer", sdp: frame.sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    const fd = localFingerprint(pc);
    if (fd === null) {
      closeSession(frame.channel_id, "no_local_fingerprint");
      return;
    }

    let fingerprintProof: string;
    try {
      fingerprintProof = sealTo(
        inner.epk,
        encodeAnswerInner({
          v: 1,
          n: inner.n,
          fb: inner.fb,
          fd,
        }),
      );
    } catch (err) {
      logWarn("rtc-host", "seal answer failed", {
        err: err instanceof Error ? err.message : String(err),
      });
      closeSession(frame.channel_id, "seal_failed");
      return;
    }

    const answerSdp = pc.localDescription?.sdp ?? answer.sdp;
    send({
      type: "rtc_answer",
      channel_id: frame.channel_id,
      sdp: answerSdp,
      fingerprint_proof: fingerprintProof,
    });
  } catch (err) {
    logWarn("rtc-host", "offer handling failed", {
      channelId: frame.channel_id,
      err: err instanceof Error ? err.message : String(err),
    });
    closeSession(frame.channel_id, "offer_failed");
  }
};

/** Handle an inbound trickle ICE candidate for an established session. */
export const handleRtcIce = async (frame: {
  readonly channel_id: string;
  readonly candidate: string;
}): Promise<void> => {
  const session = sessions.get(frame.channel_id);
  if (session === undefined || session.closed) return;
  let init: {
    candidate?: string;
    sdpMid?: string | null;
    sdpMLineIndex?: number | null;
    usernameFragment?: string | null;
  };
  try {
    const parsed: unknown = JSON.parse(frame.candidate);
    if (parsed === null || typeof parsed !== "object") return;
    init = parsed as typeof init;
  } catch {
    return;
  }
  try {
    await session.pc.addIceCandidate(init);
  } catch (err) {
    logDebug("rtc-host", "addIceCandidate failed", {
      channelId: frame.channel_id,
      err: err instanceof Error ? err.message : String(err),
    });
  }
};

/** Test/observability: number of live RTC sessions. */
export const rtcSessionCount = (): number => sessions.size;

/**
 * Test-only: negotiated maxPayloadBytes that would be applied for an SDP.
 * Mirrors the offer path so unit tests can assert the cap without ICE.
 */
export const negotiateRtcPayloadCapForTest = (sdp: string): number =>
  negotiateRtcPayloadCap(maxMessageSizeFromSdp(sdp), MAX_PAYLOAD_BYTES);
