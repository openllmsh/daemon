/**
 * Daemon-side WebRTC data-channel host (werift responder).
 *
 * The client creates the offer + data channel; this module answers, seals a
 * DTLS-fingerprint proof under the daemon's long-lived X25519 key, trickles
 * ICE, and once the data channel opens mounts the same mux OPEN dispatcher
 * that the relay-WS path uses ({@link serveMuxOnStream}).
 *
 * Signaling frames (`rtc_offer` / `rtc_answer` / `rtc_ice`) ride the control
 * channel through the relay; payload bytes never touch the relay after the
 * data channel is up.
 */
import type {
  TIceServer,
  TRelayFrame,
  TRtcNackReason,
} from "@openllmsh/protocol";
import { MAX_PAYLOAD_BYTES } from "@openllmsh/tunnel/codec";
import type { TMuxChannel } from "@openllmsh/tunnel/mux";
import { createChannel } from "@openllmsh/tunnel/mux";
import {
  decodeOfferInner,
  encodeAnswerInner,
  fingerprintFromSdp,
  maxMessageSizeFromSdp,
  negotiateRtcPayloadCap,
  resolveIceServers,
  sdpFingerprintsMatch,
  weriftIceServers,
} from "@openllmsh/tunnel/rtc-auth";
import { rtcDuplex } from "@openllmsh/tunnel/rtc-duplex";
import { preflightIceCandidate } from "@openllmsh/tunnel/rtc-ice";
import type { RTCDataChannel, RTCIceCandidate } from "werift";
import { RTCPeerConnection } from "werift";
import {
  enforceRtcSeedGate,
  onDeviceAccessAuthorityChange,
} from "./device-access-verify";
import { daemonApiKeyId } from "./env";
import { daemonPublicKey, openSealed, sealTo } from "./keypair";
import { logDebug, logWarn, safeDiagnosticMessage } from "./logger";
import { serveMuxOnStream } from "./mux-host";
import { maxConcurrentRtc } from "./rtc-cap";
import { closeRtcPeer } from "./rtc-close";
import { asRtcDataChannelLike } from "./rtc-data-channel";
import { rtcCandidateErrors } from "./rtc-udp";

/**
 * Max wait from session insert until the mux mounts on the data channel.
 * Covers a stalled DTLS/ICE handshake after the answer is sent so a half-open
 * session cannot pin an RTC slot forever.
 *
 * Deliberately SHORTER than the offering client's own establishment deadline
 * (30 s in the off-host harness). While both sat at 30 s, the daemon's
 * definitive `handshake_failed` nack landed at or after the client had already
 * given up, so the client reported an opaque timeout and the daemon's own
 * diagnosis never reached anyone. The margin below is what makes the nack
 * useful: the client learns the real reason and can retry instead of waiting
 * out a blank deadline.
 */
const RTC_HANDSHAKE_DEFAULT_TIMEOUT_MS = 20_000;
const RTC_HANDSHAKE_MAX_TIMEOUT_MS = 120_000;

const rtcHandshakeTimeoutMs = (): number => {
  const raw = process.env.OPENLLM_RTC_HANDSHAKE_TIMEOUT_MS?.trim();
  if (raw === undefined || raw === "") return RTC_HANDSHAKE_DEFAULT_TIMEOUT_MS;
  const parsed = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(parsed) || parsed < 1_000) {
    logWarn(
      "rtc-host",
      "invalid OPENLLM_RTC_HANDSHAKE_TIMEOUT_MS; using default",
      {
        timeoutMs: RTC_HANDSHAKE_DEFAULT_TIMEOUT_MS,
      },
    );
    return RTC_HANDSHAKE_DEFAULT_TIMEOUT_MS;
  }
  return Math.min(parsed, RTC_HANDSHAKE_MAX_TIMEOUT_MS);
};

type TRtcSession = {
  readonly channelId: string;
  readonly pc: RTCPeerConnection;
  dc: RTCDataChannel | null;
  mux: TMuxChannel | null;
  closed: boolean;
  nacked: boolean;
  /** Insert time; reported as elapsedMs when a handshake fails. */
  readonly startedAtMs: number;
  handshakeTimer: ReturnType<typeof setTimeout> | null;
};

let sendFrame: ((frame: TRelayFrame) => void) | null = null;
/** Cloud-served ICE servers from the daemon's own channel handshake, if any. */
let handshakeIceServers: ReadonlyArray<TIceServer> | null = null;
const sessions = new Map<string, TRtcSession>();

/** Wire the control-channel sender (idempotent; re-called on reconnect).
 *  `iceServers` carries the cloud handshake config when present. */
export const configureRtcHost = (options: {
  readonly send: (frame: TRelayFrame) => void;
  readonly iceServers?: ReadonlyArray<TIceServer> | null;
}): void => {
  sendFrame = options.send;
  if (options.iceServers !== undefined) {
    handshakeIceServers = options.iceServers;
  }
};

/** ICE-server precedence: local env (`OPENLLM_RTC_ICE_SERVERS`, or the
 *  deprecated `OPENLLM_RTC_STUN` legacy alias) → cloud handshake → default.
 *  Mapped into werift's mutable `RTCIceServer` shape. */
const iceServers = (): Array<{
  urls: string | string[];
  username?: string;
  credential?: string;
}> =>
  weriftIceServers(
    resolveIceServers(
      process.env.OPENLLM_RTC_ICE_SERVERS ?? process.env.OPENLLM_RTC_STUN,
      handshakeIceServers,
    ),
  );

/** Send a non-silent RTC reject to the offerer so it fails fast instead of
 *  waiting out the signaling/ICE timeout. Best-effort — a racing socket close
 *  just drops it. */
const sendNack = (
  channelId: string,
  reason: TRtcNackReason,
  cap?: number,
): void => {
  const send = sendFrame;
  if (send === null) return;
  try {
    send({
      type: "rtc_nack",
      channel_id: channelId,
      reason,
      ...(cap !== undefined ? { cap } : {}),
    });
  } catch {
    // control socket racing a close
  }
};

/** One handshake_failed nack then close, for any pre-mux failure path. */
const failUnmountedHandshake = (
  session: TRtcSession,
  closeReason: string,
): void => {
  if (session.closed || session.mux !== null) return;
  if (!session.nacked) {
    session.nacked = true;
    sendNack(session.channelId, "handshake_failed");
  }
  // closeSession() records the reason only at debug level, so at the default
  // `info` level a pre-mux handshake failure used to leave NO log record at
  // all — an intermittent establishment failure was indistinguishable from
  // silence. Warn here with the reason and elapsed time instead.
  logWarn("rtc-host", "rtc handshake failed before mount", {
    channelId: session.channelId,
    reason: closeReason,
    elapsedMs: Date.now() - session.startedAtMs,
  });
  closeSession(session.channelId, closeReason);
};

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

const clearHandshakeTimer = (session: TRtcSession): void => {
  if (session.handshakeTimer === null) return;
  clearTimeout(session.handshakeTimer);
  session.handshakeTimer = null;
};

const closeSession = (channelId: string, reason: string): void => {
  const session = sessions.get(channelId);
  if (session === undefined || session.closed) return;
  session.closed = true;
  clearHandshakeTimer(session);
  sessions.delete(channelId);
  try {
    session.mux?.close(reason);
  } catch {
    // mux already closed
  }
  session.mux = null;
  void closeRtcPeer(session.pc, session.dc);
  logDebug("rtc-host", "session closed", { channelId, reason });
};

/**
 * Tear down RTC sessions that have not yet mounted a mux. Mounted sessions
 * (live data channel) survive a control-channel reconnect — their peer
 * connection does not ride the relay socket.
 */
export const resetUnmountedRtcSessions = (): void => {
  for (const [channelId, session] of [...sessions.entries()]) {
    if (session.mux !== null) continue;
    closeSession(channelId, "relay_restart");
  }
};

/** Tear down every RTC session — full process reset / test cleanup. */
export const resetAllRtcSessions = (): void => {
  for (const channelId of [...sessions.keys()]) {
    closeSession(channelId, "relay_restart");
  }
};

onDeviceAccessAuthorityChange(() => {
  for (const channelId of [...sessions.keys()]) {
    closeSession(channelId, "device_access_changed");
  }
});

const attachDataChannel = (
  session: TRtcSession,
  dc: RTCDataChannel,
  maxPayloadBytes: number,
): void => {
  session.dc = dc;
  const mount = (): void => {
    if (session.closed || session.mux !== null) return;
    clearHandshakeTimer(session);
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
 * Handle an inbound `rtc_offer`. Bad inner shapes / fingerprint bindings and
 * duplicate channel IDs stay silent; admission refusals send an explicit nack.
 */
export const handleRtcOffer = async (frame: {
  readonly channel_id: string;
  readonly key_id: string;
  readonly sdp: string;
  readonly fingerprint_proof: string;
  /**
   * Who offered. The relay stamps this from the authenticated socket role
   * (`daemon` vs `browser`); a self-asserted value is not a trust signal.
   * Every RTC consumer must supply a v2 device grant, regardless of this role
   * or the offer-inner client label.
   */
  readonly consumer?: "browser" | "daemon";
}): Promise<void> => {
  const send = sendFrame;
  if (send === null) return;
  if (sessions.has(frame.channel_id)) {
    // A retransmit of an in-flight offer, not a reject — stay silent (a nack
    // would tear the caller's healthy pending attempt).
    logWarn("rtc-host", safeDiagnosticMessage`duplicate rtc_offer`, {
      channelId: frame.channel_id,
    });
    return;
  }

  const opened = openSealed(frame.fingerprint_proof);
  if (opened === null) {
    logWarn(
      "rtc-host",
      safeDiagnosticMessage`bad fingerprint_proof (open failed)`,
      {
        channelId: frame.channel_id,
      },
    );
    // The sealed proof cannot reveal which key was used. Its failure does tell
    // the offerer to refresh a possibly stale cloud identity pin, so fail fast.
    sendNack(frame.channel_id, "proof_open_failed");
    return;
  }
  const inner = decodeOfferInner(opened);
  if (inner === null) {
    logWarn("rtc-host", safeDiagnosticMessage`bad fingerprint_proof (shape)`, {
      channelId: frame.channel_id,
    });
    return;
  }

  // Bind the sealed client fingerprint to EVERY effective offer SDP
  // fingerprint. Reject an absent or conflicting set before setting it remote.
  if (!sdpFingerprintsMatch(frame.sdp, inner.fb)) {
    logWarn("rtc-host", safeDiagnosticMessage`offer fingerprint mismatch`, {
      channelId: frame.channel_id,
    });
    return;
  }
  // `rtc1` withdrawn (see `mux-host.ts`): an authenticated stale offer gets a
  // nack so its peer caches the durable posture without exposing it to probes.
  if (process.env.OPENLLM_RTC_DISABLE === "1") {
    logWarn(
      "rtc-host",
      safeDiagnosticMessage`rtc_offer refused: rtc disabled`,
      {
        channelId: frame.channel_id,
      },
    );
    sendNack(frame.channel_id, "disabled");
    return;
  }
  const cap = maxConcurrentRtc();
  if (sessions.size >= cap) {
    logWarn("rtc-host", "rtc session cap reached", {
      channelId: frame.channel_id,
      cap,
    });
    sendNack(frame.channel_id, "overloaded", cap);
    return;
  }

  // The v2 grant authenticates every client. Neither transport role nor the
  // optional client label can bypass the pin, replay or audience checks.
  const gate = enforceRtcSeedGate("grant" in inner ? inner.grant : undefined, {
    keyId: daemonApiKeyId(),
    cid: frame.channel_id,
    aud: daemonPublicKey(),
    offerVersion: inner.v,
  });
  if (gate.mode === "reject") {
    logWarn("rtc-host", "seedgate rejected", {
      channelId: frame.channel_id,
      reason: gate.reason,
    });
    // Sealed proof and fingerprint binding alone do not authenticate a client.
    // Nack so it can obtain a valid vault grant instead of timing out.
    sendNack(frame.channel_id, "seedgate");
    return;
  }

  const offerSdpMax = maxMessageSizeFromSdp(frame.sdp);
  const maxPayloadBytes = negotiateRtcPayloadCap(
    offerSdpMax,
    MAX_PAYLOAD_BYTES,
  );
  if (maxPayloadBytes === null) {
    logWarn("rtc-host", safeDiagnosticMessage`sctp max-message-size unusable`, {
      channelId: frame.channel_id,
      sdpMax: offerSdpMax,
    });
    // Offer authenticated but its SCTP limit can't carry a mux frame — a
    // capability mismatch, not a transient. Nack so the offerer stops probing.
    sendNack(frame.channel_id, "not_capable");
    return;
  }

  let pc: RTCPeerConnection;
  try {
    pc = new RTCPeerConnection({
      iceServers: [...iceServers()],
      iceFilterCandidatePair: rtcCandidateErrors(() => {
        const session = sessions.get(frame.channel_id);
        if (session === undefined || session.pc !== pc) return;
        if (session.mux === null) failUnmountedHandshake(session, "udp_failed");
        else closeSession(frame.channel_id, "udp_failed");
      }),
    });
  } catch (err) {
    logWarn(
      "rtc-host",
      safeDiagnosticMessage`RTCPeerConnection construct failed`,
      {
        err: err instanceof Error ? err.message : String(err),
      },
    );
    sendNack(frame.channel_id, "not_capable");
    return;
  }

  const session: TRtcSession = {
    channelId: frame.channel_id,
    pc,
    dc: null,
    mux: null,
    closed: false,
    nacked: false,
    startedAtMs: Date.now(),
    handshakeTimer: null,
  };
  sessions.set(frame.channel_id, session);
  session.handshakeTimer = setTimeout(() => {
    failUnmountedHandshake(session, "handshake_timeout");
  }, rtcHandshakeTimeoutMs());

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
    if (session.closed || sessions.get(session.channelId) !== session) return;
    const state = pc.connectionState;
    if (state === "failed" && session.mux === null) {
      failUnmountedHandshake(session, "pc_failed");
      return;
    }
    if (state === "failed" || state === "closed" || state === "disconnected") {
      closeSession(frame.channel_id, `pc_${state}`);
    }
  };

  try {
    await pc.setRemoteDescription({ type: "offer", sdp: frame.sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    if (session.closed) return;

    const fd = localFingerprint(pc);
    if (fd === null) {
      failUnmountedHandshake(session, "no_local_fingerprint");
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
      logWarn("rtc-host", safeDiagnosticMessage`seal answer failed`, {
        err: err instanceof Error ? err.message : String(err),
      });
      failUnmountedHandshake(session, "seal_failed");
      return;
    }

    if (session.closed) return;

    const answerSdp = pc.localDescription?.sdp ?? answer.sdp;
    send({
      type: "rtc_answer",
      channel_id: frame.channel_id,
      sdp: answerSdp,
      fingerprint_proof: fingerprintProof,
    });
  } catch (err) {
    logWarn("rtc-host", safeDiagnosticMessage`offer handling failed`, {
      channelId: frame.channel_id,
      err: err instanceof Error ? err.message : String(err),
    });
    failUnmountedHandshake(session, "offer_failed");
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
  // Off-LAN, an mDNS `.local` candidate makes werift issue a 10s multicast-DNS
  // query that never resolves, stalling ICE. Preflight it: skip fast when the
  // name doesn't resolve quickly, keep it on a LAN where it does.
  if (!(await preflightIceCandidate(init))) {
    logDebug("rtc-host", "skipping unresolvable mDNS candidate", {
      channelId: frame.channel_id,
    });
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
 * Returns `null` when the SDP's SCTP limit cannot fit a mux DATA frame.
 */
export const negotiateRtcPayloadCapForTest = (sdp: string): number | null =>
  negotiateRtcPayloadCap(maxMessageSizeFromSdp(sdp), MAX_PAYLOAD_BYTES);
