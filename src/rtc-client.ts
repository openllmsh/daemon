/**
 * Daemon-side WebRTC data-channel consumer for fleet subscription hops.
 *
 * A fleet daemon offers directly to a peer daemon when that peer advertises
 * `rtc1` and has published its X25519 pubkey. Signaling still rides the relay;
 * once open, mux traffic is direct. The resolver never waits for cold setup:
 * RTC → relay mux → JSON splice, while this module warms RTC for later hops.
 */
import { randomBytes } from "node:crypto";
import type { TRelayFrame } from "@openllmsh/protocol";
import { MAX_PAYLOAD_BYTES } from "@openllmsh/tunnel/codec";
import type { TMuxChannel } from "@openllmsh/tunnel/mux";
import { createChannel } from "@openllmsh/tunnel/mux";
import {
  decodeAnswerInner,
  encodeOfferInner,
  fingerprintFromSdp,
  maxMessageSizeFromSdp,
  negotiateRtcPayloadCap,
  RTC_AUTH_NONCE_BYTES,
  RTC_DEFAULT_STUN,
  sdpFingerprintsMatch,
  verifyAnswerInner,
} from "@openllmsh/tunnel/rtc-auth";
import type { TRtcDataChannelLike } from "@openllmsh/tunnel/rtc-duplex";
import { rtcDuplex } from "@openllmsh/tunnel/rtc-duplex";
import type { RTCDataChannel, RTCIceCandidate } from "werift";
import { RTCPeerConnection } from "werift";
import type { TEphKeypair } from "./keypair";
import { generateEphKeypair, openSealedWith, sealTo } from "./keypair";
import { logDebug, logWarn } from "./logger";

const RTC_SIGNALING_TIMEOUT_MS = 10_000;
const RTC_ICE_TIMEOUT_MS = 20_000;
export const RTC_FAILURE_CACHE_MS = 60_000;

type TRtcClientSession = {
  readonly keyId: string;
  readonly channelId: string;
  readonly pc: RTCPeerConnection;
  readonly dc: RTCDataChannel;
  readonly eph: TEphKeypair;
  readonly nonce: string;
  /** Local ICE candidates held until `rtc_offer` is on the wire — the answerer
   *  drops ICE for unknown channel ids. */
  readonly pendingIce: string[];
  /** True once `rtc_offer` has been sent (or abandoned). */
  offerSent: boolean;
  /** True once the first valid `rtc_answer` is accepted — duplicates no-op. */
  answered: boolean;
  fingerprint: string;
  mux: TMuxChannel | null;
  closed: boolean;
  signalingTimer: ReturnType<typeof setTimeout> | null;
  iceTimer: ReturnType<typeof setTimeout> | null;
};

let sendFrame: ((frame: TRelayFrame) => void) | null = null;
const sessionsByKey = new Map<string, TRtcClientSession>();
const sessionsByChannel = new Map<string, TRtcClientSession>();
const failedUntil = new Map<string, number>();

/** Wire the control-channel sender (idempotent; re-called on reconnect). */
export const configureRtcClient = (options: {
  readonly send: (frame: TRelayFrame) => void;
}): void => {
  sendFrame = options.send;
};

const iceServers = (): ReadonlyArray<{ urls: string }> => {
  const raw = process.env.OPENLLM_RTC_STUN?.trim();
  if (raw === undefined || raw.length === 0)
    return [{ urls: RTC_DEFAULT_STUN }];
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map((urls) => ({ urls }));
};

const asRtcDataChannelLike = (dc: RTCDataChannel): TRtcDataChannelLike => ({
  get readyState() {
    return dc.readyState;
  },
  get bufferedAmount() {
    return dc.bufferedAmount;
  },
  send: (data) => {
    if (typeof data === "string" || Buffer.isBuffer(data)) {
      dc.send(data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      dc.send(Buffer.from(data));
      return;
    }
    dc.send(
      Buffer.from(
        new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
      ),
    );
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

const clearTimers = (session: TRtcClientSession): void => {
  if (session.signalingTimer !== null) {
    clearTimeout(session.signalingTimer);
    session.signalingTimer = null;
  }
  if (session.iceTimer !== null) {
    clearTimeout(session.iceTimer);
    session.iceTimer = null;
  }
};

const closeSession = (session: TRtcClientSession, reason: string): void => {
  if (session.closed) return;
  session.closed = true;
  clearTimers(session);
  sessionsByKey.delete(session.keyId);
  sessionsByChannel.delete(session.channelId);
  try {
    session.mux?.close(reason);
  } catch {
    // mux already closed
  }
  session.mux = null;
  void session.pc.close().catch(() => {});
  logDebug("rtc-client", "session closed", { keyId: session.keyId, reason });
};

const cacheFailure = (keyId: string): void => {
  failedUntil.set(keyId, Date.now() + RTC_FAILURE_CACHE_MS);
};

/** Mark a failed live RTC path and prevent immediate re-offers for one minute. */
export const markRtcFailure = (keyId: string): void => {
  cacheFailure(keyId);
  const session = sessionsByKey.get(keyId);
  if (session !== undefined) closeSession(session, "rtc_failure");
};

const failureCached = (keyId: string): boolean => {
  const until = failedUntil.get(keyId);
  if (until === undefined) return false;
  if (until > Date.now()) return true;
  failedUntil.delete(keyId);
  return false;
};

const mountMux = (session: TRtcClientSession, answerSdp: string): void => {
  if (
    session.closed ||
    session.mux !== null ||
    session.dc.readyState !== "open"
  )
    return;
  const maxPayloadBytes = negotiateRtcPayloadCap(
    maxMessageSizeFromSdp(answerSdp),
    MAX_PAYLOAD_BYTES,
  );
  if (maxPayloadBytes === null) {
    markRtcFailure(session.keyId);
    return;
  }
  session.mux = createChannel({
    duplex: rtcDuplex(asRtcDataChannelLike(session.dc)),
    side: "consumer",
    maxPayloadBytes,
    onClose: () => {
      if (!session.closed) markRtcFailure(session.keyId);
    },
  });
  clearTimers(session);
  failedUntil.delete(session.keyId);
  logDebug("rtc-client", "mux mounted on data channel", {
    keyId: session.keyId,
    channelId: session.channelId,
    maxPayloadBytes,
  });
};

/** Start a best-effort fleet RTC offer. Cold setup never blocks a request. */
export const ensureRtcTo = (
  keyId: string,
  options: {
    readonly pubkey: string;
    readonly hasRtc1: boolean;
    readonly hasSeedgate1: boolean;
  },
): void => {
  if (
    options.pubkey.length === 0 ||
    !options.hasRtc1 ||
    options.hasSeedgate1 ||
    failureCached(keyId) ||
    sessionsByKey.has(keyId) ||
    sendFrame === null
  ) {
    return;
  }
  void beginConnect(keyId, options.pubkey).catch((error: unknown) => {
    logWarn("rtc-client", "beginConnect rejected", {
      keyId,
      err: error instanceof Error ? error.message : String(error),
    });
    cacheFailure(keyId);
  });
};

const sendIceCandidate = (
  session: TRtcClientSession,
  candidateJson: string,
): void => {
  if (session.closed || sendFrame === null) return;
  try {
    sendFrame({
      type: "rtc_ice",
      channel_id: session.channelId,
      candidate: candidateJson,
    });
  } catch {
    // control socket racing a close
  }
};

const flushPendingIce = (session: TRtcClientSession): void => {
  if (session.closed || !session.offerSent) return;
  const pending = session.pendingIce.splice(0, session.pendingIce.length);
  for (const candidate of pending) sendIceCandidate(session, candidate);
};

const beginConnect = async (keyId: string, pubkey: string): Promise<void> => {
  if (sessionsByKey.has(keyId) || failureCached(keyId) || sendFrame === null)
    return;
  let pc: RTCPeerConnection | null = null;
  let session: TRtcClientSession | null = null;
  try {
    pc = new RTCPeerConnection({ iceServers: [...iceServers()] });
    const dc = pc.createDataChannel("mux", { ordered: true });
    const eph = generateEphKeypair();
    const channelId = crypto.randomUUID();
    session = {
      keyId,
      channelId,
      pc,
      dc,
      eph,
      nonce: Buffer.from(randomBytes(RTC_AUTH_NONCE_BYTES)).toString("base64"),
      pendingIce: [],
      offerSent: false,
      answered: false,
      fingerprint: "",
      mux: null,
      closed: false,
      signalingTimer: null,
      iceTimer: null,
    };
    sessionsByKey.set(keyId, session);
    sessionsByChannel.set(channelId, session);
    session.signalingTimer = setTimeout(() => {
      if (session !== null && !session.closed && session.mux === null)
        markRtcFailure(keyId);
    }, RTC_SIGNALING_TIMEOUT_MS);
    dc.onopen = () => {
      if (session === null) return;
      // Payload-cap negotiation needs the answer SDP max-message-size. Falling
      // back to the local offer would under/over-size the consumer mux.
      const remoteSdp = session.pc.remoteDescription?.sdp;
      if (remoteSdp === undefined || remoteSdp.length === 0) {
        markRtcFailure(session.keyId);
        return;
      }
      mountMux(session, remoteSdp);
    };
    pc.onicecandidate = (event) => {
      if (session === null || session.closed || event.candidate == null) return;
      const candidate = event.candidate;
      const init =
        typeof (candidate as RTCIceCandidate).toJSON === "function"
          ? (candidate as RTCIceCandidate).toJSON()
          : candidate;
      const candidateJson = JSON.stringify(init);
      // Buffer until rtc_offer is sent — answerer drops ICE for unknown ids.
      if (!session.offerSent) {
        session.pendingIce.push(candidateJson);
        return;
      }
      sendIceCandidate(session, candidateJson);
    };
    pc.onconnectionstatechange = () => {
      if (session === null || session.closed) return;
      if (
        ["failed", "closed", "disconnected"].includes(
          session.pc.connectionState,
        )
      )
        markRtcFailure(keyId);
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    if (session.closed) return;
    const sdp = pc.localDescription?.sdp ?? offer.sdp;
    const fingerprint = fingerprintFromSdp(sdp);
    if (fingerprint === null) {
      markRtcFailure(keyId);
      return;
    }
    session.fingerprint = fingerprint;
    const proof = sealTo(
      pubkey,
      encodeOfferInner({
        v: 1,
        n: session.nonce,
        fb: fingerprint,
        epk: eph.publicKeyB64,
      }),
    );
    sendFrame?.({
      type: "rtc_offer",
      channel_id: channelId,
      key_id: keyId,
      sdp,
      fingerprint_proof: proof,
    });
    session.offerSent = true;
    flushPendingIce(session);
  } catch (error) {
    logWarn("rtc-client", "offer setup failed", {
      keyId,
      err: error instanceof Error ? error.message : String(error),
    });
    if (session !== null) {
      markRtcFailure(keyId);
      return;
    }
    cacheFailure(keyId);
    if (pc !== null) {
      void pc.close().catch(() => {});
    }
  }
};

/** Verify and apply the peer's sealed RTC answer. Unknown channel ids no-op. */
export const handleRtcAnswer = async (frame: {
  readonly channel_id: string;
  readonly sdp: string;
  readonly fingerprint_proof: string;
}): Promise<void> => {
  const session = sessionsByChannel.get(frame.channel_id);
  if (
    session === undefined ||
    session.closed ||
    session.fingerprint.length === 0 ||
    session.answered
  )
    return;
  const opened = openSealedWith(
    session.eph.privateKey,
    frame.fingerprint_proof,
  );
  const inner = opened === null ? null : decodeAnswerInner(opened);
  if (inner === null) {
    markRtcFailure(session.keyId);
    return;
  }
  const answerMatches = verifyAnswerInner(inner, {
    nonce: session.nonce,
    browserFingerprint: session.fingerprint,
    daemonFingerprint: inner.fd,
  });
  if (!answerMatches || !sdpFingerprintsMatch(frame.sdp, inner.fd)) {
    markRtcFailure(session.keyId);
    return;
  }
  // Accept only the first valid answer — a retransmit must not re-enter
  // setRemoteDescription or trip markRtcFailure on a healthy session.
  session.answered = true;
  try {
    await session.pc.setRemoteDescription({ type: "answer", sdp: frame.sdp });
    if (session.closed) return;
    clearTimers(session);
    // Data channel may already be open (and mux mounted) by the time the
    // answer handler resumes — do not arm a redundant ICE deadline.
    if (session.mux !== null) return;
    session.iceTimer = setTimeout(() => {
      if (!session.closed && session.mux === null)
        markRtcFailure(session.keyId);
    }, RTC_ICE_TIMEOUT_MS);
  } catch {
    markRtcFailure(session.keyId);
  }
};

/** Feed a trickle ICE candidate to an offerer session. Unknown channel ids no-op. */
export const handleRtcClientIce = async (frame: {
  readonly channel_id: string;
  readonly candidate: string;
}): Promise<void> => {
  const session = sessionsByChannel.get(frame.channel_id);
  if (session === undefined || session.closed) return;
  try {
    const parsed: unknown = JSON.parse(frame.candidate);
    if (parsed === null || typeof parsed !== "object") return;
    await session.pc.addIceCandidate(parsed as RTCIceCandidate);
  } catch {
    // Candidate timing races are expected.
  }
};

/** Return an already-open RTC mux channel; never waits for signaling. */
export const getRtcMuxChannel = (keyId: string): TMuxChannel | null => {
  if (failureCached(keyId)) return null;
  return sessionsByKey.get(keyId)?.mux ?? null;
};

/** Preserve mounted peer connections across a relay reconnect. */
export const resetUnmountedRtcClientSessions = (): void => {
  for (const session of [...sessionsByKey.values()]) {
    if (session.mux === null) closeSession(session, "relay_restart");
  }
};

/** Tear down every fleet RTC session (process stop / test cleanup). */
export const resetAllRtcClientSessions = (): void => {
  for (const session of [...sessionsByKey.values()])
    closeSession(session, "relay_restart");
  failedUntil.clear();
};
