import type { RTCDataChannel, RTCPeerConnection } from "werift";

/**
 * Finish the data-channel reset while DTLS/ICE can still send its handshake.
 * The pinned werift PeerConnection.close() tears that transport down first,
 * leaving the remote mux and admission slot alive until ICE consent expires.
 * This closes a connection, never the durable terminal session carried by it.
 */
export const closeRtcPeer = async (
  pc: RTCPeerConnection,
  dc?: RTCDataChannel | null,
): Promise<void> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let poll: ReturnType<typeof setInterval> | undefined;
  let unsubscribe: (() => void) | undefined;
  try {
    const sctp = pc.sctpTransport?.sctp;
    const pendingReset = () =>
      Boolean(sctp?.reconfigRequest) || (sctp?.reconfigQueue.length ?? 0) > 0;
    if (
      dc !== undefined &&
      dc !== null &&
      (dc.readyState === "open" ||
        dc.readyState === "closing" ||
        pendingReset())
    ) {
      await new Promise<void>((resolve) => {
        // werift can signal channel "closed" after the inbound reset while its
        // reciprocal reset is still unacknowledged. Keep ICE alive for that
        // exchange and one retry; otherwise a lost first burst is unrecoverable.
        const settled = () => {
          if (dc.readyState === "closed" && !pendingReset()) resolve();
        };
        unsubscribe = dc.stateChanged.subscribe(settled).unSubscribe;
        // The pinned dependency exposes this runtime field but marks it private
        // in its declarations. Keep that compatibility boundary explicit.
        const rto = (sctp as unknown as { rto?: number } | undefined)?.rto;
        const grace =
          typeof rto === "number" && Number.isFinite(rto)
            ? Math.min(4_000, Math.max(1_000, rto * 1_000 + 500))
            : 1_000;
        timer = setTimeout(resolve, grace);
        // A reset acknowledgement clears the library's request after emitting
        // the channel event, so observe settlement on subsequent event turns.
        poll = setInterval(settled, 20);
        if (dc.readyState === "open" || dc.readyState === "closing") dc.close();
        settled();
      });
    }
  } catch {
    // Failed handshakes and already-dead transports still need local cleanup.
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (poll !== undefined) clearInterval(poll);
    unsubscribe?.();
    try {
      await pc.close();
    } catch {
      /* already closed */
    }
  }
};
