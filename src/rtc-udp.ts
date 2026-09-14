import { StunProtocol } from "werift";
import type { CandidatePair } from "werift";
import { logDebug, logWarn } from "./logger";

/**
 * The pinned werift UDP transport has no socket error listener. Linux delivers
 * an ICMP port-unreachable as an asynchronous ECONNREFUSED event after a peer
 * disappears; leaving it unhandled can throw outside ICE's consent lifecycle.
 * Observe only this peer's UDP candidates through werift's public pair hook.
 * ICMP errors remain advisory: ICE still owns nomination and consent expiry,
 * so a failed alternate candidate cannot tear down a healthy selected path.
 */
type TRtcCandidateObserver = (pair: Pick<CandidatePair, "protocol">) => true;

export const rtcCandidateErrors = (
  onFatal: () => void,
): TRtcCandidateObserver => {
  const observed = new WeakSet<object>();
  return (pair) => {
    const protocol = pair.protocol;
    if (!(protocol instanceof StunProtocol)) return true;
    const socket = protocol.transport.socket;
    if (observed.has(socket)) return true;
    observed.add(socket);
    let reportedAdvisory = false, reportedFatal = false;
    const onError = (error: Error & { code?: string }): void => {
      const code = error.code ?? "UNKNOWN";
      if (["ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH"].includes(code)) {
        if (!reportedAdvisory) logDebug("rtc", "UDP candidate unreachable; ICE retains consent ownership", { code });
        reportedAdvisory = true;
        return;
      }
      if (!reportedFatal) {
        reportedFatal = true;
        logWarn("rtc", "UDP transport failed", { code });
        onFatal();
      }
    };
    socket.on("error", onError);
    socket.once("close", () => { socket.off("error", onError); });
    return true;
  };
};
