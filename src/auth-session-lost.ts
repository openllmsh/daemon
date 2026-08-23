/**
 * `auth.session.lost` emit on the transition into `disconnected`.
 *
 * The per-provider auth-status literal (`connected` / `disconnected` /
 * `signed_out`) is computed in `status.ts`. This module watches each snapshot
 * and emits `auth.session.lost` exactly once on `connected → disconnected`.
 * Logout is `signed_out` (no emit). Indeterminate / in-flight ticks skip
 * without rewriting the last-known literal.
 *
 * Cold start (`disconnected` with no prior `connected`) is not a loss.
 */
import type {
  TAuthSessionLostDiagnosticCode,
  TDaemonProviderAuthStatus,
  TDaemonProviderConnection,
} from "@openllmsh/protocol";
import { emitAuth } from "./auth-events";
import { isSubscriptionSlug } from "./delegation";
import { loginSlot } from "./delegation/login-flow";
import { STATUS_CHECK_FAILED_DETAIL } from "./delegation/util";
import { daemonApiKeyId } from "./env";
import { logWarn } from "./logger";

type TConnSnapshot = {
  readonly status: TDaemonProviderAuthStatus;
  readonly accountHash?: string;
};

/** Last observed auth-status literal per subscription slug. */
const lastStatus = new Map<string, TConnSnapshot>();

const literalOf = (
  conn: TDaemonProviderConnection,
): TDaemonProviderAuthStatus =>
  conn.status ?? (conn.connected ? "connected" : "disconnected");

/**
 * Map free-form `conn.detail` to a bounded diagnostic code. Never returns
 * the input string — unknown / empty details fall back to `unclassified`.
 * Does not infer `vendor_revoked` as a session-loss *reason*.
 */
export const classifyLossDetail = (
  detail?: string,
): TAuthSessionLostDiagnosticCode => {
  if (detail === undefined || detail.trim() === "") return "unclassified";
  const d = detail.toLowerCase();
  if (d.includes("keychain")) return "keychain_unavailable";
  if (
    d.includes("unreadable") ||
    d.includes("eacces") ||
    d.includes("permission denied") ||
    d.includes("parse")
  ) {
    return "store_unreadable";
  }
  if (
    d.includes("timeout") ||
    d.includes("timed out") ||
    d === "status check failed"
  ) {
    return "probe_timeout";
  }
  if (d.includes("not installed") || d.includes("cli not installed")) {
    return "cli_unavailable";
  }
  if (
    d.includes("revoked") ||
    d.includes("unauthorized") ||
    d.includes("401")
  ) {
    return "vendor_revoked_unknown";
  }
  if (
    d.includes("not signed in") ||
    d.includes("no stored credential") ||
    (d.includes("credential") && d.includes("absent"))
  ) {
    return "credential_absent";
  }
  return "unclassified";
};

/**
 * Observe one computed status snapshot's connections and emit
 * `auth.session.lost` for every subscription provider that transitioned
 * `connected → disconnected` with no in-flight login. Best-effort: `emitAuth`
 * is a no-op when the control channel is not running.
 */
export const noteConnectionsForSessionLost = (
  connections: ReadonlyArray<TDaemonProviderConnection>,
): void => {
  for (const conn of connections) {
    const slug = conn.provider;
    if (!isSubscriptionSlug(slug)) continue;
    if (loginSlot(slug).inFlight()) continue;
    if (conn.detail === STATUS_CHECK_FAILED_DETAIL) continue;
    const next = literalOf(conn);
    const prev = lastStatus.get(slug);
    if (prev?.status === "connected" && next === "disconnected") {
      const reason = "credential_gone" as const;
      const diagnostic_code = classifyLossDetail(conn.detail);
      logWarn("auth-session-lost", "subscription session lost", {
        slug,
        reason,
        diagnostic_code,
        ...(prev.accountHash !== undefined
          ? { account_hash: prev.accountHash }
          : {}),
      });
      emitAuth({
        event: "auth.session.lost",
        key_id: daemonApiKeyId() ?? "local",
        slug,
        reason,
        diagnostic_code,
        ...(prev.accountHash !== undefined
          ? { account_hash: prev.accountHash }
          : {}),
      });
    }
    const carriedHash = conn.account_hash ?? prev?.accountHash;
    lastStatus.set(slug, {
      status: next,
      ...(carriedHash !== undefined ? { accountHash: carriedHash } : {}),
    });
  }
};

/** Test-only: the trackers are process-global and leak across suites. */
export const resetSessionLostTrackerForTests = (): void => {
  lastStatus.clear();
};
