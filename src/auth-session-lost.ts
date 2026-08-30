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
  TSubscriptionProviderSlug,
} from "@openllmsh/protocol";
import { emitAuth } from "./auth-events";
import { isSubscriptionSlug } from "./delegation";
import { loginSlot } from "./delegation/login-flow";
import { STATUS_CHECK_FAILED_DETAIL } from "./delegation/util";
import { daemonApiKeyId } from "./env";
import { logWarn } from "./logger";

export type TAuthStatusBaseline = {
  readonly status: TDaemonProviderAuthStatus;
  readonly accountHash?: string;
};

export type TAuthLossEdge = {
  readonly slug: TSubscriptionProviderSlug;
  readonly lost: boolean;
  readonly diagnostic_code?: TAuthSessionLostDiagnosticCode;
  readonly account_hash?: string;
  readonly next: TAuthStatusBaseline;
};

/** Last observed auth-status literal per subscription slug. */
const lastStatus = new Map<string, TAuthStatusBaseline>();

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
    d === STATUS_CHECK_FAILED_DETAIL
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
 * Pure connected→disconnected edge for one connection, plus the next baseline.
 * Returns `null` when the slug is not a subscription, login is in-flight, or
 * the tick is an indeterminate status-check failure (baseline unchanged).
 */
export const detectAuthLossEdge = (
  prev: TAuthStatusBaseline | undefined,
  conn: TDaemonProviderConnection,
): TAuthLossEdge | null => {
  const slug = conn.provider;
  if (!isSubscriptionSlug(slug)) return null;
  if (loginSlot(slug).inFlight()) return null;
  if (conn.detail === STATUS_CHECK_FAILED_DETAIL) return null;
  const nextStatus = conn.status;
  const lost = prev?.status === "connected" && nextStatus === "disconnected";
  const accountHash = conn.account_hash ?? prev?.accountHash;
  return {
    slug,
    lost,
    ...(lost ? { diagnostic_code: classifyLossDetail(conn.detail) } : {}),
    ...(accountHash !== undefined ? { account_hash: accountHash } : {}),
    next: {
      status: nextStatus,
      ...(accountHash !== undefined ? { accountHash } : {}),
    },
  };
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
    const edge = detectAuthLossEdge(lastStatus.get(conn.provider), conn);
    if (edge === null) continue;
    if (edge.lost) {
      const diagnostic_code = edge.diagnostic_code ?? "unclassified";
      logWarn("auth-session-lost", "subscription session lost", {
        slug: edge.slug,
        diagnostic_code,
        ...(edge.account_hash !== undefined
          ? { account_hash: edge.account_hash }
          : {}),
      });
      emitAuth({
        event: "auth.session.lost",
        key_id: daemonApiKeyId() ?? "local",
        slug: edge.slug,
        diagnostic_code,
        ...(edge.account_hash !== undefined
          ? { account_hash: edge.account_hash }
          : {}),
      });
    }
    lastStatus.set(edge.slug, edge.next);
  }
};

/** Test-only: the trackers are process-global and leak across suites. */
export const resetSessionLostTrackerForTests = (): void => {
  lastStatus.clear();
};
