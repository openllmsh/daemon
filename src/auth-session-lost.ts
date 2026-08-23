/**
 * Falling-edge `auth.session.lost` detection (audit 2026-08-21 §7 item 5).
 *
 * The subscription login FSM emits `auth.login.succeeded` / `.failed` from the
 * flow itself (`login-flow`). The MIRROR — "you were signed out" — has no flow:
 * it is the falling edge of a previously-connected provider, observed on the
 * status-compute path (hello / the ~2.5s watcher / post-command push). This
 * module watches each computed snapshot and emits `auth.session.lost` exactly
 * once when a provider that WAS connected reads not-connected, with no login in
 * flight.
 *
 * Two guards keep it quiet:
 *   - Cold start (`connected: false` with no prior observation) is NOT a loss —
 *     only a recorded `connected: true` → `false` transition emits.
 *   - A transient probe failure never flips `connected` to `false` (status.ts
 *     `statusFailure` preserves the last-known connection), so this never fires
 *     on a status hiccup.
 *
 * A `logout` / `cancel` command that caused the drop stamps the reason via
 * {@link markSessionLostReason}; otherwise it defaults to `credential_gone`.
 * (`vendor_revoked` has no local signal, so it is never inferred here.)
 */
import type {
  TAuthSessionLostDiagnosticCode,
  TAuthSessionLostReason,
  TDaemonProviderConnection,
} from "@openllmsh/protocol";
import { emitAuth } from "./auth-events";
import {
  RECENT_USER_ACTION_MS,
  recentUserAuthAction,
  resetUserAuthActionsForTests,
} from "./auth-user-action";
import { isSubscriptionSlug } from "./delegation";
import { loginSlot } from "./delegation/login-flow";
import { STATUS_CHECK_FAILED_DETAIL } from "./delegation/util";
import { daemonApiKeyId } from "./env";
import { logWarn } from "./logger";

type TConnSnapshot = {
  readonly connected: boolean;
  readonly accountHash?: string;
};

/** Last observed connection per subscription slug — the falling-edge baseline. */
const lastConnected = new Map<string, TConnSnapshot>();

/** A command-attributed reason for the NEXT falling edge of a slug (else the
 *  default `credential_gone` is used). Consumed on emit or on reconnect. */
const pendingLostReason = new Map<string, TAuthSessionLostReason>();

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
 * Attribute the next falling edge of `slug` to `reason` (e.g. a `logout`
 * command). Consumed by {@link noteConnectionsForSessionLost} on the edge, or
 * dropped when the provider is seen still-connected (the command did not take).
 */
export const markSessionLostReason = (
  slug: string,
  reason: TAuthSessionLostReason,
): void => {
  pendingLostReason.set(slug, reason);
};

/**
 * Observe one computed status snapshot's connections and emit
 * `auth.session.lost` for every subscription provider that transitioned
 * connected → not-connected with no in-flight login. Best-effort: `emitAuth`
 * is a no-op when the control channel is not running.
 */
export const noteConnectionsForSessionLost = (
  connections: ReadonlyArray<TDaemonProviderConnection>,
  recentActionWindowMs: number = RECENT_USER_ACTION_MS,
): void => {
  for (const conn of connections) {
    const slug = conn.provider;
    if (!isSubscriptionSlug(slug)) continue;
    // A login in flight momentarily reads not-connected (a re-login). Neither
    // emit a loss NOR disturb the baseline — the falling edge (if the login
    // then fails) is recognized on the first snapshot after the slot clears,
    // against the PRE-login baseline. Overwriting it here would erase the "was
    // connected" fact and swallow the loss.
    if (loginSlot(slug).inFlight()) continue;
    // Indeterminate status (last-known preserved upstream). Same skip: do not
    // emit, do not consume a pending logout stamp, do not rewrite lastConnected.
    if (conn.detail === STATUS_CHECK_FAILED_DETAIL) continue;
    const now = conn.connected === true;
    const prev = lastConnected.get(slug);
    if (prev?.connected === true && !now) {
      const reason = pendingLostReason.get(slug) ?? "credential_gone";
      pendingLostReason.delete(slug);
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
    } else if (now) {
      // Still (or freshly) connected — a stamped logout is stale only when the
      // user has not just requested logout (in-window ticks can still read
      // connected while the slow delegate is clearing tokens).
      if (!recentUserAuthAction(slug, recentActionWindowMs)) {
        pendingLostReason.delete(slug);
      }
    }
    // Carry the last-known account hash forward when a still-connected snapshot
    // omits it (a status push can report `connected` without re-deriving the
    // hash), so the eventual disconnect still emits the right account. A fresh
    // hash always wins; a genuine disconnect keeps whatever we last held.
    const carriedHash = conn.account_hash ?? prev?.accountHash;
    lastConnected.set(slug, {
      connected: now,
      ...(carriedHash !== undefined ? { accountHash: carriedHash } : {}),
    });
  }
};

/** Test-only: the trackers are process-global and leak across suites. */
export const resetSessionLostTrackerForTests = (): void => {
  lastConnected.clear();
  pendingLostReason.clear();
  resetUserAuthActionsForTests();
};
