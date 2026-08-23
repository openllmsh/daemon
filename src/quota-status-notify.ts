/**
 * Quota-status transition detector (LEAF module).
 *
 * Status snapshots are often repeated by the control-channel watcher. This
 * module keeps a per-provider/account baseline and returns only fresh entries
 * into a state that merits a cloud notification. It has no delivery policy:
 * callers decide how and where to send returned transitions.
 */
import type {
  TDaemonProviderConnection,
  TDaemonQuotaStatusReached,
  TProviderUsageWindow,
} from "@openllmsh/protocol";

type TQuotaStatus = "allowed" | "allowed_warning" | "rejected";

type TQuotaBaseline = {
  readonly status: TQuotaStatus;
  readonly resetEpoch: number | undefined;
};

/** Last fresh quota status observed for each provider account. */
const lastQuotaStatus = new Map<string, TQuotaBaseline>();

const quotaKey = (slug: string, accountHash: string | undefined): string =>
  `${slug}\0${accountHash ?? "-"}`;

const isSubscriptionProviderSlug = (
  slug: string,
): slug is TDaemonQuotaStatusReached["slug"] =>
  slug === "claude_code" ||
  slug === "chatgpt" ||
  slug === "kimi_code" ||
  slug === "grok" ||
  slug === "cursor";

const isNotifiableTransition = (
  previous: TQuotaStatus | undefined,
  next: TQuotaStatus,
): boolean => {
  if (next === "allowed") return false;
  if (previous === next) return false;
  // A rejected account recovering only to warning is a de-escalation, not a
  // new warning. A later fresh allowed baseline intentionally re-arms it.
  if (previous === "rejected" && next === "allowed_warning") return false;
  return true;
};

const farthestFiniteReset = (
  windows: ReadonlyArray<TProviderUsageWindow>,
  minPercentUsed: number | undefined,
): number | undefined => {
  let farthest: number | undefined;
  for (const window of windows) {
    if (minPercentUsed !== undefined && window.percent_used < minPercentUsed) {
      continue;
    }
    const resetAt = window.reset_at_ms;
    if (typeof resetAt !== "number" || !Number.isFinite(resetAt)) continue;
    farthest = farthest === undefined ? resetAt : Math.max(farthest, resetAt);
  }
  return farthest;
};

/**
 * Reset epoch of the window that is still holding the current status.
 * Matches `reduceQuotaStatus` thresholds: ≥100 rejected, ≥80 warning.
 * Vendor `limit_reached` / `allowed === false` can reject with no window
 * at 100 — then use the farthest finite reset among all `windows`.
 */
const sustainingWindowResetAtMs = (
  status: TQuotaStatus,
  windows: ReadonlyArray<TProviderUsageWindow>,
): number | undefined => {
  if (status === "rejected") {
    const atCap = farthestFiniteReset(windows, 100);
    if (atCap !== undefined) return atCap;
    return farthestFiniteReset(windows, undefined);
  }
  if (status === "allowed_warning") {
    return farthestFiniteReset(windows, 80);
  }
  return undefined;
};

/**
 * Observe quota snapshots and return the newly reached notification states.
 *
 * Cold-start warning/rejected snapshots intentionally emit: without a prior
 * baseline the user may already be affected, and cloud deduplication protects
 * against duplicate devices.
 */
export const noteConnectionsForQuota = (
  connections: ReadonlyArray<TDaemonProviderConnection>,
): ReadonlyArray<TDaemonQuotaStatusReached> => {
  const transitions: TDaemonQuotaStatusReached[] = [];

  for (const connection of connections) {
    const usage = connection.usage;
    if (
      !isSubscriptionProviderSlug(connection.provider) ||
      usage?.kind !== "quota" ||
      usage.stale === true
    )
      continue;

    const next = usage.status;
    const resetEpoch = sustainingWindowResetAtMs(next, usage.windows);
    const key = quotaKey(connection.provider, connection.account_hash);
    const previous = lastQuotaStatus.get(key);
    const prevEpoch = previous?.resetEpoch;
    // Only a strictly later finite window re-arms. Missing or smaller epochs
    // are vendor flaps of the same window, not a new billing period.
    const epochAdvanced =
      resetEpoch !== undefined &&
      prevEpoch !== undefined &&
      resetEpoch > prevEpoch;
    if (
      (next === "allowed_warning" || next === "rejected") &&
      (isNotifiableTransition(previous?.status, next) || epochAdvanced)
    ) {
      transitions.push({
        slug: connection.provider,
        status: next,
        ...(connection.account_hash === undefined
          ? {}
          : { account_hash: connection.account_hash }),
        ...(usage.plan === undefined ? {} : { plan: usage.plan }),
        ...(resetEpoch === undefined ? {} : { reset_at_ms: resetEpoch }),
      });
    }
    const effectiveEpoch =
      resetEpoch !== undefined &&
      (prevEpoch === undefined || resetEpoch >= prevEpoch)
        ? resetEpoch
        : prevEpoch;
    lastQuotaStatus.set(key, { status: next, resetEpoch: effectiveEpoch });
  }

  return transitions;
};

/** Test-only: process-global baselines must not leak across suites. */
export const resetQuotaStatusTrackerForTests = (): void => {
  lastQuotaStatus.clear();
};
