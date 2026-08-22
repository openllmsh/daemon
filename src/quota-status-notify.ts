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
} from "@openllmsh/protocol";

type TQuotaStatus = "allowed" | "allowed_warning" | "rejected";

/** Last fresh quota status observed for each provider account. */
const lastQuotaStatus = new Map<string, TQuotaStatus>();

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
    const key = quotaKey(connection.provider, connection.account_hash);
    const previous = lastQuotaStatus.get(key);
    if (
      (next === "allowed_warning" || next === "rejected") &&
      isNotifiableTransition(previous, next)
    ) {
      transitions.push({
        slug: connection.provider,
        status: next,
        ...(connection.account_hash === undefined
          ? {}
          : { account_hash: connection.account_hash }),
        ...(usage.plan === undefined ? {} : { plan: usage.plan }),
      });
    }
    lastQuotaStatus.set(key, next);
  }

  return transitions;
};

/** Test-only: process-global baselines must not leak across suites. */
export const resetQuotaStatusTrackerForTests = (): void => {
  lastQuotaStatus.clear();
};
