/**
 * Pure vendor-payload → canonical-usage reducers.
 *
 * The daemon's resilience contract: every provider's usage read reduces
 * into the ONE canonical `TProviderUsageSnapshot` struct
 * (`packages/protocol/provider-usage.ts`) at this boundary — no fetch, no
 * fs, no spawn — so a vendor payload reshape is absorbed inside a pure,
 * unit-testable function and never leaks a format change downstream
 * (relay persistence, the calibration estimator, the UI all consume only
 * the canonical struct).
 */
import type { TProviderUsageWindow } from "@quantidexyz/openllmp";

/**
 * Duration label for a vendor-stated quota window — "5-hour", "7-day",
 * "30-minute" — matching claude-code's label convention. The label is the
 * window's IDENTITY downstream (the calibration series key), so stating
 * the duration means a vendor window reshape (e.g. Codex's 5h primary
 * becoming a weekly primary) automatically re-keys the series instead of
 * silently changing what a positional name means.
 */
export const windowLabelFromSeconds = (seconds: number): string => {
  if (seconds % 86_400 === 0) return `${seconds / 86_400}-day`;
  if (seconds % 3_600 === 0) return `${seconds / 3_600}-hour`;
  return `${Math.max(1, Math.round(seconds / 60))}-minute`;
};

/** Prettified positional fallback: "primary_window" → "Primary". */
const positionalLabel = (key: string): string => {
  const stem = key.replace(/_window$/, "").replace(/_/g, " ");
  return stem.length === 0 ? key : stem.charAt(0).toUpperCase() + stem.slice(1);
};

const isRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Reduce Codex's `rate_limit` object to canonical windows GENERICALLY:
 * any object value carrying a numeric `used_percent` is a window
 * (`primary_window`, `secondary_window`, whatever ships next) — a
 * renamed, added, or nulled-out key needs no code change here. OpenAI has
 * already reshaped this once (5h primary + weekly secondary → a single
 * weekly primary), so window identity comes from the STATED duration
 * (`limit_window_seconds`) when present; positional names are only the
 * fallback for windows that don't state one.
 *
 * `additional_rate_limits` (per-feature pools, e.g. model promos) are
 * deliberately NOT reduced: they meter DIFFERENT usage, and everything
 * downstream (representative selection, cross-window K transfer) assumes
 * one provider's windows all meter the SAME usage.
 */
export const reduceChatgptWindows = (
  rateLimit: unknown,
): TProviderUsageWindow[] => {
  if (!isRecord(rateLimit)) return [];
  const windows: TProviderUsageWindow[] = [];
  for (const [key, value] of Object.entries(rateLimit)) {
    if (!isRecord(value) || typeof value.used_percent !== "number") continue;
    const seconds =
      typeof value.limit_window_seconds === "number" &&
      value.limit_window_seconds > 0
        ? value.limit_window_seconds
        : null;
    const base =
      seconds !== null ? windowLabelFromSeconds(seconds) : positionalLabel(key);
    // Two windows can state the SAME duration — disambiguate with the
    // positional name so their series stay distinct.
    const label = windows.some((w) => w.label === base)
      ? `${base} · ${positionalLabel(key)}`
      : base;
    windows.push({
      label,
      percent_used: value.used_percent,
      reset_at_ms:
        typeof value.reset_at === "number" ? value.reset_at * 1000 : null,
      ...(seconds !== null ? { window_ms: seconds * 1000 } : {}),
    });
  }
  return windows;
};

/**
 * Reduce Codex's `additional_rate_limits` — per-feature pools (e.g. the
 * GPT-5.3-Codex-Spark promo pool) that meter DIFFERENT usage than the
 * main windows — into display-only `extra_pools`. Each entry's nested
 * `rate_limit` reduces through the same generic window walk; the pool's
 * `limit_name` becomes (or prefixes) the label. These must never join
 * `windows`: calibration and the card's tightest-window meter both
 * assume one provider's windows meter the SAME usage.
 */
export const reduceChatgptPools = (
  additionalRateLimits: unknown,
): TProviderUsageWindow[] => {
  if (!Array.isArray(additionalRateLimits)) return [];
  const pools: TProviderUsageWindow[] = [];
  for (const entry of additionalRateLimits as ReadonlyArray<unknown>) {
    if (!isRecord(entry)) continue;
    const name =
      typeof entry.limit_name === "string" && entry.limit_name.length > 0
        ? entry.limit_name
        : typeof entry.metered_feature === "string"
          ? entry.metered_feature
          : "Feature pool";
    const windows = reduceChatgptWindows(entry.rate_limit);
    for (const w of windows) {
      pools.push({
        ...w,
        label: windows.length === 1 ? name : `${name} · ${w.label}`,
      });
    }
  }
  return pools;
};

/** Credit state carried on the canonical quota snapshot, when reported. */
export type TReducedCredits = {
  readonly balance: string;
  readonly unlimited?: boolean;
  readonly reset_credits?: number;
};

/**
 * Reduce Codex's `credits` + `rate_limit_reset_credits` into the
 * canonical credit state — capacity that exists OUTSIDE the quota
 * windows (a purchasable balance; limit-reset credits that lift a hit
 * limit). Returns undefined when the payload reports neither.
 */
export const reduceChatgptCredits = (
  payload: unknown,
): TReducedCredits | undefined => {
  if (!isRecord(payload)) return undefined;
  const credits = isRecord(payload.credits) ? payload.credits : null;
  const resets = isRecord(payload.rate_limit_reset_credits)
    ? payload.rate_limit_reset_credits
    : null;
  if (credits === null && resets === null) return undefined;
  const resetCount =
    resets !== null && typeof resets.available_count === "number"
      ? resets.available_count
      : undefined;
  return {
    balance: typeof credits?.balance === "string" ? credits.balance : "0",
    ...(credits?.unlimited === true ? { unlimited: true } : {}),
    ...(resetCount !== undefined ? { reset_credits: resetCount } : {}),
  };
};

/**
 * Overall quota status. The vendor's own verdict (`limit_reached` /
 * `allowed`) wins when it ships one — percent thresholds are only the
 * fallback, since a vendor can reject before any meter reads 100.
 */
export const reduceQuotaStatus = (
  rateLimit: unknown,
  windows: ReadonlyArray<TProviderUsageWindow>,
): "allowed" | "allowed_warning" | "rejected" => {
  const maxPct = windows.reduce((a, w) => Math.max(a, w.percent_used), 0);
  const verdict = isRecord(rateLimit) ? rateLimit : {};
  const rejected =
    verdict.limit_reached === true ||
    verdict.allowed === false ||
    maxPct >= 100;
  return rejected ? "rejected" : maxPct >= 80 ? "allowed_warning" : "allowed";
};
