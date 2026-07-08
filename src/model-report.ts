/**
 * Daemon writer for the cloud's per-user model cache
 * (live-provider-model-catalog proposal §4).
 *
 * On each tick, ask every CONNECTED delegate that implements
 * `listModels()` for the vendor's live model list and POST the batch to
 * `POST /api/daemon/models`. The cloud upserts one `(user_id, provider)`
 * row per entry with `source: 'daemon'` — provider-granular, so two
 * daemons with disjoint provider setups merge instead of clobbering
 * (each only reports providers it can see).
 *
 * Cadence: piggybacks on the bootstrap tick in `main.ts`, throttled here
 * to the cloud's cache TTL — a fresh row makes re-reporting pointless,
 * so re-reporting on the same period keeps the row perpetually fresh
 * with the minimum number of vendor calls. Per-provider throttle: one
 * delegate's failure (returns null) doesn't block another's cadence.
 * Metadata only — model ids + optional display/context data; failures
 * are silently dropped (the cloud falls back to the static catalog).
 */
import type { TDaemonModelReportEntry } from "@quantidexyz/openllmp";
import { reportModels } from "./cloud-client";
import { DELEGATES } from "./delegation";

/** Mirrors the cloud's `MODEL_CACHE_TTL_MS` (1h, enforced on read). */
const REPORT_TTL_MS = 60 * 60 * 1000;
/**
 * A null/empty fetch (signed out, vendor error) retries on THIS slower
 * cadence instead of every 5-min bootstrap tick — a persistently failing
 * provider must not burn a vendor call per tick forever. Reset per slug
 * on a successful connect so a fresh login reports immediately.
 */
const FAILURE_RETRY_MS = 15 * 60 * 1000;

type TAttempt = { readonly at: number; readonly ok: boolean };
const lastAttempt = new Map<string, TAttempt>();

/** Reset the throttle — all slugs, or one (post-connect / tests). */
export const resetModelReportThrottle = (slug?: string): void => {
  if (slug === undefined) lastAttempt.clear();
  else lastAttempt.delete(slug);
};

const isDue = (slug: string, now: number): boolean => {
  const prev = lastAttempt.get(slug);
  if (prev === undefined) return true;
  return now - prev.at >= (prev.ok ? REPORT_TTL_MS : FAILURE_RETRY_MS);
};

/**
 * Collect + report due model lists. Never throws; resolves when the
 * report round-trip settles (callers fire-and-forget from the loop).
 */
export const maybeReportModels = async (
  now: number = Date.now(),
): Promise<void> => {
  const due = Object.entries(DELEGATES).filter(
    ([slug, delegate]) => delegate.listModels !== undefined && isDue(slug, now),
  );
  // Fetch concurrently — each delegate's call is individually bounded
  // (`fetchModelList`), but sequential awaits would still let one slow
  // vendor delay every other provider's report.
  const results = await Promise.all(
    due.map(async ([slug, delegate]) => ({
      slug,
      models: await (delegate.listModels?.().catch(() => null) ??
        Promise.resolve(null)),
    })),
  );
  const entries: TDaemonModelReportEntry[] = [];
  for (const { slug, models } of results) {
    // EVERY attempt stamps — a failed/empty fetch backs off on
    // FAILURE_RETRY_MS rather than re-firing each bootstrap tick.
    const ok = models !== null && models.length > 0;
    // Stamp on FETCH, not successful report — if the report POST fails
    // the next TTL tick retries (reportModels swallows errors; the
    // cloud row just goes stale → catalog fallback, not corruption).
    lastAttempt.set(slug, { at: now, ok });
    if (ok) entries.push({ provider: slug, models });
  }
  if (entries.length === 0) return;
  await reportModels({ entries });
};
