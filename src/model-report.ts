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

const lastReportedAtMs = new Map<string, number>();

/** Test-only: reset the per-provider throttle. */
export const resetModelReportThrottle = (): void => {
  lastReportedAtMs.clear();
};

/**
 * Collect + report due model lists. Never throws; resolves when the
 * report round-trip settles (callers fire-and-forget from the loop).
 */
export const maybeReportModels = async (
  now: number = Date.now(),
): Promise<void> => {
  const entries: TDaemonModelReportEntry[] = [];
  for (const [slug, delegate] of Object.entries(DELEGATES)) {
    if (delegate.listModels === undefined) continue;
    const last = lastReportedAtMs.get(slug) ?? 0;
    if (now - last < REPORT_TTL_MS) continue;
    const models = await delegate.listModels().catch(() => null);
    if (models === null || models.length === 0) continue;
    entries.push({ provider: slug, models });
    // Stamp on successful FETCH, not successful report — if the report
    // POST fails the next tick retries (reportModels swallows errors,
    // so stamp before the send and accept a lost hour on cloud failure;
    // the cloud row just goes stale → catalog fallback, not corruption).
    lastReportedAtMs.set(slug, now);
  }
  if (entries.length === 0) return;
  await reportModels({ entries });
};
