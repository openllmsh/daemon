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
 * A vendor CLI version change bypasses the TTL because some providers
 * gate model visibility by client version (Codex does this today).
 * Metadata only — model ids + optional display/context data; failures
 * are silently dropped (the cloud falls back to the static catalog).
 */
import type { TDaemonModelReportEntry } from "@openllmsh/protocol";
import { reportModels } from "./cloud-client";
import { DELEGATES } from "./delegation";

/** Mirrors the cloud's `MODEL_CACHE_TTL_MS` (30m, enforced on read). */
const REPORT_TTL_MS = 30 * 60 * 1000;
/**
 * A null/empty fetch (signed out, vendor error) retries on THIS slower
 * cadence instead of every 5-min bootstrap tick — a persistently failing
 * provider must not burn a vendor call per tick forever. Reset per slug
 * on a successful connect so a fresh login reports immediately.
 */
const FAILURE_RETRY_MS = 15 * 60 * 1000;

type TAttempt = {
  readonly at: number;
  readonly ok: boolean;
  readonly cliVersion?: string;
};

/** The result of collecting and attempting one due model-list report. */
export type TMaybeModelReportResult = {
  /** Whether at least one live provider listing was POSTed to the cloud. */
  readonly attempted: boolean;
  /** Number of successful provider model listings included in the report. */
  readonly reported: number;
  /** Whether a provider listing or the cloud POST failed. */
  readonly failed: boolean;
  /** Safe diagnostic for failed provider listings or a cloud POST failure. */
  readonly error?: string;
};

const lastAttempt = new Map<string, TAttempt>();

/** Reset the throttle — all slugs, or one (post-connect / tests). */
export const resetModelReportThrottle = (slug?: string): void => {
  if (slug === undefined) lastAttempt.clear();
  else lastAttempt.delete(slug);
};

const isDue = (
  slug: string,
  now: number,
  cliVersion: string | undefined,
): boolean => {
  const prev = lastAttempt.get(slug);
  if (prev === undefined) return true;
  if (cliVersion !== undefined && cliVersion !== prev.cliVersion) return true;
  return now - prev.at >= (prev.ok ? REPORT_TTL_MS : FAILURE_RETRY_MS);
};

/**
 * Collect + report due model lists without throwing. The returned outcome lets
 * explicit callers surface a cloud-report failure, while background callers
 * simply ignore it and remain best-effort.
 */
export const maybeReportModels = async (
  now: number = Date.now(),
): Promise<TMaybeModelReportResult> => {
  const candidates = await Promise.all(
    Object.entries(DELEGATES)
      .filter(([, delegate]) => delegate.listModels !== undefined)
      .map(async ([slug, delegate]) => {
        const conn = await delegate.status().catch(() => null);
        const cliVersion = conn?.cli_version;
        return isDue(slug, now, cliVersion)
          ? { slug, delegate, cliVersion }
          : null;
      }),
  );
  const due = candidates.filter((c) => c !== null);

  // Fetch concurrently — each delegate's call is individually bounded
  // (`fetchModelList`), but sequential awaits would still let one slow
  // vendor delay every other provider's report.
  const results = await Promise.all(
    due.map(async ({ slug, delegate, cliVersion }) => ({
      slug,
      cliVersion,
      models: await (delegate.listModels?.().catch(() => null) ??
        Promise.resolve(null)),
    })),
  );
  const entries: TDaemonModelReportEntry[] = [];
  const failedProviders: string[] = [];
  for (const { slug, cliVersion, models } of results) {
    // EVERY attempt stamps — a failed/empty fetch backs off on
    // FAILURE_RETRY_MS rather than re-firing each bootstrap tick.
    const ok = models !== null && models.length > 0;
    // Stamp on FETCH, not successful report — if the report POST fails
    // the next TTL tick retries (the cloud row just goes stale → catalog
    // fallback, not corruption).
    lastAttempt.set(slug, {
      at: now,
      ok,
      ...(cliVersion ? { cliVersion } : {}),
    });
    if (models === null) {
      failedProviders.push(slug);
      continue;
    }
    // `cli_version` rides along so the cloud can refuse a write from a
    // device whose CLI is OLDER than the one that produced the current
    // row (version-gated model lists must not shrink cross-device).
    if (models.length > 0) {
      entries.push({
        provider: slug,
        models,
        ...(cliVersion ? { cli_version: cliVersion } : {}),
      });
    }
  }
  const listingError =
    failedProviders.length > 0
      ? `model listing failed for ${failedProviders.join(", ")}`
      : undefined;
  if (entries.length === 0) {
    return {
      attempted: false,
      reported: 0,
      failed: failedProviders.length > 0,
      ...(listingError === undefined ? {} : { error: listingError }),
    };
  }

  const result = await reportModels({ entries });
  if (result.ok) {
    return {
      attempted: true,
      reported: entries.length,
      failed: failedProviders.length > 0,
      ...(listingError === undefined ? {} : { error: listingError }),
    };
  }

  return {
    attempted: true,
    // Cloud rejected / could not accept the POST — nothing was reported.
    reported: 0,
    failed: true,
    error:
      listingError === undefined
        ? result.error
        : `${listingError}; ${result.error}`,
  };
};
