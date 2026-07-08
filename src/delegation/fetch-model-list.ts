import type { TProviderModelEntry } from "@quantidexyz/openllmp";

/**
 * Bound on a delegate's vendor model-list fetch — matches the
 * cloud-side refresher (`packages/api/lib/model-list-refresh.ts`).
 * Without it a half-open connection would hang the daemon's report
 * path indefinitely instead of degrading to catalog fallback.
 */
export const MODEL_LIST_FETCH_TIMEOUT_MS = 10_000;

/**
 * Shared fetch for delegate `listModels()` implementations: bounded
 * timeout, JSON body handed to the caller's provider-specific `parse`,
 * and `null` on ANY failure (non-2xx / timeout / parse / empty) —
 * never an empty list, so a vendor hiccup can't wipe a user's cached
 * entries. Common behavior (like this timeout) lives here once instead
 * of per delegate.
 */
export const fetchModelList = async (
  url: string,
  headers: Readonly<Record<string, string>>,
  parse: (body: unknown) => ReadonlyArray<TProviderModelEntry>,
): Promise<ReadonlyArray<TProviderModelEntry> | null> => {
  try {
    const resp = await fetch(url, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(MODEL_LIST_FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) return null;
    const entries = parse(await resp.json());
    return entries.length > 0 ? entries : null;
  } catch {
    return null;
  }
};
