import type { TProviderModelEntry } from "@quantidexyz/openllmp";
import { MODEL_LIST_FETCH_TIMEOUT_MS } from "@quantidexyz/openllmp";

/**
 * Coerce a provider-reported value into a positive integer, or
 * `undefined` — the shared shape check for `context_window` /
 * `context_length` fields across the delegate parsers.
 */
export const positiveInt = (v: unknown): number | undefined => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : undefined;
};

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
