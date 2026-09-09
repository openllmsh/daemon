/**
 * The daemon's ONE AsyncLocalStorage module. Refresh spawn metadata and the
 * status-tick correlation bag both live here so a later reader never has to
 * hunt a second ALS.
 */
import { AsyncLocalStorage } from "node:async_hooks";

export type TRefreshSpawnBag = {
  meta:
    | {
        readonly spawned_at_ms: number | null;
        readonly child_pid: number | null;
      }
    | undefined;
  timeoutMs: number | undefined;
};

export const refreshSpawnBag = new AsyncLocalStorage<TRefreshSpawnBag>();

/** Who kicked `makeRefresher` — demand-path tag for `refresh_spawns.last`. */
export type TRefreshCaller = "upstream" | "usage" | "models" | "login";

export const refreshCallerBag = new AsyncLocalStorage<TRefreshCaller>();

export const currentRefreshCaller = (): TRefreshCaller | null =>
  refreshCallerBag.getStore() ?? null;

/**
 * Manual "Refresh usage" may call the existing native `readToken` path.
 * Default usage reads stay stored-only. The bag is scoped per provider
 * fetch so a sibling/later usage() cannot inherit permission, and so the
 * quota write can be tied to the status snapshot's `account_hash`.
 */
export type TUsageNativeRefreshBag = {
  readonly expectedAccountHash?: string;
};

const usageNativeRefreshBag = new AsyncLocalStorage<TUsageNativeRefreshBag>();

export const usageNativeRefreshAllowed = (): boolean =>
  usageNativeRefreshBag.getStore() !== undefined;

export const expectedUsageAccountHash = (): string | undefined =>
  usageNativeRefreshBag.getStore()?.expectedAccountHash;

export const withUsageNativeRefresh = <T>(
  fn: () => Promise<T>,
  expectedAccountHash?: string,
): Promise<T> =>
  usageNativeRefreshBag.run(
    expectedAccountHash === undefined ? {} : { expectedAccountHash },
    fn,
  );

export type TOpTick = {
  readonly tick_id: number;
  readonly slug?: string;
};

export const opTickContext = new AsyncLocalStorage<TOpTick>();

let nextTickId = 0;

export const nextStatusTickId = (): number => {
  nextTickId += 1;
  return nextTickId;
};

/** `null` off a status tick (e.g. a request-path refresh). */
export const currentTickId = (): number | null =>
  opTickContext.getStore()?.tick_id ?? null;
