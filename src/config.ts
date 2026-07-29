/**
 * Runtime config + catalog cache.
 *
 * The daemon does NOT compile the model catalog or routing config in — it
 * pulls a single bootstrap snapshot from the cloud
 * (`GET /api/daemon/bootstrap`) and refreshes on a TTL. This keeps the
 * binary's dependency closure to core + schema + effect (no
 * `@openllm/api`, no db) and lets config update without recompiling.
 *
 * The walker makes ZERO routing decisions (the cloud resolved the chain
 * and 307'd it as `?__plan=`), so the daemon only needs from the snapshot:
 * model id → `provider_model_id` (catalog), the per-user plan-signing key,
 * and the cloud-state for `/status`. The fallback/binding/token-limit
 * fields ride along in the wire shape but are unused on the box.
 */

import type {
  TDaemonBootstrap,
  TDaemonCatalogEntry,
  TSubMethod,
} from "@openllmsh/protocol";
import {
  fetchBootstrap,
  InvalidApiKeyError,
  NoApiKeyError,
} from "./cloud-client";
import { clearPlanCache } from "./plan-cache";

const EMPTY: TDaemonBootstrap = {
  catalog: [],
  provider_prefixes: [],
  user_fallback_groups: [],
  user_model_fallback_bindings: [],
};

/**
 * Outcome of the last bootstrap attempt — surfaced on `GET /status` so
 * the dashboard knows whether to show the API-key picker (`no_key` /
 * `invalid_key`), a retry hint (`unreachable`), or the provider cards
 * (`ok`).
 */
export type TCloudState = "ok" | "no_key" | "invalid_key" | "unreachable";

let snapshot: TDaemonBootstrap = EMPTY;
let byModelId: Map<string, TDaemonCatalogEntry> = new Map();
let cloudState: TCloudState = "no_key";

export const getCloudState = (): TCloudState => cloudState;

/**
 * Refresh the cloud snapshot, recording the outcome in `cloudState`.
 * Never throws — classifies the failure instead so the control surface
 * and dashboard can react (the daemon stays up and serving on a stale /
 * empty snapshot regardless).
 *
 * Returns `true` when `cloudState` CHANGED, so the caller can re-push the
 * daemon's status: a transient boot-time `unreachable` that recovers to `ok`
 * on the next retry must surface immediately, not wait for the next command
 * (otherwise the dashboard shows "can't reach the cloud" indefinitely even
 * though everything is working — the bug this fixes).
 */
export const refreshBootstrap = async (): Promise<boolean> => {
  const prev = cloudState;
  try {
    snapshot = await fetchBootstrap();
    byModelId = new Map(snapshot.catalog.map((e) => [e.model_id, e]));
    cloudState = "ok";
    // A fresh snapshot may carry new routing config — drop any cached signed
    // plans so a stale chain never outlives the config that produced it.
    clearPlanCache();
  } catch (err) {
    if (err instanceof NoApiKeyError) cloudState = "no_key";
    else if (err instanceof InvalidApiKeyError) cloudState = "invalid_key";
    else cloudState = "unreachable";
  }
  return cloudState !== prev;
};

/**
 * The per-user key for verifying the cloud's `?__plan=` signature (handed
 * over at bootstrap). Null when the cloud has no signing secret configured
 * — the walker then accepts unsigned plans (dev). See `walker.ts`.
 */
export const planSigningKey = (): string | null =>
  snapshot.plan_signing_key ?? null;

/**
 * The cloud's resolved `ACTIVE_SUB_METHOD` preference from the last
 * bootstrap (`bridge` | `handrolled` | null = no preference). The daemon
 * NEVER reads an `ACTIVE_SUB_METHOD` env of its own — this snapshot field
 * is the only source; a daemon that has never bootstrapped has no
 * preference, and a stale snapshot keeps the last-known value. Sampled
 * once per hop at selection time (`sub-method.ts`) so it never switches
 * mid-hop. See `docs/proposals/active-sub-method.md`.
 */
export const activeSubMethod = (): TSubMethod | null =>
  snapshot.active_sub_method ?? null;

/**
 * Per-provider overrides layered on top of `activeSubMethod` (from the
 * same bootstrap snapshot — `provider:method` entries in the cloud's
 * `ACTIVE_SUB_METHOD` env). Empty when the cloud sent none / predates the
 * field. Sampled together with the global preference once per request so
 * a mid-walk bootstrap refresh never switches a hop.
 */
export const activeSubMethodOverrides = (): Readonly<
  Record<string, TSubMethod>
> => snapshot.active_sub_methods ?? {};

/**
 * Cloud-controlled opt-in for the daemon's signed-plan cache (default off —
 * absent on older clouds keeps the rider inert). See `plan-cache.ts`.
 */
export const planCacheEnabled = (): boolean => snapshot.plan_cache === true;

/**
 * The fleet-peer key id serving `provider` (subscription tunnel — feature
 * §1), from the last bootstrap. Null when no online fleet daemon serves it
 * (or the cloud predates the field) — the walker then falls through exactly
 * as before the tunnel existed.
 */
export const fleetSubscriptionServerFor = (provider: string): string | null =>
  snapshot.fleet_subscriptions?.find((f) => f.provider === provider)?.key_id ??
  null;

/**
 * The daemon version the cloud currently publishes (bare semver), from the last
 * bootstrap. Null when unpublished or the cloud is too old to advertise it. The
 * self-updater compares it to `DAEMON_VERSION`. See `self-update.ts`.
 */
export const latestVersion = (): string | null =>
  snapshot.latest_version ?? null;

/**
 * The `openllm` CLI version the cloud currently publishes (bare semver),
 * from the last bootstrap. Null when unpublished or the cloud is too old to
 * advertise it. The CLI converger compares it to the installed binary's
 * version. See `cli-self-update.ts`.
 */
export const latestCliVersion = (): string | null =>
  snapshot.latest_cli_version ?? null;

/**
 * Look up a model id in the cached catalog → its `{ provider,
 * provider_model_id }` row. The walker uses this to resolve each `__plan`
 * hop to its concrete upstream model id (falling back to splitting the
 * `provider/model` pair when uncached).
 */
export const lookupCatalogEntry = (
  modelId: string,
): TDaemonCatalogEntry | null => byModelId.get(modelId) ?? null;
