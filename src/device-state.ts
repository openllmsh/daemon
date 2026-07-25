/**
 * The daemon's view of the openllm CLI on this box.
 *
 * This used to be a manifest-driven WALK: for every registry item, fetch a
 * SHA-gated `install.sh` from the gateway and run it with `-s` to parse a
 * one-line JSON verdict, caching the result because the walk was expensive. All
 * of that is gone — clients are configured at RUN time by `openllm <client>`, so
 * there is nothing installed per client to probe, diverge, or stamp. See
 * `docs/proposals/remove-registry-runtime-config-merge.md`.
 *
 * What remains is the ONE piece of install state the dashboard needs, and the
 * daemon already knows it without running anything: whether the CLI binary is
 * present and what version it reports. The auto-update loop
 * (`cli-self-update.ts`) resolves the same path, so this is a cheap
 * `existsSync` + a `--version` spawn, cached because the spawn is not free on a
 * hot status path.
 */

import { existsSync } from "node:fs";
import type { TDaemonCliState } from "@openllmsh/protocol";
import { cliBinaryPath, legacyCliBinaryPath } from "./cli-self-update";
import { cliVersion } from "./delegation/util";
import { logDebug } from "./logger";

/** How long a probed CLI state stays fresh. */
const CACHE_TTL_MS = 30_000;

let cache: { state: TDaemonCliState; at: number } | null = null;

/** The installed CLI binary, preferring the current name over the legacy one. */
const installedBinary = (): string | null => {
  for (const path of [cliBinaryPath(), legacyCliBinaryPath()]) {
    if (existsSync(path)) return path;
  }
  return null;
};

/**
 * Probe the CLI's presence + version. Cheap, but not free (it spawns
 * `--version`), so the result is cached for {@link CACHE_TTL_MS}.
 */
export const refreshCliState = async (): Promise<TDaemonCliState> => {
  const bin = installedBinary();
  if (bin === null) {
    cache = { state: { installed: false, version: null }, at: Date.now() };
    return cache.state;
  }
  // Legacy binaries print `openllmc vX.Y.Z`, current ones `openllm vX.Y.Z`.
  const out = await cliVersion(bin);
  const version = out?.match(/openllmc? v(\S+)/)?.[1] ?? null;
  cache = { state: { installed: true, version }, at: Date.now() };
  logDebug("device-state", "cli state", { installed: true, version });
  return cache.state;
};

/**
 * The CLI state for a status push. Serves the cache when fresh; otherwise
 * kicks off a refresh and reports what we last knew (or "not installed" on the
 * very first call) so a status push is never blocked on a spawn.
 */
export const getCliState = (): TDaemonCliState => {
  const now = Date.now();
  if (cache !== null && now - cache.at < CACHE_TTL_MS) return cache.state;
  void refreshCliState().catch(() => {
    // Best-effort: a failed probe keeps the previous value.
  });
  return cache?.state ?? { installed: false, version: null };
};
