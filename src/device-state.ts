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
import { binarySignature } from "./bin-signature";
import { cliBinaryPath, legacyCliBinaryPath } from "./cli-self-update";
import { cliVersion } from "./delegation/util";
import { logDebug } from "./logger";

/** Cached probe, keyed by the binary's PATH + stat signature: the `--version`
 *  spawn re-runs only when the signature changes (a self-update), never on a
 *  timer — so the confined spawn stays off the hot status path. */
interface CliStateCache {
  path: string;
  signature: string | null;
  version: string | null;
}
let cache: CliStateCache = { path: "", signature: null, version: null };

/** The installed CLI binary, preferring the current name over the legacy one. */
const installedBinary = (): string | null => {
  for (const path of [cliBinaryPath(), legacyCliBinaryPath()]) {
    if (existsSync(path)) return path;
  }
  return null;
};

/**
 * Probe the CLI's presence + version. The `--version` spawn is CONFINED
 * (sandbox-wrapped like any vendor spawn) but only fires when the binary's stat
 * signature changed since the last probe (see {@link binarySignature}) — an
 * unchanged binary returns the cached version with no spawn at all.
 */
export const refreshCliState = async (): Promise<TDaemonCliState> => {
  const bin = installedBinary();
  if (bin === null) {
    cache = { path: "", signature: null, version: null };
    return { installed: false, version: null };
  }
  const signature = binarySignature(bin);
  // Unchanged binary since the last successful probe → reuse the version, no spawn.
  if (cache.path === bin && cache.signature === signature) {
    return { installed: true, version: cache.version };
  }
  // Legacy binaries print `openllmc vX.Y.Z`, current ones `openllm vX.Y.Z`.
  const out = await cliVersion(bin);
  const version = out?.match(/openllmc? v(\S+)/)?.[1] ?? null;
  cache = { path: bin, signature, version };
  logDebug("device-state", "cli state", { installed: true, version });
  return { installed: true, version };
};

/**
 * The CLI state for a status push. A `statSync` is cheap enough to run on every
 * call: when the binary is unchanged it returns the cached version with no
 * spawn; when it changed (or on first sight) it kicks a background refresh and
 * reports the last-known value so the push is never blocked on a spawn.
 */
export const getCliState = (): TDaemonCliState => {
  const bin = installedBinary();
  if (bin === null) {
    cache = { path: "", signature: null, version: null };
    return { installed: false, version: null };
  }
  if (cache.path === bin && cache.signature === binarySignature(bin)) {
    return { installed: true, version: cache.version };
  }
  void refreshCliState().catch(() => {
    // Best-effort: a failed probe keeps the previous value.
  });
  return {
    installed: true,
    version: cache.path === bin ? cache.version : null,
  };
};
