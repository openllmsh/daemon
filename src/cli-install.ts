/**
 * The daemon's isolated RUN-VIEW of the vendor CLIs — a SYMLINK, never a copy.
 * There is ONE binary per CLI, the user's NON-isolated copy (installed OUT of
 * band by the user-run daemon install script or the user themselves — the daemon
 * NEVER installs a vendor CLI). The isolated path under `<stateDir>/cli/<provider>/`
 * is always a symlink to that host binary; isolation is preserved by the RUN env
 * (`cliEnv` points HOME/config at the isolated dir), not by a separate binary, so
 * credentials + config never collide with the user's personal
 * `~/.claude` / `~/.codex` / `~/.kimi-code` while the binary itself is shared.
 *
 * `cliInstallState` is the single chokepoint every delegate's `installed`/`status`
 * reads (run on every status push). It is SELF-HEALING: if the isolated symlink is
 * missing but the host binary exists, it links it before probing — so a CLI the
 * user just installed shows up on the next status push with no command. The
 * host-binary candidate paths live in `cli-paths.ts` (`hostCliCandidates`).
 */
import { existsSync, symlinkSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { dirname } from "node:path";
import type { TCliProvider } from "./cli-paths";
import {
  cliBin,
  cliConfigDir,
  cliEnv,
  cliHome,
  cliRoot,
  hostCliCandidates,
} from "./cli-paths";
import { runCapture } from "./delegation/util";

export type TCliInstallState = {
  readonly installed: boolean;
  readonly version: string | null;
};

/** Create the isolated provider dirs (root + home + config) before a write. */
const ensureIsolatedDirs = async (provider: TCliProvider): Promise<void> => {
  await mkdir(cliRoot(provider), { recursive: true });
  await mkdir(cliHome(provider), { recursive: true });
  await mkdir(cliConfigDir(provider), { recursive: true });
};

/**
 * Point the isolated CLI path (`cliBin(provider)`) at the host binary via a
 * SYMLINK — never a copy, so the isolated CLI takes no disk space. Replaces any
 * existing link/file at the isolated path so it always tracks the current host
 * binary (e.g. after the user updates their CLI). Writes ONLY into the
 * always-granted state dir (`<stateDir>/cli/<provider>/`); it merely READS the
 * host binary, so it needs no grant on the host CLI's own dir.
 */
export const linkIsolatedCli = async (
  provider: TCliProvider,
  hostBin: string,
): Promise<void> => {
  await ensureIsolatedDirs(provider);
  const dst = cliBin(provider);
  await mkdir(dirname(dst), { recursive: true });
  await rm(dst, { force: true });
  symlinkSync(hostBin, dst);
};

/**
 * Is the vendor CLI the daemon runs installed + runnable? SELF-HEALING: the
 * daemon never installs, so the isolated run-view symlink is created lazily here —
 * if `cliBin(provider)` is absent but the user's host binary exists
 * (`hostCliCandidates`), link it first, then probe. A user who installs the CLI
 * out of band (the daemon install script, or by hand) therefore shows as
 * installed on the next status read with no command. Best-effort version read.
 *
 * Results are cached for `CLI_INSTALL_STATE_TTL_MS` (default 30 s) so the
 * 2.5 s status watcher does not spawn `--version` on every tick. The version
 * of an installed CLI only changes on self-update, which restarts the daemon
 * anyway — so a short cache is safe for status accuracy.
 */

/** Cache TTL — 30 s balances accuracy against the 2.5 s status watcher. */
const CLI_INSTALL_STATE_TTL_MS = 30_000;

interface CliInstallCacheEntry {
  readonly result: TCliInstallState;
  readonly expiresAt: number;
}

/** Per-provider cache of `cliInstallState` results. */
const cliInstallStateCache = new Map<TCliProvider, CliInstallCacheEntry>();

/**
 * Clear the `cliInstallState` cache — used by tests that change
 * `OPENLLM_DAEMON_STATE_DIR` between calls, and by the self-update handler
 * after a CLI binary is swapped on disk.
 */
export const clearCliInstallStateCache = (): void => {
  cliInstallStateCache.clear();
};

export const cliInstallState = async (
  provider: TCliProvider,
): Promise<TCliInstallState> => {
  const cached = cliInstallStateCache.get(provider);
  if (cached !== undefined && cached.expiresAt > Date.now()) {
    return cached.result;
  }

  const bin = cliBin(provider);
  if (!existsSync(bin)) {
    // No isolated run-view yet — link it from the host binary if that exists.
    const host = hostCliCandidates(provider).find((c) => existsSync(c));
    if (host === undefined) {
      const result: TCliInstallState = { installed: false, version: null };
      cliInstallStateCache.set(provider, {
        result,
        expiresAt: Date.now() + CLI_INSTALL_STATE_TTL_MS,
      });
      return result;
    }
    await linkIsolatedCli(provider, host);
  }
  const notInstalled: TCliInstallState = { installed: false, version: null };
  if (!existsSync(bin)) {
    cliInstallStateCache.set(provider, {
      result: notInstalled,
      expiresAt: Date.now() + CLI_INSTALL_STATE_TTL_MS,
    });
    return notInstalled;
  }
  const out = await runCapture([bin, "--version"], cliEnv(provider));
  const version = out?.match(/\d+\.\d+\.\d+/)?.[0] ?? null;
  const result: TCliInstallState = { installed: true, version };
  cliInstallStateCache.set(provider, {
    result,
    expiresAt: Date.now() + CLI_INSTALL_STATE_TTL_MS,
  });
  return result;
};
