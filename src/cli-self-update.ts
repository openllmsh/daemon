/**
 * CLI (`openllmc`) converger — the daemon keeps the INSTALLED CLI binary on
 * the cloud's pinned release, on the same auto-update tick and under the same
 * opt-out toggle as its own self-update (`self-update.ts`). One flow, one
 * toggle: disabling daemon auto-update pins the CLI too.
 *
 * Same converge-to-published policy (update on ANY mismatch, so republishing
 * an older tag rolls CLIs back) and the same trust gates (SHA-256 of the
 * decompressed bytes against the published digest; atomic same-dir temp +
 * rename swap; darwin dequarantine + ad-hoc sign). Differences from the
 * daemon's own updater:
 *
 *   - No drain / no restart — the CLI is not this process; the swap is just a
 *     file replace. A running `openllmc` keeps its old inode (POSIX rename).
 *   - The daemon NEVER installs the CLI — an absent binary at
 *     `~/.openllm/bin/openllmc` is a skip, mirroring the vendor-CLI policy in
 *     `cli-install.ts`. Manual `openllmc self-update` also still works; both
 *     paths write verified bytes via distinct pid-suffixed temps, so a race is
 *     last-writer-wins with a complete binary either way.
 *   - Its own attempt cooldown file (`cli-update-state.json`) so a daemon
 *     attempt never masks a CLI attempt (or vice versa).
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { autoUpdateEnabled } from "./auto-update-pref";
import { cliVersion } from "./delegation/util";
import { daemonEnv, stateDir } from "./env";
import { hardenMacBinary } from "./harden-binary";
import { logError, logInfo, logWarn } from "./logger";
import { currentTarget, fetchBinary, fetchDigest } from "./self-update";

// Don't retry the SAME target version within this window after a swap that
// didn't converge (a mis-published release) — bounds repeated downloads.
const ATTEMPT_COOLDOWN_MS = 60 * 60 * 1000;

/** Where the install script places the CLI (`~/.openllm/bin/openllmc`). */
export const cliBinaryPath = (): string => join(stateDir(), "bin", "openllmc");

type TAttempt = { readonly version: string; readonly ts: number };

const attemptFile = (): string => join(stateDir(), "cli-update-state.json");

const recentlyAttempted = (version: string): boolean => {
  try {
    const raw = JSON.parse(readFileSync(attemptFile(), "utf-8")) as TAttempt;
    return raw.version === version && Date.now() - raw.ts < ATTEMPT_COOLDOWN_MS;
  } catch {
    return false;
  }
};

const recordAttempt = (version: string): void => {
  try {
    writeFileSync(
      attemptFile(),
      JSON.stringify({ version, ts: Date.now() } satisfies TAttempt),
      { mode: 0o600 },
    );
  } catch {
    // best-effort — the in-memory `updating` guard still prevents a tight loop
  }
};

/**
 * The installed CLI's version, probed by spawning `openllmc --version`
 * (output `openllmc vX.Y.Z`). Null when the binary is absent, won't run, or
 * prints something unparseable — the converger then leaves it alone.
 */
const installedCliVersion = async (bin: string): Promise<string | null> => {
  const out = await cliVersion(bin);
  return out?.match(/openllmc v(\S+)/)?.[1] ?? null;
};

// Re-entrancy guard: a bootstrap tick and a forced dashboard update could both
// fire `maybeUpdateCli`; only one download+swap should run. Independent of the
// daemon updater's flag — the two converge different files and may overlap.
let updating = false;

/**
 * Converge the installed `openllmc` to `latest` (the cloud's published CLI
 * version) when it differs. No-op (returns) when not applicable — auto-update
 * opted out, CLI not installed, dev-linked binary, already converged, unknown
 * target, no release, or a recent attempt. Never throws into the caller.
 *
 * Gated on the SAME preference as the daemon's self-update
 * ({@link autoUpdateEnabled}); an explicit user request (the dashboard's
 * "update now" command) passes `force: true` to bypass it.
 */
export const maybeUpdateCli = async (
  latest: string | null,
  opts?: { readonly force?: boolean },
): Promise<void> => {
  if (updating) return;
  if (opts?.force !== true && !autoUpdateEnabled()) return;
  if (latest === null || latest.length === 0) return;
  const bin = cliBinaryPath();
  // The daemon never installs the CLI — absent means skip, not install.
  if (!existsSync(bin)) return;
  const current = await installedCliVersion(bin);
  if (current === null) {
    logWarn(
      "cli-update",
      "installed openllmc did not report a version — skipping",
    );
    return;
  }
  // A from-source dev link never auto-updates (same guard as both updaters).
  if (current === "0.0.0-dev") return;
  if (current === latest) return; // already converged
  const target = currentTarget();
  if (target === null) {
    logWarn("cli-update", `unknown target ${process.platform}-${process.arch}`);
    return;
  }
  if (recentlyAttempted(latest)) return;

  updating = true;
  const tmp = join(dirname(bin), `.openllmc.update.${process.pid}.tmp`);
  try {
    const origin = daemonEnv().cloudOrigin;
    const base = `${origin}/api/cli/binary/${target}`;
    const [bytes, expected] = await Promise.all([
      fetchBinary(base),
      fetchDigest(`${base}.sha256`),
    ]);
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== expected) {
      logError("cli-update", "checksum mismatch — refusing update", {
        target,
        latest,
        expected,
        actual,
      });
      return;
    }
    writeFileSync(tmp, bytes, { mode: 0o755 });
    chmodSync(tmp, 0o755); // force mode regardless of umask
    renameSync(tmp, bin); // atomic on POSIX; a running openllmc keeps its inode
    hardenMacBinary(bin); // dequarantine + ad-hoc sign so arm64 can exec it
    // Record only AFTER a successful swap — a transient download failure should
    // retry on the next tick, but a swap that doesn't converge (mis-publish)
    // must back off.
    recordAttempt(latest);
    logInfo("cli-update", `updated openllmc ${current} → ${latest}`);
  } catch (err) {
    logError("cli-update", err, { target, latest });
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
  } finally {
    updating = false; // no exit path here — always allow the next attempt
  }
};
