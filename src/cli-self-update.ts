/**
 * CLI (`openllm`) converger — the daemon keeps the INSTALLED CLI binary on
 * the cloud's pinned release, on the same auto-update tick and under the same
 * opt-out toggle as its own self-update (`self-update.ts`). One flow, one
 * toggle: disabling daemon auto-update pins the CLI too.
 *
 * Same converge-to-published policy (STRICTLY NEWER only — a republished
 * older tag never downgrades an installed CLI) and the same trust gates (SHA-256 of the
 * decompressed bytes against the published digest; atomic same-dir temp +
 * rename swap; darwin dequarantine + ad-hoc sign). Differences from the
 * daemon's own updater:
 *
 *   - No drain / no restart — the CLI is not this process; the swap is just a
 *     file replace. A running `openllm` keeps its old inode (POSIX rename).
 *   - The daemon NEVER installs the CLI — an absent binary at
 *     `~/.openllm/bin/openllm` (or the legacy `openllmc` path) is a skip, mirroring the vendor-CLI policy in
 *     `cli-install.ts`. Manual `openllm self-update` also still works — the two
 *     writers serialize through ONE cross-process lock dir
 *     (`updateLockDirFor(dest)`, `packages/protocol/update-lock.ts`) covering
 *     probe → backup → rename → legacy-link → attempt marker, so a race can
 *     never leave `.prev` unrelated to the final binary or `state.json`
 *     describing the other update.
 *   - Its own attempt SLOT (`cli`) in the shared `state.json` so a daemon
 *     attempt never masks a CLI attempt (or vice versa) — rejections are
 *     per-slot too (`rejectedUpdates.cli`), since a bad daemon build must not
 *     block the CLI's release of the same tag.
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  acquireUpdateLock,
  updateLockDirFor,
} from "@openllmsh/protocol/update-lock";
import { evaluateUpdatePolicy } from "@openllmsh/protocol/update-policy";
import { executableName } from "../../pty-native/session/local-runtime";
import type { TDaemonTarget } from "../release-types";
import { autoUpdateEnabled } from "./auto-update-pref";
import { invalidateMatchingCliVersionOutput } from "./cli-version-cache";
import { getCloudState } from "./config";
import { cliVersion, runCapture } from "./delegation/spawn";
import { daemonEnv, daemonUpdateRoute, stateDir } from "./env";
import { hardenMacBinary } from "./harden-binary";
import { logError, logInfo, logWarn, safeDiagnosticMessage } from "./logger";
import type { TSelfUpdateOutcome } from "./self-update";
import {
  currentTarget,
  DeterministicArtifactError,
  fetchBinary,
  fetchDigest,
  MAX_BINARY_BYTES,
  manualUpdateRemedy,
  prevBinaryPath,
  restorePreviousBinary,
  writePrevBinaryAtomic,
} from "./self-update";
import {
  autoUpdateSuspended,
  isUpdateRejected,
  readState,
  recentlyAttempted,
  recordAttempt,
  rejectUpdateVersion,
} from "./state-file";

/** Where the install script places the CLI (`~/.openllm/bin/openllm`). */
export const cliBinaryPath = (): string =>
  join(stateDir(), "bin", executableName("openllm"));

/** Pre-rename install location (`~/.openllm/bin/openllmc`) — still converged
 *  (and migrated to the new name) so existing machines pick up the renamed
 *  binary through auto-update alone. */
export const legacyCliBinaryPath = (): string =>
  join(stateDir(), "bin", executableName("openllmc"));

/**
 * DEV-ONLY override: an absolute path to a runnable `openllm` the daemon should
 * spawn/probe INSTEAD of the installed binary. Set by `scripts/dev.ts` (a shim
 * that execs the working-tree CLI source) so browser-triggered sessions run
 * this repo's CLI, not the shipped `~/.openllm/bin/openllm`. Unset in
 * production — `resolveOpenllmCli` then falls back to the installed paths, so
 * prod behaviour is unchanged. The self-update convergers deliberately do NOT
 * consult this (they must always converge the real installed binary).
 */
export const cliBinaryOverride = (): string | null => {
  const p = process.env.OPENLLM_CLI_PATH;
  return p !== undefined && p.length > 0 && existsSync(p) ? p : null;
};

/**
 * Resolve the `openllm` CLI the daemon should run: the dev override first (when
 * present + existing), then the installed binary (current name, then legacy).
 * Null when none exist. This is the ONE resolver every spawn/attach/probe site
 * shares so dev and prod never drift.
 */
export const resolveOpenllmCli = (): string | null =>
  cliBinaryOverride() ??
  [cliBinaryPath(), legacyCliBinaryPath()].find(existsSync) ??
  null;

/**
 * The installed CLI's version via the shared stamp-keyed `cliVersion` cache
 * (output `openllm vX.Y.Z`; legacy binaries print `openllmc vX.Y.Z`). Null
 * when the binary is absent, won't run, or prints something unparseable —
 * the converger then leaves it alone. Shares in-flight work with
 * `device-state`; an unchanged binary is not re-spawned.
 */
const parseProductCliVersion = (out: string | null): string | null =>
  out?.match(/openllmc? v(\S+)/)?.[1] ?? null;

const installedCliVersion = async (
  bin: string,
  opts?: { readonly reprobeUnknown?: boolean },
): Promise<string | null> => {
  const versionOpts =
    opts?.reprobeUnknown === true ? { reprobe: true } : undefined;
  const out = await cliVersion(bin, undefined, versionOpts);
  const parsed = parseProductCliVersion(out);
  if (parsed !== null) return parsed;
  if (opts?.reprobeUnknown !== true) return null;
  if (out === null) return null;
  if (!invalidateMatchingCliVersionOutput(bin, out)) return null;
  const again = await cliVersion(bin, undefined, { reprobe: true });
  return parseProductCliVersion(again);
};

// Re-entrancy guard: a bootstrap tick and a forced dashboard update could both
// fire `maybeUpdateCli`; only one download+swap should run. Independent of the
// daemon updater's flag — the two converge different files and may overlap.
let updating = false;

// The auto-update suspension (state file unwritable) logs once per process.
let cliGuardSuspensionWarned = false;

/**
 * Converge the installed `openllm` CLI to `latest` (the cloud's published CLI
 * version) when it differs. No-op (returns) when not applicable — auto-update
 * opted out, CLI not installed, dev-linked binary, already converged, unknown
 * target, no release, or a recent attempt. Never throws into the caller.
 *
 * Gated on the SAME preference as the daemon's self-update
 * ({@link autoUpdateEnabled}); an explicit user request (the dashboard's
 * "update now" command) passes `force: true` to bypass it.
 */
export type TMaybeUpdateCliOpts = {
  readonly force?: boolean;
  /**
   * Explicit `update` only. Bypass a process-local miss / invalidate one
   * unparseable product observation and allow a single recovery probe.
   * Not `force` (preference override). Bootstrap, periodic ticks, status
   * readers, and auto-update-enable catch-up must omit this.
   */
  readonly reprobeUnknown?: boolean;
};

/** Bound on the pre-swap `<binary> --self-test` health probe. */
const CLI_PROBE_TIMEOUT_MS = 10_000;
const CLI_PROBE_MAX_BYTES = 4_096;

/** How long the converger waits on the swap lock before yielding the tick. */
const CLI_UPDATE_LOCK_WAIT_MS = 30_000;

/**
 * Download → verify → probe → backup → swap the installed CLI to `latest`.
 * Mirrors {@link applyDaemonSelfUpdate}: every failure stage records a try so
 * the next tick backs off, deterministic artifact failures reject the version
 * permanently, and the current binary is kept at `<dest>.prev` (written via
 * temp + fsync + rename) for rollback. The pre-swap probe runs `--self-test`
 * (not `--version`): the CLI's version print exits BEFORE the lazy command
 * graph loads, so it can't catch a binary that crashes on every real command;
 * `--self-test` loads the whole graph and prints the same version line.
 */
export const applyCliSelfUpdate = async (args: {
  /** Canonical install path the new binary lands on (`cliBinaryPath()`). */
  readonly dest: string;
  /** The existing binary to keep as `<dest>.prev` (may be the legacy path). */
  readonly backupOf: string;
  readonly latest: string;
  readonly target: TDaemonTarget;
  readonly origin: string;
  /** Legacy `openllmc` path to replace with a compat symlink after the swap. */
  readonly legacySymlink?: string;
  readonly maxBytes?: number;
  readonly probeVersion?: (path: string) => Promise<string | null>;
  /** Test override for the swap-lock wait window. */
  readonly lockWaitMs?: number;
}): Promise<TSelfUpdateOutcome> => {
  const { dest, backupOf, latest, target, origin } = args;
  const maxBytes = args.maxBytes ?? MAX_BINARY_BYTES;
  const probe =
    args.probeVersion ??
    // `--self-test`, NOT `--version` (see the doc comment above): the probe
    // must prove the staged binary loads its whole command graph, not just
    // that its pre-lazy-import version print works.
    ((path: string): Promise<string | null> =>
      runCapture([path, "--self-test"], undefined, {
        kind: "probe",
        probe: true,
        timeoutMs: CLI_PROBE_TIMEOUT_MS,
        maxBytes: CLI_PROBE_MAX_BYTES,
      }));
  const tmp = join(dirname(dest), `.openllm.update.${process.pid}.tmp`);
  const cleanupTmp = (): void => {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
  };
  try {
    const base = `${origin}/api/cli/binary/${target}`;
    // Digest first — the advertised sha256 is the rejection key, and a
    // rejected artifact must not spend the ~40 MB download again.
    let expected: string;
    try {
      expected = await fetchDigest(`${base}.sha256`);
    } catch (err) {
      recordAttempt("cli", latest, {
        digest:
          err instanceof DeterministicArtifactError
            ? err.artifactKey
            : undefined,
      });
      if (err instanceof DeterministicArtifactError) {
        // Malformed/oversized digest body — deterministic; reject keyed to
        // the content that failed so a corrected re-publish is allowed.
        rejectUpdateVersion("cli", latest, err.artifactKey ?? "");
      }
      return {
        kind: "failed",
        stage: "download",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    if (isUpdateRejected("cli", latest, expected)) {
      // This exact advertised artifact already failed deterministic checks —
      // a corrected re-publish advertises a different digest and passes.
      recordAttempt("cli", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "rejected",
        detail: `v${latest} artifact ${expected.slice(0, 12)}… previously failed deterministic checks`,
      };
    }
    let bytes: Buffer;
    try {
      bytes = await fetchBinary(base, maxBytes);
    } catch (err) {
      recordAttempt("cli", latest, { digest: expected });
      if (err instanceof DeterministicArtifactError) {
        // Oversize / bad gzip — the advertised artifact can never succeed;
        // reject keyed to its digest instead of looping the download.
        rejectUpdateVersion("cli", latest, expected);
      }
      return {
        kind: "failed",
        stage: "download",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== expected) {
      // Mis-published artifact: deterministic — reject permanently.
      rejectUpdateVersion("cli", latest, expected);
      recordAttempt("cli", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "checksum",
        detail: `expected ${expected}, got ${actual}`,
      };
    }
    try {
      writeFileSync(tmp, bytes, { mode: 0o755 });
      chmodSync(tmp, 0o755); // force mode regardless of umask
    } catch (err) {
      recordAttempt("cli", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "write",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    hardenMacBinary(tmp); // sign before the probe so arm64 can exec it
    // Cross-process swap lock: `openllm self-update` races this converger over
    // the same dest + `.prev`. Serialize probe → backup → rename → link →
    // attempt marker so an interleave can't leave a mismatched pair. A held
    // lock is not a failure — report busy and let the next tick retry.
    const release = await acquireUpdateLock(updateLockDirFor(dest), {
      waitMs: args.lockWaitMs ?? CLI_UPDATE_LOCK_WAIT_MS,
    });
    if (release === null) {
      cleanupTmp();
      return { kind: "busy" };
    }
    try {
      const out = await probe(tmp);
      if (parseProductCliVersion(out) !== latest) {
        rejectUpdateVersion("cli", latest, expected);
        recordAttempt("cli", latest, { digest: expected });
        cleanupTmp();
        return {
          kind: "failed",
          stage: "probe",
          detail:
            out === null
              ? "binary did not run"
              : `expected v${latest}, got ${out.trim().slice(0, 200)}`,
        };
      }
      try {
        // Mode-preserving temp + fsync + rename copy — the rollback copy
        // lands runnable and can never be torn by a crash mid-write.
        writePrevBinaryAtomic(backupOf, prevBinaryPath(dest));
      } catch (err) {
        recordAttempt("cli", latest, { digest: expected });
        cleanupTmp();
        return {
          kind: "failed",
          stage: "write",
          detail: `rollback backup failed: ${
            err instanceof Error ? err.message : String(err)
          }`,
        };
      }
      renameSync(tmp, dest); // atomic on POSIX; a running CLI keeps its inode
      hardenMacBinary(dest); // dequarantine + ad-hoc sign so arm64 can exec it
      if (args.legacySymlink !== undefined) {
        // Replace the old binary file with a transitional symlink so
        // absolute-path callers (old MCP entries, hooks) keep working.
        try {
          rmSync(args.legacySymlink, { force: true });
          symlinkSync(dest, args.legacySymlink);
        } catch {
          // best-effort — the new path is authoritative either way
        }
      }
      recordAttempt("cli", latest, { digest: expected });
      return { kind: "updated" };
    } finally {
      release();
    }
  } catch (err) {
    recordAttempt("cli", latest);
    cleanupTmp();
    return {
      kind: "failed",
      stage: "write",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
};

export const maybeUpdateCli = async (
  latest: string | null,
  opts?: TMaybeUpdateCliOpts,
): Promise<void> => {
  if (updating) return;
  if (opts?.force !== true && !autoUpdateEnabled()) return;
  if (latest === null || latest.length === 0) return;
  const origin = daemonEnv().cloudOrigin;
  // Never act on a stale snapshot: `latest_cli_version` is last-good data
  // while the cloud is degraded — and the binary endpoints live on the same
  // service. A forced (explicit user) check may still try.
  if (opts?.force !== true && getCloudState() !== "ok") return;
  let bin = cliBinaryPath();
  // Rename migration: a machine installed before the openllmc → openllm
  // rename has only the legacy path. Converge THAT file — the swap below
  // writes the renamed binary to the NEW path and leaves a compat symlink.
  const legacy = legacyCliBinaryPath();
  const legacyOnly = !existsSync(bin) && existsSync(legacy);
  if (legacyOnly) bin = legacy;
  // The daemon never installs the CLI — absent means skip, not install.
  if (!existsSync(bin)) return;
  let current = await installedCliVersion(bin, {
    reprobeUnknown: opts?.reprobeUnknown === true,
  });
  if (current === null) {
    // Self-heal (TCB-3): a converger swap that left a binary which cannot even
    // report `--version` wedges the CLI forever — this lane would keep skipping
    // on `current === null`. If a recorded attempt exists and the `.prev`
    // backup is still there AND still runs, roll back once and pin the bad
    // version rejected. The restore happens under the SAME swap lock the
    // updater uses so it can't race a manual `openllm self-update` mid-swap.
    const attempt = readState().updateAttempts.cli;
    const healLockDir = updateLockDirFor(cliBinaryPath());
    const release =
      !legacyOnly && attempt !== undefined
        ? await acquireUpdateLock(healLockDir, {
            waitMs: CLI_UPDATE_LOCK_WAIT_MS,
          })
        : null;
    try {
      if (
        !legacyOnly &&
        attempt !== undefined &&
        release !== null &&
        restorePreviousBinary(cliBinaryPath())
      ) {
        rejectUpdateVersion("cli", attempt.version, attempt.digest ?? "");
        logError(
          "cli-update",
          `installed openllm CLI could not run after the v${attempt.version} update — restored ${prevBinaryPath(cliBinaryPath())}; v${attempt.version} will not be reinstalled`,
        );
        bin = cliBinaryPath();
        current = await installedCliVersion(bin, { reprobeUnknown: true });
        if (current === null) {
          logWarn(
            "cli-update",
            safeDiagnosticMessage`restored openllm CLI still did not report a version — skipping`,
          );
          return;
        }
      } else {
        logWarn(
          "cli-update",
          `installed openllm CLI did not report a version — skipping; ${manualUpdateRemedy(origin)}`,
        );
        return;
      }
    } finally {
      release?.();
    }
  }
  // A from-source dev link never auto-updates (same guard as both updaters).
  if (current === "0.0.0-dev") return;
  if (current === latest) return; // already converged
  // Fail closed (round-3): an unpersisted deterministic reject means other
  // processes can retry the bad artifact — do not join the churn until a
  // state write lands. One log line per process.
  if (autoUpdateSuspended()) {
    if (!cliGuardSuspensionWarned) {
      cliGuardSuspensionWarned = true;
      logWarn(
        "cli-update",
        "update state is not writable — CLI auto-update suspended until rejection guards can be persisted",
      );
    }
    return;
  }
  const verdict = evaluateUpdatePolicy({
    currentVersion: current,
    latestVersion: latest,
    ...daemonUpdateRoute(),
  });
  if (!verdict.allow) {
    logInfo(
      "cli-update",
      `refusing openllm CLI ${current} → ${latest}: ${verdict.reason ?? "update policy"} — ${manualUpdateRemedy(origin)}`,
    );
    return;
  }
  const target = currentTarget();
  if (target === null) {
    // No prebuilt binary for this arch — the openllm CLI repo README documents
    // building the host binary (`bun run compile:host`).
    logWarn(
      "cli-update",
      `unsupported host ${process.platform}-${process.arch} — no prebuilt openllm CLI for this arch; build from source: https://github.com/openllmsh/cli#build-from-source`,
    );
    return;
  }
  if (isUpdateRejected("cli", latest)) {
    logInfo(
      "cli-update",
      `openllm CLI v${latest} was rejected on this host (failed its post-download check) — it will not be reinstalled; ${manualUpdateRemedy(origin)}`,
    );
    return;
  }
  if (recentlyAttempted("cli", latest)) return;

  updating = true;
  const dest = cliBinaryPath(); // always land on the NEW name
  try {
    const outcome = await applyCliSelfUpdate({
      dest,
      backupOf: bin,
      latest,
      target,
      origin,
      ...(legacyOnly ? { legacySymlink: legacy } : {}),
    });
    if (outcome.kind === "updated") {
      logInfo("cli-update", `updated openllm CLI ${current} → ${latest}`);
      return;
    }
    if (outcome.kind === "busy") {
      logInfo(
        "cli-update",
        `openllm CLI swap lock is held by another update — retrying on the next tick`,
      );
      return;
    }
    if (outcome.stage === "checksum") {
      logError(
        "cli-update",
        safeDiagnosticMessage`checksum mismatch — refusing update`,
        { target, latest, detail: outcome.detail ?? "" },
      );
    } else if (outcome.stage === "probe") {
      logError(
        "cli-update",
        `downloaded openllm CLI v${latest} failed its pre-swap --self-test check (${outcome.detail ?? "unknown"}) — rejected; ${manualUpdateRemedy(origin)}`,
        { target, latest },
      );
    } else {
      logError("cli-update", outcome.detail ?? outcome.stage, {
        target,
        latest,
        stage: outcome.stage,
      });
    }
  } catch (err) {
    logError("cli-update", err, { target, latest });
  } finally {
    updating = false; // no exit path here — always allow the next attempt
  }
};
