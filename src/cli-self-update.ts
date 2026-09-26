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
 *     (`updateLockDirFor(dest)`, `packages/tunnel/update-lock.ts`) covering
 *     probe → backup → rename → legacy-link → attempt marker, so a race can
 *     never leave `.prev` unrelated to the final binary or `state.json`
 *     describing the other update.
 *   - Its own attempt SLOT (`cli`) in the shared `state.json` so a daemon
 *     attempt never masks a CLI attempt (or vice versa) — rejections are
 *     per-slot too (`rejectedUpdates.cli`), since a bad daemon build must not
 *     block the CLI's release of the same tag.
 */

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { evaluateUpdatePolicy } from "@openllmsh/protocol/update-policy";
import {
  acquireUpdateLock,
  updateLockDirFor,
} from "@openllmsh/tunnel/update-lock";
import { executableName } from "../../tunnel/session/local-runtime";
import type { TDaemonTarget } from "../release-types";
import { autoUpdateEnabled } from "./auto-update-pref";
import { invalidateMatchingCliVersionOutput } from "./cli-version-cache";
import { getCloudState } from "./config";
import { cliVersion } from "./delegation/spawn";
import { daemonEnv, daemonUpdateRoute, stateDir } from "./env";
import { hardenMacBinary } from "./harden-binary";
import { logError, logInfo, logWarn, safeDiagnosticMessage } from "./logger";
import type {
  TBinaryProbeVerdict,
  TDownloadBounds,
  TSelfUpdateOutcome,
} from "./self-update";
import {
  currentTarget,
  DeterministicArtifactError,
  fetchBinary,
  fetchDigest,
  fsyncFileSync,
  MAX_BINARY_BYTES,
  manualUpdateRemedy,
  prevBinaryPath,
  probeBinaryVerdict,
  restorePreviousBinary,
  sweepStaleUpdateTemps,
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
  // FSS-05: never let a missing/unwritable system TMPDIR decide whether the
  // CLI counts as installed — the binary's own directory is the one we can
  // always write (it holds the staged update during a swap).
  const probeEnv = { TMPDIR: dirname(bin) };
  const out = await cliVersion(bin, probeEnv, versionOpts);
  const parsed = parseProductCliVersion(out);
  if (parsed !== null) return parsed;
  if (opts?.reprobeUnknown !== true) return null;
  if (out === null) return null;
  if (!invalidateMatchingCliVersionOutput(bin, out)) return null;
  const again = await cliVersion(bin, probeEnv, { reprobe: true });
  return parseProductCliVersion(again);
};

/** sha256 of an installed binary, or null when it cannot be read. */
const sha256File = (path: string): string | null => {
  try {
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  } catch {
    return null;
  }
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

/**
 * Self-heal bounds (RT-2/TD-5/FSS-04): the SECOND `--version` probe that may
 * precede a `.prev` restore gets a long leash — a slow first run must still
 * be able to prove the binary healthy before we touch it. The version-only
 * fallback path also requires the recorded attempt to be RECENT — an
 * attempt older than this cannot explain a binary found broken today.
 */
const CLI_HEAL_PROBE_TIMEOUT_MS = 60_000;
const CLI_HEAL_ATTEMPT_MAX_AGE_MS = 10 * 60_000;

/** How long the converger waits on the swap lock before yielding the tick. */
const CLI_UPDATE_LOCK_WAIT_MS = 30_000;

/**
 * Set while `applyCliSelfUpdate` holds the swap lock (UP-3): the daemon's
 * post-swap restart drains disposable children — a probe killed mid-swap used
 * to look like a dead binary and get a good release rejected. The probe now
 * holds a task lease, and `maybeSelfUpdate` awaits this marker so the swap
 * region lands before the drain runs.
 */
let cliSwapInFlightRegion: Promise<void> | null = null;
export const cliSwapInFlight = (): Promise<void> | null =>
  cliSwapInFlightRegion;

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
  /** The version this converge observed installed when it decided to update.
   *  UP-4: the lock re-checks it so a manual update that landed during our
   *  download is never overwritten by stale bytes. */
  readonly expectedInstalled?: string | null;
  /** Test seam: full verdict probe for the staged binary (UP-2/UP-3). */
  readonly probeVerdict?: (
    path: string,
    flag: "--version" | "--self-test",
  ) => Promise<TBinaryProbeVerdict>;
  /** Test seam: shorten the staged probe bound. */
  readonly probeTimeoutMs?: number;
  /** Test seam: tighten the download stall/total/connect bounds (NR2-2). */
  readonly download?: TDownloadBounds & { readonly connectMs?: number };
  /**
   * Test seam: observe/override the durability steps (FSS-18). The required
   * order is harden-staged → fsync file → probe → backup → rename → symlink
   * → fsync dir; a test records the sequence and can make a step throw.
   */
  readonly hooks?: {
    readonly fsyncFile?: (path: string) => void;
    readonly fsyncDir?: (dir: string) => void;
    readonly harden?: (path: string) => void;
    readonly onWarn?: (message: string) => void;
  };
}): Promise<TSelfUpdateOutcome> => {
  const { dest, backupOf, latest, target, origin } = args;
  const maxBytes = args.maxBytes ?? MAX_BINARY_BYTES;
  const fsyncFile = args.hooks?.fsyncFile ?? fsyncFileSync;
  const fsyncDir = args.hooks?.fsyncDir ?? fsyncFileSync;
  const harden = args.hooks?.harden ?? hardenMacBinary;
  const onWarn =
    args.hooks?.onWarn ?? ((message: string) => logWarn("cli-update", message));
  const verdictProbe =
    args.probeVerdict ??
    ((path: string, flag: "--version" | "--self-test") =>
      probeBinaryVerdict(path, flag, {
        timeoutMs: args.probeTimeoutMs ?? CLI_PROBE_TIMEOUT_MS,
        maxBytes: CLI_PROBE_MAX_BYTES,
      }));
  // FSS-16/UP-1: unique staging name + sweep temps a dead updater left behind.
  sweepStaleUpdateTemps(dirname(dest));
  const tmp = join(
    dirname(dest),
    `.openllm.update.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
  );
  try {
    const base = `${origin}/api/cli/binary/${target}`;
    // Digest first — the advertised sha256 is the rejection key, and a
    // rejected artifact must not spend the ~40 MB download again.
    let expected: string;
    try {
      expected = await fetchDigest(`${base}.sha256`, args.download);
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
      bytes = await fetchBinary(base, maxBytes, args.download);
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
      // Sign/dequarantine the STAGED bytes before the fsync AND before the
      // probe: the probe must exec the file in its final state, and the fsync
      // must make that SAME final state durable — hardening after the fsync
      // would leave the xattr changes outside the durability point (FSS-18).
      harden(tmp);
      // FSS-18: fsync the staged bytes before the rename lands on `dest`.
      fsyncFile(tmp);
    } catch (err) {
      recordAttempt("cli", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "write",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    // Cross-process swap lock: `openllm self-update` races this converger over
    // the same dest + `.prev`. The lock covers the DECISION too (UP-4): the
    // installed version is re-read inside it so a manual update that landed
    // during our download is never overwritten by stale bytes.
    const release = await acquireUpdateLock(updateLockDirFor(dest), {
      waitMs: args.lockWaitMs ?? CLI_UPDATE_LOCK_WAIT_MS,
    });
    if (release === null) {
      return { kind: "busy" };
    }
    let markSwapDone: () => void = () => {};
    cliSwapInFlightRegion = new Promise<void>((resolve) => {
      markSwapDone = resolve;
    });
    try {
      // UP-4: re-check what is installed NOW. A manual `openllm self-update`
      // that finished while we downloaded already landed `latest` — proceed
      // only when the file is still the one this converge set out to replace.
      const anchor = existsSync(dest)
        ? dest
        : existsSync(backupOf)
          ? backupOf
          : null;
      if (anchor !== null) {
        const installedVerdict = await verdictProbe(anchor, "--version");
        if (installedVerdict.kind === "inconclusive") {
          // The probe never judged the installed file (timeout, drained
          // child, transient spawn failure) — we cannot prove it is still
          // the version this converge set out to replace. Overwriting on an
          // UNPROVEN recheck could clobber a concurrent manual update with
          // stale bytes, so yield the tick instead.
          return { kind: "busy" };
        }
        const installedNow =
          installedVerdict.kind === "ok"
            ? parseProductCliVersion(installedVerdict.out)
            : null;
        if (installedNow === latest) {
          recordAttempt("cli", latest, { digest: expected });
          return { kind: "updated" };
        }
        if (
          installedNow !== null &&
          args.expectedInstalled !== undefined &&
          installedNow !== args.expectedInstalled
        ) {
          // The installed file changed under our download — a concurrent
          // updater owns it now. Nothing is recorded; the next tick
          // re-evaluates against the NEW binary.
          return { kind: "busy" };
        }
        // installedNow === null can only remain after a `failed` verdict —
        // the installed file provably cannot run, so overwriting it with a
        // verified binary heals rather than clobbers a working update.
      }
      if (args.probeVersion !== undefined) {
        // Legacy contract (tests): null output = a completed probe with no
        // version banner — a deterministic artifact failure.
        const out = await args.probeVersion(tmp);
        if (parseProductCliVersion(out) !== latest) {
          rejectUpdateVersion("cli", latest, expected);
          recordAttempt("cli", latest, { digest: expected });
          return {
            kind: "failed",
            stage: "probe",
            detail:
              out === null
                ? "binary did not run"
                : `expected v${latest}, got ${out.trim().slice(0, 200)}`,
          };
        }
      } else {
        // `--self-test`, NOT `--version` (see the doc comment above): the
        // probe must prove the staged binary loads its whole command graph.
        const verdict = await verdictProbe(tmp, "--self-test");
        if (verdict.kind === "inconclusive") {
          // UP-2/TD-5: a timed-out or drain-killed probe never judged the
          // bytes — record the try, back off, do NOT reject the artifact.
          recordAttempt("cli", latest, { digest: expected });
          return {
            kind: "failed",
            stage: "probe-inconclusive",
            detail: verdict.detail,
          };
        }
        const probed =
          verdict.kind === "ok" ? parseProductCliVersion(verdict.out) : null;
        if (probed !== latest) {
          rejectUpdateVersion("cli", latest, expected);
          recordAttempt("cli", latest, { digest: expected });
          return {
            kind: "failed",
            stage: "probe",
            detail:
              verdict.kind === "failed"
                ? `binary did not run: ${verdict.detail}`
                : `expected v${latest}, got ${verdict.out.slice(0, 200)}`,
          };
        }
      }
      try {
        // Mode-preserving temp + fsync + rename copy — the rollback copy
        // lands runnable and can never be torn by a crash mid-write.
        writePrevBinaryAtomic(backupOf, prevBinaryPath(dest));
      } catch (err) {
        recordAttempt("cli", latest, { digest: expected });
        return {
          kind: "failed",
          stage: "write",
          detail: `rollback backup failed: ${
            err instanceof Error ? err.message : String(err)
          }`,
        };
      }
      renameSync(tmp, dest); // atomic on POSIX; a running CLI keeps its inode
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
      // FSS-18: fsync the directory so the rename's (and compat symlink's)
      // dirents survive a crash. This is the LAST filesystem step — nothing
      // may mutate the install dir after it. A refusal does not un-swap the
      // binary, but it must not be silent.
      try {
        fsyncDir(dirname(dest));
      } catch (err) {
        onWarn(
          `post-swap directory fsync failed — openllm CLI v${latest} is installed but not proven crash-durable: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
      recordAttempt("cli", latest, { digest: expected });
      return { kind: "updated" };
    } finally {
      cliSwapInFlightRegion = null;
      markSwapDone();
      release();
    }
  } catch (err) {
    recordAttempt("cli", latest);
    return {
      kind: "failed",
      stage: "write",
      detail: err instanceof Error ? err.message : String(err),
    };
  } finally {
    // FSS-16: the staging temp never survives an exit path — success renamed
    // it away, and every failure/throw path reaches here.
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
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
  // UP-1: claim this converge BEFORE the first await — the early checks are
  // all synchronous, so setting the flag here is the only correct point.
  if (updating) return;
  updating = true;
  try {
    return await convergeCli(latest, opts, bin, legacyOnly, origin);
  } finally {
    updating = false;
  }
};

/**
 * The converge body, run under the `updating` flag. Split so the flag can be
 * set synchronously before ANY await (UP-1).
 */
const convergeCli = async (
  latest: string,
  opts: TMaybeUpdateCliOpts | undefined,
  bin: string,
  legacyOnly: boolean,
  origin: string,
): Promise<void> => {
  let current = await installedCliVersion(bin, {
    reprobeUnknown: opts?.reprobeUnknown === true,
  });
  if (current === null) {
    // Self-heal (TCB-3): a converger swap that left a binary which cannot even
    // report `--version` wedges the CLI forever — this lane would keep
    // skipping on `current === null`.
    //
    // RT-2/TD-5/FSS-04: ONE failed or timed-out probe is NEVER proof of a
    // dead binary — a slow first run, a drained probe child, or a broken
    // TMPDIR caches the same `null` a crashed binary produces. So: re-probe
    // ONCE with a long bound (a slow-but-healthy binary still proves itself),
    // then restore `.prev` ONLY when a recent attempt record names THIS
    // artifact — a digest match, or an attempt for the version we would
    // install — AND the attempt is RECENT: an attempt older than
    // `CLI_HEAL_ATTEMPT_MAX_AGE_MS` cannot explain a binary found broken
    // today (it ran fine in between, so today's failure has another cause).
    // A probe that stays inconclusive NEVER heals and NEVER rejects: the
    // bytes were not judged.
    const second = await probeBinaryVerdict(bin, "--version", {
      timeoutMs: CLI_HEAL_PROBE_TIMEOUT_MS,
    });
    if (second.kind === "ok") {
      current = parseProductCliVersion(second.out);
      // An exit-0 with an unparseable banner still counts as broken below.
    }
    if (current === null) {
      const provablyBroken =
        second.kind === "failed" ||
        (second.kind === "ok" && parseProductCliVersion(second.out) === null);
      const attempt = readState().updateAttempts.cli;
      let healed = false;
      if (!legacyOnly && provablyBroken && attempt !== undefined) {
        const binDigest = sha256File(bin);
        // Round-3 rework: BOTH proofs are age-bounded. A digest match proves
        // WHICH binary the attempt produced, but an attempt from days ago
        // cannot explain a binary that only broke today — restoring `.prev`
        // and rejecting on that evidence would downgrade a CLI the attempt
        // did not break.
        const attemptFresh =
          Date.now() - attempt.ts <= CLI_HEAL_ATTEMPT_MAX_AGE_MS;
        // The attempt's recorded artifact digest matches the installed bytes
        // → the attempt unambiguously describes this binary.
        const artifactProven =
          attemptFresh &&
          binDigest !== null &&
          attempt.digest !== undefined &&
          attempt.digest.length > 0 &&
          attempt.digest === binDigest;
        // Version-only fallback: the attempt is for the version we would
        // install AND is fresh enough to plausibly have produced the binary.
        const recentMatch =
          attemptFresh && binDigest !== null && attempt.version === latest;
        if (binDigest !== null && (artifactProven || recentMatch)) {
          // Restore under the SAME swap lock the updater uses, and re-check
          // the digest inside it — a file swapped while we probed is not
          // ours to roll back.
          const release = await acquireUpdateLock(
            updateLockDirFor(cliBinaryPath()),
            { waitMs: CLI_UPDATE_LOCK_WAIT_MS },
          );
          if (release !== null) {
            try {
              if (
                sha256File(cliBinaryPath()) === binDigest &&
                restorePreviousBinary(cliBinaryPath())
              ) {
                // Key the reject to the bad bytes — never a blank/version-wide
                // wildcard (a corrected re-publish must be allowed through).
                rejectUpdateVersion("cli", attempt.version, binDigest);
                logError(
                  "cli-update",
                  `installed openllm CLI could not run after the v${attempt.version} update — restored ${prevBinaryPath(cliBinaryPath())}; v${attempt.version} will not be reinstalled`,
                );
                healed = true;
              }
            } finally {
              release();
            }
          }
        }
      }
      if (!healed) {
        logWarn(
          "cli-update",
          `installed openllm CLI did not report a version — skipping; ${manualUpdateRemedy(origin)}`,
        );
        return;
      }
      bin = cliBinaryPath();
      current = await installedCliVersion(bin, { reprobeUnknown: true });
      if (current === null) {
        logWarn(
          "cli-update",
          safeDiagnosticMessage`restored openllm CLI still did not report a version — skipping`,
        );
        return;
      }
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

  const dest = cliBinaryPath(); // always land on the NEW name
  try {
    const outcome = await applyCliSelfUpdate({
      dest,
      backupOf: bin,
      latest,
      target,
      origin,
      expectedInstalled: current,
      ...(legacyOnly ? { legacySymlink: legacyCliBinaryPath() } : {}),
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
    } else if (outcome.stage === "probe-inconclusive") {
      // TD-5/UP-2: transient probe — attempt recorded, artifact NOT rejected.
      logWarn(
        "cli-update",
        `pre-swap probe of openllm CLI v${latest} was inconclusive (${outcome.detail ?? "unknown"}) — backing off without rejecting the artifact`,
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
  }
};
