/**
 * Spawn helpers for official-CLI delegation: capture runs, browser/PTY
 * login spawns, and terminal-output hygiene. Split out of `util.ts`
 * (which re-exports everything here — import from either).
 *
 * Bright line (proposal §6): nothing read from a CLI's store may be sent
 * off-box. These helpers feed the LOCAL runner + the local usage panel
 * only.
 */
import {
  closeSync,
  existsSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { rm } from "node:fs/promises";
import { connect } from "node:net";
import { platform } from "node:os";
import { join } from "node:path";
import type { TDoctorEventTimings } from "@openllmsh/protocol";
import type {
  TReapOutcome,
  TSupervisedChild,
  TSuperviseSpawnOptions,
} from "../child-supervisor";
import { listChildRegistryRecords, superviseSpawn } from "../child-supervisor";
import type { TCliVersionOpts } from "../cli-version-cache";
import { cachedCliVersion } from "../cli-version-cache";
import { spawnCommand } from "../command";
import {
  budgetFromSignal,
  createDeadlineBudget,
  splitReapBudget,
  timeoutCallbackLatenessMs,
} from "../deadline-budget";
import { opaqueDoctorCorrelation } from "../doctor-report/correlation";
import { stateDir } from "../env";
import {
  logDebug,
  logError,
  logInfo,
  logWarn,
  safeDiagnosticMessage,
} from "../logger";
import { cleanNativeSpawnEnv } from "../native-runtime/types";
import { currentTickId } from "../op-context";
import { childEnvironment } from "../sandbox/child-policy";
import { SandboxLaunchError, sandboxSpawnArgs } from "../sandbox/exec";
import {
  daemonTempDir,
  leaseDaemonTmpDirWithIdentity,
  mintDaemonTmpDir,
  removeTreeDeferred,
} from "../sandbox/working-set";
import { spawn as admittedSpawn } from "../windows-process";
import { redactSensitiveArgv } from "./redact-sensitive-argv";

/**
 * Merge spawn env overrides onto a base env. An override value of `undefined`
 * deletes that key from the result (needed so Muse can strip ambient
 * `META_API_KEY` — Bun also treats undefined as unset, but an explicit delete
 * keeps Node and object consumers honest).
 */
export const mergeSpawnEnv = (
  base: NodeJS.ProcessEnv | Readonly<Record<string, string | undefined>>,
  overrides?: Readonly<Record<string, string | undefined>>,
): Record<string, string> => {
  const next: Record<string, string> = {};
  for (const [key, value] of Object.entries(base)) {
    if (value !== undefined) next[key] = value;
  }
  if (overrides === undefined) return next;
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete next[key];
    else next[key] = value;
  }
  return next;
};

/**
 * The spawn env for a vendor CLI child — the shared allowlisted ambient env
 * plus this call's explicit overlay, via {@link cleanNativeSpawnEnv}. NEVER a
 * merge onto `process.env`: `OPENLLM_API_KEY` and the rest of the daemon env
 * must not reach the child (the builder's authority-prefix strip covers
 * overlay-injected secrets too, and its `OPENLLM_DAEMON_STATE_DIR` pin lets
 * an openllm-code descendant — e.g. the `--sandbox-exec` shim or a nested
 * `openllmd --version` — resolve the REAL state dir under a child `HOME`
 * that points at an isolated CLI home). An overlay value of `undefined`
 * deletes that key from the result (e.g. Muse strips ambient `META_API_KEY`).
 * `env === undefined` yields the plain allowlisted env — a no-overlay spawn
 * must still not inherit the daemon env.
 *
 * Pure — no temp-dir minting: callers that build an env WITHOUT handing a
 * minted dir to a supervised child use this, so an unmanaged `run-*` dir can
 * never leak into `<state>/tmp` (rework-7 / RG-2). Supervised spawn paths
 * use {@link spawnEnvLeased} and then own the minted dir's lifecycle.
 */
export const spawnEnv = (
  env: Record<string, string | undefined> | undefined,
): Record<string, string> => buildSpawnEnv(env);

const buildSpawnEnv = (
  env: Record<string, string | undefined> | undefined,
): Record<string, string> => {
  const overlay: Record<string, string> = {};
  const deletes: string[] = [];
  for (const [key, value] of Object.entries(env ?? {})) {
    if (value === undefined) deletes.push(key);
    else overlay[key] = value;
  }
  const child = cleanNativeSpawnEnv(overlay);
  for (const key of deletes) delete child[key];
  return child;
};

export type TSpawnEnvLeased = {
  readonly env: Record<string, string>;
  /**
   * Per-run temp dir minted for this spawn under `<state>/tmp`, or `null`
   * when the child's `TMPDIR` did not point at the shared daemon tmp root
   * (a caller-pinned TMPDIR elsewhere is respected untouched). When non-null
   * the caller OWNS its lifecycle: bind it to the supervised child via
   * {@link bindMintedTmpToChild} once the spawn succeeds, or discard it via
   * {@link discardMintedTmpDir} when the spawn never produces a child.
   */
  readonly tmpDir: string | null;
};

/**
 * {@link spawnEnv} plus RG-2 per-run temp isolation: when the resolved child
 * env still points `TMPDIR` at the SHARED `<state>/tmp` root (`cliEnv`/
 * `sessionEnv` pin it there because installers need a granted temp
 * location), every spawn — wrapped or `probe` — gets its own `run-<rand>`
 * subdir instead of writing scratch into the root it would share with every
 * other vendor child and the sweep could never attribute.
 *
 * The minted dir is UNLEASED until {@link bindMintedTmpToChild} ties it to
 * the actual child: a child-owned dir must never carry a daemon fallback
 * lease (rework-7 — a daemon lease keeps the dir only for the daemon's
 * lifetime and strands it ownerless when the child outlives the daemon, and
 * it was never removed on child exit). Every supervised spawn site removes
 * the dir deterministically — on child exit via the bound watcher, on
 * spawn failure via {@link discardMintedTmpDir}. A `TMPDIR` pointing
 * anywhere else is a caller's choice — left alone, nothing minted.
 */
export const spawnEnvLeased = (
  env: Record<string, string | undefined> | undefined,
): TSpawnEnvLeased => {
  const child = buildSpawnEnv(env);
  const tmpdir = child.TMPDIR;
  if (tmpdir === undefined || tmpdir.length === 0) {
    return { env: child, tmpDir: null };
  }
  let pinned: string;
  let root: string;
  try {
    pinned = realpathSync(tmpdir);
    root = realpathSync(join(stateDir(), "tmp"));
  } catch {
    return { env: child, tmpDir: null };
  }
  if (pinned !== root) return { env: child, tmpDir: null };
  const minted = mintDaemonTmpDir(undefined, "run");
  if (minted === null) return { env: child, tmpDir: null };
  child.TMPDIR = minted;
  return { env: child, tmpDir: minted };
};

/**
 * Remove a minted `run-*` dir. Fire-and-forget: the bounded deferred delete
 * drains it off the caller's path; anything it cannot finish stays leased
 * (or unleased-and-counted) for the sweep, never silently stranded.
 * Idempotent — safe to call after the exit watcher already removed it.
 */
export const discardMintedTmpDir = (leased: TSpawnEnvLeased): void => {
  if (leased.tmpDir === null) return;
  // A dir bound to a child belongs to that child's exit watcher. Deleting it
  // here would pull the scratch dir from under a child that is still running
  // (an abandoned or not-yet-reaped child), rework-8.
  if (boundMintedTmpDirs.has(leased.tmpDir)) return;
  removeTreeDeferred(leased.tmpDir);
};

/**
 * Remove a minted dir only after `released` settles (the child and its
 * process tree are gone). Used where the dir must outlive the function that
 * spawned the child, for example a timed-out PTY login (rework-8).
 */
export const discardMintedTmpDirAfter = (
  leased: TSpawnEnvLeased,
  released: Promise<unknown>,
): void => {
  const discard = (): void => discardMintedTmpDir(leased);
  void released.then(discard, discard);
};

/** Minted dirs whose removal belongs to a child's exit watcher. */
const boundMintedTmpDirs = new Set<string>();

/**
 * Tie a minted `run-*` dir to the supervised child it was minted for. Two
 * halves, both off the spawn path:
 *   - the lease upgrade: the child registry record `superviseSpawn`
 *     resolved is copied into the dir's lease, so the sweep attributes the
 *     dir to the REAL child (a dead lease past grace is reapable even if
 *     the daemon died first);
 *   - the exit watcher: `proc.exited` removes the dir outright. This is
 *     the deterministic half — a fast child that exits before its registry
 *     record lands still gets its dir deleted, without depending on the
 *     lease state or the daemon's lifetime.
 */
export const bindMintedTmpToChild = (
  leased: TSpawnEnvLeased,
  proc: {
    readonly pid?: unknown;
    readonly exited: Promise<number>;
  },
  sessionId: string,
  released?: Promise<unknown>,
): void => {
  const dir = leased.tmpDir;
  if (dir === null) return;
  boundMintedTmpDirs.add(dir);
  const sweep = (): void => {
    boundMintedTmpDirs.delete(dir);
    removeTreeDeferred(dir);
  };
  // Wait for the supervisor's process-tree release too: the wrapper can exit
  // while descendants still use the dir (rework-8).
  void Promise.allSettled([proc.exited, released]).then(sweep);
  if (typeof proc.pid === "number") {
    leaseMintedTmpToChild(dir, proc.pid, sessionId);
  }
};

/** Poll bound for the registry record carrying the child's identity. */
const CHILD_LEASE_POLL_MS = 1000;
// Few reads: each one loads the whole child registry synchronously (rework-8).
const CHILD_LEASE_POLL_STEP_MS = 250;

/**
 * Re-lease a minted run dir to the spawned child's pid + start identity —
 * WITHOUT spending a second `ps` subprocess: `superviseSpawn` already
 * resolves that identity into the daemon child registry off the spawn hot
 * path, so the upgrade polls that record and copies it into the lease
 * (rework-6 — a `ps` per spawn is a real forked child, and spawn-sequence
 * tests record them). Detached and best-effort: a fast child can exit
 * before its record lands (the supervisor deliberately skips a record for
 * an already-exited pid), leaving the dir unleased — fine, because the
 * bound exit watcher in {@link bindMintedTmpToChild} removes it outright
 * and an unleased remnant is only ever counted by the sweep.
 */
export const leaseMintedTmpToChild = (
  dir: string,
  pid: number,
  sessionId: string,
): void => {
  void (async () => {
    for (
      let waited = 0;
      waited < CHILD_LEASE_POLL_MS;
      waited += CHILD_LEASE_POLL_STEP_MS
    ) {
      const record = listChildRegistryRecords().find((r) => r.pid === pid);
      if (record !== undefined) {
        leaseDaemonTmpDirWithIdentity(
          dir,
          pid,
          record.processStartTime,
          sessionId,
        );
        return;
      }
      await new Promise<void>((resolve) => {
        setTimeout(resolve, CHILD_LEASE_POLL_STEP_MS);
      });
    }
  })().catch(() => {
    // Lease upgrades are best-effort — the exit watcher still removes the dir.
  });
};

/**
 * The working directory for a spawned isolated CLI. SECURITY: the daemon runs
 * with cwd `/` (launchd/systemd start it with no `WorkingDirectory`), and a
 * child inherits it. A vendor CLI launched at `/` enumerates project context
 * from the filesystem ROOT — statting `/Volumes/*`, which on macOS trips the
 * TCC "wants to access files on a network volume" consent prompt (attributed to
 * the daemon as the responsible parent) and needlessly walks the whole disk.
 *
 * So pin the cwd to the child's OWN isolated home (`env.HOME`, e.g.
 * `~/.openllm/cli/claude_code/home` for claude) — which `cliEnv` always sets and
 * the sandbox working set grants read-write — so the CLI's project scan is
 * confined to its empty isolated home, NEVER `/`. Falls back to the daemon-owned
 * temp dir (always created + granted) when no isolated HOME is present or the
 * home dir doesn't yet exist (a not-yet-created cwd would make `Bun.spawn`
 * `ENOENT`). Never returns `/`.
 */
export const spawnCwd = (
  env: Record<string, string | undefined> | undefined,
): string => {
  const home = env?.HOME;
  // Reject `/` explicitly: it "exists", so an env with `HOME=/` (or a daemon
  // whose HOME wasn't isolated) would otherwise pass the existsSync check and
  // re-introduce the exact root-cwd bug this helper exists to prevent.
  if (home !== undefined && home.length > 0 && home !== "/" && existsSync(home))
    return home;
  return daemonTempDir();
};

/**
 * Surface a child that was KILLED BY A SIGNAL (`signalCode` set) — the silent
 * failure mode behind "the flow doesn't trigger, no errors". The OS sandbox
 * SIGKILLs/SIGABRTs a child that hits a denied operation, and a plain exit-code
 * check misses it. Logging the command + signal at ERROR level puts the actual
 * culprit in `openllmd.err.log` instead of letting it vanish. Returns whether a
 * kill was detected (so callers can treat it as a definite failure). No-op for
 * a clean exit.
 */
export type TLogIfKilledOpts = {
  /**
   * Whether the killed child ran through the `--sandbox-exec` shim. The
   * "OS sandbox denial" hint is only defensible for a CONFINED child; a
   * `probe:true` spawn runs UNWRAPPED (see {@link sandboxSpawnArgs}), so a
   * signal death there cannot be a Seatbelt denial — it's an external signal
   * (a daemon restart/drain, a manual kill). Blaming the sandbox there actively
   * misdirects diagnosis. Defaults to `true` (confined) when the caller can't
   * say, preserving the historical hint for unknown call sites.
   */
  readonly confined?: boolean;
};

export const logIfKilled = (
  argv: ReadonlyArray<string>,
  proc: {
    readonly signalCode: string | null;
    readonly exitCode: number | null;
  },
  opts?: TLogIfKilledOpts,
): boolean => {
  // The `--sandbox-exec` shim mirrors a signal death of its tail as exit code
  // `128 + N` (the daemon-side proc is the SHIM, so its signalCode is null) —
  // without this mapping a sandbox kill of a wrapped child is invisible here
  // and the spawn just looks like a quiet non-zero exit. A CLI can exit 130
  // by its own convention (ctrl-c), so this is a diagnostic breadcrumb, not a
  // hard verdict.
  const signal =
    proc.signalCode ??
    (proc.exitCode !== null && proc.exitCode > 128 && proc.exitCode <= 128 + 31
      ? (SIGNAL_NAMES[proc.exitCode - 128] ?? `signal ${proc.exitCode - 128}`)
      : null);
  if (signal === null) return false;
  // Only a CONFINED child can be Seatbelt-denied. An unconfined (`probe`) kill
  // is an EXTERNAL signal — attributing it to the sandbox sent a real incident's
  // diagnosis down a dead end. Default to the sandbox hint only when confinement
  // is unknown or true.
  const confined = opts?.confined !== false;
  logError("delegation", `child killed by ${signal}`, {
    command: argv[0],
    argv: [...argv],
    signal,
    confined,
    hint: confined
      ? "likely an OS sandbox denial — see DaemonStatus.sandbox / the sandbox working set"
      : "external signal on an unconfined child — likely a daemon restart/drain or manual kill (the sandbox was not involved)",
  });
  return true;
};

/** Conventional signal number → name, for the shim's `128 + N` exit mirror. */
const SIGNAL_NAMES: Record<number, string> = {
  1: "SIGHUP",
  2: "SIGINT",
  3: "SIGQUIT",
  4: "SIGILL",
  5: "SIGTRAP",
  6: "SIGABRT",
  7: "SIGBUS",
  8: "SIGFPE",
  9: "SIGKILL",
  10: "SIGUSR1",
  11: "SIGSEGV",
  12: "SIGUSR2",
  13: "SIGPIPE",
  14: "SIGALRM",
  15: "SIGTERM",
};

/** Hard ceiling for one-shot vendor CLI captures and probes. */
export const DEFAULT_CAPTURE_TIMEOUT_MS = 5_000;
const MIN_CAPTURE_TIMEOUT_MS = 250;

const captureTimeoutMs = (timeoutMs: number | undefined): number =>
  Math.max(MIN_CAPTURE_TIMEOUT_MS, timeoutMs ?? DEFAULT_CAPTURE_TIMEOUT_MS);

export type TRunCaptureOpts = {
  /** Skip the sandbox shim for a read-only probe that needs direct execution. */
  readonly probe?: boolean;
  /** Classify the disposable child independently of sandbox-shim behavior. */
  readonly kind?: "probe" | "vendor-capture";
  /** Hard ceiling for stdout capture plus child exit before group termination. */
  readonly timeoutMs?: number;
  /** Early-cancel: terminate the process group when aborted (status-probe race). */
  readonly signal?: AbortSignal;
  /** Exit 0 with empty stdout is success (logout prints nothing). */
  readonly allowEmpty?: boolean;
  /**
   * When set, stop reading stdout after this many bytes and treat overflow
   * as failure. Version probes pass a small cap so a hung printer cannot
   * fill memory/disk.
   */
  readonly maxBytes?: number;
  readonly producer?: TNativeAuthProducer;
  readonly operationId?: string;
};

/** Subscribe to `signal` abort; invoke `onAbort` immediately if already aborted. */
export const bindAbort = (
  signal: AbortSignal | undefined,
  onAbort: () => void,
): (() => void) => {
  if (signal === undefined) return () => {};
  if (signal.aborted) {
    onAbort();
    return () => {};
  }
  signal.addEventListener("abort", onAbort, { once: true });
  return (): void => {
    signal.removeEventListener("abort", onAbort);
  };
};

/**
 * Read abort without using `=== true` on a property TypeScript may have
 * narrowed to `false` after an earlier early-return. A later abort remains
 * observable.
 */
const signalAbortRequested = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted ?? false;

type TCaptureOutcome =
  | { readonly kind: "complete"; readonly out: string; readonly code: number }
  | { readonly kind: "timeout" }
  | { readonly kind: "aborted" }
  | { readonly kind: "overflow" };

type TCaptureCompleteHook = () => void;

let captureCompleteHookForTests: TCaptureCompleteHook | null = null;

/** Test-only: run after `complete` settles, before `Promise.race` reactions. */
export const setCaptureCompleteHookForTests = (
  hook: TCaptureCompleteHook | null,
): void => {
  captureCompleteHookForTests = hook;
};

type TCaptureTimeoutScheduler = (
  callback: () => void,
  delayMs: number,
) => ReturnType<typeof setTimeout>;

let captureTimeoutSchedulerForTests: TCaptureTimeoutScheduler | null = null;
let loginTimeoutSchedulerForTests: TCaptureTimeoutScheduler | null = null;

export type TNativeAuthProducer =
  | "claude-refresh"
  | "claude-auth-status"
  | "claude-login"
  | "claude-logout";

const nativeAuthOperationMeta = (
  operationId: string | undefined,
): { readonly operation_id: string } | Record<string, never> => {
  const id = opaqueDoctorCorrelation(operationId);
  return id !== undefined ? { operation_id: id } : {};
};

const nativeAuthDoctorObservation = (
  operationId: string | undefined,
  timings: TDoctorEventTimings,
): {
  readonly timings: TDoctorEventTimings;
  readonly correlation_id?: string;
} => {
  const correlation_id = opaqueDoctorCorrelation(operationId);
  return {
    timings,
    ...(correlation_id !== undefined ? { correlation_id } : {}),
  };
};

let nativeAuthOperationSeq = 0;

/** Ephemeral correlation id for one native-auth child. Not an account identity. */
export const newNativeAuthOperationId = (): string => {
  nativeAuthOperationSeq += 1;
  return `na-${nativeAuthOperationSeq.toString(36)}-${Math.floor(performance.now()).toString(36)}`;
};

/**
 * Test-only: replace the capture watchdog `setTimeout`. Used to inject a
 * delayed fire for lateness fields. Production always uses `setTimeout`.
 */
export const setCaptureTimeoutSchedulerForTests = (
  scheduler: TCaptureTimeoutScheduler | null,
): void => {
  captureTimeoutSchedulerForTests = scheduler;
};

/**
 * Test-only: replace the login watchdog `setTimeout`. Used to inject a
 * delayed fire for lateness fields. Production always uses `setTimeout`.
 */
export const setLoginTimeoutSchedulerForTests = (
  scheduler: TCaptureTimeoutScheduler | null,
): void => {
  loginTimeoutSchedulerForTests = scheduler;
};

export type TRunCaptureResult =
  | { readonly kind: "ok"; readonly text: string }
  | { readonly kind: "timeout" }
  | { readonly kind: "aborted" }
  | { readonly kind: "failed" };

/**
 * Run a command and capture trimmed stdout. Distinguishes timeout from
 * abort / non-zero / empty / spawn failure. stdin is ignored so it never
 * blocks. `env` is merged onto the parent env — used to run the isolated vendor
 * CLIs with their home pointed inside the OpenLLM dir.
 *
 * The stdout read and root child exit share one hard deadline. On expiry, use
 * the supervisor's process-group termination rather than `proc.kill()`: a
 * descendant holding the inherited stdout fd must be reaped for EOF to occur.
 */
export const runCaptureResult = async (
  argv: ReadonlyArray<string>,
  env?: Record<string, string | undefined>,
  opts?: TRunCaptureOpts,
): Promise<TRunCaptureResult> => {
  if (signalAbortRequested(opts?.signal)) return { kind: "aborted" };
  // Minted before the try so the finally can discard the dir on EVERY path
  // that never reaches a live child (argv/env setup or the spawn itself).
  const leased = spawnEnvLeased(env);
  // Set once a child exists: an error after that point must stop the child
  // (its exit watcher then removes the minted dir), rework-8.
  let spawned: { terminate: () => Promise<unknown> } | null = null;
  try {
    const setupStartedAtMs = performance.now();
    const command = spawnCommand(
      process.platform,
      argv[0] ?? "",
      argv.slice(1),
    );
    const spawnOptions: TSuperviseSpawnOptions = {
      kind: opts?.kind ?? (opts?.probe === true ? "probe" : "vendor-capture"),
      stdin: "ignore",
      stdout: "pipe",
      stderr: "ignore",
      cwd: spawnCwd(env),
      env: leased.env,
    };
    const child = superviseSpawn(
      sandboxSpawnArgs(command, { probe: opts?.probe }),
      spawnOptions,
    );
    spawned = child;
    const spawnedAtMs = performance.now();
    const spawnSetupMs = spawnedAtMs - setupStartedAtMs;
    const proc = child.subprocess;
    await child.sandbox?.ready;
    // Tie the minted tmp dir to the real child — the lease upgrade is async
    // off the spawn path, and the exit watcher removes the dir outright when
    // the child dies (rework-7 / RG-2).
    bindMintedTmpToChild(leased, proc, "capture", child.whenReleased);
    if (opts?.producer !== undefined) {
      logDebug("spawn", "native auth child started", {
        producer: opts.producer,
        ...nativeAuthOperationMeta(opts.operationId),
        phase: "start",
        child_pid: typeof proc.pid === "number" ? proc.pid : null,
        tick_id: currentTickId(),
        configured_timeout_ms: captureTimeoutMs(opts.timeoutMs),
        spawn_setup_ms: spawnSetupMs,
        clock: "performance.now",
      });
    }
    const stdout = proc.stdout;
    if (stdout === undefined || typeof stdout === "number") {
      await child.terminate();
      return { kind: "failed" };
    }
    const configuredTimeoutMs = captureTimeoutMs(opts?.timeoutMs);
    const parentBudget = budgetFromSignal(opts?.signal);
    const budget =
      parentBudget?.child(configuredTimeoutMs) ??
      createDeadlineBudget(configuredTimeoutMs, opts?.signal);
    const remainingAtSpawn = budget.remainingMs();
    let timer: ReturnType<typeof setTimeout> | null = null;
    let timerArmedAtMs: number | null = null;
    let timerFiredAtMs: number | null = null;
    let timerDelayMs = remainingAtSpawn;
    let stdoutClosed = false;
    let rootExitCode: number | null = null;
    const unbind = bindAbort(opts?.signal, () => {
      void child.terminate(splitReapBudget(budget.remainingMs()));
    });
    let unbindAbortWait = (): void => {};
    try {
      const readStdout = async (): Promise<{
        readonly out: string;
        readonly overflow: boolean;
      }> => {
        const cap = opts?.maxBytes;
        if (cap === undefined || cap <= 0) {
          const out = await new Response(stdout).text();
          return { out, overflow: false };
        }
        const reader = stdout.getReader();
        const chunks: Uint8Array[] = [];
        let n = 0;
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value === undefined) continue;
            n += value.byteLength;
            if (n > cap) {
              try {
                await reader.cancel();
              } catch {
                // already closed
              }
              return { out: "", overflow: true };
            }
            chunks.push(value);
          }
        } finally {
          try {
            reader.releaseLock();
          } catch {
            // already released
          }
        }
        const merged = new Uint8Array(n);
        let offset = 0;
        for (const c of chunks) {
          merged.set(c, offset);
          offset += c.byteLength;
        }
        return { out: new TextDecoder().decode(merged), overflow: false };
      };
      void proc.exited.then((code) => {
        rootExitCode = code;
      });
      const complete = (async (): Promise<TCaptureOutcome> => {
        const read = await readStdout().finally(() => {
          stdoutClosed = true;
        });
        if (read.overflow) return { kind: "overflow" };
        const code = await proc.exited;
        return { kind: "complete", out: read.out, code };
      })();
      const scheduleTimeout =
        captureTimeoutSchedulerForTests ??
        ((
          callback: () => void,
          delayMs: number,
        ): ReturnType<typeof setTimeout> => setTimeout(callback, delayMs));
      const timeout = new Promise<TCaptureOutcome>((resolve) => {
        timerDelayMs = budget.remainingMs();
        timerArmedAtMs = performance.now();
        timer = scheduleTimeout(() => {
          timerFiredAtMs = performance.now();
          resolve({ kind: "timeout" });
        }, timerDelayMs);
      });
      const abortWait =
        opts?.signal === undefined
          ? null
          : new Promise<TCaptureOutcome>((resolve) => {
              unbindAbortWait = bindAbort(opts.signal, () =>
                resolve({ kind: "aborted" }),
              );
            });
      if (captureCompleteHookForTests !== null) {
        const hook = captureCompleteHookForTests;
        void complete.then(() => {
          hook();
        });
      }
      const outcome = await Promise.race(
        abortWait === null
          ? [complete, timeout]
          : [complete, timeout, abortWait],
      );
      const raceObservedAtMs = performance.now();
      // Race winner is authoritative. Unbind before branching so a late abort
      // cannot flip the shared flag and discard a completed stdout.
      unbind();
      unbindAbortWait();
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      if (outcome.kind === "timeout") {
        const stdoutClosedAtRace = stdoutClosed;
        const rootExitedAtRace =
          rootExitCode !== null ||
          proc.exitCode !== null ||
          proc.signalCode !== null;
        const rootExitCodeAtRace = rootExitCode ?? proc.exitCode;
        const armed = timerArmedAtMs ?? spawnedAtMs;
        const fired = timerFiredAtMs ?? raceObservedAtMs;
        const lateness = timeoutCallbackLatenessMs(armed, fired, timerDelayMs);
        const timeoutMessage =
          opts?.producer === "claude-auth-status"
            ? safeDiagnosticMessage`Authentication status probe exceeded its time budget.`
            : opts?.producer === "claude-refresh"
              ? safeDiagnosticMessage`Credential refresh exceeded its time budget.`
              : opts?.producer === "claude-logout"
                ? safeDiagnosticMessage`Logout exceeded its time budget.`
                : safeDiagnosticMessage`Native capture exceeded its time budget.`;
        const raceMeta = {
          configured_timeout_ms: configuredTimeoutMs,
          deadline_ms: remainingAtSpawn,
          remaining_at_spawn_ms: remainingAtSpawn,
          budget_remaining_ms_at_spawn: remainingAtSpawn,
          spawn_elapsed_ms: raceObservedAtMs - spawnedAtMs,
          spawn_setup_ms: spawnSetupMs,
          timer_armed_at_ms: armed,
          timer_fired_at_ms: fired,
          race_observed_at_ms: raceObservedAtMs,
          timeout_callback_lateness_ms: lateness,
          stdout_closed: stdoutClosedAtRace,
          root_exited: rootExitedAtRace,
          root_exit_code: rootExitCodeAtRace,
          clock: "performance.now" as const,
          child_pid: typeof proc.pid === "number" ? proc.pid : null,
          tick_id: currentTickId(),
          kind: spawnOptions.kind,
          probe: opts?.probe === true,
          reason_code: "timeout" as const,
          phase: "timeout_race" as const,
          cancel_requested: signalAbortRequested(opts?.signal),
          ...(opts?.producer !== undefined ? { producer: opts.producer } : {}),
          ...nativeAuthOperationMeta(opts?.operationId),
          ...(opts?.producer === undefined
            ? { argv: redactSensitiveArgv(argv) }
            : {}),
        };
        const raceDoctor = nativeAuthDoctorObservation(opts?.operationId, {
          configured_timeout_ms: configuredTimeoutMs,
          spawn_elapsed_ms: raceObservedAtMs - spawnedAtMs,
          budget_remaining_ms_at_spawn: remainingAtSpawn,
          timeout_callback_lateness_ms: Math.max(0, lateness),
          stdout_closed: stdoutClosedAtRace,
          root_exited: rootExitedAtRace,
          ...(typeof rootExitCodeAtRace === "number"
            ? { root_exit_code: rootExitCodeAtRace }
            : {}),
        });
        logWarn("spawn", timeoutMessage, raceMeta, raceDoctor);
        const cleanupStartedAtMs = performance.now();
        const reap = await child.terminate(
          splitReapBudget(budget.remainingMs()),
        );
        const cleanupMs = performance.now() - cleanupStartedAtMs;
        const cleanup = childCleanupOutcome(
          reap,
          signalAbortRequested(opts?.signal),
        );
        logInfo(
          "spawn",
          safeDiagnosticMessage`Native capture cleanup finished.`,
          {
            ...raceMeta,
            phase: "cleanup",
            reason_code: "cleanup",
            cleanup_ms: cleanupMs,
            cleanup_reap: cleanup.reap,
            cleanup_confirmed: cleanup.confirmed,
            cancel_requested: cleanup.cancel_requested,
          },
          nativeAuthDoctorObservation(opts?.operationId, {
            cleanup_ms: cleanupMs,
            stdout_closed: stdoutClosedAtRace,
            root_exited: rootExitedAtRace,
            ...(typeof rootExitCodeAtRace === "number"
              ? { root_exit_code: rootExitCodeAtRace }
              : {}),
          }),
        );

        return { kind: "timeout" };
      }
      if (outcome.kind === "aborted") {
        await child.terminate(splitReapBudget(budget.remainingMs()));
        return { kind: "aborted" };
      }
      if (outcome.kind === "overflow") {
        await child.terminate(splitReapBudget(budget.remainingMs()));
        return { kind: "failed" };
      }
      // `probe:true` runs UNWRAPPED — a signal death there is not a sandbox
      // denial (this was the mislabeled `--version` status-probe drain).
      logIfKilled(redactSensitiveArgv(argv), proc, {
        confined: opts?.probe !== true,
      });
      if (outcome.code !== 0) return { kind: "failed" };
      const trimmed = outcome.out.trim();
      if (trimmed.length > 0) return { kind: "ok", text: trimmed };
      return opts?.allowEmpty === true
        ? { kind: "ok", text: "" }
        : { kind: "failed" };
    } finally {
      unbind();
      unbindAbortWait();
      if (timer !== null) clearTimeout(timer);
      budget.release();
    }
  } catch (error) {
    // A throw after spawn (stdout read, budget setup) must not leave the
    // child running with its scratch dir deleted under it.
    if (spawned !== null) await spawned.terminate().catch(() => undefined);
    if (error instanceof SandboxLaunchError) throw error;
    return { kind: "failed" };
  } finally {
    // Removes the dir only when no child was bound to it (setup or spawn
    // failed); a bound dir is removed by the child's exit watcher.
    discardMintedTmpDir(leased);
  }
};

/** Run a command and capture trimmed stdout (best-effort). Returns null on
 *  spawn failure, non-zero exit, abort, or a timeout. */
export const runCapture = async (
  argv: ReadonlyArray<string>,
  env?: Record<string, string | undefined>,
  opts?: TRunCaptureOpts,
): Promise<string | null> => {
  const result = await runCaptureResult(argv, env, opts);
  return result.kind === "ok" ? result.text : null;
};

/** Run a binary's `--version` (best-effort). Returns null on failure.
 *  UNWRAPPED (`probe: true`): a fixed-argv, read-only `<bin> --version` is the
 *  canonical skip-the-shim probe (see {@link TSandboxSpawnOpts.probe}). Leaving
 *  it confined was a latent bug — harmless while `--version` was a pure print,
 *  but the `openllm` CLI's `--version` now spawns a nested `openllmd --version`
 *  child, and a confined caller spawning that child can be Seatbelt/Landlock
 *  denied (→ null → the CLI converger's "did not report a version" skip).
 *  Stamp-keyed via {@link cachedCliVersion}: success and completed failure
 *  reuse until the resolved binary identity changes (no TTL). */
export const cliVersion = (
  bin: string,
  env?: Record<string, string>,
  opts?: TCliVersionOpts,
): Promise<string | null> => cachedCliVersion(bin, env, opts);

export type TLoginResult = {
  readonly code: number;
  /** Combined stdout+stderr (trimmed), for surfacing failures. */
  readonly output: string;
  /** True when we abandoned the child (early `until` match or timeout) rather
   *  than it exiting on its own — its OUTPUT is still valid (the token/cred was
   *  produced first), it just never cleanly exited. */
  readonly abandoned: boolean;
  /** Wall clock immediately after `superviseSpawn`. Null when no child ran. */
  readonly spawned_at_ms: number | null;
  /** Child pid immediately after `superviseSpawn`. Null when no child ran. */
  readonly child_pid: number | null;
  /** `performance.now()` spawn setup duration. */
  readonly spawn_setup_ms?: number;
  /** `performance.now()` child-wait duration until race/exit. */
  readonly child_wait_ms?: number;
  /**
   * Actual group-reap result. Absent when no child ran. `confirmed: false`
   * means termination was not observed — retain ownership. Not implied by
   * `signal` being cancellable.
   */
  readonly cleanup?: TChildCleanupOutcome;
  /**
   * Settles when supervisor tracking is dropped. Pending while cleanup is
   * unconfirmed. P1 should await this instead of parsing thrown handles.
   */
  readonly whenReleased?: Promise<TReapOutcome>;
};

/**
 * Confirmed process-group cleanup for an owned login/capture child.
 * `cancellable: true` on a signal is never treated as completed termination.
 */
export type TChildCleanupOutcome = {
  readonly reap: TReapOutcome;
  readonly confirmed: boolean;
  readonly cancel_requested: boolean;
};

export const childCleanupOutcome = (
  reap: TReapOutcome,
  cancelRequested: boolean,
): TChildCleanupOutcome => ({
  reap,
  confirmed: reap !== "reap_unconfirmed",
  cancel_requested: cancelRequested,
});

const noChildResult = (abandoned: boolean): TLoginResult => ({
  code: -1,
  output: "",
  abandoned,
  spawned_at_ms: null,
  child_pid: null,
});

const spawnStamp = (proc: {
  readonly pid?: number;
}): Pick<TLoginResult, "spawned_at_ms" | "child_pid"> => ({
  spawned_at_ms: Date.now(),
  child_pid: typeof proc.pid === "number" ? proc.pid : null,
});

export type TSpawnLoginOpts = {
  /** Hard ceiling: kill the child after this and return what was captured.
   *  A browser OAuth needs the user to sign in, so it's generous. */
  readonly timeoutMs?: number;
  /** When the COMBINED output matches this, the child has produced what we
   *  need (e.g. a printed verification prompt) — kill it and return immediately
   *  instead of waiting for it to exit. Vendor CLIs (themselves Bun/Node
   *  binaries) can hang in `__cxa_finalize`/atexit AFTER printing it, so waiting
   *  on `proc.exited` would block forever + pile up 99%-CPU runaways. We don't
   *  need the exit — only the output. */
  readonly until?: RegExp;
  /** Skip the `--sandbox-exec` wrap (see `TSandboxSpawnOpts.probe`). REQUIRED
   *  for children that must operate a macOS-keychain-backed credential store
   *  (claude/cursor status + refresh): securityd refuses keychain reads for a
   *  Seatbelt-confined caller, so a wrapped spawn reports "not signed in" and
   *  a wrapped refresh silently never persists the rotated token. */
  readonly probe?: boolean;
  /** Early-cancel the login child. Refresh must not pass an observer abort here. */
  readonly signal?: AbortSignal;
  /**
   * Refresh-only: after the spawn deadline fires, decide whether to defer
   * SIGTERM for {@link TSpawnLoginOpts.persistenceGraceMs}. True only when a
   * validated newer store is already visible. The child stays supervised; a
   * later exit or bounded terminate still finalizes ownership.
   */
  readonly onDeadline?: () => boolean | Promise<boolean>;
  /** Finite persistence grace after a true {@link TSpawnLoginOpts.onDeadline}. */
  readonly persistenceGraceMs?: number;
  readonly producer?: TNativeAuthProducer;
  readonly operationId?: string;
};

/**
 * Cap for `onDeadline` (store re-read). A hung Darwin `security`/keychain must
 * not delay SIGTERM; grace starts only after a finished verified persist.
 */
export const DEADLINE_CHECK_CAP_MS = 400;

const awaitOnDeadline = async (
  check: (() => boolean | Promise<boolean>) | undefined,
): Promise<boolean> => {
  if (check === undefined) return false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    return await Promise.race([
      Promise.resolve(check()).then((v) => v === true),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(false), DEADLINE_CHECK_CAP_MS);
      }),
    ]);
  } catch {
    return false;
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
};

const waitWithCap = async (
  work: Promise<unknown>,
  capMs: number,
): Promise<void> => {
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    await Promise.race([
      work.then(() => undefined),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, capMs);
      }),
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
};

/** Default login ceiling — long enough for a human to complete the browser
 *  OAuth, short enough that a wedged child is reaped, not left forever. */
export const DEFAULT_LOGIN_TIMEOUT_MS = 5 * 60_000;

/** After `opts.until` first matches, wait this long for the rest of a
 *  chunk-split token to arrive before killing — so the captured token is the
 *  COMPLETE one even though the regex isn't boundary-anchored. */
export const UNTIL_SETTLE_MS = 400;

/**
 * Spawn a vendor CLI's login command and capture its output. The CLI opens the
 * user's browser; the user signs in and the CLI completes via its own localhost
 * callback, at which point the credential is in the CLI's OWN store. stdin is
 * ignored (browser-driven; headless daemon has no usable stdin).
 *
 * Robustness (load-bearing): we NEVER block indefinitely on the child exiting.
 * Output is STREAMED; if `opts.until` matches we kill the child and return
 * (the vendor CLI can hang in atexit AFTER printing the token — see
 * `TSpawnLoginOpts.until`), and a `timeoutMs` ceiling reaps a wedged child
 * regardless. Either way the captured output is returned — the caller re-reads
 * the store / parses the token from it.
 */
export const spawnLogin = async (
  argv: ReadonlyArray<string>,
  env?: Record<string, string | undefined>,
  opts?: TSpawnLoginOpts,
): Promise<TLoginResult> => {
  const loginOpts = opts;
  if (signalAbortRequested(loginOpts?.signal)) {
    return noChildResult(true);
  }
  const setupStartedAtMs = performance.now();
  const timeoutMs = loginOpts?.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS;
  const parentBudget = budgetFromSignal(loginOpts?.signal);
  const budget =
    parentBudget?.child(timeoutMs) ??
    createDeadlineBudget(timeoutMs, loginOpts?.signal);
  const remainingAtSpawn = budget.remainingMs();
  const leased = spawnEnvLeased(env);
  let child: TSupervisedChild;
  try {
    child = superviseSpawn(
      sandboxSpawnArgs(argv, { probe: loginOpts?.probe }),
      {
        kind: "login",
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        cwd: spawnCwd(env),
        env: leased.env,
      },
    );
  } catch (error) {
    // Spawn never produced a child — the minted dir is ours to remove
    // (rework-7 / RG-2: no run-* may outlive its spawn attempt).
    discardMintedTmpDir(leased);
    budget.release();
    throw error;
  }
  let terminatePromise: Promise<TReapOutcome> | null = null;
  const requestTerminate = (): Promise<TReapOutcome> => {
    if (terminatePromise === null) {
      terminatePromise = child.terminate(splitReapBudget(budget.remainingMs()));
    }
    return terminatePromise;
  };
  try {
    await child.sandbox?.ready;
    const spawnedAtMs = performance.now();
    const spawnSetupMs = spawnedAtMs - setupStartedAtMs;
    const proc = child.subprocess;
    // Tie the minted tmp dir to the real child — the lease upgrade is async
    // off the spawn path, and the exit watcher removes the dir outright when
    // the child dies (rework-7 / RG-2).
    bindMintedTmpToChild(leased, proc, "login", child.whenReleased);
    const stamp = spawnStamp(proc);
    const unbindEarlyAbort = bindAbort(loginOpts?.signal, () => {
      void requestTerminate();
    });
    if (loginOpts?.producer !== undefined) {
      logDebug("spawn", "native auth child started", {
        producer: loginOpts.producer,
        ...nativeAuthOperationMeta(loginOpts.operationId),
        phase: "start",
        child_pid: stamp.child_pid,
        tick_id: currentTickId(),
        configured_timeout_ms: timeoutMs,
        remaining_at_spawn_ms: remainingAtSpawn,
        spawn_setup_ms: spawnSetupMs,
        clock: "performance.now",
      });
    }
    const stdout = proc.stdout;
    const stderr = proc.stderr;
    if (
      stdout === undefined ||
      typeof stdout === "number" ||
      stderr === undefined ||
      typeof stderr === "number"
    ) {
      unbindEarlyAbort();
      const reap = await requestTerminate();
      return {
        code: -1,
        output: "",
        abandoned: true,
        spawn_setup_ms: spawnSetupMs,
        cleanup: childCleanupOutcome(
          reap,
          signalAbortRequested(loginOpts?.signal),
        ),
        whenReleased: child.whenReleased,
        ...stamp,
      };
    }
    const dec = new TextDecoder();
    let out = "";
    let err = "";
    let abandoned = false;
    let killTimer: ReturnType<typeof setTimeout> | null = null;
    let settleTimer: ReturnType<typeof setTimeout> | null = null;
    let timerArmedAtMs: number | null = null;
    let timerFiredAtMs: number | null = null;
    let timerDelayMs = remainingAtSpawn;
    let stdoutClosed = false;
    let stderrClosed = false;
    let rootExitCode: number | null = null;
    let cleanupMs: number | null = null;
    let cleanup: TChildCleanupOutcome | undefined;
    const cancelRequested = (): boolean =>
      signalAbortRequested(loginOpts?.signal);
    void proc.exited.then((code) => {
      rootExitCode = code;
    });
    let markAbandoned!: () => void;
    const abandonedGate = new Promise<void>((resolve) => {
      markAbandoned = resolve;
    });
    const readers: Array<ReadableStreamDefaultReader<Uint8Array>> = [];
    const kill = (): void => {
      if (abandoned) return;
      abandoned = true;
      markAbandoned();
      for (const reader of readers) {
        void reader.cancel().catch(() => {});
      }
      void requestTerminate();
    };

    const emitLoginTimeoutRace = (opts: {
      readonly stdoutClosed: boolean;
      readonly stderrClosed: boolean;
      readonly rootExited: boolean;
      readonly rootExitCode: number | null;
    }): {
      readonly raceObservedAtMs: number;
      readonly armed: number;
      readonly fired: number;
      readonly lateness: number;
    } => {
      const raceObservedAtMs = performance.now();
      const armed = timerArmedAtMs ?? spawnedAtMs;
      const fired = timerFiredAtMs ?? raceObservedAtMs;
      const lateness = timeoutCallbackLatenessMs(armed, fired, timerDelayMs);
      logWarn(
        "spawn",
        loginOpts?.producer === "claude-refresh"
          ? safeDiagnosticMessage`Credential refresh exceeded its time budget.`
          : safeDiagnosticMessage`Login exceeded its time budget.`,
        {
          configured_timeout_ms: timeoutMs,
          deadline_ms: remainingAtSpawn,
          remaining_at_spawn_ms: remainingAtSpawn,
          budget_remaining_ms_at_spawn: remainingAtSpawn,
          spawn_elapsed_ms: raceObservedAtMs - spawnedAtMs,
          spawn_setup_ms: spawnSetupMs,
          timer_armed_at_ms: armed,
          timer_fired_at_ms: fired,
          race_observed_at_ms: raceObservedAtMs,
          timeout_callback_lateness_ms: lateness,
          stdout_closed: opts.stdoutClosed,
          stderr_closed: opts.stderrClosed,
          root_exited: opts.rootExited,
          root_exit_code: opts.rootExitCode,
          clock: "performance.now",
          child_pid: stamp.child_pid,
          tick_id: currentTickId(),
          kind: "login",
          probe: loginOpts?.probe === true,
          reason_code: "timeout",
          phase: "timeout_race",
          abandoned: true,
          cancel_requested: cancelRequested(),
          ...(loginOpts?.producer !== undefined
            ? { producer: loginOpts.producer }
            : {}),
          ...nativeAuthOperationMeta(loginOpts?.operationId),
        },
        nativeAuthDoctorObservation(loginOpts?.operationId, {
          configured_timeout_ms: timeoutMs,
          spawn_elapsed_ms: raceObservedAtMs - spawnedAtMs,
          budget_remaining_ms_at_spawn: remainingAtSpawn,
          timeout_callback_lateness_ms: Math.max(0, lateness),
          stdout_closed: opts.stdoutClosed,
          stderr_closed: opts.stderrClosed,
          root_exited: opts.rootExited,
          ...(typeof opts.rootExitCode === "number"
            ? { root_exit_code: opts.rootExitCode }
            : {}),
        }),
      );
      return { raceObservedAtMs, armed, fired, lateness };
    };

    const emitLoginCleanup = (opts: {
      readonly stdoutClosed: boolean;
      readonly stderrClosed: boolean;
      readonly rootExited: boolean;
      readonly rootExitCode: number | null;
      readonly cleanupMs: number;
      readonly cleanup: TChildCleanupOutcome;
    }): void => {
      logInfo(
        "spawn",
        safeDiagnosticMessage`Login cleanup finished.`,
        {
          configured_timeout_ms: timeoutMs,
          spawn_setup_ms: spawnSetupMs,
          stdout_closed: opts.stdoutClosed,
          stderr_closed: opts.stderrClosed,
          root_exited: opts.rootExited,
          root_exit_code: opts.rootExitCode,
          cleanup_ms: opts.cleanupMs,
          cleanup_reap: opts.cleanup.reap,
          cleanup_confirmed: opts.cleanup.confirmed,
          cancel_requested: opts.cleanup.cancel_requested,
          clock: "performance.now",
          child_pid: stamp.child_pid,
          tick_id: currentTickId(),
          kind: "login",
          probe: loginOpts?.probe === true,
          reason_code: "cleanup",
          phase: "cleanup",
          abandoned: true,
          ...(loginOpts?.producer !== undefined
            ? { producer: loginOpts.producer }
            : {}),
          ...nativeAuthOperationMeta(loginOpts?.operationId),
        },
        nativeAuthDoctorObservation(loginOpts?.operationId, {
          cleanup_ms: opts.cleanupMs,
          stdout_closed: opts.stdoutClosed,
          stderr_closed: opts.stderrClosed,
          root_exited: opts.rootExited,
          ...(typeof opts.rootExitCode === "number"
            ? { root_exit_code: opts.rootExitCode }
            : {}),
        }),
      );
    };

    const onTimeout = (): void => {
      void (async (): Promise<void> => {
        if (abandoned) return;
        const stdoutClosedAtDeadline = stdoutClosed;
        const stderrClosedAtDeadline = stderrClosed;
        const rootExitedAtDeadline =
          rootExitCode !== null ||
          proc.exitCode !== null ||
          proc.signalCode !== null;
        const rootExitCodeAtDeadline = rootExitCode ?? proc.exitCode;
        emitLoginTimeoutRace({
          stdoutClosed: stdoutClosedAtDeadline,
          stderrClosed: stderrClosedAtDeadline,
          rootExited: rootExitedAtDeadline,
          rootExitCode: rootExitCodeAtDeadline,
        });
        const defer = await awaitOnDeadline(loginOpts?.onDeadline);
        if (abandoned) return;
        if (defer) {
          const graceMs = Math.max(0, loginOpts?.persistenceGraceMs ?? 0);
          if (
            graceMs > 0 &&
            proc.exitCode === null &&
            proc.signalCode === null
          ) {
            await waitWithCap(proc.exited, graceMs);
          }
          if (abandoned) return;
          if (proc.exitCode !== null || proc.signalCode !== null) return;
        }
        const cleanupStartedAtMs = performance.now();
        kill();
        const reap = await requestTerminate();
        cleanupMs = performance.now() - cleanupStartedAtMs;
        cleanup = childCleanupOutcome(reap, cancelRequested());
        emitLoginCleanup({
          stdoutClosed: stdoutClosedAtDeadline,
          stderrClosed: stderrClosedAtDeadline,
          rootExited: rootExitedAtDeadline,
          rootExitCode: rootExitCodeAtDeadline,
          cleanupMs,
          cleanup,
        });
      })().catch((err: unknown) => {
        logError("spawn", err, {
          phase: "timeout_worker",
          child_pid: stamp.child_pid,
          tick_id: currentTickId(),
        });
        try {
          kill();
        } catch {
          // containment — do not end login-slot ownership from this worker
        }
        void requestTerminate().catch((reapErr: unknown) => {
          logError("spawn", reapErr, {
            phase: "timeout_worker_reap",
            child_pid: stamp.child_pid,
            tick_id: currentTickId(),
          });
        });
      });
    };
    const scheduleTimeout =
      loginTimeoutSchedulerForTests ??
      ((callback: () => void, delayMs: number): ReturnType<typeof setTimeout> =>
        setTimeout(callback, delayMs));
    timerDelayMs = budget.remainingMs();
    timerArmedAtMs = performance.now();
    killTimer = scheduleTimeout(() => {
      timerFiredAtMs = performance.now();
      onTimeout();
    }, timerDelayMs);
    const unbindAbort = bindAbort(opts?.signal, kill);

    const pump = async (
      stream: ReadableStream<Uint8Array>,
      onChunk: (s: string) => void,
      onClose: () => void,
    ): Promise<void> => {
      const reader = stream.getReader();
      readers.push(reader);
      try {
        for (;;) {
          if (abandoned) break;
          const { done, value } = await reader.read();
          if (done) {
            onClose();
            break;
          }
          if (abandoned) break;
          if (value !== undefined) onChunk(dec.decode(value));
          // Early-return once the awaited output appears (the child may never exit
          // cleanly — it can WEDGE after printing the token). Match the COMBINED
          // stream so a token on either fd is seen. We don't kill immediately: a
          // token can arrive split across read chunks, so a SETTLE delay lets the
          // remaining bytes land before we kill + parse — capturing the FULL token
          // without needing a stricter (and more brittle) trailing-boundary regex.
          if (
            opts?.until !== undefined &&
            settleTimer === null &&
            !abandoned &&
            opts.until.test(`${out}\n${err}`)
          ) {
            settleTimer = setTimeout(kill, UNTIL_SETTLE_MS);
          }
        }
      } catch {
        // Cancelled reader after abandon — captured output is still valid.
      } finally {
        try {
          reader.releaseLock();
        } catch {
          // Already cancelled.
        }
      }
    };

    await Promise.race([
      Promise.all([
        pump(
          stdout,
          (s) => {
            out += s;
          },
          () => {
            stdoutClosed = true;
          },
        ),
        pump(
          stderr,
          (s) => {
            err += s;
          },
          () => {
            stderrClosed = true;
          },
        ),
        proc.exited,
      ]),
      abandonedGate,
    ]);
    unbindEarlyAbort();
    unbindAbort();
    if (killTimer !== null) clearTimeout(killTimer);
    if (settleTimer !== null) clearTimeout(settleTimer);
    if (abandoned) {
      const cleanupStartedAtMs = performance.now();
      const reap = await requestTerminate();
      cleanupMs = performance.now() - cleanupStartedAtMs;
      cleanup = childCleanupOutcome(reap, cancelRequested());
    }

    // Only surface a SIGNAL kill we did NOT cause (a sandbox/OS kill) — our own
    // `until`/timeout kill is expected and its output is valid.
    if (!abandoned) logIfKilled(argv, proc, { confined: opts?.probe !== true });
    const childWaitMs = performance.now() - spawnedAtMs;
    if (loginOpts?.producer !== undefined) {
      logDebug("spawn", "native auth child finished", {
        producer: loginOpts.producer,
        ...nativeAuthOperationMeta(loginOpts.operationId),
        phase: "result",
        reason_code: abandoned ? "abandoned" : "complete",
        abandoned,
        child_pid: stamp.child_pid,
        tick_id: currentTickId(),
        clock: "performance.now",
        spawn_setup_ms: spawnSetupMs,
        child_wait_ms: childWaitMs,
        ...(cleanupMs !== null ? { cleanup_ms: cleanupMs } : {}),
        ...(cleanup !== undefined
          ? {
              cleanup_reap: cleanup.reap,
              cleanup_confirmed: cleanup.confirmed,
              cancel_requested: cleanup.cancel_requested,
            }
          : {}),
      });
    }
    // Join with a newline, NOT bare concatenation: a token printed as the last
    // bytes of stdout (no trailing newline) must not fuse with the first bytes
    // of stderr, or a greedy token match would swallow the spillover.
    return {
      code: proc.exitCode ?? -1,
      output: `${out}\n${err}`.trim(),
      abandoned,
      spawn_setup_ms: spawnSetupMs,
      child_wait_ms: childWaitMs,
      ...(cleanup !== undefined ? { cleanup } : {}),
      whenReleased: child.whenReleased,
      ...stamp,
    };
  } catch (error) {
    const reap = await requestTerminate();
    if (error instanceof SandboxLaunchError) throw error;
    return {
      code: -1,
      output: "",
      abandoned: true,
      cleanup: childCleanupOutcome(
        reap,
        signalAbortRequested(loginOpts?.signal),
      ),
      whenReleased: child.whenReleased,
      spawned_at_ms: Date.now(),
      child_pid:
        typeof child.subprocess.pid === "number" ? child.subprocess.pid : null,
    };
  } finally {
    budget.release();
  }
};

// OSC (ESC ] … BEL/ST), CSI (ESC [ … final), and lone ESC. Built from a
// string so the source stays free of raw control bytes.
const ANSI_RE = new RegExp(
  "\\u001b\\][^]*?(?:\\u0007|\\u001b\\\\)" +
    "|\\u001b\\[[0-9;?]*[ -/]*[@-~]" +
    "|\\u001b[@-Z\\\\-_]",
  "g",
);

/**
 * Strip ANSI/terminal control sequences (CSI colour codes, OSC, lone escapes)
 * from CLI output so a value parsed out of it isn't fused with rendering bytes.
 */
export const stripAnsi = (s: string): string => s.replace(ANSI_RE, "");

/** Strip URL query strings from diagnostics so OAuth parameters never surface
 * in a local log or dashboard error while retaining the actionable origin/path. */
export const redactUrls = (value: string): string =>
  value.replace(/(https?:\/\/[^\s?]+)\?\S*/g, "$1?<redacted>");

/**
 * Build the `script(1)` argv that runs `argv` under a PSEUDO-TERMINAL, writing
 * the terminal capture to `typescript` — or null on an OS without `script`
 * (caller falls back to a plain pipe spawn). Some vendor CLIs only run attached
 * to a real terminal (e.g. `kimi -p`'s raw-mode-gated print mode), emitting
 * NOTHING under a plain pipe. Shared by
 * {@link spawnLoginPty} (which POLLS the typescript for an `until` regex) and
 * the exec-fixture capture (which ignores the typescript — pass `/dev/null` —
 * and drives off its HTTP recorder instead).
 *
 * Subtleties baked in:
 *   - `-F` (BSD) / `-f` (util-linux, inside `-qfc`) is LOAD-BEARING: without it
 *     `script` BUFFERS the typescript and only flushes on close, so a poller
 *     reads empty until the child exits. `-F` flushes after every write.
 *   - `script` allocates the PTY at the DEFAULT 80×24 — window size is an ioctl
 *     (TIOCSWINSZ), NOT `COLUMNS`/`LINES` — so a TUI rendering a fixed-width box
 *     wraps a long value mid-line. We resize the slave with `stty` INSIDE the
 *     PTY (runs on the controlling tty before the real command via `exec`).
 *     `2>/dev/null` keeps an `stty`-less environment from breaking the flow.
 *   - BSD (`script -q <file> cmd…`) vs util-linux (`script -qfc "cmd" <file>`)
 *     differ in argument order.
 */
export const ptyScriptArgv = (
  argv: ReadonlyArray<string>,
  typescript: string,
): string[] | null => {
  const os = platform();
  if (os !== "darwin" && os !== "linux") return null;
  const escapeShellArg = (arg: string): string =>
    `'${arg.replace(/'/g, "'\\''")}'`;
  const cmd = argv.map(escapeShellArg).join(" ");
  const widen = `stty cols 1000 rows 50 2>/dev/null; exec ${cmd}`;
  return os === "darwin"
    ? ["script", "-F", "-q", typescript, "sh", "-c", widen]
    : ["script", "-qfc", widen, typescript];
};

/**
 * Like {@link spawnLogin}, but runs `argv` under a PSEUDO-TERMINAL (via
 * `script(1)`). Some vendor CLIs only work attached to a real terminal — e.g.
 * `kimi -p`'s raw-mode-gated print mode writes to its controlling terminal
 * (`/dev/tty`), so spawned with a plain pipe (no controlling TTY) it emits
 * NOTHING and the headless daemon captures `outputLen: 0`. A PTY makes it
 * actually run, and we capture its terminal output to a `script` typescript
 * file which we POLL — so `opts.until` returns the instant the match appears.
 *
 * Key subtleties, each load-bearing (see the harness in `tests/`):
 *   - stdin is `/dev/null` (`"ignore"`): a Bun pipe/stream/inherited stdin makes
 *     `script` block before it sets up the PTY (empirically 0 bytes captured).
 *   - the child does NOT EOF-exit despite `/dev/null`: it reads the PTY SLAVE,
 *     not `script`'s stdin, so its stdin stays open for the browser flow.
 *   - we read the typescript FILE, not `script`'s stdout: piping `script`'s
 *     stdout under `Bun.spawn` also yields 0 bytes.
 *   - BSD (`script -q <file> cmd…`) vs util-linux (`script -qfc "cmd" <file>`)
 *     differ; unsupported elsewhere → falls back to plain {@link spawnLogin}.
 */
export const spawnLoginPty = async (
  argv: ReadonlyArray<string>,
  env?: Record<string, string | undefined>,
  opts?: TSpawnLoginOpts,
): Promise<TLoginResult> => {
  const ptyOpts = opts;
  const os = platform();
  if (os !== "darwin" && os !== "linux") return spawnLogin(argv, env, ptyOpts);
  if (signalAbortRequested(ptyOpts?.signal)) {
    return noChildResult(true);
  }

  const leased = spawnEnvLeased(env);
  // Set once the PTY child exists: the minted dir must outlive the child's
  // whole process tree, not only this function (rework-8).
  let released: Promise<unknown> | null = null;

  // Wrap the WHOLE `script(1)` argv — the PTY wrapper and the vendor CLI it
  // runs are one confined tree.
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS;
  const parentBudget = budgetFromSignal(opts?.signal);
  const budget =
    parentBudget?.child(timeoutMs) ??
    createDeadlineBudget(timeoutMs, opts?.signal);
  try {
    const tsFile = join(
      leased.tmpDir ?? daemonTempDir(),
      `openllmd-pty-${process.pid}-${Date.now().toString(36)}.log`,
    );
    await Bun.write(tsFile, "");
    // PTY argv (shared with the exec-fixture capture). Non-null here: the OS
    // was already gated to darwin/linux above. We POLL `tsFile` for
    // `opts.until`.
    const scriptArgv = ptyScriptArgv(argv, tsFile) ?? [...argv];
    const child = superviseSpawn(
      sandboxSpawnArgs(scriptArgv, { probe: opts?.probe }),
      {
        kind: "login",
        stdin: "ignore",
        stdout: "ignore",
        stderr: "ignore",
        cwd: spawnCwd(env),
        env: leased.env,
      },
    );
    const proc = child.subprocess;
    released = Promise.allSettled([proc.exited, child.whenReleased]);
    await child.sandbox?.ready;
    // Lease upgrade only — NOT the exit watcher: the typescript lives inside
    // the minted dir and is read once more after the child exits, so removal
    // must wait for the function's own cleanup (the finally below removes the
    // whole dir; the child is dead on every path by then).
    if (leased.tmpDir !== null && typeof proc.pid === "number") {
      leaseMintedTmpToChild(leased.tmpDir, proc.pid, "login-pty");
    }
    const stamp = spawnStamp(proc);
    const spawnedAtMs = performance.now();
    let terminatePromise: Promise<TReapOutcome> | null = null;
    const requestTerminate = (): Promise<TReapOutcome> => {
      if (terminatePromise === null) {
        terminatePromise = child.terminate(
          splitReapBudget(budget.remainingMs()),
        );
      }
      return terminatePromise;
    };

    const readFile = (): Promise<string> =>
      Bun.file(tsFile)
        .text()
        .catch(() => "");
    let abandoned = false;
    let captured = "";
    const kill = (): void => {
      if (abandoned) return;
      abandoned = true;
      void requestTerminate();
    };
    const unbindAbort = bindAbort(opts?.signal, kill);
    let ptyCleanup: TChildCleanupOutcome | undefined;
    try {
      for (;;) {
        if (abandoned) break;
        captured = await readFile();
        if (opts?.until?.test(stripAnsi(captured)) === true) {
          // Settle: let the rest of the token line render before we kill + parse.
          await new Promise((r) => setTimeout(r, UNTIL_SETTLE_MS));
          captured = await readFile();
          kill();
          break;
        }
        if (proc.exitCode !== null || proc.signalCode !== null) break; // exited
        if (budget.expired()) {
          logWarn(
            "spawn",
            ptyOpts?.producer === "claude-refresh"
              ? safeDiagnosticMessage`Credential refresh exceeded its time budget.`
              : safeDiagnosticMessage`Login exceeded its time budget.`,
            {
              configured_timeout_ms: timeoutMs,
              spawn_elapsed_ms: performance.now() - spawnedAtMs,
              clock: "performance.now",
              child_pid: stamp.child_pid,
              kind: "login",
              probe: ptyOpts?.probe === true,
              reason_code: "timeout",
              phase: "timeout_race",
              abandoned: true,
              cancel_requested: signalAbortRequested(ptyOpts?.signal),
              ...(ptyOpts?.producer !== undefined
                ? { producer: ptyOpts.producer }
                : {}),
              ...nativeAuthOperationMeta(ptyOpts?.operationId),
            },
            nativeAuthDoctorObservation(ptyOpts?.operationId, {
              configured_timeout_ms: timeoutMs,
              spawn_elapsed_ms: performance.now() - spawnedAtMs,
            }),
          );
          const defer = await awaitOnDeadline(ptyOpts?.onDeadline);
          if (defer) {
            const graceMs = Math.max(0, ptyOpts?.persistenceGraceMs ?? 0);
            if (
              graceMs > 0 &&
              proc.exitCode === null &&
              proc.signalCode === null
            ) {
              await waitWithCap(proc.exited, graceMs);
            }
            if (proc.exitCode !== null || proc.signalCode !== null) break;
          }
          kill();
          break;
        }
        await new Promise((r) =>
          setTimeout(r, Math.min(400, budget.remainingMs())),
        );
      }
      if (abandoned) {
        const cleanupStartedAtMs = performance.now();
        const reap = await requestTerminate();
        const ptyCleanupMs = performance.now() - cleanupStartedAtMs;
        ptyCleanup = childCleanupOutcome(
          reap,
          signalAbortRequested(ptyOpts?.signal),
        );
        logInfo(
          "spawn",
          safeDiagnosticMessage`Login cleanup finished.`,
          {
            cleanup_ms: ptyCleanupMs,
            cleanup_reap: ptyCleanup.reap,
            cleanup_confirmed: ptyCleanup.confirmed,
            cancel_requested: ptyCleanup.cancel_requested,
            clock: "performance.now",
            child_pid: stamp.child_pid,
            kind: "login",
            reason_code: "cleanup",
            phase: "cleanup",
            abandoned: true,
            ...(ptyOpts?.producer !== undefined
              ? { producer: ptyOpts.producer }
              : {}),
            ...nativeAuthOperationMeta(ptyOpts?.operationId),
          },
          nativeAuthDoctorObservation(ptyOpts?.operationId, {
            cleanup_ms: ptyCleanupMs,
          }),
        );
      } else {
        const leftover = budget.remainingMs();
        let timer: ReturnType<typeof setTimeout> | null = null;
        try {
          await Promise.race([
            proc.exited,
            new Promise<void>((resolve) => {
              timer = setTimeout(resolve, leftover);
            }),
          ]);
        } finally {
          if (timer !== null) clearTimeout(timer);
        }
        if (proc.exitCode === null && proc.signalCode === null) {
          const reap = await requestTerminate();
          abandoned = true;
          ptyCleanup = childCleanupOutcome(
            reap,
            signalAbortRequested(ptyOpts?.signal),
          );
        }
      }
    } finally {
      unbindAbort();
    }
    captured = await readFile(); // final read (token written just before exit)
    await rm(tsFile, { force: true }).catch(() => {});
    if (!abandoned)
      logIfKilled(scriptArgv, proc, { confined: opts?.probe !== true });
    return {
      code: proc.exitCode ?? -1,
      output: stripAnsi(captured),
      abandoned,
      ...(ptyCleanup !== undefined ? { cleanup: ptyCleanup } : {}),
      whenReleased: child.whenReleased,
      ...stamp,
    };
  } finally {
    // No child: remove the dir now. A child: remove it only after the child
    // and its process tree are released; a timed-out or abandoned child can
    // still be writing into it (rework-8).
    if (released === null) discardMintedTmpDir(leased);
    else discardMintedTmpDirAfter(leased, released);
    budget.release();
  }
};

/**
 * The env a GUI opener may inherit: only what it needs to reach the user's
 * desktop session — display/bus sockets, desktop-identity hints, locale —
 * never the daemon's working env. `OPENLLM_API_KEY` & co. would otherwise
 * land in EVERY browser process (and whatever it spawns) as a plain
 * inherited var.
 */
const OPENER_ENV_KEYS: ReadonlySet<string> = new Set([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "LANG",
  "LANGUAGE",
  "TERM",
  "COLORTERM",
  "TMPDIR",
  "TEMP",
  "TMP",
  "TZ",
  // GUI session reachability.
  "DISPLAY",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
  "DBUS_SESSION_BUS_ADDRESS",
  "XDG_RUNTIME_DIR",
  "XDG_CURRENT_DESKTOP",
  "XDG_SESSION_DESKTOP",
  "XDG_SESSION_TYPE",
  "XDG_CONFIG_HOME",
  "XDG_CONFIG_DIRS",
  "XDG_DATA_HOME",
  "XDG_DATA_DIRS",
  "DESKTOP_SESSION",
  "KDE_FULL_SESSION",
  "GNOME_DESKTOP_SESSION_ID",
  "XDG_MENU_PREFIX",
  // xdg-open's generic mode honours the user's preferred browser.
  "BROWSER",
]);

/**
 * Build the opener's env from the ambient one via `OPENER_ENV_KEYS` (plus the
 * `LC_*` locale family). Pure; the test seam for `openUrl`'s env hygiene.
 */
export const browserOpenerEnv = (
  ambient: Readonly<Record<string, string | undefined>> = process.env,
): Record<string, string> => {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(ambient)) {
    if (value === undefined) continue;
    if (!OPENER_ENV_KEYS.has(key) && !key.startsWith("LC_")) continue;
    env[key] = value;
  }
  return env;
};

/** A random transient-unit suffix — a fixed name would collide when two opens
 *  race (`systemd-run` rejects a duplicate unit), and hex is always a valid
 *  unit-name component. */
const randomUnitSuffix = (): string =>
  crypto.randomUUID().replace(/-/g, "").slice(0, 12);

export type TOpenerArgvDeps = {
  /** Ambient env the transient service's `--setenv` list derives from. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Path of the launcher script {@link writeOpenerScript} produced. The URL
   *  rides in the script CONTENT (mode 0600 under the daemon's private tmp
   *  dir), never in argv — `ps`, the transient unit's ExecStart, journald and
   *  the Windows process command line would each keep a copy of an
   *  argv-carried URL (S4R-1). Required on every OS; without it no safe
   *  opener exists. */
  readonly scriptPath?: string;
};

/**
 * Quote `value` as a POSIX single-quoted shell word — embedded `'`, `$`,
 * backticks and newlines all stay literal inside the quotes (the `'\''` idiom
 * closes, re-opens and continues the quote). The sign-in URL therefore reaches
 * the opener byte-for-byte while remaining in file content, not argv.
 */
const shSingleQuoted = (value: string): string =>
  `'${value.replaceAll("'", "'\\''")}'`;

/**
 * Escape a URL for a `cmd.exe` batch line. `"`, CR and LF become percent
 * escapes — they could otherwise break out of the quoted argument or split
 * the line into a second command. Every `%` then doubles: batch expands `%`
 * even inside double quotes, so a `%20` in an OAuth URL would otherwise lose
 * bytes to parameter expansion.
 */
const cmdQuotedUrl = (url: string): string =>
  url
    .replaceAll('"', "%22")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A")
    .replaceAll("%", "%%");

/** Which launcher file {@link writeOpenerScript} writes. `open`/`xdg-open`
 *  produce a POSIX `sh` script; `cmd` produces a Windows batch file whose
 *  `start` builtin opens the URL (cmd has no sh to hand off to). */
export type TOpenerScriptKind = "open" | "xdg-open" | "cmd";

/** Ownership marker embedded in every launcher {@link writeOpenerScript}
 *  writes. The stale-launcher sweep reads the file's head and deletes only
 *  when this marker is present — a same-named foreign file is never ours to
 *  remove (the tmp dir can be shared or redirected). Exported for the sweep
 *  regression suite. */
export const OPENER_SCRIPT_MARKER = "openllm-opener-v1";

const openerScriptContent = (kind: TOpenerScriptKind, url: string): string => {
  if (kind === "cmd") {
    // `start` returns as soon as the browser launch is queued; the `(goto)`
    // idiom then ends the batch WITHOUT the "batch file cannot be found"
    // error a trailing `del "%~f0"` would print, while `&` still runs the
    // self-delete. CRLF line endings: `goto` misbehaves on LF-only batches.
    return `@echo off\r\nrem ${OPENER_SCRIPT_MARKER}\r\nstart "" "${cmdQuotedUrl(url)}"\r\n(goto) 2>nul & del /f /q "%~f0"\r\n`;
  }
  // Delete the script before the opener starts.
  // S4R-1 (P3): The opener requires the URL in argv.
  // Other local users can see that URL in the process list.
  return `#!/bin/sh\n# ${OPENER_SCRIPT_MARKER}\nrm -f -- "$0"\nexec ${kind} ${shSingleQuoted(url)}\n`;
};

/** Launcher filenames carry this prefix so a sweep can find exactly the files
 *  we wrote — nothing else under the daemon tmp dir matches it. (The brief
 *  `open-*.sh` name an intermediate, never-shipped revision used is NOT
 *  matched: it is a common prefix, and sweeping it could delete foreign
 *  files when the tmp dir is shared or redirected.) */
const OPENER_SCRIPT_PREFIX = "openllm-open-";

const isOpenerScriptName = (name: string): boolean =>
  name.startsWith(OPENER_SCRIPT_PREFIX) &&
  (name.endsWith(".sh") || name.endsWith(".cmd"));

/** Bytes of file head the ownership check reads — the marker line sits in the
 *  first two lines of every generated launcher, far under this bound. */
const OPENER_MARKER_READ_BYTES = 512;

/** True only when `path` carries {@link OPENER_SCRIPT_MARKER} in its head —
 *  the ownership proof a sweep requires before deleting a launcher-named
 *  file. Never throws. */
const isOpenerScriptFile = (path: string): boolean => {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return false;
  }
  try {
    const head = Buffer.alloc(OPENER_MARKER_READ_BYTES);
    const n = readSync(fd, head, 0, head.length, 0);
    return head.subarray(0, n).toString("utf8").includes(OPENER_SCRIPT_MARKER);
  } catch {
    return false;
  } finally {
    try {
      closeSync(fd);
    } catch {
      // best-effort close
    }
  }
};

/**
 * A launcher older than this can only come from a queued transient unit that
 * never ran or a killed opener — `systemd-run` hands the script to the user
 * manager within seconds, so this bound is generous. Anything fresher belongs
 * to an open that is still in flight and must be left alone.
 */
export const OPENER_SCRIPT_STALE_MS = 10 * 60_000;

/**
 * Grace window between spawning the opener and the backstop delete. A unit
 * that runs self-deletes the script long before this; a unit that failed to
 * start leaves it, and {@link armOpenerScriptCleanup} removes it once this
 * window passes — bounded residue, never a permanent file.
 */
export const OPENER_SCRIPT_GRACE_MS = 120_000;

/**
 * Remove launcher scripts older than {@link OPENER_SCRIPT_STALE_MS} from `dir`
 * (bounded stale-launcher cleanup). One directory listing; a file is touched
 * only when its NAME matches {@link OPENER_SCRIPT_PREFIX} AND its head carries
 * {@link OPENER_SCRIPT_MARKER} — the ownership proof that keeps the sweep off
 * foreign same-named files when the tmp dir is shared or redirected. Never
 * throws — a missed file waits for the next open's sweep or the armed timer.
 */
export const sweepStaleOpenerScripts = (
  dir: string = daemonTempDir(),
  now: number = Date.now(),
): void => {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    if (!isOpenerScriptName(name)) continue;
    const path = join(dir, name);
    try {
      if (now - statSync(path).mtimeMs <= OPENER_SCRIPT_STALE_MS) continue;
      if (!isOpenerScriptFile(path)) continue;
      rmSync(path, { force: true });
    } catch {
      // best-effort — a raced-away or busy file is retried on the next open
    }
  }
};

/**
 * Schedule the backstop delete of a launcher script (the asynchronous
 * unit-failure cleanup path). `systemd-run --user --no-block` can exit 0 for
 * a start job that then fails BEFORE `/bin/sh` runs — the script's
 * self-delete never executes and the URL-bearing file would sit in daemon
 * state indefinitely. The unref'd timer removes it after
 * {@link OPENER_SCRIPT_GRACE_MS}; a unit that did run already self-deleted,
 * so the delete is then a harmless no-op. Never holds the process open.
 */
export const armOpenerScriptCleanup = (
  scriptPath: string,
  delayMs: number = OPENER_SCRIPT_GRACE_MS,
): void => {
  setTimeout(() => {
    try {
      rmSync(scriptPath, { force: true });
    } catch {
      // best-effort — the next open's sweep still catches a leftover
    }
  }, delayMs).unref();
};

/**
 * Write the launcher script a browser-open runs so the URL never sits in
 * process argv (S4R-1): POSIX gets a self-deleting 0600 `sh` script, Windows
 * a self-deleting `.cmd` batch — in both cases only the script PATH reaches
 * argv. Written under `dir` — the daemon's private tmp root by default — so
 * only the daemon's uid can read it for the brief window it exists, and a
 * stale-launcher sweep runs first so failed predecessors cannot accumulate.
 * Returns the script path, or null when the write failed (the caller then
 * logs the URL for a manual open).
 */
export const writeOpenerScript = (
  opener: TOpenerScriptKind,
  url: string,
  dir: string = daemonTempDir(),
): string | null => {
  try {
    sweepStaleOpenerScripts(dir);
    const path = join(
      dir,
      `${OPENER_SCRIPT_PREFIX}${randomUnitSuffix()}${opener === "cmd" ? ".cmd" : ".sh"}`,
    );
    writeFileSync(path, openerScriptContent(opener, url), { mode: 0o600 });
    return path;
  } catch {
    return null;
  }
};

// Startup sweep. The unref'd backstop timer in {@link armOpenerScriptCleanup}
// dies with the process: a daemon killed or crashed inside
// `OPENER_SCRIPT_GRACE_MS` leaves the URL-bearing launcher on disk forever,
// and failed opens accumulate. This module loads at process start in every
// binary that can spawn an opener (the daemon pulls it in eagerly —
// `daemon-runtime` → `self-update` → `spawn`), so sweeping here bounds the
// residue to one restart instead of relying only on the next open's sweep.
// The stale-age floor keeps a fresh in-flight launcher of a second live
// daemon (dev + prod share the state dir) untouched.
sweepStaleOpenerScripts();

/**
 * Bound on the user-manager socket probe. A unix connect completes or refuses
 * immediately; the timer only guards a pathological kernel stall so a login
 * can never hang on the check.
 */
export const SYSTEMD_PROBE_TIMEOUT_MS = 500;

/** True only when a unix socket at `path` accepts a connection — i.e. a live
 *  listener, not a stale socket file or a planted regular file. */
const unixSocketAccepts = (path: string, timeoutMs: number): Promise<boolean> =>
  new Promise((resolve) => {
    let socket: ReturnType<typeof connect>;
    try {
      // `connect` throws synchronously on a path over the AF_UNIX limit, so a
      // long XDG_RUNTIME_DIR must yield "unreachable", not a rejection.
      socket = connect(path);
    } catch {
      resolve(false);
      return;
    }
    const finish = (ok: boolean): void => {
      clearTimeout(timer);
      socket.destroy();
      resolve(ok);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    timer.unref();
    socket.unref();
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });

/**
 * Is a systemd USER manager reachable? `INVOCATION_ID` only proves the daemon
 * itself is supervised — `systemd-run --user` can still fail asynchronously
 * when no user manager instance is running (e.g. a system-scope service), so
 * probing it is the actual gate (S4R-2). The manager's private control socket
 * at `$XDG_RUNTIME_DIR/systemd/private` is exactly what `systemd-run --user`
 * talks to. Pathname existence is NOT proof — a crashed manager leaves a
 * stale socket file and anything can plant a regular file there — so the path
 * must stat as a socket AND accept a connection. Refused/timeout → the
 * attempt is certainly doomed and the caller prints the URL instead.
 */
export const systemdUserManagerPresent = async (
  env: Readonly<Record<string, string | undefined>> = process.env,
): Promise<boolean> => {
  const xdg = env.XDG_RUNTIME_DIR;
  if (typeof xdg !== "string" || xdg.length === 0) return false;
  const socketPath = join(xdg, "systemd", "private");
  try {
    if (!statSync(socketPath).isSocket()) return false;
  } catch {
    return false;
  }
  return unixSocketAccepts(socketPath, SYSTEMD_PROBE_TIMEOUT_MS);
};

/**
 * The opener argv for a URL on `os` — or `null` when no SAFE launcher exists.
 *
 * On Linux a browser must NEVER be a daemon child: inside the shipped systemd
 * unit (`NoNewPrivileges=yes` + `RestrictNamespaces=yes`, `service.ts`) a
 * Chrome/Chromium sandbox cannot create user namespaces and fails or crashes,
 * and a `systemctl restart` / self-update kills any browser still in the
 * unit's cgroup mid-login. Under systemd we therefore ask the USER MANAGER to
 * start `xdg-open` as a transient SERVICE (`systemd-run --user --collect
 * --quiet --no-block --unit=<random>`) — not a scope: a `systemd-run --scope`
 * would still make `systemd-run` the browser's parent inside the daemon's
 * own cgroup/security context. A service is owned by the user manager
 * (clean prctl/seccomp state, the user's real session cgroup) and survives
 * a daemon exit or restart; `--no-block` keeps the login flow off the unit's
 * start job. The service does NOT inherit our env, so the GUI-session
 * allowlist rides in explicit `--setenv` pairs (all non-secret).
 *
 * The URL is never placed on the command line (S4R-1): `ps`, the transient
 * unit's ExecStart, and journald would each keep a copy. POSIX openers instead
 * run the 0600 launcher script written by {@link writeOpenerScript}
 * (`deps.scriptPath`) — it self-deletes and then execs the real opener. Since
 * no argv element carries the URL, systemd-run's `${VAR}` argument expansion
 * has nothing to rewrite, on ANY systemd version.
 *
 * With no systemd USER manager (see {@link systemdUserManagerPresent}) there
 * is no out-of-unit launcher, so the caller prints the URL instead of spawning
 * a doomed child. macOS `open` is already out-of-process (it hands the URL to
 * LaunchServices; the browser is never our child). Windows `start` is a `cmd`
 * builtin, so a `.cmd` launcher batch is the no-argv hand-off there —
 * `cmd /d /c <file>` runs the script and only the script PATH ever sits in
 * argv. `/d` skips the AutoRun hook; `%`-doubling inside the batch keeps an
 * OAuth `%20` intact (`cmdQuotedUrl`).
 */
export const openerArgv = (
  // The URL rides in `deps.scriptPath` content, never in argv — the parameter
  // stays so the call sites and the "no argv element carries it" tests keep
  // their shape.
  _url: string,
  os: NodeJS.Platform = process.platform,
  underSystemd: boolean,
  deps?: TOpenerArgvDeps,
): string[] | null => {
  const scriptPath = deps?.scriptPath;
  if (os === "win32") {
    if (scriptPath === undefined) return null;
    return ["cmd", "/d", "/c", scriptPath];
  }
  if (os !== "darwin" && os !== "linux") return null;
  if (os === "linux" && !underSystemd) return null;
  if (scriptPath === undefined) return null;
  if (os === "darwin") return ["/bin/sh", scriptPath];
  const openerEnv = browserOpenerEnv(deps?.env ?? process.env);
  return [
    "systemd-run",
    "--user",
    "--collect",
    "--quiet",
    "--no-block",
    `--unit=openllm-open-${randomUnitSuffix()}`,
    ...Object.entries(openerEnv).map(
      ([key, value]) => `--setenv=${key}=${value}`,
    ),
    "--",
    "/bin/sh",
    scriptPath,
  ];
};

/**
 * The URL form safe to write to a log line: `origin + pathname` only. The
 * query and fragment can carry OAuth `code`/`state` secrets, so failure
 * diagnostics never log them (the full URL still reaches the user through the
 * `auth.login.prompt` card, and through the no-launcher manual-open log where
 * it IS the fallback). Unparseable input yields a fixed placeholder.
 */
export const redactUrlForLog = (url: string): string => {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "(unparseable URL)";
  }
};

/** Test seam: substitutes the browser-launcher spawn so a test can drive the
 *  failure paths without launching a real browser. Production never sets
 *  this. */
let openerSpawnForTests: typeof admittedSpawn | null = null;
export const setOpenerSpawnForTests = (
  spawn: typeof admittedSpawn | null,
): void => {
  openerSpawnForTests = spawn;
};

/**
 * The async body of {@link openUrl}: probe the manager, write the launcher,
 * spawn it, arm the backstop cleanup. Never throws — every failure path ends
 * in the manual-open log.
 *
 * Exported for the regression suite: a direct call bypasses {@link openUrl}'s
 * NODE_ENV=test browser guard, so under the test runner the spawn step runs
 * ONLY through {@link setOpenerSpawnForTests} — never a real launcher.
 */
export const openUrlBestEffort = async (url: string): Promise<void> => {
  const os = platform();
  // Probe the systemd USER MANAGER itself, not INVOCATION_ID (S4R-2): the var
  // only proves we are supervised, while `systemd-run --user` fails
  // asynchronously — silently, after this function returns — when no user
  // manager is running. The probe connects to the same socket systemd-run
  // would dial, so a stale socket file or a planted regular file still reads
  // as "no manager" and takes the manual-open fallback.
  const userManager =
    os === "linux" && (await systemdUserManagerPresent(process.env));
  // The URL rides in a self-deleting 0600 launcher script, never argv (S4R-1):
  // an `sh` script on POSIX, a `.cmd` batch on Windows.
  const scriptPath =
    os === "win32" || os === "darwin" || (os === "linux" && userManager)
      ? writeOpenerScript(
          os === "win32" ? "cmd" : os === "darwin" ? "open" : "xdg-open",
          url,
        )
      : null;
  const argv = openerArgv(url, os, userManager, {
    env: process.env,
    ...(scriptPath !== null ? { scriptPath } : {}),
  });
  if (argv === null) {
    // No safe launcher: no systemd user manager, or the script write failed —
    // log the URL for a manual open rather than spawn a GUI browser as a
    // daemon child.
    logInfo(
      "spawn",
      safeDiagnosticMessage`Browser auto-open is unavailable; open the sign-in URL manually.`,
      { url },
    );
    return;
  }
  try {
    // Deliberately UNWRAPPED (no `sandboxSpawnArgs`): opening the user's
    // browser is a user-facing action like the session-PTY exemption — the
    // launcher must reach the real GUI session/LaunchServices state, and it
    // takes only the URL string (no filesystem payload to confine). Under the
    // test runner a direct call to this exported body must install the seam —
    // the real launcher would pop a browser on the developer's machine.
    const spawnImpl =
      openerSpawnForTests ??
      (process.env.NODE_ENV === "test" ? null : admittedSpawn);
    if (spawnImpl === null) return;
    const proc = spawnImpl(argv, {
      stdin: "ignore",
      stdout: "ignore",
      stderr: "ignore",
      cwd: spawnCwd(undefined),
      // The opener runs the user's browser — daemon secrets must not ride
      // along. POSIX gets the GUI-session allowlist; Windows keeps its env
      // (minus the daemon-authority prefixes) since `cmd` depends on more of
      // the system env than the fixed list models.
      env:
        os === "win32"
          ? childEnvironment(process.env)
          : browserOpenerEnv(process.env),
    });
    // `systemd-run --no-block` can exit 0 for a start job that then fails
    // BEFORE the script runs — self-delete never executes and the URL-bearing
    // file would persist indefinitely. The backstop timer removes it after the
    // grace window; the per-write sweep bounds anything older.
    if (scriptPath !== null) armOpenerScriptCleanup(scriptPath);
    // A spawned-but-failed opener (systemd-run rejects, `open` exits nonzero)
    // is otherwise invisible — surface the manual-open fallback explicitly so
    // the "no browser opened" report has a cause (S4R-2). Fire-and-forget: the
    // card already shows the URL.
    void proc.exited.then((code) => {
      if (code !== 0) {
        // The unit never ran (or the launcher failed) — the script will not
        // self-delete, so remove it here rather than leave the URL on disk.
        if (scriptPath !== null) {
          try {
            rmSync(scriptPath, { force: true });
          } catch {
            // best-effort cleanup — the file sits in the daemon-private tmp
          }
        }
        logWarn(
          "spawn",
          "Browser opener exited non-zero — open the sign-in URL manually",
          // Redacted: the URL's query can carry OAuth code/state secrets.
          { opener: argv[0], code, url: redactUrlForLog(url) },
        );
      }
    });
  } catch {
    if (scriptPath !== null) {
      try {
        rmSync(scriptPath, { force: true });
      } catch {
        // best-effort cleanup — the file sits in the daemon-private tmp
      }
    }
    // best-effort — the user can copy the URL from the card detail; say so.
    // The URL is logged REDACTED: its query can carry OAuth `code`/`state`
    // secrets that must not land in `openllmd.log` (rework P3).
    logWarn(
      "spawn",
      "Browser opener failed to spawn — open the sign-in URL manually",
      { url: redactUrlForLog(url) },
    );
  }
};

/**
 * Best-effort open a URL in the user's default browser — a self-deleting
 * launcher script run by macOS `open`, Windows `cmd`, or a transient
 * `systemd-run --user` SERVICE running `xdg-open` under systemd (see
 * {@link openerArgv}). Used by the browser / device-code login flows to bring
 * up the vendor's auth page FROM the daemon — some vendor CLIs print the URL
 * but their own auto-open doesn't reach the user's GUI session when the
 * daemon spawns them (e.g. codex). Fire-and-forget and never throws: the user
 * can copy the URL from the card, and when no safe launcher exists the URL is
 * logged.
 */
export const openUrl = (url: string): void => {
  // Never launch a real browser under the test runner (`bun test` sets
  // NODE_ENV=test) — a device/browser login test that reaches this line would
  // otherwise pop a tab on the developer's machine. Production is unaffected.
  if (process.env.NODE_ENV === "test") return;
  // The manager probe is async; the login flow does not wait on a browser.
  void openUrlBestEffort(url).catch(() => {});
};
