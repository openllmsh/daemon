/**
 * Isolated macOS login keychain. Split out of `util.ts` (which re-exports
 * everything here — import from either).
 *
 * On macOS, Claude Code stores its OAuth credential in the login Keychain
 * (there is NO file-based override — confirmed via the Claude Code docs).
 * Vendor CLIs resolve their keychain by HOME path: the implicit default is
 * `<home>/Library/Keychains/login.keychain-db`, and the user-domain search
 * list + default keychain live in `<home>/Library/Preferences/
 * com.apple.security.plist` (HOME-scoped — verified on macOS 27: writes under
 * an isolated HOME land in that HOME's plist, never the user's real one).
 *
 * ── File name (macOS 26+ fix) ─────────────────────────────────────────
 * macOS 26+ REFUSES `unlock-keychain -p ""` on any file named
 * `login.keychain-db` (exit 51 — the name is special-cased to the account
 * password; upstream quicksand PR #37, proven on macOS 27). So the isolated
 * chain lives at `openllm-isolated.keychain-db` and we make it the user-domain
 * search-list + default keychain of the isolated HOME (`security
 * list-keychains -d user -s` / `default-keychain -d user -s`, which need
 * `Library/Preferences` to exist — `security` silently drops the write
 * otherwise). A legacy `login.keychain-db` under the isolated HOME is
 * migrated by rename: items and ACLs are preserved, and the name-keyed
 * refusal stops applying. The user's real login keychain is never touched.
 *
 * ── Readiness gate (2026-08 GUI-prompt fix) ─────────────────────────────
 * The isolated keychain is created empty-password. If that invariant ever
 * breaks (a pre-existing file whose password drifted from `""`, e.g. one
 * created under the old reserved-name-under-sandbox path that itself popped a
 * dialog), `unlock-keychain -p ""` fails. Historically we still ran
 * `dump-keychain` — and let the vendor CLI (`claude auth status`) open the
 * locked chain — which raises a `builtin:unlock-keychain` SecurityAgent GUI
 * dialog every status tick. So `ensureKeychainReady` now RETURNS a tri-state:
 * NOTHING that could prompt (our dump/grant, or the vendor CLI in
 * `claude-code.ts`) runs unless it reports `present` (unlocked THIS call AND
 * the vendor-visible search list/default configured). A genuine
 * empty-password drift self-heals once (rename-aside + recreate); a chain
 * that still can't unlock is negative-cached so it stops re-prompting.
 * See docs/plan/2026-08-22-daemon-keychain-gui-prompt-wedge-fix.md.
 */
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  opendirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir, platform } from "node:os";
import { basename, dirname, join } from "node:path";
import { superviseSpawn } from "../child-supervisor";
import type { TDeadlineBudget } from "../deadline-budget";
import {
  budgetFromSignal,
  createDeadlineBudget,
  splitReapBudget,
  waitUntilExpired,
} from "../deadline-budget";
import {
  logDebug,
  logError,
  logInfo,
  logWarn,
  safeDiagnosticMessage,
} from "../logger";
import { currentTickId } from "../op-context";
import { sandboxSpawnArgs } from "../sandbox/exec";
import { unwrapKeychainSpawn } from "../sandbox/policy";
import { classifyStatError } from "./observation-cache";
import { redactSensitiveArgv } from "./redact-sensitive-argv";
import { bindAbort, logIfKilled, spawnCwd } from "./spawn";
import type { TStoreRead } from "./util";

let platformOverrideForTests: NodeJS.Platform | null = null;
const isMac = (): boolean =>
  (platformOverrideForTests ?? platform()) === "darwin";

/** Override platform detection for deterministic unit tests. */
export const setKeychainPlatformForTests = (
  value: NodeJS.Platform | null,
): void => {
  platformOverrideForTests = value;
};

/** Readiness = the shared tri-state: `present` (created + unlocked this call),
 *  `indeterminate` (create/unlock failed or the chain is unusable). Off macOS
 *  there is nothing to gate, so it is always `present`. */
const READY: TStoreRead<void> = { kind: "present", value: undefined };

/** The isolated keychain file. MUST NOT end in `login` — on macOS 26+
 *  `security` special-cases `*login.keychain-db` to the account password, so
 *  `unlock-keychain -p ""` exits 51 no matter the path (name-keyed, not
 *  path-keyed; verified on macOS 27). */
const ISOLATED_KEYCHAIN_NAME = "openllm-isolated.keychain-db";
const LEGACY_LOGIN_KEYCHAIN_NAME = "login.keychain-db";

const isolatedKeychainPath = (home: string): string =>
  join(home, "Library", "Keychains", ISOLATED_KEYCHAIN_NAME);

/** Pre-2.8 name. Still readable data — migrated by rename, never read in
 *  place (its name makes `unlock-keychain -p ""` fail on macOS 26+). */
const legacyLoginKeychainPath = (home: string): string =>
  join(home, "Library", "Keychains", LEGACY_LOGIN_KEYCHAIN_NAME);

/** Where `security list-keychains -d user -s` / `default-keychain -d user -s`
 *  persist for the isolated HOME. `security` writes this only when
 *  `Library/Preferences` already exists — a missing dir silently drops the
 *  write while still exiting 0 (verified on macOS 27). */
const domainPrefsPath = (home: string): string =>
  join(home, "Library", "Preferences", "com.apple.security.plist");

type TSpawnMode = "ignore" | "pipe";

/** Per-command ceiling; the caller's monotonic budget includes FIFO queue wait. */
const DEFAULT_SECURITY_SPAWN_TIMEOUT_MS = 4_000;

/** Hard ceiling on `OPENLLM_SECURITY_TIMEOUT_MS`. The env knob tunes the wait
 *  WITHIN a bound; an effectively-unbounded configured wait lets one wedged
 *  `security` child stall readiness (and every gated vendor spawn) for as
 *  long as the env asks. Values above are clamped, with a one-time warning. */
export const MAX_SECURITY_SPAWN_TIMEOUT_MS = 60_000;

/** One warning per process per condition — an over-cap env value, a corrupt
 *  marker, or a truncated parked-chain scan would otherwise spam the log on
 *  every readiness call. Cleared by `resetKeychainStateForTests`. */
const keychainWarnedOnce = new Set<string>();

const warnKeychainOnce = (
  key: string,
  message: string,
  meta?: Record<string, unknown>,
): void => {
  if (keychainWarnedOnce.has(key)) return;
  keychainWarnedOnce.add(key);
  logWarn("keychain", message, meta);
};

/** Do not start a `security` child with less than this remaining — a sliver
 *  spawn just times out and logs. Capped by `securitySpawnTimeoutMs()` so
 *  tests that inject a 20–30ms timeout still spawn at the head of an empty
 *  lane. */
export const KEYCHAIN_LANE_SPAWN_FLOOR_MS = 400;

/** Per-call so tests can drive `OPENLLM_SECURITY_TIMEOUT_MS`. Finite + positive
 *  or the default; above the hard cap it is clamped with a one-time warning so
 *  a wedged `security` child can never stall readiness for an unbounded wait.
 *  Dump/unlock on a one-cred isolated chain is fast. */
const securitySpawnTimeoutMs = (): number => {
  const raw = process.env.OPENLLM_SECURITY_TIMEOUT_MS;
  if (raw === undefined) return DEFAULT_SECURITY_SPAWN_TIMEOUT_MS;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_SECURITY_SPAWN_TIMEOUT_MS;
  if (n > MAX_SECURITY_SPAWN_TIMEOUT_MS) {
    warnKeychainOnce(
      "security-timeout-clamped",
      "OPENLLM_SECURITY_TIMEOUT_MS exceeds the hard cap; clamped",
      { configured_ms: n, clamped_ms: MAX_SECURITY_SPAWN_TIMEOUT_MS },
    );
    return MAX_SECURITY_SPAWN_TIMEOUT_MS;
  }
  return n;
};

const laneSpawnFloorMs = (): number =>
  Math.min(KEYCHAIN_LANE_SPAWN_FLOOR_MS, securitySpawnTimeoutMs());

/** Skip a spawn when remaining is below the floor, except when the floor
 *  *is* the whole configured timeout (`min(400, 20) === 20`). In that case
 *  1ms of scheduling would skip the empty-lane head — tests inject 20–30ms
 *  and T14/T15 count those spawns. Full expiry still skips. */
const remainingBelowSpawnFloor = (remainingMs: number): boolean => {
  const configured = securitySpawnTimeoutMs();
  const floor = laneSpawnFloorMs();
  if (floor >= configured) return false;
  return remainingMs < floor;
};

type TSecurityOutcome =
  | {
      readonly kind: "complete";
      readonly code: number;
      readonly stdout: string;
      readonly stderr: string;
    }
  | { readonly kind: "timeout" }
  | { readonly kind: "aborted" };

const FAILED_SPAWN = { code: -1, stdout: "", stderr: "" } as const;

/** ONE `security` spawn helper (create/unlock/dump/read all route here).
 *  Unconfined on macOS (`sandbox/policy.ts`): `security` talks to securityd,
 *  which refuses a Seatbelt-confined caller. These paths are macOS-only.
 *  `stdout`/`stderr` are captured only when the mode is `pipe` (unlock needs
 *  stderr to classify a failure; dump/read need stdout). Never throws.
 *  Bounded: a hung `security` (e.g. blocked on SecurityAgent) is killed so
 *  `inFlightKeychains` can settle. */
type TSecuritySpawnOpts = {
  readonly stdout: TSpawnMode;
  readonly stderr: TSpawnMode;
  readonly signal?: AbortSignal;
};

type TSecurityResult = {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly aborted: boolean;
};

type TKeychainCounters = {
  attempts: number;
  timeouts: number;
  aborted: number;
  skipped_expired: number;
  skipped_floor: number;
  skipped: number;
  complete_ok: number;
  complete_fail: number;
  by_verb: Record<string, number>;
};

const emptyKeychainCounters = (): TKeychainCounters => ({
  attempts: 0,
  timeouts: 0,
  aborted: 0,
  skipped_expired: 0,
  skipped_floor: 0,
  skipped: 0,
  complete_ok: 0,
  complete_fail: 0,
  by_verb: {},
});

let keychainCounters = emptyKeychainCounters();
let lastWatcherSnapshot = emptyKeychainCounters();

let securitySpawnSetupHookForTests: (() => Promise<void> | void) | null = null;
let lastSecurityTimerMsForTests: number | null = null;

/** Test-only: run after `superviseSpawn`, before the child timeout is armed. */
export const setSecuritySpawnSetupHookForTests = (
  hook: (() => Promise<void> | void) | null,
): void => {
  securitySpawnSetupHookForTests = hook;
};

/** Test-only: delay passed to `setTimeout` for the last security child. */
export const lastSecurityTimerMsForTestsSnapshot = (): number | null =>
  lastSecurityTimerMsForTests;

const cloneKeychainCounters = (
  counters: TKeychainCounters,
): TKeychainCounters => ({
  ...counters,
  by_verb: { ...counters.by_verb },
});

export const keychainTelemetrySnapshot = (): Readonly<TKeychainCounters> =>
  cloneKeychainCounters(keychainCounters);

/** Did anything at all happen in this window? `by_verb` is derived from the
 *  scalars, so the scalars alone decide. */
const hasKeychainActivity = (d: TKeychainCounters): boolean =>
  d.attempts !== 0 ||
  d.timeouts !== 0 ||
  d.aborted !== 0 ||
  d.skipped_expired !== 0 ||
  d.skipped_floor !== 0 ||
  d.skipped !== 0 ||
  d.complete_ok !== 0 ||
  d.complete_fail !== 0;

const deltaKeychainCounters = (
  now: TKeychainCounters,
  prev: TKeychainCounters,
): TKeychainCounters => {
  const by_verb: Record<string, number> = {};
  for (const verb of new Set([
    ...Object.keys(now.by_verb),
    ...Object.keys(prev.by_verb),
  ])) {
    const d = (now.by_verb[verb] ?? 0) - (prev.by_verb[verb] ?? 0);
    if (d !== 0) by_verb[verb] = d;
  }
  return {
    attempts: now.attempts - prev.attempts,
    timeouts: now.timeouts - prev.timeouts,
    aborted: now.aborted - prev.aborted,
    skipped_expired: now.skipped_expired - prev.skipped_expired,
    skipped_floor: now.skipped_floor - prev.skipped_floor,
    skipped: now.skipped - prev.skipped,
    complete_ok: now.complete_ok - prev.complete_ok,
    complete_fail: now.complete_fail - prev.complete_fail,
    by_verb,
  };
};

/** One debug line per watcher tick: totals + deltas since the last tick. */
export const logKeychainWatcherTick = (): void => {
  const snapshot = keychainTelemetrySnapshot();
  const deltas = deltaKeychainCounters(keychainCounters, lastWatcherSnapshot);
  lastWatcherSnapshot = cloneKeychainCounters(keychainCounters);
  // A quiet tick logs NOTHING. The unconditional version wrote ~5.7k all-zero
  // lines a day on an idle host, which buys no history and costs log budget
  // that a wedged machine needs for the ticks that DID spawn. Live counters
  // stay readable at any moment on `GET /status` (`keychain_spawns`); this line
  // exists only to reconstruct *when* activity happened, after the fact.
  // Routine summaries stay DEBUG (default log gate is `info`) so a benign
  // partition/`complete_fail` delta does not flood the combined log. Actionable
  // timeout/error lines keep their levels; counter names stay on the wire.
  if (!hasKeychainActivity(deltas)) return;
  logDebug("keychain", "keychain spawn snapshot", { snapshot, deltas });
};

const noteKeychainVerb = (verb: string): void => {
  keychainCounters.by_verb[verb] = (keychainCounters.by_verb[verb] ?? 0) + 1;
};

const securityVerb = (argv: ReadonlyArray<string>): string =>
  argv[0] ?? "unknown";

/** Wait for shared producer work without giving one observer ownership of it. */
const awaitSharedStoreRead = async <T>(
  work: Promise<TStoreRead<T>>,
  signal: AbortSignal | undefined,
  cause: string,
): Promise<TStoreRead<T>> => {
  if (signal === undefined) return work;
  if (signal.aborted) return { kind: "indeterminate", cause };

  let unbind = (): void => {};
  const aborted = new Promise<TStoreRead<T>>((resolve) => {
    unbind = bindAbort(signal, () => {
      resolve({ kind: "indeterminate", cause });
    });
  });
  try {
    return await Promise.race([work, aborted]);
  } finally {
    unbind();
  }
};

let macosKeychainLane: Promise<void> = Promise.resolve();

/**
 * One FIFO lane for OpenLLM-issued `security` commands only. Vendor CLI
 * auth-status / refresh / login / logout talk to securityd themselves and must
 * not occupy this lane. Queue waiters that abort before spawn never start.
 * `onSkip` is the typed skip: expiry or remaining below the spawn floor
 * returns it instead of `operation()`, still releasing the slot after the
 * predecessor settles so the lane cannot leak.
 */
export const withMacosKeychainAccess = async <T>(
  operation: () => Promise<T>,
  budget?: TDeadlineBudget,
  onSkip?: () => T,
): Promise<T> => {
  if (!isMac()) return operation();
  const previous = macosKeychainLane;
  let release = (): void => {};
  const occupied = new Promise<void>((resolve) => {
    release = resolve;
  });
  macosKeychainLane = previous.then(
    () => occupied,
    () => occupied,
  );
  const waitPrev = previous.catch(() => {});
  if (budget !== undefined) {
    await Promise.race([waitPrev, waitUntilExpired(budget)]);
    const remaining = budget.remainingMs();
    if (budget.expired() || remainingBelowSpawnFloor(remaining)) {
      void waitPrev.finally(() => {
        release();
      });
      if (onSkip !== undefined) return onSkip();
      return operation();
    }
  }
  await waitPrev;
  try {
    return await operation();
  } finally {
    release();
  }
};

/** The ONLY environment `/usr/bin/security` may see. `security` talks to
 *  securityd and needs nothing of the daemon's env — API keys, cloud
 *  credentials, proxy settings and `SSH_AUTH_SOCK` must never reach a child
 *  process that also handles credential material. HOME is forced to the
 *  isolated home (that is what makes `-d user` writes land in the isolated
 *  `com.apple.security.plist`), PATH is pinned to system dirs, and only
 *  TMPDIR, USER/LOGNAME and locale vars pass through. Keep this allowlist
 *  local to the security lane; a later branch unifies env builders. */
const SECURITY_ENV_PASSTHROUGH = new Set(["TMPDIR", "USER", "LOGNAME", "LANG"]);

const securitySpawnEnv = (home: string): Record<string, string> => {
  const env: Record<string, string> = {
    HOME: home,
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
  };
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (SECURITY_ENV_PASSTHROUGH.has(key) || key.startsWith("LC_")) {
      env[key] = value;
    }
  }
  return env;
};

const spawnSecurityNow = async (
  argv: ReadonlyArray<string>,
  home: string,
  opts: TSecuritySpawnOpts,
  budget: TDeadlineBudget,
  queuedAtMs: number,
): Promise<TSecurityResult> => {
  if (opts.signal?.aborted === true) {
    keychainCounters.aborted++;
    return { ...FAILED_SPAWN, timedOut: false, aborted: true };
  }
  if (budget.expired()) {
    keychainCounters.skipped_expired++;
    return { ...FAILED_SPAWN, timedOut: true, aborted: false };
  }
  const verb = securityVerb(argv);
  const laneWaitMs = Math.max(0, Date.now() - queuedAtMs);
  const remainingAtSpawn = budget.remainingMs();
  const configuredTimeoutMs = securitySpawnTimeoutMs();
  const preSpawnMs = performance.now();
  try {
    const child = superviseSpawn(
      sandboxSpawnArgs(["security", ...argv], { probe: unwrapKeychainSpawn() }),
      {
        kind: "probe",
        stdin: "ignore",
        stdout: opts.stdout,
        stderr: opts.stderr,
        cwd: spawnCwd({ HOME: home }),
        env: securitySpawnEnv(home),
      },
    );
    if (securitySpawnSetupHookForTests !== null) {
      await securitySpawnSetupHookForTests();
    }
    const spawnedAtMs = performance.now();
    const spawnSetupMs = spawnedAtMs - preSpawnMs;
    keychainCounters.attempts++;
    noteKeychainVerb(verb);
    const proc = child.subprocess;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let unbindAbortWait = (): void => {};
    const readPiped = async (
      stream: unknown,
      mode: TSpawnMode,
    ): Promise<string> => {
      if (mode !== "pipe" || !(stream instanceof ReadableStream)) return "";
      try {
        return await new Response(stream).text();
      } catch {
        return "";
      }
    };
    try {
      const complete = Promise.all([
        readPiped(proc.stdout, opts.stdout),
        readPiped(proc.stderr, opts.stderr),
        proc.exited,
      ]).then(
        ([stdout, stderr, code]): TSecurityOutcome => ({
          kind: "complete",
          code,
          stdout,
          stderr,
        }),
      );
      void complete.catch(() => {});
      // Setup (Bun.spawn + test hook) is part of the absolute 4 s budget.
      // Arm from remaining *after* spawn so a slow spawn cannot extend the
      // deadline. Pre-spawn remaining stays in telemetry only.
      const remainingAfterSpawn = budget.remainingMs();
      lastSecurityTimerMsForTests = remainingAfterSpawn;
      const timeout =
        remainingAfterSpawn === 0
          ? Promise.resolve<TSecurityOutcome>({ kind: "timeout" })
          : new Promise<TSecurityOutcome>((resolve) => {
              timer = setTimeout(
                () => resolve({ kind: "timeout" }),
                remainingAfterSpawn,
              );
            });
      const abortWait =
        opts.signal === undefined
          ? null
          : new Promise<TSecurityOutcome>((resolve) => {
              unbindAbortWait = bindAbort(opts.signal, () =>
                resolve({ kind: "aborted" }),
              );
            });
      const outcome = await Promise.race(
        abortWait === null
          ? [complete, timeout]
          : [complete, timeout, abortWait],
      );
      if (outcome.kind === "aborted" || outcome.kind === "timeout") {
        const reap = await child.terminate(
          splitReapBudget(budget.remainingMs()),
        );
        try {
          proc.kill();
        } catch {
          // mock / already gone
        }
        if (reap === "reap_unconfirmed") {
          logError(
            "keychain",
            safeDiagnosticMessage`security command did not reap after SIGKILL`,
            {
              argv: redactSensitiveArgv(["security", ...argv]),
            },
          );
        }
        if (outcome.kind === "timeout") {
          keychainCounters.timeouts++;
          logError(
            "keychain",
            safeDiagnosticMessage`security command timed out`,
            {
              argv: redactSensitiveArgv(["security", ...argv]),
              configured_timeout_ms: configuredTimeoutMs,
              lane_wait_ms: laneWaitMs,
              budget_remaining_ms_at_spawn: remainingAtSpawn,
              spawn_setup_ms: spawnSetupMs,
              spawn_elapsed_ms: performance.now() - spawnedAtMs,
              verb,
              child_pid: child.pid,
              tick_id: currentTickId(),
            },
          );
          return { ...FAILED_SPAWN, timedOut: true, aborted: false };
        }
        keychainCounters.aborted++;
        return { ...FAILED_SPAWN, timedOut: false, aborted: true };
      }
      logIfKilled(redactSensitiveArgv(["security", ...argv]), proc, {
        confined: unwrapKeychainSpawn() !== true,
      });
      if (outcome.code === 0) keychainCounters.complete_ok++;
      else keychainCounters.complete_fail++;
      return {
        code: outcome.code,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        timedOut: false,
        aborted: false,
      };
    } finally {
      unbindAbortWait();
      if (timer !== null) clearTimeout(timer);
    }
  } catch {
    return { ...FAILED_SPAWN, timedOut: false, aborted: false };
  }
};

const spawnSecurity = async (
  argv: ReadonlyArray<string>,
  home: string,
  opts: TSecuritySpawnOpts,
): Promise<TSecurityResult> => {
  const parentBudget = budgetFromSignal(opts.signal);
  const budget =
    parentBudget?.child(securitySpawnTimeoutMs()) ??
    createDeadlineBudget(securitySpawnTimeoutMs(), opts.signal);
  const queuedAtMs = Date.now();
  const skippedSpawn = (reason: "expired" | "floor"): TSecurityResult => {
    if (opts.signal?.aborted === true) {
      keychainCounters.aborted++;
      return { ...FAILED_SPAWN, timedOut: false, aborted: true };
    }
    if (reason === "floor") keychainCounters.skipped_floor++;
    else keychainCounters.skipped_expired++;
    return { ...FAILED_SPAWN, timedOut: true, aborted: false };
  };
  return withMacosKeychainAccess(
    async () => {
      if (budget.expired()) return skippedSpawn("expired");
      if (remainingBelowSpawnFloor(budget.remainingMs())) {
        return skippedSpawn("floor");
      }
      return spawnSecurityNow(argv, home, opts, budget, queuedAtMs);
    },
    budget,
    () => skippedSpawn(budget.expired() ? "expired" : "floor"),
  );
};

/** Boolean convenience over `spawnSecurity` for the fire-and-check callers. */
const runSecurity = async (
  argv: ReadonlyArray<string>,
  home: string,
  signal?: AbortSignal,
): Promise<boolean> =>
  (
    await spawnSecurity(argv, home, {
      stdout: "ignore",
      stderr: "ignore",
      ...(signal !== undefined ? { signal } : {}),
    })
  ).code === 0;

// In-flight ensures, keyed by keychain path — the SINGLE owner of the
// create/heal race. Overlapping callers await the SAME operation.
//
// Transient create/settings/unlock failures share one retry-not-before map.
// After the capped delay, exactly one keyed owner may re-probe; success
// clears the entry immediately. There is no permanent unusable latch.
const inFlightKeychains = new Map<string, Promise<TStoreRead<void>>>();
const inFlightObserveKeychains = new Map<string, Promise<TStoreRead<void>>>();
const TRANSIENT_RETRY_CAP_MS = 60_000;
const transientTimeouts = new Map<
  string,
  { readonly count: number; readonly nextAtMs: number }
>();
/** Passive observe backoff — must not suppress active ensure/login/inference. */
const observeTransientTimeouts = new Map<
  string,
  { readonly count: number; readonly nextAtMs: number }
>();

/** Process-local positive unlock skip. Empty at start so the first unlock
 *  after boot is always real. No clock — mtime/size are content-replacement
 *  only; `show-keychain-info` confirms auto-lock is off, not lock state. */
type TUnlockSkip = {
  readonly unlockedByUs: true;
  readonly mtimeMs: number;
  readonly size: number;
  readonly autoLockOff: true;
};

const unlockSkip = new Map<string, TUnlockSkip>();
const pendingUnlockSkip = new Map<
  string,
  { readonly mtimeMs: number; readonly size: number }
>();
const autoLockOffByKc = new Map<string, boolean>();

/** Second classifier beside `matchUnlockFailureToken`. `-25308` stays
 *  TRANSIENT for recreate (must not nuke a good credential); it DOES
 *  invalidate a skip because the chain may have relocked under us. */
const isInteractionNotAllowed = (stderr: string): boolean => {
  const s = stderr.toLowerCase();
  // The literal message, verified with `security error -25308`, is "User
  // interaction is not allowed." — note the "is". `security` reports the text
  // WITHOUT the numeric code (e.g. "security: SecKeychainSearchCopyNext: User
  // interaction is not allowed."), so a numeric-only match never fires on a
  // real host; the `-25308` arm is kept only for callers that do surface codes.
  return (
    s.includes("-25308") || /interaction\s+(?:is\s+)?not\s+allowed/.test(s)
  );
};

const invalidateUnlockSkip = (kc: string): void => {
  unlockSkip.delete(kc);
  pendingUnlockSkip.delete(kc);
};

const noteKeychainIoResult = (kc: string, res: TSecurityResult): void => {
  // Timeouts stay `unknown` with observe/active backoff. Tear the skip only
  // on a classified lock-state change (`-25308`); mtime/size drift is
  // detected by `skipEligible` on the next call.
  if (isInteractionNotAllowed(res.stderr)) {
    invalidateUnlockSkip(kc);
  }
};

/** Parse `security show-keychain-info`. The grammar is POSITIONAL, not
 *  `name: value` — verified against macOS 15 (`security` writes this line to
 *  **stderr**, so pass both streams):
 *
 *      Keychain "x.keychain-db" no-timeout                 → auto-lock OFF
 *      Keychain "x.keychain-db" lock-on-sleep no-timeout   → locks on sleep
 *      Keychain "x.keychain-db" timeout=900s               → idle auto-lock
 *      Keychain "x.keychain-db" lock-on-sleep timeout=300s → both (the default)
 *
 *  Auto-lock is off IFF `no-timeout` is present AND `lock-on-sleep` is not.
 *  Our own chains are created with a bare `set-keychain-settings`, which yields
 *  the first form. Returns `null` when the output is not recognisable at all,
 *  so an inconclusive probe is never cached as a verdict. */
export const parseAutoLockOffForTests = (out: string): boolean | null =>
  parseAutoLockOff(out);

export const isInteractionNotAllowedForTests = (stderr: string): boolean =>
  isInteractionNotAllowed(stderr);

const parseAutoLockOff = (out: string): boolean | null => {
  const lower = out.toLowerCase();
  const noTimeout = lower.includes("no-timeout");
  const hasTimeout = /timeout=\d+s/.test(lower);
  // Neither token ⇒ this is not show-keychain-info output (empty, an error, a
  // future format). Unknown is NOT "auto-lock on".
  if (!noTimeout && !hasTimeout) return null;
  return noTimeout && !lower.includes("lock-on-sleep");
};

const confirmAutoLockOff = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  const cached = autoLockOffByKc.get(kc);
  if (cached !== undefined) return cached;
  const res = await spawnSecurity(["show-keychain-info", kc], home, {
    stdout: "pipe",
    stderr: "pipe",
    ...(signal !== undefined ? { signal } : {}),
  });
  noteKeychainIoResult(kc, res);
  const parsed =
    res.code === 0 && !res.timedOut && !res.aborted
      ? // `security` prints this line on STDERR; stdout is empty. Read both so
        // the parse does not depend on which stream macOS chooses.
        parseAutoLockOff(`${res.stderr}\n${res.stdout}`)
      : null;
  // Cache only a CONCLUSIVE verdict. A timeout, abort, non-zero exit or
  // unrecognised output must not poison the cache with `false`: that is
  // process-lifetime state, so one transient failure would disable the skip for
  // this chain until the daemon restarts — and the caller already treats
  // "not confirmed" as "do not skip" for this call.
  if (parsed === null) return false;
  autoLockOffByKc.set(kc, parsed);
  return parsed;
};

const recordUnlockSuccessForSkip = (kc: string): void => {
  const meta = keychainMetadata(kc);
  if (meta.mtimeMs === null || meta.size === null) {
    invalidateUnlockSkip(kc);
    return;
  }
  pendingUnlockSkip.set(kc, { mtimeMs: meta.mtimeMs, size: meta.size });
};

const skipEligible = (kc: string): boolean => {
  const skip = unlockSkip.get(kc);
  if (skip === undefined) return false;
  if (!existsSync(kc)) {
    invalidateUnlockSkip(kc);
    return false;
  }
  const meta = keychainMetadata(kc);
  if (
    meta.mtimeMs === null ||
    meta.size === null ||
    meta.mtimeMs !== skip.mtimeMs ||
    meta.size !== skip.size
  ) {
    invalidateUnlockSkip(kc);
    return false;
  }
  return skip.unlockedByUs && skip.autoLockOff;
};

const tryPromoteUnlockSkip = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  if (skipEligible(kc)) return true;
  const pending = pendingUnlockSkip.get(kc);
  if (pending === undefined) return false;
  if (!existsSync(kc)) {
    invalidateUnlockSkip(kc);
    return false;
  }
  const meta = keychainMetadata(kc);
  if (
    meta.mtimeMs === null ||
    meta.size === null ||
    meta.mtimeMs !== pending.mtimeMs ||
    meta.size !== pending.size
  ) {
    invalidateUnlockSkip(kc);
    return false;
  }
  const autoLockOff = await confirmAutoLockOff(home, kc, signal);
  if (!autoLockOff) {
    pendingUnlockSkip.delete(kc);
    return false;
  }
  unlockSkip.set(kc, {
    unlockedByUs: true,
    mtimeMs: pending.mtimeMs,
    size: pending.size,
    autoLockOff: true,
  });
  pendingUnlockSkip.delete(kc);
  return true;
};

const dumpCache = new Map<
  string,
  {
    readonly mtimeMs: number;
    readonly value: TStoreRead<ReadonlyArray<string>>;
  }
>();

type TKeychainPayloads = {
  readonly values: ReadonlyArray<string>;
  readonly secretUnreadable: boolean;
};

/** Complete credential reads, keyed by isolated keychain + service prefix. */
const inFlightKeychainReads = new Map<
  string,
  Promise<TStoreRead<TKeychainPayloads>>
>();

// A chain we recreated once this process (bounds self-heal to one attempt per
// path per process — launchd KeepAlive resets it on restart).
const healedKeychains = new Set<string>();

// Keychain paths whose user-domain search list + default keychain this
// process has pointed at the isolated chain. The write persists in the
// isolated HOME's `com.apple.security.plist`, so one successful configure
// covers the rest of this process's calls.
const domainConfigured = new Set<string>();

// First existing-chain unlock logged once per path per process. This is the
// boot breadcrumb that distinguishes a healthy unlock from a self-heal.
const initialExistingKeychainUnlocks = new Set<string>();

// Throttle the create-failure log so a persistent failure doesn't spam the
// error stream on every periodic status observation. One line per window.
const lastKeychainFailureLogMs = new Map<string, number>();
const KEYCHAIN_FAILURE_LOG_INTERVAL_MS = 5 * 60 * 1000;

const logKeychainFailure = (kc: string): void => {
  const now = Date.now();
  if (
    now - (lastKeychainFailureLogMs.get(kc) ?? 0) <
    KEYCHAIN_FAILURE_LOG_INTERVAL_MS
  )
    return;
  lastKeychainFailureLogMs.set(kc, now);
  logError(
    "keychain",
    safeDiagnosticMessage`failed to create the isolated login keychain — claude login will pop the 'Keychain Not Found' dialog and hang`,
    { keychain: kc },
  );
};

const logSelfHeal = (kc: string): void =>
  logError(
    "keychain",
    safeDiagnosticMessage`recreated a drifted isolated login keychain (empty-password unlock failed); the provider will require re-login`,
    { keychain: kc },
  );

/** The positive classifier token, preserving the established matching order. */
export const matchUnlockFailureToken = (stderr: string): string | null => {
  const s = stderr.toLowerCase();
  if (s.includes("-25293")) return "-25293";
  if (s.includes("-25295")) return "-25295";
  if (s.includes("passphrase you entered")) return "passphrase you entered";
  if (s.includes("username or passphrase")) return "username or passphrase";
  return null;
};

/** Keep stderr evidence useful without retaining passwords or directory paths. */
export const redactSecurityStderr = (stderr: string): string => {
  const withoutPasswords = stderr
    // Quoted values may carry escaped quotes (`-p "a\"b"`): consume `\.`
    // pairs inside the quotes so the whole value is replaced, never a tail.
    .replace(
      /(^|\s)(-p|--password)=(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S*)/g,
      "$1$2=[redacted]",
    )
    .replace(
      /(^|\s)(-p|--password)\s+(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)/g,
      "$1$2 [redacted]",
    )
    .replace(/(^|\s)(?:-p|--password)(?=\s*$)/g, "$1")
    // Keep the established excerpt for the common trailing `-p value` form.
    .replace(/\s+-p \[redacted\]$/, "");
  const pathBasename = (path: string): string => {
    const value = path.trim();
    const name = basename(value);
    return name.length > 0 ? name : "<path>";
  };
  const knownHomePath =
    /(?:\/Users\/|\/home\/|\/var\/|\/private\/|\/tmp\/|~\/)[\s\S]*?(?=\s+(?=-{1,2}[A-Za-z])|\s+(?=(?:\/Users\/|\/home\/|\/var\/|\/private\/|\/tmp\/|~\/))|$)/g;

  return withoutPasswords
    .replace(/(["'])((?:\/|~\/)[\s\S]*?)\1/g, (_match, _quote, path) =>
      pathBasename(path),
    )
    .replace(knownHomePath, pathBasename)
    .replace(/(?:\/|~\/)[^\s"'`]+/g, pathBasename)
    .trim()
    .slice(0, 200);
};

/** A non-null `matchUnlockFailureToken` is auth-drift (recreate). Everything
 *  else — empty stderr the sandbox shim may swallow, user-canceled (-128), or
 *  interaction-not-allowed (-25308) — is TRANSIENT: do NOT recreate (fail-safe;
 *  the readiness gate already prevents any prompt), so a transient securityd
 *  hiccup never nukes a good credential. */
type TKeychainMetadata = {
  readonly mtimeMs: number | null;
  readonly size: number | null;
};

const keychainMetadata = (kc: string): TKeychainMetadata => {
  try {
    const { mtimeMs, size } = statSync(kc);
    return { mtimeMs, size };
  } catch {
    return { mtimeMs: null, size: null };
  }
};

/**
 * Cheap identity for idle observation reuse. Includes replacement identity
 * (`ino`) plus mtime/size. `skipEligible` is the existing unlock-skip seam —
 * true only after we unlocked this chain, auto-lock is off, and metadata still
 * matches. Never treat this as proof the chain is unlocked if skip is false.
 */
export type TKeychainStoreIdentity = {
  readonly path: string;
  readonly present: boolean;
  readonly mtimeMs: number | null;
  readonly size: number | null;
  readonly ino: number | null;
  readonly skipEligible: boolean;
  readonly statOk: boolean;
};

export const keychainStoreIdentity = (home: string): TKeychainStoreIdentity => {
  const path = isolatedKeychainPath(home);
  if (!isMac()) {
    return {
      path,
      present: false,
      mtimeMs: null,
      size: null,
      ino: null,
      skipEligible: true,
      statOk: true,
    };
  }
  try {
    const st = statSync(path);
    return {
      path,
      present: true,
      mtimeMs: st.mtimeMs,
      size: st.size,
      ino: Number(st.ino),
      skipEligible: skipEligible(path),
      statOk: true,
    };
  } catch (err) {
    const absent = classifyStatError(err) === "absent";
    return {
      path,
      present: false,
      mtimeMs: null,
      size: null,
      ino: null,
      skipEligible: false,
      statOk: absent,
    };
  }
};

/** Upper bound on directory entries read on the readiness path. */
const DIR_SCAN_MAX_ENTRIES = 4096;

/** Read at most `max` entry names from `dir` without materialising the whole
 *  directory (readdirSync would allocate every name up front). */
const boundedDirNames = (
  dir: string,
  max: number = DIR_SCAN_MAX_ENTRIES,
): string[] => {
  const names: string[] = [];
  const handle = opendirSync(dir);
  try {
    for (
      let entry = handle.readSync();
      entry !== null;
      entry = handle.readSync()
    ) {
      names.push(entry.name);
      if (names.length >= max) break;
    }
  } finally {
    handle.closeSync();
  }
  return names;
};

const brokenKeychainCount = (kc: string): number => {
  try {
    const prefix = `${basename(kc)}.broken-`;
    return boundedDirNames(dirname(kc)).filter((name) =>
      name.startsWith(prefix),
    ).length;
  } catch {
    return 0;
  }
};

const stagingPrefixForPid = (pid: number): string => `.openllm-staging-${pid}-`;

const ownedStagingPath = (dir: string): string =>
  join(
    dir,
    `${stagingPrefixForPid(process.pid)}${randomBytes(8).toString("hex")}.keychain-db`,
  );

const isOwnedStagingName = (name: string): boolean =>
  name.startsWith(stagingPrefixForPid(process.pid)) &&
  name.endsWith(".keychain-db");

const sweepOwnedStaging = (dir: string): void => {
  try {
    for (const f of boundedDirNames(dir)) {
      if (isOwnedStagingName(f)) rmSync(join(dir, f), { force: true });
    }
  } catch {
    // dir unreadable / race — non-fatal
  }
};

const removeOwnedPath = (path: string): void => {
  try {
    rmSync(path, { force: true });
  } catch {}
};

type TPreparedStaging = {
  readonly path: string;
  readonly unlocked: boolean;
};

/** Create + settings + unlock a unique owned staging keychain. Never touches
 *  the final path. Failure removes only this process's staging. */
const prepareStagingKeychain = async (
  home: string,
  dir: string,
  signal?: AbortSignal,
): Promise<TPreparedStaging | null> => {
  try {
    mkdirSync(dir, { recursive: true });
  } catch {
    return null;
  }
  sweepOwnedStaging(dir);
  const staging = ownedStagingPath(dir);
  const created = await runSecurity(
    ["create-keychain", "-p", "", staging],
    home,
    signal,
  );
  if (!created) {
    removeOwnedPath(staging);
    return null;
  }
  const settings = await runSecurity(
    ["set-keychain-settings", staging],
    home,
    signal,
  );
  if (!settings) {
    removeOwnedPath(staging);
    return null;
  }
  const unlocked = await runSecurity(
    ["unlock-keychain", "-p", "", staging],
    home,
    signal,
  );
  if (!unlocked) {
    removeOwnedPath(staging);
    return null;
  }
  return { path: staging, unlocked: true };
};

/** Create + configure the isolated keychain at `kc`. Staging keeps a failed
 *  create from ever leaving a partial file at the final path (and dodges any
 *  name-sensitive securityd handling — `create-keychain` at the
 *  `login.keychain-db` name inside $HOME under Seatbelt is refused).
 *  Staging is owner-pid unique; settings must succeed before install.
 *  Returns whether `kc` now exists and unlocks. */
const createIsolatedKeychain = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  const dir = dirname(kc);
  const prepared = await prepareStagingKeychain(home, dir, signal);
  if (prepared === null) return false;
  try {
    renameSync(prepared.path, kc);
  } catch {
    removeOwnedPath(prepared.path);
    return existsSync(kc);
  }
  return (
    existsSync(kc) &&
    (await runSecurity(["unlock-keychain", "-p", "", kc], home, signal))
  );
};

type TRecreateOutcome = {
  readonly created: boolean;
  readonly unlocked: boolean;
  readonly replaced: boolean;
};

/** Build and verify staging while the original remains. Move the original
 *  aside only immediately before install; restore it if install/verify fails.
 *  Timeout/cancel/ambiguous errors never authorize replacement (caller). */
const recreateIsolatedKeychain = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<TRecreateOutcome> => {
  invalidateUnlockSkip(kc);
  autoLockOffByKc.delete(kc);
  const dir = dirname(kc);
  const prepared = await prepareStagingKeychain(home, dir, signal);
  if (prepared === null) {
    logWarn("keychain", safeDiagnosticMessage`keychain self-heal outcome`, {
      created: false,
      unlocked: false,
    });
    return { created: false, unlocked: false, replaced: false };
  }
  const aside = `${kc}.broken-${process.pid}-${Date.now()}`;
  let originalMoved = false;
  try {
    if (existsSync(kc)) {
      renameSync(kc, aside);
      originalMoved = true;
    }
    renameSync(prepared.path, kc);
  } catch {
    removeOwnedPath(prepared.path);
    if (originalMoved && !existsSync(kc)) {
      try {
        renameSync(aside, kc);
      } catch {}
    }
    logWarn("keychain", safeDiagnosticMessage`keychain self-heal outcome`, {
      created: true,
      unlocked: false,
    });
    return { created: true, unlocked: false, replaced: false };
  }
  const unlocked = await runSecurity(
    ["unlock-keychain", "-p", "", kc],
    home,
    signal,
  );
  if (!unlocked && originalMoved) {
    try {
      rmSync(kc, { force: true });
    } catch {}
    try {
      renameSync(aside, kc);
    } catch {}
    logWarn("keychain", safeDiagnosticMessage`keychain self-heal outcome`, {
      created: true,
      unlocked: false,
    });
    return { created: true, unlocked: false, replaced: false };
  }
  logSelfHeal(kc);
  logWarn("keychain", safeDiagnosticMessage`keychain self-heal outcome`, {
    created: true,
    unlocked,
  });
  return { created: true, unlocked, replaced: true };
};

/** True only when THIS PROCESS has verified (by read-back) that the isolated
 *  HOME's user-domain config points at `kc`. The flag is set exclusively by
 *  `ensureDomainKeychainConfig` after `verifyDomainKeychainConfig` passes —
 *  neither a `com.apple.security.plist` file merely existing nor a write that
 *  exited 0 counts as proof. */
const domainConfiguredFor = (kc: string): boolean => domainConfigured.has(kc);

/** securityd canonicalizes stored paths (e.g. `/tmp/x` is reported back as
 *  `/private/tmp/x` — verified on macOS 27), so comparisons must normalize
 *  both sides the same way. */
const canonKeychainPath = (path: string): string => {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
};

/** `list-keychains -d user` / `default-keychain -d user` print one
 *  `"<path>"` line per entry (or nothing / exit 1 when unset). */
const parseKeychainPathList = (stdout: string): string[] =>
  stdout
    .split("\n")
    .map((line) => /^\s*"(.+)"\s*$/.exec(line)?.[1])
    .filter((p): p is string => typeof p === "string");

/** Read back the isolated HOME's user-domain search list and default
 *  keychain from securityd and require BOTH to name `kc` exactly — the one
 *  admissible proof of configuration. A stale plist, a half-landed write, or
 *  config left pointing at some other chain all fail here, which is what
 *  re-triggers the `-s` writes (or fails readiness closed). */
const verifyDomainKeychainConfig = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  const expected = canonKeychainPath(kc);
  const listed = await spawnSecurity(["list-keychains", "-d", "user"], home, {
    stdout: "pipe",
    stderr: "ignore",
    ...(signal !== undefined ? { signal } : {}),
  });
  if (listed.code !== 0) return false;
  const entries = parseKeychainPathList(listed.stdout);
  if (entries.length !== 1 || canonKeychainPath(entries[0]) !== expected) {
    return false;
  }
  const defaulted = await spawnSecurity(
    ["default-keychain", "-d", "user"],
    home,
    {
      stdout: "pipe",
      stderr: "ignore",
      ...(signal !== undefined ? { signal } : {}),
    },
  );
  if (defaulted.code !== 0) return false;
  const defaults = parseKeychainPathList(defaulted.stdout);
  return defaults.length === 1 && canonKeychainPath(defaults[0]) === expected;
};

/** Point the isolated HOME's user-domain search list and default keychain at
 *  `kc`, so a vendor CLI run with `HOME=<home>` reaches it without the
 *  implicit `login.keychain-db` fallback. The writes are HOME-scoped
 *  (`com.apple.security.plist` under `home`); `Library/Preferences` must
 *  exist or `security` exits 0 having written NOTHING — which is exactly why
 *  a 0 exit is never trusted: every state (persisted or just-written) is
 *  proven by reading the domain back through the same isolated HOME. */
const ensureDomainKeychainConfig = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  if (domainConfigured.has(kc)) return true;
  try {
    // Sync fs on purpose: callers of `ensureKeychainReady` may await the op
    // from a resolved-promise poll loop that never yields to the event loop —
    // an `fs/promises` await here would starve them (and us).
    mkdirSync(dirname(domainPrefsPath(home)), { recursive: true });
  } catch {
    return false;
  }
  // A persisted config from an earlier process (or another writer) is proven
  // only by read-back — verifying first also makes the common already-
  // configured case write-free.
  if (await verifyDomainKeychainConfig(home, kc, signal)) {
    domainConfigured.add(kc);
    return true;
  }
  const listed = await runSecurity(
    ["list-keychains", "-d", "user", "-s", kc],
    home,
    signal,
  );
  if (!listed) return false;
  const defaulted = await runSecurity(
    ["default-keychain", "-d", "user", "-s", kc],
    home,
    signal,
  );
  if (!defaulted) return false;
  // Verify the writes actually landed. `security` exits 0 on a silently
  // dropped write, so an unverifiable post-write state must fail closed —
  // never cache a lie.
  if (await verifyDomainKeychainConfig(home, kc, signal)) {
    domainConfigured.add(kc);
    return true;
  }
  domainConfigured.delete(kc);
  logError(
    "keychain",
    safeDiagnosticMessage`keychain domain config writes did not verify on read-back`,
    { keychain: basename(kc) },
  );
  return false;
};

/** Count a chain's items via `dump-keychain` METADATA only — one `class:`
 *  line per item; secret payloads are never requested or logged. Returns
 *  null when the chain cannot be unlocked/inspected so the caller fails
 *  closed. The file's basename must be free of `login.keychain-db` (the
 *  macOS 26+ name-keyed refusal would force every unlock of it to fail). */
const keychainItemCount = async (
  home: string,
  kcPath: string,
  signal?: AbortSignal,
): Promise<number | null> => {
  const unlocked = await spawnSecurity(
    ["unlock-keychain", "-p", "", kcPath],
    home,
    {
      stdout: "ignore",
      stderr: "ignore",
      ...(signal !== undefined ? { signal } : {}),
    },
  );
  if (unlocked.code !== 0) return null;
  const dump = await spawnSecurity(["dump-keychain", kcPath], home, {
    stdout: "pipe",
    stderr: "ignore",
    ...(signal !== undefined ? { signal } : {}),
  });
  if (dump.code !== 0) return null;
  return dump.stdout.split("\n").filter((line) => line.startsWith("class:"))
    .length;
};

/** How a legacy-chain resolution ended. `resolved` lets readiness continue;
 *  a failure carries the indeterminate cause surfaced to callers —
 *  `keychain_migration_conflict` when BOTH chains hold vendor items (no
 *  chain may be picked silently), `keychain_migration_failed` for I/O and
 *  inspection failures. */
type TLegacyMigration =
  | { readonly resolved: true }
  | { readonly resolved: false; readonly cause: string };

const migrationResolved: TLegacyMigration = { resolved: true };
const migrationFailed = (cause: string): TLegacyMigration => ({
  resolved: false,
  cause,
});

/** Durable record that a legacy-chain migration COMPLETED, kept next to the
 *  keychains so a parked `*-superseded-*` backup is never mistaken for a
 *  pending migration again. Without it every readiness call would
 *  rediscover the parked loser, re-inspect both chains, and park it under a
 *  NEW superseded name — unbounded re-spawns plus unbounded file growth,
 *  and a healthy canonical chain could keep failing closed. Only the parked
 *  paths the marker names are disarmed: an UN-parked `login.keychain-db`,
 *  and any parked file with no completed-migration record (e.g. left behind
 *  by a failed inspection's restore), stay pending. */
const MIGRATION_MARKER_NAME = "openllm-migration.json";

/** A marker bigger than this is corruption, not state: an unbounded
 *  `readFileSync` on the readiness path would stall the daemon event loop.
 *  Treated as unreadable — every parked chain stays pending (fail closed). */
const MIGRATION_MARKER_MAX_BYTES = 64 * 1024;

/** The ONLY file names a completed migration can park — generated at one site
 *  (`resolveSupersededLegacy` stages `<pid>-<ms>` asides). A `parked` marker
 *  entry naming anything else is corruption or a forgery; it must never
 *  disarm a pending legacy chain. */
const GENERATED_PARKED_NAME =
  /^openllm-(?:legacy|isolated)-superseded-\d+-\d+\.keychain-db$/;

const migrationMarkerPath = (home: string): string =>
  join(dirname(legacyLoginKeychainPath(home)), MIGRATION_MARKER_NAME);

/** A `parked` marker entry is trusted only when it names a file the migration
 *  itself could have generated AND that file still resolves (realpath) inside
 *  the isolated HOME's Keychains dir — a right-looking string for a missing
 *  file, a symlink escaping the dir, or a name we never generate can never
 *  disarm a pending legacy chain (fail closed). Valid entries are
 *  canonicalised to `dir/name`, the same string the parked finder compares. */
const validMarkerEntries = (
  raw: unknown,
  keychainsDir: string,
): ReadonlySet<string> => {
  const trusted = new Set<string>();
  if (!Array.isArray(raw)) return trusted;
  let realDir: string;
  try {
    realDir = realpathSync(keychainsDir);
  } catch {
    return trusted;
  }
  // Each candidate costs a realpath syscall — cap the count validated per
  // read so a fat `parked` array cannot stall the readiness path.
  // Newest entries last (append order): trust the most recent ones so a
  // full marker never hides a freshly parked chain.
  for (const entry of raw.slice(-PARKED_SCAN_MAX_ENTRIES)) {
    if (typeof entry !== "string") continue;
    const name = basename(entry);
    if (!GENERATED_PARKED_NAME.test(name)) continue;
    try {
      if (dirname(realpathSync(entry)) !== realDir) continue;
    } catch {
      // Missing or unresolvable — the chain it named stays pending.
      continue;
    }
    trusted.add(join(keychainsDir, name));
  }
  return trusted;
};

const readMigrationMarker = (home: string): ReadonlySet<string> => {
  const keychainsDir = dirname(legacyLoginKeychainPath(home));
  let parsed: unknown;
  try {
    const marker = migrationMarkerPath(home);
    const size = statSync(marker).size;
    if (size > MIGRATION_MARKER_MAX_BYTES) {
      warnKeychainOnce(
        "migration-marker-oversized",
        "keychain migration marker exceeds the size cap; treating it as corrupt",
        { marker_size: size },
      );
      return new Set();
    }
    parsed = JSON.parse(readFileSync(marker, "utf8"));
  } catch {
    // Absent or unreadable — nothing is known-resolved.
    return new Set();
  }
  const raw =
    parsed !== null && typeof parsed === "object"
      ? (parsed as { readonly parked?: unknown }).parked
      : undefined;
  return validMarkerEntries(raw, keychainsDir);
};

/** Persist "migration completed" atomically (tmp + rename) so a crash can
 *  never leave a half-written marker that re-arms a parked chain. Records
 *  the parked backup's absolute path plus a timestamp — both so exactly
 *  that file is disarmed and so a human can see what was parked when. A
 *  write failure only means the parked chain stays resumable next call —
 *  log and continue; the migration itself already succeeded. Entries the
 *  reader can no longer validate (renamed, deleted, or never a generated
 *  `*-superseded-*` name inside the Keychains dir) are dropped here. */
const recordMigrationCompleted = (
  home: string,
  parked: string | null,
): void => {
  const known = new Set(readMigrationMarker(home));
  if (parked !== null) {
    known.delete(parked);
    known.add(parked);
  }
  // Keep the marker bounded: retain only the newest entries.
  const kept = [...known].slice(-PARKED_SCAN_MAX_ENTRIES);
  const marker = migrationMarkerPath(home);
  const tmp = join(
    dirname(marker),
    `.${MIGRATION_MARKER_NAME}.${process.pid}.tmp`,
  );
  try {
    writeFileSync(
      tmp,
      `${JSON.stringify({ completedAtMs: Date.now(), parked: kept })}\n`,
    );
    renameSync(tmp, marker);
  } catch {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // Best-effort cleanup of the temp file.
    }
    logWarn(
      "keychain",
      safeDiagnosticMessage`could not record the completed keychain migration; the parked chain stays resumable`,
      { keychain: basename(parked ?? marker) },
    );
  }
};

/** Both legacy `login.keychain-db` and the canonical chain exist. Stage the
 *  legacy file under a refusal-free aside name, inspect item counts on BOTH
 *  chains (metadata only), then act on what holds items:
 *    - legacy-only holds items → promote it to the canonical name (items +
 *      ACLs preserved) and park the empty canonical as a recoverable backup;
 *    - canonical-only (or neither) holds items → keep canonical, park the
 *      empty legacy aside;
 *    - BOTH hold items → CONFLICT: restore the original layout and fail
 *      closed. Silently picking either chain would strand the other's
 *      credentials, so an operator must remove one by hand.
 *  Every failure restores the original layout and reports the failure cause
 *  so readiness fails closed instead of stranding data. */
const resolveSupersededLegacy = async (
  home: string,
  kc: string,
  legacy: string,
  signal?: AbortSignal,
): Promise<TLegacyMigration> => {
  const stamp = `${process.pid}-${Date.now()}`;
  const dir = dirname(legacy);
  const legacyAside = join(
    dir,
    `openllm-legacy-superseded-${stamp}.keychain-db`,
  );
  try {
    renameSync(legacy, legacyAside);
  } catch {
    logError(
      "keychain",
      safeDiagnosticMessage`could not stage the legacy login-named isolated keychain for inspection; failing closed`,
      { keychain: basename(legacy) },
    );
    return migrationFailed("keychain_migration_failed");
  }
  /** Best-effort restore of the legacy file's original name. It staying
   *  parked is still recoverable (the path is logged), so a restore failure
   *  never widens the failure. */
  const restoreLegacy = (): void => {
    if (existsSync(legacy) || !existsSync(legacyAside)) return;
    try {
      renameSync(legacyAside, legacy);
    } catch {
      logWarn(
        "keychain",
        safeDiagnosticMessage`legacy keychain remains parked after a failed inspection`,
        { keychain: basename(legacyAside) },
      );
    }
  };
  const legacyItems = await keychainItemCount(home, legacyAside, signal);
  const kcItems = await keychainItemCount(home, kc, signal);
  if (legacyItems === null || kcItems === null) {
    restoreLegacy();
    logError(
      "keychain",
      safeDiagnosticMessage`could not inspect both isolated keychains; failing closed rather than guessing which holds credentials`,
      { keychain: basename(kc), legacy: basename(legacy) },
    );
    return migrationFailed("keychain_migration_failed");
  }
  if (legacyItems > 0 && kcItems > 0) {
    // BOTH chains hold vendor items. Picking either silently would strand
    // the other's credentials, so restore the original layout untouched and
    // fail closed until an operator removes one chain by hand.
    restoreLegacy();
    logError(
      "keychain",
      safeDiagnosticMessage`both isolated keychains hold vendor items; refusing to pick one — inspect both keychains and delete one manually, then retry`,
      {
        canonical_keychain: kc,
        legacy_keychain: legacy,
        canonical_items: kcItems,
        legacy_items: legacyItems,
      },
    );
    return migrationFailed("keychain_migration_conflict");
  }
  if (legacyItems > 0 && kcItems === 0) {
    // The legacy chain carries the stored credentials — promote it to the
    // canonical name (preserving items + ACLs, same as a rename migration)
    // and park the empty canonical chain as the recoverable backup.
    const kcAside = join(
      dir,
      `openllm-isolated-superseded-${stamp}.keychain-db`,
    );
    try {
      renameSync(kc, kcAside);
      renameSync(legacyAside, kc);
    } catch {
      if (!existsSync(kc) && existsSync(kcAside)) {
        try {
          renameSync(kcAside, kc);
        } catch {
          logError(
            "keychain",
            safeDiagnosticMessage`could not restore the canonical isolated keychain after a failed legacy promotion`,
            { keychain: basename(kcAside) },
          );
        }
      }
      restoreLegacy();
      return migrationFailed("keychain_migration_failed");
    }
    logInfo("keychain", "kept the legacy chain — it holds the stored items", {
      kept: "legacy",
      legacy_items: legacyItems,
      canonical_aside: basename(kcAside),
    });
    recordMigrationCompleted(home, kcAside);
    return migrationResolved;
  }
  logInfo("keychain", "kept the canonical chain; legacy parked as a backup", {
    kept: "canonical",
    canonical_items: kcItems,
    legacy_items: legacyItems,
    legacy_aside: basename(legacyAside),
  });
  recordMigrationCompleted(home, legacyAside);
  return migrationResolved;
};

/** Per-scan ceiling on parked-candidate `statSync` calls — a dir holding an
 *  absurd number of `*-superseded-*` names must not stall the daemon event
 *  loop on the readiness path. Entries beyond the cap are simply unexamined:
 *  `readdir` order is arbitrary, so a truncated scan still resolves the
 *  newest pending chain it did see rather than pretending none exists. */
const PARKED_SCAN_MAX_ENTRIES = 256;

/** The newest `openllm-legacy-superseded-*.keychain-db` under the isolated
 *  HOME that is still PENDING migration. A parked file is left behind when a
 *  both-chains inspection failed AND the original `login.keychain-db` name
 *  could not be restored — it still holds the credentials, so the next
 *  readiness call must finish the migration rather than silently run on an
 *  empty chain. A parked path the completed-migration marker names is a
 *  resolved backup, never a migration source: without that record the same
 *  file would be re-staged, re-inspected, and re-parked on EVERY call. */
const findParkedLegacyKeychain = (home: string): string | null => {
  const dir = dirname(legacyLoginKeychainPath(home));
  const resolvedBackups = readMigrationMarker(home);
  let names: string[];
  try {
    names = boundedDirNames(dir);
  } catch {
    return null;
  }
  let newest: string | null = null;
  let newestMs = -1;
  let examined = 0;
  for (const name of names) {
    if (
      !name.startsWith("openllm-legacy-superseded-") ||
      !name.endsWith(".keychain-db")
    ) {
      continue;
    }
    const path = join(dir, name);
    if (resolvedBackups.has(path)) continue;
    if (examined >= PARKED_SCAN_MAX_ENTRIES) {
      warnKeychainOnce(
        "parked-scan-truncated",
        "parked legacy keychain scan truncated at the entry cap; unexamined entries stay pending",
        { scanned: examined, cap: PARKED_SCAN_MAX_ENTRIES },
      );
      break;
    }
    examined++;
    try {
      const mtimeMs = statSync(path).mtimeMs;
      if (mtimeMs > newestMs) {
        newest = path;
        newestMs = mtimeMs;
      }
    } catch {
      // A vanished or unreadable entry is not a migration source.
    }
  }
  return newest;
};

/** Resolve a leftover pre-2.8 `login.keychain-db` under the isolated HOME.
 *  When the new chain is absent, RENAME the legacy file to it — the macOS 26+
 *  refusal is keyed on the file NAME, so a rename both preserves every item
 *  (with its ACLs) and restores empty-password unlock. When both exist,
 *  inspect both and keep the chain holding the stored items. A parked
 *  `openllm-legacy-superseded-*` file counts as the legacy chain so an
 *  interrupted inspection resumes instead of stranding credentials — but
 *  ONLY while no completed-migration marker names it (a resolved backup is
 *  never pending again). Every failure reports its cause so the caller
 *  fails closed: continuing on a fresh EMPTY chain while credentials sit
 *  unmigrated would be silent credential loss. Never touches the user's
 *  real login keychain — `home` is always the isolated one. */
const resolveLegacyKeychain = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<TLegacyMigration> => {
  let legacy = legacyLoginKeychainPath(home);
  if (!existsSync(legacy)) {
    const parked = findParkedLegacyKeychain(home);
    if (parked === null) return migrationResolved;
    legacy = parked;
  }
  if (!existsSync(kc)) {
    try {
      renameSync(legacy, kc);
      logInfo("keychain", "migrated the legacy login-named isolated keychain", {
        keychain: basename(kc),
      });
      recordMigrationCompleted(home, null);
      return migrationResolved;
    } catch {
      logError(
        "keychain",
        safeDiagnosticMessage`legacy login-named isolated keychain could not be migrated; failing closed`,
        { keychain: basename(legacy) },
      );
      return migrationFailed("keychain_migration_failed");
    }
  }
  return await resolveSupersededLegacy(home, kc, legacy, signal);
};

/** Ensure the isolated login keychain exists and is UNLOCKED for this call,
 *  reporting readiness as a tri-state. Create when missing; unlock with the
 *  empty password; on a classified empty-password DRIFT of an existing file,
 *  self-heal once (rename-aside + recreate); if it still won't unlock, mark it
 *  unusable so callers stop touching it. A transient unlock failure stays
 *  retryable (returns `indeterminate`, never recreates). No-op `present` off
 *  macOS. */
const noteUnlockSuccess = (kc: string): TStoreRead<void> => {
  transientTimeouts.delete(kc);
  observeTransientTimeouts.delete(kc);
  recordUnlockSuccessForSkip(kc);
  return READY;
};

const noteTransientFailure = (kc: string, cause: string): TStoreRead<void> => {
  const prev = transientTimeouts.get(kc);
  const count = (prev?.count ?? 0) + 1;
  const delayMs = Math.min(TRANSIENT_RETRY_CAP_MS, 2_500 * 2 ** (count - 1));
  transientTimeouts.set(kc, { count, nextAtMs: Date.now() + delayMs });
  return { kind: "indeterminate", cause };
};

const noteObserveTransientFailure = (
  kc: string,
  cause: string,
): TStoreRead<void> => {
  const prev = observeTransientTimeouts.get(kc);
  const count = (prev?.count ?? 0) + 1;
  const delayMs = Math.min(TRANSIENT_RETRY_CAP_MS, 2_500 * 2 ** (count - 1));
  observeTransientTimeouts.set(kc, {
    count,
    nextAtMs: Date.now() + delayMs,
  });
  return { kind: "indeterminate", cause };
};

const ensureKeychainNow = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<TStoreRead<void>> => {
  // Migrate (or disarm) the pre-2.8 login-named chain before probing `kc`.
  // A failed migration must NOT fall through to create/unlock — the daemon
  // would front an EMPTY canonical chain while the credentials sit parked in
  // the legacy file: silent credential loss.
  const migration = await resolveLegacyKeychain(home, kc, signal);
  if (!migration.resolved) {
    if (signal?.aborted === true) {
      return { kind: "indeterminate", cause: "keychain_wait_aborted" };
    }
    logKeychainFailure(kc);
    return noteTransientFailure(kc, migration.cause);
  }
  const existedAtStart = existsSync(kc);
  const isInitialExistingUnlock =
    existedAtStart && !initialExistingKeychainUnlocks.has(kc);
  if (isInitialExistingUnlock) initialExistingKeychainUnlocks.add(kc);
  if (!existedAtStart) {
    if (!(await createIsolatedKeychain(home, kc, signal))) {
      logKeychainFailure(kc);
      return noteTransientFailure(kc, "keychain_create_failed");
    }
  }
  // Unlock at the FINAL path (securityd keys unlock state by path). The path
  // never carries a `login`-suffixed name, so the macOS 26+ name-keyed
  // refusal cannot fire here. Capture stderr to classify a failure.
  const res = await spawnSecurity(["unlock-keychain", "-p", "", kc], home, {
    stdout: "ignore",
    stderr: "pipe",
    ...(signal !== undefined ? { signal } : {}),
  });
  if (isInitialExistingUnlock) {
    logInfo("keychain", "keychain initial empty-password unlock", {
      unlocked: res.code === 0,
    });
  }
  if (res.code === 0) return noteUnlockSuccess(kc);

  noteKeychainIoResult(kc, res);
  // Caller abort (status-race cancel) is not a keychain fault — skip timeout
  // accounting so a healthy chain is never marked unusable.
  if (res.aborted) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  if (res.timedOut) {
    return noteTransientFailure(kc, "keychain_unlock_transient");
  }

  const failureToken = matchUnlockFailureToken(res.stderr);
  if (failureToken !== null) {
    invalidateUnlockSkip(kc);
    if (!healedKeychains.has(kc)) {
      const metadata = keychainMetadata(kc);
      logWarn("keychain", safeDiagnosticMessage`keychain auth-drift evidence`, {
        classifier_token: failureToken,
        exit_code: res.code,
        stderr_length: res.stderr.length,
        stderr_excerpt: redactSecurityStderr(res.stderr),
        keychain_mtime_ms: metadata.mtimeMs,
        keychain_size: metadata.size,
        broken_count: brokenKeychainCount(kc),
      });
      const outcome = await recreateIsolatedKeychain(home, kc, signal);
      if (outcome.replaced) healedKeychains.add(kc);
      if (outcome.unlocked) return noteUnlockSuccess(kc);
    }
    return noteTransientFailure(kc, "keychain_unlock_transient");
  }
  return noteTransientFailure(kc, "keychain_unlock_transient");
};

/**
 * macOS only: ensure an isolated, unlocked login keychain and REPORT
 * readiness. `present` ⇒ safe to run any keychain-touching op (our
 * `dump-keychain`, `set-key-partition-list`, or the vendor CLI reading the
 * store). `indeterminate` ⇒ a create/unlock failure or an unusable chain —
 * callers MUST NOT proceed (that is the GUI-prompt path). Concurrency-deduped;
 * negative-cached; `present` off macOS.
 */
export const ensureKeychainReady = async (
  home: string,
  signal?: AbortSignal,
): Promise<TStoreRead<void>> => {
  if (!isMac()) return READY;
  const kc = isolatedKeychainPath(home);
  const backoff = transientTimeouts.get(kc);
  if (backoff !== undefined && backoff.nextAtMs > Date.now()) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  let op = inFlightKeychains.get(kc);
  if (op === undefined) {
    if (signal?.aborted === true) {
      return { kind: "indeterminate", cause: "keychain_wait_aborted" };
    }
    if (skipEligible(kc) && domainConfiguredFor(kc)) {
      keychainCounters.skipped++;
      return READY;
    }
    // The producer owns its command deadline. A status observer's cancellation
    // must not kill readiness work an inference waiter still needs.
    // Promote (one-shot show-keychain-info) is part of this owner so a
    // mid-unlock joiner cannot skip and two first-callers cannot double-spawn.
    op = (async (): Promise<TStoreRead<void>> => {
      const ready = await (async (): Promise<TStoreRead<void>> => {
        if (await tryPromoteUnlockSkip(home, kc)) {
          keychainCounters.skipped++;
          return READY;
        }
        return ensureKeychainNow(home, kc);
      })();
      if (ready.kind !== "present") return ready;
      // `present` also gates VENDOR spawns — and a vendor CLI resolves the
      // chain through the isolated HOME's search list + default keychain, not
      // by path. An unlocked-but-unconfigured chain would land it on the
      // "A keychain cannot be found" dialog this gate exists to prevent.
      if (await ensureDomainKeychainConfig(home, kc)) return ready;
      return noteTransientFailure(kc, "keychain_config_failed");
    })().finally(() => {
      if (inFlightKeychains.get(kc) === op) inFlightKeychains.delete(kc);
    });
    inFlightKeychains.set(kc, op);
  }
  return awaitSharedStoreRead(op, signal, "keychain_wait_aborted");
};

/** The single gate EVERY macOS Claude/Cursor vendor-CLI spawn must pass
 *  IMMEDIATELY before exec: the spawn env's isolated HOME must have a
 *  verified-ready keychain, or the CLI would fall off the isolated search
 *  list onto the "A keychain cannot be found" dialog — or worse, the real
 *  user's keychain. Off darwin there is nothing to gate; a spawn env
 *  without HOME is a test fixture and is left alone. An env HOME equal to
 *  the daemon's own home means the vendor runs under the REAL user home —
 *  the isolated-keychain machinery must never touch that, so the gate is
 *  a no-op there too. */
export const ensureVendorKeychainReady = async (
  env: Record<string, string>,
  signal?: AbortSignal,
): Promise<TStoreRead<void>> => {
  const home = env.HOME;
  if (!isMac() || home === undefined || home.length === 0) return READY;
  if (home === homedir()) return READY;
  return ensureKeychainReady(home, signal);
};

/**
 * Passive idle readiness: unlock an EXISTING isolated keychain or report
 * unknown. Never create, recreate, rename-aside, or grant ACLs. Classified
 * empty-password drift is indeterminate — repair stays on login / inference /
 * `readToken` via {@link ensureKeychainReady}.
 */
const observeKeychainNow = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<TStoreRead<void>> => {
  if (!existsSync(kc)) {
    return { kind: "indeterminate", cause: "keychain_absent" };
  }
  const res = await spawnSecurity(["unlock-keychain", "-p", "", kc], home, {
    stdout: "ignore",
    stderr: "pipe",
    ...(signal !== undefined ? { signal } : {}),
  });
  if (res.code === 0) {
    observeTransientTimeouts.delete(kc);
    // Passive `present` can also release a vendor spawn (`claude auth
    // status`); that needs the isolated HOME's domain config, which only the
    // active path may write. Report unknown until it does — never prompt.
    if (!domainConfiguredFor(kc)) {
      return noteObserveTransientFailure(kc, "keychain_unconfigured");
    }
    return noteUnlockSuccess(kc);
  }
  noteKeychainIoResult(kc, res);
  if (res.aborted) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  return noteObserveTransientFailure(kc, "keychain_unlock_transient");
};

export const observeKeychainReady = async (
  home: string,
  signal?: AbortSignal,
): Promise<TStoreRead<void>> => {
  if (!isMac()) return READY;
  const kc = isolatedKeychainPath(home);
  const backoff = observeTransientTimeouts.get(kc);
  if (backoff !== undefined && backoff.nextAtMs > Date.now()) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  let op = inFlightObserveKeychains.get(kc);
  if (op === undefined) {
    if (signal?.aborted === true) {
      return { kind: "indeterminate", cause: "keychain_wait_aborted" };
    }
    if (skipEligible(kc) && domainConfiguredFor(kc)) {
      keychainCounters.skipped++;
      return READY;
    }
    op = (async (): Promise<TStoreRead<void>> => {
      const ready = await (async (): Promise<TStoreRead<void>> => {
        if (await tryPromoteUnlockSkip(home, kc)) {
          keychainCounters.skipped++;
          return READY;
        }
        return observeKeychainNow(home, kc);
      })();
      if (ready.kind !== "present") return ready;
      if (domainConfiguredFor(kc)) return ready;
      return noteObserveTransientFailure(kc, "keychain_unconfigured");
    })().finally(() => {
      if (inFlightObserveKeychains.get(kc) === op) {
        inFlightObserveKeychains.delete(kc);
      }
    });
    inFlightObserveKeychains.set(kc, op);
  }
  return awaitSharedStoreRead(op, signal, "keychain_wait_aborted");
};

/** Test-only: process-global keychain caches leak across suites. */
export const resetKeychainStateForTests = (): void => {
  inFlightKeychains.clear();
  inFlightObserveKeychains.clear();
  healedKeychains.clear();
  domainConfigured.clear();
  initialExistingKeychainUnlocks.clear();
  lastKeychainFailureLogMs.clear();
  transientTimeouts.clear();
  observeTransientTimeouts.clear();
  unlockSkip.clear();
  pendingUnlockSkip.clear();
  autoLockOffByKc.clear();
  dumpCache.clear();
  inFlightKeychainReads.clear();
  macosKeychainLane = Promise.resolve();
  keychainCounters = emptyKeychainCounters();
  lastWatcherSnapshot = emptyKeychainCounters();
  securitySpawnSetupHookForTests = null;
  lastSecurityTimerMsForTests = null;
  keychainWarnedOnce.clear();
};

/**
 * macOS only: ensure the isolated login keychain exists + is unlocked so a
 * CLI run with `HOME=<home>` (e.g. `claude auth login`) can WRITE its
 * credential without the "Keychain Not Found" dialog. Returns the same
 * tri-state as `ensureKeychainReady` — prompt-capable vendor login must not
 * spawn unless this is `present`.
 */
export const ensureIsolatedKeychain = async (
  home: string,
): Promise<TStoreRead<void>> => ensureKeychainReady(home);

/**
 * `security set-key-partition-list` matched no item. `-s` selects symmetric
 * KEYS, but every vendor CLI we host stores its credential as a generic
 * PASSWORD (`class: "genp"`) — a keychain holding only those has no key to
 * partition, so `security` exits 1 with this. That is "nothing to grant", NOT a
 * refusal: the credential is still readable prompt-free. Reporting it as a
 * failure false-fails an otherwise healthy login.
 */
const noKeyToPartition = (stderr: string): boolean =>
  /SecItemCopyMatching/i.test(stderr) &&
  /could not be found in the keychain/i.test(stderr);

/**
 * macOS only: grant command-line tools prompt-free access to the items in
 * the isolated keychain. Run AFTER a login writes them. Gated on readiness.
 * Returns whether the keychain ended up in the granted state (true off macOS,
 * and true when there was no key to partition — see {@link noKeyToPartition}).
 */
export const grantKeychainToolAccess = async (
  home: string,
): Promise<boolean> => {
  if (!isMac()) return true;
  if ((await ensureKeychainReady(home)).kind !== "present") return false;
  const kc = isolatedKeychainPath(home);
  const res = await spawnSecurity(
    ["set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", "", kc],
    home,
    { stdout: "ignore", stderr: "pipe" },
  );
  noteKeychainIoResult(kc, res);
  if (res.code === 0) return true;
  if (noKeyToPartition(res.stderr)) {
    logInfo("keychain", "no key to partition — grant not needed", {
      keychain_path: isolatedKeychainPath(home),
    });
    return true;
  }
  logWarn("keychain", safeDiagnosticMessage`partition-list grant failed`, {
    exit_code: res.code,
    stderr_excerpt: redactSecurityStderr(res.stderr),
  });
  return false;
};

/**
 * Discover every generic-password service name in the isolated keychain
 * that STARTS WITH `prefix`. Claude suffixes its keychain service with a
 * per-install hash (e.g. `Claude Code-credentials-753e4afa`) so multiple
 * configs don't collide, so an exact-name lookup misses it. `dump-keychain`
 * lists attributes only (no `-d`), so it doesn't prompt for item SECRETS —
 * but it DOES open the keychain, so callers MUST have a `present` readiness
 * first (a locked chain would prompt). `readIsolatedKeychain` enforces that.
 */
const keychainMtimeMs = (kc: string): number => {
  try {
    return statSync(kc).mtimeMs;
  } catch {
    return -1;
  }
};

export const findKeychainServices = async (
  home: string,
  prefix: string,
  signal?: AbortSignal,
): Promise<TStoreRead<ReadonlyArray<string>>> => {
  const kc = isolatedKeychainPath(home);
  const mtimeMs = keychainMtimeMs(kc);
  const cacheKey = `${kc}\0${prefix}`;
  const cached = dumpCache.get(cacheKey);
  if (cached !== undefined && cached.mtimeMs === mtimeMs) {
    return cached.value;
  }
  const dump = await spawnSecurity(["dump-keychain", kc], home, {
    stdout: "pipe",
    stderr: "pipe",
    ...(signal !== undefined ? { signal } : {}),
  });
  noteKeychainIoResult(kc, dump);
  if (dump.code !== 0) {
    return { kind: "indeterminate", cause: `dump-keychain_exit_${dump.code}` };
  }
  const { stdout } = dump;
  const names = new Set<string>();
  for (const line of stdout.split("\n")) {
    const m = line.match(/"svce"<blob>="([^"]*)"/);
    if (m?.[1]?.startsWith(prefix) === true) {
      names.add(m[1]);
    }
  }
  const value: TStoreRead<ReadonlyArray<string>> = {
    kind: "present",
    value: [...names],
  };
  dumpCache.set(cacheKey, { mtimeMs, value });
  return value;
};

const readKeychainSecret = async (
  home: string,
  service: string,
  signal?: AbortSignal,
): Promise<string | null> => {
  const kc = isolatedKeychainPath(home);
  const found = await spawnSecurity(
    ["find-generic-password", "-s", service, "-w", kc],
    home,
    {
      stdout: "pipe",
      stderr: "pipe",
      ...(signal !== undefined ? { signal } : {}),
    },
  );
  noteKeychainIoResult(kc, found);
  if (found.code !== 0) return null;
  const { stdout } = found;
  const trimmed = stdout.trim();
  return trimmed.length > 0 ? trimmed : null;
};

/**
 * Read a generic-password `-w` payload from the ISOLATED login keychain,
 * matching `servicePrefix` (Claude's service name carries a per-install
 * hash suffix, so we match by prefix and try each candidate). `validate`
 * rejects a wrong-but-matching item — the first valid payload wins.
 * Returns `absent` off macOS / when no matching item exists;
 * `indeterminate` when the keychain isn't ready (locked / unusable) or when
 * dump-keychain / secret read fails. NEVER dumps a not-ready chain (that is
 * the GUI-prompt path).
 */
const readIsolatedKeychainNow = async (
  home: string,
  servicePrefix: string,
  observeOnly: boolean,
): Promise<TStoreRead<TKeychainPayloads>> => {
  const ready = observeOnly
    ? await observeKeychainReady(home)
    : await ensureKeychainReady(home);
  if (ready.kind !== "present") return ready;
  const services = await findKeychainServices(home, servicePrefix);
  if (services.kind !== "present") return services;

  const values: string[] = [];
  let secretUnreadable = false;
  try {
    for (const service of services.value) {
      const secret = await readKeychainSecret(home, service);
      if (secret === null) {
        secretUnreadable = true;
      } else {
        values.push(secret);
      }
    }
    return { kind: "present", value: { values, secretUnreadable } };
  } catch (err) {
    return {
      kind: "indeterminate",
      cause: err instanceof Error ? err.name : "keychain_read_failed",
    };
  }
};

export const readIsolatedKeychain = async (
  home: string,
  servicePrefix: string,
  validate?: (payload: string) => boolean,
  signal?: AbortSignal,
  observeOnly = false,
): Promise<TStoreRead<string>> => {
  if (!isMac()) return { kind: "absent" };
  const key = `${isolatedKeychainPath(home)}\0${servicePrefix}\0${observeOnly ? "observe" : "mutate"}`;
  let op = inFlightKeychainReads.get(key);
  if (op === undefined) {
    if (signal?.aborted === true) {
      return { kind: "indeterminate", cause: "keychain_read_aborted" };
    }
    op = readIsolatedKeychainNow(home, servicePrefix, observeOnly).finally(
      () => {
        if (inFlightKeychainReads.get(key) === op) {
          inFlightKeychainReads.delete(key);
        }
      },
    );
    inFlightKeychainReads.set(key, op);
  }

  const payloads = await awaitSharedStoreRead(
    op,
    signal,
    "keychain_read_aborted",
  );
  if (payloads.kind !== "present") return payloads;
  for (const payload of payloads.value.values) {
    if (validate === undefined || validate(payload)) {
      return { kind: "present", value: payload };
    }
  }
  if (payloads.value.secretUnreadable) {
    return { kind: "indeterminate", cause: "keychain_secret_unreadable" };
  }
  return { kind: "absent" };
};
