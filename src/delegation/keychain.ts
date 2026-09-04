/**
 * Isolated macOS login keychain. Split out of `util.ts` (which re-exports
 * everything here — import from either).
 *
 * On macOS, Claude Code stores its OAuth credential in the login Keychain
 * (there is NO file-based override — confirmed via the Claude Code docs).
 * Claude resolves the login keychain by HOME path, so running it with an
 * isolated HOME and no keychain there fails with the system dialog "A
 * keychain cannot be found to store <user>". The fix: give the isolated
 * HOME its OWN login keychain at `<home>/Library/Keychains/login.keychain-db`.
 *
 * We deliberately do NOT call `security default-keychain`/`list-keychains`:
 * those mutate the live securityd SESSION search list (not HOME-scoped),
 * which would pollute the user's real keychain environment. Instead we
 * create + unlock the keychain at the HOME-derived path (which Claude
 * finds on its own) and READ it back by EXPLICIT path (the `security` CLI
 * resolves the default via the session, not HOME, so the path is required).
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
 * `claude-code.ts`) runs unless it reports `present` (unlocked THIS call). A
 * genuine empty-password drift self-heals once (rename-aside + recreate); a
 * chain that still can't unlock is negative-cached so it stops re-prompting.
 * See docs/plan/2026-08-22-daemon-keychain-gui-prompt-wedge-fix.md.
 */
import { randomBytes } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { mkdir, readdir, rename, rm } from "node:fs/promises";
import { platform } from "node:os";
import { basename, dirname, join } from "node:path";
import { superviseSpawn } from "../child-supervisor";
import type { TDeadlineBudget } from "../deadline-budget";
import {
  budgetFromSignal,
  createDeadlineBudget,
  splitReapBudget,
  waitUntilExpired,
} from "../deadline-budget";
import { logError, logInfo, logWarn } from "../logger";
import { sandboxSpawnArgs } from "../sandbox/exec";
import { unwrapKeychainSpawn } from "../sandbox/policy";
import { bindAbort, logIfKilled, spawnCwd } from "./spawn";
import type { TStoreRead } from "./util";

const MAC = platform() === "darwin";

/** Readiness = the shared tri-state: `present` (created + unlocked this call),
 *  `indeterminate` (create/unlock failed or the chain is unusable). Off macOS
 *  there is nothing to gate, so it is always `present`. */
const READY: TStoreRead<void> = { kind: "present", value: undefined };

const loginKeychainPath = (home: string): string =>
  join(home, "Library", "Keychains", "login.keychain-db");

/** The argv with secret-bearing option VALUES redacted for logging: `-w`
 *  carries the OAuth credential payload (`add-generic-password`), `-p` a
 *  keychain password, `-k` the partition-list unlock password — none may
 *  reach `openllmd.err.log`. */
const redactSecurityArgv = (argv: ReadonlyArray<string>): string[] =>
  argv.map((arg, i) =>
    i > 0 &&
    (argv[i - 1] === "-w" || argv[i - 1] === "-p" || argv[i - 1] === "-k")
      ? "<redacted>"
      : arg,
  );

type TSpawnMode = "ignore" | "pipe";

/** Per-command ceiling; the caller's monotonic budget includes FIFO queue wait. */
const DEFAULT_SECURITY_SPAWN_TIMEOUT_MS = 4_000;

/** Per-call so tests can drive `OPENLLM_SECURITY_TIMEOUT_MS`. Finite + positive
 *  or the default. Dump/unlock on a one-cred isolated chain is fast. */
const securitySpawnTimeoutMs = (): number => {
  const raw = process.env.OPENLLM_SECURITY_TIMEOUT_MS;
  if (raw === undefined) return DEFAULT_SECURITY_SPAWN_TIMEOUT_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_SECURITY_SPAWN_TIMEOUT_MS;
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
 */
export const withMacosKeychainAccess = async <T>(
  operation: () => Promise<T>,
  budget?: TDeadlineBudget,
): Promise<T> => {
  if (!MAC) return operation();
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
    if (budget.expired()) {
      void waitPrev.finally(() => {
        release();
      });
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

const spawnSecurityNow = async (
  argv: ReadonlyArray<string>,
  home: string,
  opts: TSecuritySpawnOpts,
  budget: TDeadlineBudget,
): Promise<TSecurityResult> => {
  if (opts.signal?.aborted === true) {
    return { ...FAILED_SPAWN, timedOut: false, aborted: true };
  }
  if (budget.expired()) {
    return { ...FAILED_SPAWN, timedOut: true, aborted: false };
  }
  try {
    const child = superviseSpawn(
      sandboxSpawnArgs(["security", ...argv], { probe: unwrapKeychainSpawn() }),
      {
        kind: "probe",
        stdin: "ignore",
        stdout: opts.stdout,
        stderr: opts.stderr,
        cwd: spawnCwd({ HOME: home }),
        env: { ...process.env, HOME: home },
      },
    );
    const proc = child.subprocess;
    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
      const complete = Promise.all([
        opts.stdout === "pipe" && proc.stdout instanceof ReadableStream
          ? new Response(proc.stdout).text()
          : Promise.resolve(""),
        opts.stderr === "pipe" && proc.stderr instanceof ReadableStream
          ? new Response(proc.stderr).text()
          : Promise.resolve(""),
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
      const timeout = new Promise<TSecurityOutcome>((resolve) => {
        timer = setTimeout(
          () => resolve({ kind: "timeout" }),
          budget.remainingMs(),
        );
      });
      const abortWait =
        opts.signal === undefined
          ? null
          : new Promise<TSecurityOutcome>((resolve) => {
              bindAbort(opts.signal, () => resolve({ kind: "aborted" }));
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
          logError("keychain", "security command did not reap after SIGKILL", {
            argv: redactSecurityArgv(["security", ...argv]),
          });
        }
        if (outcome.kind === "timeout") {
          logError("keychain", "security command timed out", {
            argv: redactSecurityArgv(["security", ...argv]),
          });
          return { ...FAILED_SPAWN, timedOut: true, aborted: false };
        }
        return { ...FAILED_SPAWN, timedOut: false, aborted: true };
      }
      logIfKilled(redactSecurityArgv(["security", ...argv]), proc, {
        confined: unwrapKeychainSpawn() !== true,
      });
      return {
        code: outcome.code,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        timedOut: false,
        aborted: false,
      };
    } finally {
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
  return withMacosKeychainAccess(async () => {
    if (budget.expired()) {
      return {
        ...FAILED_SPAWN,
        timedOut: opts.signal?.aborted !== true,
        aborted: opts.signal?.aborted === true,
      };
    }
    return spawnSecurityNow(argv, home, opts, budget);
  }, budget);
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
const TRANSIENT_RETRY_CAP_MS = 60_000;
const transientTimeouts = new Map<
  string,
  { readonly count: number; readonly nextAtMs: number }
>();

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
    "failed to create the isolated login keychain — claude login will pop the 'Keychain Not Found' dialog and hang",
    { keychain: kc },
  );
};

const logSelfHeal = (kc: string): void =>
  logError(
    "keychain",
    "recreated a drifted isolated login keychain (empty-password unlock failed); the provider will require re-login",
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

/** errSecAuthFailed (-25293) / errSecInvalidKeychain (-25295) / the passphrase
 *  message ⇒ the empty password genuinely no longer works (recreate).
 *  Everything else — incl. an empty stderr the sandbox shim may swallow, a
 *  user-canceled (-128), or interaction-not-allowed (-25308) — is treated as
 *  TRANSIENT: do NOT recreate (fail-safe; the readiness gate already prevents
 *  any prompt), so a transient securityd hiccup never nukes a good credential. */
const classifyUnlockFailure = (stderr: string): "auth" | "transient" =>
  matchUnlockFailureToken(stderr) === null ? "transient" : "auth";

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

const brokenKeychainCount = async (kc: string): Promise<number> => {
  try {
    const prefix = `${basename(kc)}.broken-`;
    return (await readdir(dirname(kc))).filter((name) =>
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

const sweepOwnedStaging = async (dir: string): Promise<void> => {
  try {
    for (const f of await readdir(dir)) {
      if (isOwnedStagingName(f)) await rm(join(dir, f), { force: true });
    }
  } catch {
    // dir unreadable / race — non-fatal
  }
};

const removeOwnedPath = async (path: string): Promise<void> => {
  await rm(path, { force: true }).catch(() => {});
};

type TPreparedStaging = {
  readonly path: string;
  readonly unlocked: boolean;
};

/** Create + settings + unlock a unique owned staging keychain. Never touches
 *  the final reserved path. Failure removes only this process's staging. */
const prepareStagingKeychain = async (
  home: string,
  dir: string,
  signal?: AbortSignal,
): Promise<TPreparedStaging | null> => {
  try {
    await mkdir(dir, { recursive: true });
  } catch {
    return null;
  }
  await sweepOwnedStaging(dir);
  const staging = ownedStagingPath(dir);
  const created = await runSecurity(
    ["create-keychain", "-p", "", staging],
    home,
    signal,
  );
  if (!created) {
    await removeOwnedPath(staging);
    return null;
  }
  const settings = await runSecurity(
    ["set-keychain-settings", staging],
    home,
    signal,
  );
  if (!settings) {
    await removeOwnedPath(staging);
    return null;
  }
  const unlocked = await runSecurity(
    ["unlock-keychain", "-p", "", staging],
    home,
    signal,
  );
  if (!unlocked) {
    await removeOwnedPath(staging);
    return null;
  }
  return { path: staging, unlocked: true };
};

/** Create + configure the isolated login keychain at `kc`. macOS `securityd`
 *  REFUSES `create-keychain` at the RESERVED `login.keychain-db` name inside
 *  the $HOME subtree under Seatbelt. Staging is owner-pid unique; settings
 *  must succeed before install. Returns whether `kc` now exists and unlocks. */
const createIsolatedKeychain = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  const dir = dirname(kc);
  const prepared = await prepareStagingKeychain(home, dir, signal);
  if (prepared === null) return false;
  try {
    await rename(prepared.path, kc);
  } catch {
    await removeOwnedPath(prepared.path);
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
  const dir = dirname(kc);
  const prepared = await prepareStagingKeychain(home, dir, signal);
  if (prepared === null) {
    logWarn("keychain", "keychain self-heal outcome", {
      created: false,
      unlocked: false,
    });
    return { created: false, unlocked: false, replaced: false };
  }
  const aside = `${kc}.broken-${process.pid}-${Date.now()}`;
  let originalMoved = false;
  try {
    if (existsSync(kc)) {
      await rename(kc, aside);
      originalMoved = true;
    }
    await rename(prepared.path, kc);
  } catch {
    await removeOwnedPath(prepared.path);
    if (originalMoved && !existsSync(kc)) {
      await rename(aside, kc).catch(() => {});
    }
    logWarn("keychain", "keychain self-heal outcome", {
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
    await rm(kc, { force: true }).catch(() => {});
    await rename(aside, kc).catch(() => {});
    logWarn("keychain", "keychain self-heal outcome", {
      created: true,
      unlocked: false,
    });
    return { created: true, unlocked: false, replaced: false };
  }
  logSelfHeal(kc);
  logWarn("keychain", "keychain self-heal outcome", {
    created: true,
    unlocked,
  });
  return { created: true, unlocked, replaced: true };
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
  return READY;
};

const noteTransientFailure = (kc: string, cause: string): TStoreRead<void> => {
  const prev = transientTimeouts.get(kc);
  const count = (prev?.count ?? 0) + 1;
  const delayMs = Math.min(TRANSIENT_RETRY_CAP_MS, 2_500 * 2 ** (count - 1));
  transientTimeouts.set(kc, { count, nextAtMs: Date.now() + delayMs });
  return { kind: "indeterminate", cause };
};

const ensureKeychainNow = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<TStoreRead<void>> => {
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
  // Unlock at the FINAL path (securityd keys unlock state by path). Unlocking
  // the reserved name by explicit path is fine — only `create-keychain` at it
  // fails. Capture stderr to classify a failure.
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

  // Caller abort (status-race cancel) is not a keychain fault — skip timeout
  // accounting so a healthy chain is never marked unusable.
  if (res.aborted) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  if (res.timedOut)
    return noteTransientFailure(kc, "keychain_unlock_transient");

  const failureToken = matchUnlockFailureToken(res.stderr);
  if (classifyUnlockFailure(res.stderr) === "auth") {
    if (!healedKeychains.has(kc)) {
      const metadata = keychainMetadata(kc);
      logWarn("keychain", "keychain auth-drift evidence", {
        classifier_token: failureToken,
        exit_code: res.code,
        stderr_length: res.stderr.length,
        stderr_excerpt: redactSecurityStderr(res.stderr),
        keychain_mtime_ms: metadata.mtimeMs,
        keychain_size: metadata.size,
        broken_count: await brokenKeychainCount(kc),
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
  if (!MAC) return READY;
  const kc = loginKeychainPath(home);
  const backoff = transientTimeouts.get(kc);
  if (backoff !== undefined && backoff.nextAtMs > Date.now()) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  let op = inFlightKeychains.get(kc);
  if (op === undefined) {
    if (signal?.aborted === true) {
      return { kind: "indeterminate", cause: "keychain_wait_aborted" };
    }
    // The producer owns its command deadline. A status observer's cancellation
    // must not kill readiness work an inference waiter still needs.
    op = ensureKeychainNow(home, kc).finally(() => {
      if (inFlightKeychains.get(kc) === op) inFlightKeychains.delete(kc);
    });
    inFlightKeychains.set(kc, op);
  }
  return awaitSharedStoreRead(op, signal, "keychain_wait_aborted");
};

/** Test-only: process-global keychain caches leak across suites. */
export const resetKeychainStateForTests = (): void => {
  inFlightKeychains.clear();
  healedKeychains.clear();
  initialExistingKeychainUnlocks.clear();
  lastKeychainFailureLogMs.clear();
  transientTimeouts.clear();
  dumpCache.clear();
  inFlightKeychainReads.clear();
  macosKeychainLane = Promise.resolve();
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
 * macOS only: grant command-line tools prompt-free access to the items in
 * the isolated keychain. Run AFTER a login writes them. Gated on readiness.
 * Returns whether the partition-list grant succeeded (true off macOS).
 */
export const grantKeychainToolAccess = async (
  home: string,
): Promise<boolean> => {
  if (!MAC) return true;
  if ((await ensureKeychainReady(home)).kind !== "present") return false;
  return runSecurity(
    [
      "set-key-partition-list",
      "-S",
      "apple-tool:,apple:",
      "-s",
      "-k",
      "",
      loginKeychainPath(home),
    ],
    home,
  );
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
  const kc = loginKeychainPath(home);
  const mtimeMs = keychainMtimeMs(kc);
  const cacheKey = `${kc}\0${prefix}`;
  const cached = dumpCache.get(cacheKey);
  if (cached !== undefined && cached.mtimeMs === mtimeMs) {
    return cached.value;
  }
  const { code, stdout } = await spawnSecurity(["dump-keychain", kc], home, {
    stdout: "pipe",
    stderr: "ignore",
    ...(signal !== undefined ? { signal } : {}),
  });
  if (code !== 0) {
    return { kind: "indeterminate", cause: `dump-keychain_exit_${code}` };
  }
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
  const { code, stdout } = await spawnSecurity(
    ["find-generic-password", "-s", service, "-w", loginKeychainPath(home)],
    home,
    {
      stdout: "pipe",
      stderr: "ignore",
      ...(signal !== undefined ? { signal } : {}),
    },
  );
  if (code !== 0) return null;
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
): Promise<TStoreRead<TKeychainPayloads>> => {
  const ready = await ensureKeychainReady(home);
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
): Promise<TStoreRead<string>> => {
  if (!MAC) return { kind: "absent" };
  const key = `${loginKeychainPath(home)}\0${servicePrefix}`;
  let op = inFlightKeychainReads.get(key);
  if (op === undefined) {
    if (signal?.aborted === true) {
      return { kind: "indeterminate", cause: "keychain_read_aborted" };
    }
    op = readIsolatedKeychainNow(home, servicePrefix).finally(() => {
      if (inFlightKeychainReads.get(key) === op) {
        inFlightKeychainReads.delete(key);
      }
    });
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
