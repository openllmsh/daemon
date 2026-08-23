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
import { existsSync, statSync } from "node:fs";
import { mkdir, readdir, rename, rm } from "node:fs/promises";
import { platform } from "node:os";
import { dirname, join } from "node:path";
import { logError } from "../logger";
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
    i > 0 && (argv[i - 1] === "-w" || argv[i - 1] === "-p" || argv[i - 1] === "-k")
      ? "<redacted>"
      : arg,
  );

type TSpawnMode = "ignore" | "pipe";

/** Under the 5s walker auth cutoff so a hung unlock cannot stall hops. */
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
  | { readonly kind: "complete"; readonly code: number; readonly stdout: string; readonly stderr: string }
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

const spawnSecurity = async (
  argv: ReadonlyArray<string>,
  home: string,
  opts: TSecuritySpawnOpts,
): Promise<TSecurityResult> => {
  if (opts.signal?.aborted === true) {
    return { ...FAILED_SPAWN, timedOut: false, aborted: true };
  }
  try {
    const proc = Bun.spawn(
      sandboxSpawnArgs(["security", ...argv], { probe: unwrapKeychainSpawn() }),
      {
        stdin: "ignore",
        stdout: opts.stdout,
        stderr: opts.stderr,
        cwd: spawnCwd({ HOME: home }),
        env: { ...process.env, HOME: home },
      },
    );
    // Drain both pipes AND exit under one deadline — a hung `exited` (GUI
    // dialog) used to poison `inFlightKeychains` forever.
    let timer: ReturnType<typeof setTimeout> | null = null;
    const unbind = bindAbort(opts.signal, () => {
      try {
        proc.kill();
      } catch {
        // already gone
      }
    });
    try {
      const complete = Promise.all([
        opts.stdout === "pipe"
          ? new Response(proc.stdout).text()
          : Promise.resolve(""),
        opts.stderr === "pipe"
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
      // If the timeout wins the race, `complete` stays pending; consume a late
      // rejection (an aborted pipe read after `proc.kill()`) so it can never
      // surface as an unhandledRejection.
      void complete.catch(() => {});
      const timeout = new Promise<TSecurityOutcome>((resolve) => {
        timer = setTimeout(
          () => resolve({ kind: "timeout" }),
          securitySpawnTimeoutMs(),
        );
      });
      const abortWait =
        opts.signal === undefined
          ? null
          : new Promise<TSecurityOutcome>((resolve) => {
              bindAbort(opts.signal, () => resolve({ kind: "aborted" }));
            });
      const outcome = await Promise.race(
        abortWait === null ? [complete, timeout] : [complete, timeout, abortWait],
      );
      if (outcome.kind === "aborted") {
        proc.kill();
        return { ...FAILED_SPAWN, timedOut: false, aborted: true };
      }
      if (outcome.kind === "timeout") {
        proc.kill();
        logError("keychain", "security command timed out", {
          argv: redactSecurityArgv(["security", ...argv]),
        });
        return { ...FAILED_SPAWN, timedOut: true, aborted: false };
      }
      // Through the `--sandbox-exec` shim the daemon sees `128 + signal` as an
      // exit CODE, not a signalCode, so this only fires for a kill of the shim
      // itself; a sandbox kill of the `security` child is attributed by the
      // SHIM's own log line (command name only — already redacted, never the
      // `-w` OAuth payload). Kept for the unwrapped paths. `security` is spawned
      // with the same `probe` flag, so its confinement matches: unwrapped on
      // macOS (securityd refuses a confined caller) ⇒ an unconfined kill.
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
      unbind();
      if (timer !== null) clearTimeout(timer);
    }
  } catch {
    return { ...FAILED_SPAWN, timedOut: false, aborted: false };
  }
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
// Positive TTL (UNLOCK_READY_TTL_MS): after a successful empty-password
// unlock, skip re-poking securityd for a short window. Auto-lock is disabled
// on the isolated chain we create, so a 15s skip is safe; a classified auth
// failure still self-heals. Transient TIMEOUTS back off exponentially and
// mark the chain unusable after N consecutive timeouts so a wedged securityd
// cannot be poked every 2.5s forever.
const inFlightKeychains = new Map<string, Promise<TStoreRead<void>>>();
const UNLOCK_READY_TTL_MS = 15_000;
const unlockedUntilMs = new Map<string, number>();
const TRANSIENT_TIMEOUT_UNUSABLE_AFTER = 5;
const transientTimeouts = new Map<
  string,
  { readonly count: number; readonly nextAtMs: number }
>();

const DUMP_CACHE_TTL_MS = 5_000;
const dumpCache = new Map<
  string,
  {
    readonly mtimeMs: number;
    readonly atMs: number;
    readonly value: TStoreRead<ReadonlyArray<string>>;
  }
>();

// A chain we recreated once this process (bounds self-heal to one attempt per
// path per process — launchd KeepAlive resets it on restart).
const healedKeychains = new Set<string>();

// A chain whose empty-password unlock is auth-failed AND whose recreate also
// failed: give up until restart. `ensureKeychainReady` short-circuits on these
// with ZERO spawns, so a hopeless chain stops re-prompting every 2.5s.
const unusableKeychains = new Set<string>();

// Throttle the create-failure log so a persistent failure doesn't spam the
// error stream on every ~2.5s status tick. One line per keychain per window.
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

/** errSecAuthFailed (-25293) / errSecInvalidKeychain (-25295) / the passphrase
 *  message ⇒ the empty password genuinely no longer works (recreate).
 *  Everything else — incl. an empty stderr the sandbox shim may swallow, a
 *  user-canceled (-128), or interaction-not-allowed (-25308) — is treated as
 *  TRANSIENT: do NOT recreate (fail-safe; the readiness gate already prevents
 *  any prompt), so a transient securityd hiccup never nukes a good credential. */
const classifyUnlockFailure = (stderr: string): "auth" | "transient" => {
  const s = stderr.toLowerCase();
  if (
    s.includes("-25293") ||
    s.includes("-25295") ||
    s.includes("passphrase you entered") ||
    s.includes("username or passphrase")
  )
    return "auth";
  return "transient";
};

/** Create + configure the isolated login keychain at `kc`. macOS `securityd`
 *  REFUSES `create-keychain` at the RESERVED `login.keychain-db` name inside
 *  the $HOME subtree under Seatbelt (it routes through session login-keychain
 *  machinery that needs the real `~/Library/Keychains` the deny-$HOME policy
 *  blocks → `errSec 161` or a GUI auth prompt). So create + configure at a
 *  NON-reserved staging name, THEN atomically rename into place. Auto-lock is
 *  disabled on the STAGING name only (set-keychain-settings on the reserved
 *  name pops "User canceled" under the sandbox); the setting persists through
 *  the rename. See docs/audit/2026-06-22-daemon-mac-sandbox-failures.md §3.
 *  Returns whether `kc` now exists. */
const createIsolatedKeychain = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  const dir = dirname(kc);
  await mkdir(dir, { recursive: true });
  const staging = join(dir, `.openllm-staging-${process.pid}.keychain-db`);
  // Sweep orphaned staging files from a prior run that crashed between create +
  // rename (the filename carries the pid). Best-effort. `.broken-*` files (a
  // rename-aside from self-heal) are deliberately LEFT for forensics/recovery.
  try {
    for (const f of await readdir(dir)) {
      if (f.startsWith(".openllm-staging-") && f.endsWith(".keychain-db")) {
        await rm(join(dir, f), { force: true });
      }
    }
  } catch {
    // dir unreadable / race — non-fatal
  }
  const created = await runSecurity(
    ["create-keychain", "-p", "", staging],
    home,
    signal,
  );
  if (created) {
    await runSecurity(["set-keychain-settings", staging], home, signal);
    try {
      await rename(staging, kc);
    } catch {
      await rm(staging, { force: true });
    }
  } else {
    await rm(staging, { force: true });
  }
  return existsSync(kc);
};

/** Rename the drifted chain aside (reversible, forensic), recreate fresh, and
 *  unlock. Returns whether the fresh chain unlocked with the empty password. */
const recreateIsolatedKeychain = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<boolean> => {
  const aside = `${kc}.broken-${process.pid}-${Date.now()}`;
  try {
    await rename(kc, aside);
  } catch {
    // Can't preserve it — remove so create can proceed. Best-effort.
    try {
      await rm(kc, { force: true });
    } catch {
      // still there — create will no-op and we return false below
    }
  }
  logSelfHeal(kc);
  if (!(await createIsolatedKeychain(home, kc, signal))) return false;
  return runSecurity(["unlock-keychain", "-p", "", kc], home, signal);
};

/** Ensure the isolated login keychain exists and is UNLOCKED for this call,
 *  reporting readiness as a tri-state. Create when missing; unlock with the
 *  empty password; on a classified empty-password DRIFT of an existing file,
 *  self-heal once (rename-aside + recreate); if it still won't unlock, mark it
 *  unusable so callers stop touching it. A transient unlock failure stays
 *  retryable (returns `indeterminate`, never recreates). No-op `present` off
 *  macOS. */
const noteUnlockSuccess = (kc: string): TStoreRead<void> => {
  unlockedUntilMs.set(kc, Date.now() + UNLOCK_READY_TTL_MS);
  transientTimeouts.delete(kc);
  return READY;
};

const noteUnlockTimeout = (kc: string): TStoreRead<void> => {
  const prev = transientTimeouts.get(kc);
  const count = (prev?.count ?? 0) + 1;
  if (count >= TRANSIENT_TIMEOUT_UNUSABLE_AFTER) {
    unusableKeychains.add(kc);
    transientTimeouts.delete(kc);
    return { kind: "indeterminate", cause: "keychain_unusable" };
  }
  const delayMs = 2_500 * 2 ** (count - 1);
  transientTimeouts.set(kc, { count, nextAtMs: Date.now() + delayMs });
  return { kind: "indeterminate", cause: "keychain_unlock_transient" };
};

const ensureKeychainNow = async (
  home: string,
  kc: string,
  signal?: AbortSignal,
): Promise<TStoreRead<void>> => {
  if (!existsSync(kc)) {
    if (!(await createIsolatedKeychain(home, kc, signal))) {
      // A later `claude auth login` would pop "Keychain Not Found" and wedge.
      logKeychainFailure(kc);
      return { kind: "indeterminate", cause: "keychain_create_failed" };
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
  if (res.code === 0) return noteUnlockSuccess(kc);

  // Caller abort (status-race cancel) is not a keychain fault — skip timeout
  // accounting so a healthy chain is never marked unusable.
  if (res.aborted) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  if (res.timedOut) return noteUnlockTimeout(kc);

  if (classifyUnlockFailure(res.stderr) === "auth") {
    if (!healedKeychains.has(kc)) {
      healedKeychains.add(kc);
      if (await recreateIsolatedKeychain(home, kc, signal))
        return noteUnlockSuccess(kc);
    }
    // Auth-drift and (already healed OR recreate failed) → terminal.
    unusableKeychains.add(kc);
    return { kind: "indeterminate", cause: "keychain_unusable" };
  }
  // Transient — retryable next call; no recreate, no negative-cache.
  return { kind: "indeterminate", cause: "keychain_unlock_transient" };
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
  if (unusableKeychains.has(kc)) {
    return { kind: "indeterminate", cause: "keychain_unusable" };
  }
  const backoff = transientTimeouts.get(kc);
  if (backoff !== undefined && backoff.nextAtMs > Date.now()) {
    return { kind: "indeterminate", cause: "keychain_unlock_transient" };
  }
  const until = unlockedUntilMs.get(kc) ?? 0;
  if (until > Date.now()) return READY;
  const pending = inFlightKeychains.get(kc);
  if (pending !== undefined) return pending;
  const op = ensureKeychainNow(home, kc, signal).finally(() => {
    inFlightKeychains.delete(kc);
  });
  inFlightKeychains.set(kc, op);
  return op;
};

/** Test-only: process-global keychain caches leak across suites. */
export const resetKeychainStateForTests = (): void => {
  inFlightKeychains.clear();
  healedKeychains.clear();
  unusableKeychains.clear();
  lastKeychainFailureLogMs.clear();
  unlockedUntilMs.clear();
  transientTimeouts.clear();
  dumpCache.clear();
};

/**
 * macOS only: ensure the isolated login keychain exists + is unlocked so a
 * CLI run with `HOME=<home>` (e.g. `claude auth login`) can WRITE its
 * credential without the "Keychain Not Found" dialog. Void wrapper over
 * `ensureKeychainReady` for the create-so-login-can-write callers that
 * legitimately ignore readiness (they must attempt creation regardless).
 * No-op off macOS.
 */
export const ensureIsolatedKeychain = async (home: string): Promise<void> => {
  await ensureKeychainReady(home);
};

/**
 * macOS only: grant command-line tools prompt-free access to the items in
 * the isolated keychain. Run AFTER a login writes them, so our later
 * `security find-generic-password` reads don't trigger the "security
 * wants to access the keychain" GUI prompt. Gated on readiness: a locked /
 * unusable chain is skipped (its `set-key-partition-list` could prompt).
 * Best-effort.
 */
export const grantKeychainToolAccess = async (home: string): Promise<void> => {
  if (!MAC) return;
  if ((await ensureKeychainReady(home)).kind !== "present") return;
  await runSecurity(
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
  if (
    cached !== undefined &&
    cached.mtimeMs === mtimeMs &&
    Date.now() - cached.atMs < DUMP_CACHE_TTL_MS
  ) {
    return cached.value;
  }
  const { code, stdout } = await spawnSecurity(
    ["dump-keychain", kc],
    home,
    {
      stdout: "pipe",
      stderr: "ignore",
      ...(signal !== undefined ? { signal } : {}),
    },
  );
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
  dumpCache.set(cacheKey, { mtimeMs, atMs: Date.now(), value });
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
export const readIsolatedKeychain = async (
  home: string,
  servicePrefix: string,
  validate?: (payload: string) => boolean,
  signal?: AbortSignal,
): Promise<TStoreRead<string>> => {
  if (!MAC) return { kind: "absent" };
  const ready = await ensureKeychainReady(home, signal);
  if (ready.kind !== "present") return ready; // locked / unusable — no dump
  const services = await findKeychainServices(home, servicePrefix, signal);
  if (services.kind !== "present") return services;
  if (services.value.length === 0) return { kind: "absent" };
  let secretUnreadable = false;
  try {
    for (const service of services.value) {
      const secret = await readKeychainSecret(home, service, signal);
      if (secret === null) {
        secretUnreadable = true;
        continue;
      }
      if (validate !== undefined && !validate(secret)) continue;
      return { kind: "present", value: secret };
    }
    if (secretUnreadable) {
      return { kind: "indeterminate", cause: "keychain_secret_unreadable" };
    }
    return { kind: "absent" };
  } catch (err) {
    return {
      kind: "indeterminate",
      cause: err instanceof Error ? err.name : "keychain_read_failed",
    };
  }
};
