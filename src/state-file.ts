/**
 * Consolidated daemon-private state — ONE `state.json` under the state dir
 * instead of a scatter of single-purpose files. Holds the self-update attempt
 * cooldowns (daemon + CLI slots) and the crash-loop boot history. Strictly
 * daemon-private: nothing outside this binary reads or writes `state.json`, so
 * its shape is free to evolve — unlike the shared `.env` or the `installed/`
 * stamps, which are deployed contracts.
 *
 * CONCURRENCY INVARIANT: every mutation goes through {@link mutateState},
 * which MUST stay fully synchronous — read-fresh, transform, atomic
 * temp+rename write, with no awaits in between. The daemon and CLI update
 * convergers run concurrently (fired un-awaited on the same bootstrap tick),
 * but single-threaded JS plus sync-only file I/O means their read-modify-write
 * cycles can never interleave, so one slot's record can't clobber the other's.
 * That merge-preserving behavior is the guarantee that previously motivated
 * two separate attempt files.
 *
 * Best-effort + never throws (mirrors `logger.ts` / `boot-guard.ts`): a
 * read failure yields defaults, a write failure is swallowed — the in-memory
 * guards in the callers still prevent tight loops.
 */
import {
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { stateDir } from "./env";

/** Which converger recorded an update attempt. */
export type TUpdateSlot = "daemon" | "cli";

/**
 * One converger's last try at reaching `version`.
 *
 * `failures` counts CONSECUTIVE tries at this version that have not yet
 * proven convergence (a failed download/checksum/write/probe, or a swap
 * whose relaunched binary still reports the old version). It resets whenever
 * `version` changes. `retryAfterMs` is the jittered exponential backoff that
 * applies from `ts` — stored at record time so a tick never re-rolls the
 * dice and the delay provably grows across failures.
 */
export type TUpdateAttempt = {
  readonly version: string;
  readonly ts: number;
  readonly failures?: number;
  readonly retryAfterMs?: number;
  /**
   * The artifact digest this attempt targeted (the manifest-advertised
   * sha256 when known) — lets a post-swap rejection (crash-loop rollback,
   * broken-install self-heal) pin the exact artifact that failed rather
   * than the whole version.
   */
  readonly digest?: string;
};

/**
 * Liveness sentinel for the RTC native-crash breaker. Written at boot, cleared
 * on ANY graceful exit (a `process.on("exit")` hook). A native signal
 * (SIGSEGV/SIGBUS/SIGKILL) runs NO exit hook, so a sentinel that SURVIVES to the
 * next boot means the prior run died to a signal — the discriminator the breaker
 * keys on. `rtcEnabled` records whether RTC was live that run, so only
 * RTC-attributable crashes count.
 */
export type TRtcRun = {
  readonly pid: number;
  readonly startedAt: number;
  readonly rtcEnabled: boolean;
};

export type TDaemonState = {
  readonly updateAttempts: {
    readonly daemon?: TUpdateAttempt;
    readonly cli?: TUpdateAttempt;
  };
  readonly bootHistory: readonly number[];
  /**
   * Seed-derived device-access public key (SPKI DER, base64) pinned from
   * bootstrap. `null` means explicitly un-provisioned; absent means never
   * set. Survives restarts so enforcement does not wait on the next poll.
   */
  readonly deviceAccessPubkey?: string | null;
  /** RTC native-crash breaker: this run's liveness sentinel (see {@link TRtcRun}). */
  readonly rtcRun?: TRtcRun | null;
  /** Timestamps of detected native crashes while RTC was live (bounded window). */
  readonly rtcCrashes?: readonly number[];
  /** The daemon version {@link rtcCrashes} belongs to — a version change discards it. */
  readonly rtcCrashesVersion?: string | null;
  /**
   * Published artifacts a converger must never install again: a downloaded
   * artifact that failed a deterministic check (SHA-256 mismatch, size cap,
   * decompression, malformed digest) or the pre-swap health probe, or a
   * version that crash-looped right after a swap (rolled back by
   * `boot-guard.ts`). Keyed by version + ARTIFACT DIGEST — a corrected
   * re-publish of the same version produces a different advertised digest and
   * updates normally; only the exact bad bytes stay blocked. `digest: ""`
   * records "this version, whatever the bytes" (crash loops where the digest
   * was never captured, legacy version-only records) and matches any
   * advertised digest. PER SLOT — a rejected daemon `2.8.0` says nothing
   * about the CLI `2.8.0` (different binaries, different artifacts). Each
   * list is bounded (newest {@link REJECTED_UPDATES_MAX}); a still-advertised
   * bad artifact re-confirms its entry on every encounter and can therefore
   * never age out of the list.
   */
  readonly rejectedUpdates?: {
    readonly daemon?: readonly TRejectedUpdate[];
    readonly cli?: readonly TRejectedUpdate[];
  };
};

/**
 * Fallback next-try window for attempt records written before per-attempt
 * backoff existed (no `retryAfterMs`) — keeps the old flat cooldown semantics
 * for those records.
 */
export const UPDATE_ATTEMPT_COOLDOWN_MS = 60 * 60 * 1000;

/**
 * Backoff schedule for a failed (or not-yet-converged) update try: the first
 * retry waits ~15 min, doubling each consecutive failure up to a 6 h cap —
 * a mis-published release stops re-downloading the ~40 MB binary on every
 * bootstrap tick instead of looping hourly forever. Jitter ±25% breaks
 * lockstep across the fleet.
 */
export const UPDATE_FAILURE_BASE_DELAY_MS = 15 * 60 * 1000;
export const UPDATE_FAILURE_MAX_DELAY_MS = 6 * 60 * 60 * 1000;

/** Upper bound for the rejected-artifact list ({@link TDaemonState.rejectedUpdates}). */
export const REJECTED_UPDATES_MAX = 16;

/**
 * One rejected artifact: `version` + the advertised artifact `digest` that
 * proved bad. `digest === ""` means "this version regardless of bytes" —
 * legacy version-only records and post-swap rejections that never captured a
 * digest — which matches ANY advertised digest (fail closed).
 */
export type TRejectedUpdate = {
  readonly version: string;
  readonly digest: string;
};

/**
 * Exponential backoff with symmetric ±25% jitter: `baseMs * 2^(attempt-1)`,
 * scaled by `rng()` in [0.75, 1.25], then hard-clamped to `capMs` — the cap
 * bounds the FINAL delay (jitter can't push past it; near-cap attempts still
 * jitter because sub-cap values compress against the bound). Shared by the
 * update-attempt records and the bootstrap retry loop — one bounded
 * primitive, one jitter contract. `attempt` is clamped so `2^` can't
 * overflow into a negative/huge delay.
 */
export const exponentialBackoffMs = (
  attempt: number,
  baseMs: number,
  capMs: number,
  rng: () => number = Math.random,
): number => {
  const exp = baseMs * 2 ** Math.min(Math.max(attempt, 1) - 1, 31);
  const jitter = 0.75 + Math.min(Math.max(rng(), 0), 1) * 0.5;
  return Math.round(Math.min(capMs, exp * jitter));
};

/** The delay a failed/non-converged update try waits before re-trying. */
export const updateFailureDelayMs = (
  failures: number,
  rng: () => number = Math.random,
): number =>
  exponentialBackoffMs(
    failures,
    UPDATE_FAILURE_BASE_DELAY_MS,
    UPDATE_FAILURE_MAX_DELAY_MS,
    rng,
  );

const DEFAULT_STATE: TDaemonState = { updateAttempts: {}, bootHistory: [] };

export const stateFilePath = (): string => join(stateDir(), "state.json");

const isAttempt = (v: unknown): v is TUpdateAttempt => {
  if (typeof v !== "object" || v === null) return false;
  const a = v as TUpdateAttempt;
  if (typeof a.version !== "string" || typeof a.ts !== "number") return false;
  if (a.failures !== undefined && typeof a.failures !== "number") return false;
  if (a.retryAfterMs !== undefined && typeof a.retryAfterMs !== "number") {
    return false;
  }
  if (a.digest !== undefined && typeof a.digest !== "string") return false;
  return true;
};

const numberList = (v: unknown): number[] =>
  Array.isArray(v) ? v.filter((n): n is number => typeof n === "number") : [];

/**
 * Coerce one rejected-list entry: the current `{version, digest}` object, or
 * a bare string (round-2 version-only records) upgraded to `digest: ""` —
 * "any bytes of this version" (fail closed: a record whose artifact identity
 * was never captured can't be proven different from what's advertised).
 */
const coerceRejectedEntry = (v: unknown): TRejectedUpdate | null => {
  if (typeof v === "string") {
    return v.length > 0 ? { version: v, digest: "" } : null;
  }
  if (typeof v !== "object" || v === null) return null;
  const e = v as { version?: unknown; digest?: unknown };
  if (typeof e.version !== "string" || e.version.length === 0) return null;
  return {
    version: e.version,
    digest: typeof e.digest === "string" ? e.digest : "",
  };
};

const rejectedEntryList = (v: unknown): TRejectedUpdate[] =>
  Array.isArray(v)
    ? v.map(coerceRejectedEntry).filter((e): e is TRejectedUpdate => e !== null)
    : [];

/**
 * Coerce `rejectedUpdates` into the per-slot shape. A legacy FLAT array
 * (written before rejections were per-product) is conservatively applied to
 * BOTH slots — an artifact once proven bad stays rejected rather than being
 * silently re-allowed for one product.
 */
const coerceRejectedUpdates = (
  v: unknown,
): { daemon?: TRejectedUpdate[]; cli?: TRejectedUpdate[] } | undefined => {
  if (Array.isArray(v)) {
    const legacy = rejectedEntryList(v).slice(-REJECTED_UPDATES_MAX);
    return legacy.length > 0 ? { daemon: legacy, cli: legacy } : undefined;
  }
  if (typeof v !== "object" || v === null) return undefined;
  const raw = v as { daemon?: unknown; cli?: unknown };
  const daemon = rejectedEntryList(raw.daemon).slice(-REJECTED_UPDATES_MAX);
  const cli = rejectedEntryList(raw.cli).slice(-REJECTED_UPDATES_MAX);
  if (daemon.length === 0 && cli.length === 0) return undefined;
  return {
    ...(daemon.length > 0 ? { daemon } : {}),
    ...(cli.length > 0 ? { cli } : {}),
  };
};

const isRtcRun = (v: unknown): v is TRtcRun =>
  typeof v === "object" &&
  v !== null &&
  typeof (v as TRtcRun).pid === "number" &&
  Number.isInteger((v as TRtcRun).pid) &&
  typeof (v as TRtcRun).startedAt === "number" &&
  Number.isFinite((v as TRtcRun).startedAt) &&
  typeof (v as TRtcRun).rtcEnabled === "boolean";

/** Coerce parsed-unknown JSON into a valid state, field by field. */
const coerceState = (v: unknown): TDaemonState => {
  if (typeof v !== "object" || v === null) return DEFAULT_STATE;
  const raw = v as {
    updateAttempts?: unknown;
    bootHistory?: unknown;
    deviceAccessPubkey?: unknown;
    rtcRun?: unknown;
    rtcCrashes?: unknown;
    rtcCrashesVersion?: unknown;
    rejectedUpdates?: unknown;
  };
  const attempts =
    typeof raw.updateAttempts === "object" && raw.updateAttempts !== null
      ? (raw.updateAttempts as { daemon?: unknown; cli?: unknown })
      : {};
  const pubkey =
    raw.deviceAccessPubkey === null
      ? null
      : typeof raw.deviceAccessPubkey === "string" &&
          raw.deviceAccessPubkey.length > 0
        ? raw.deviceAccessPubkey
        : undefined;
  const rtcCrashes = numberList(raw.rtcCrashes);
  const rtcCrashesVersion =
    typeof raw.rtcCrashesVersion === "string" &&
    raw.rtcCrashesVersion.length > 0
      ? raw.rtcCrashesVersion
      : undefined;
  const rejectedUpdates = coerceRejectedUpdates(raw.rejectedUpdates);
  return {
    updateAttempts: {
      ...(isAttempt(attempts.daemon) ? { daemon: attempts.daemon } : {}),
      ...(isAttempt(attempts.cli) ? { cli: attempts.cli } : {}),
    },
    bootHistory: numberList(raw.bootHistory),
    ...(pubkey !== undefined ? { deviceAccessPubkey: pubkey } : {}),
    ...(isRtcRun(raw.rtcRun) ? { rtcRun: raw.rtcRun } : {}),
    ...(rtcCrashes.length > 0 ? { rtcCrashes } : {}),
    ...(rtcCrashesVersion !== undefined ? { rtcCrashesVersion } : {}),
    ...(rejectedUpdates !== undefined ? { rejectedUpdates } : {}),
  };
};

/**
 * Atomic write: pid-suffixed temp + rename. Best-effort — NEVER throws, and
 * returns whether the write landed so update-guard callers can fail closed
 * when their safety records can't persist (see {@link autoUpdateSuspended}).
 */
const writeStateAtomic = (state: TDaemonState): boolean => {
  const tmp = join(stateDir(), `.state.json.${process.pid}.tmp`);
  try {
    mkdirSync(stateDir(), { recursive: true });
    writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    renameSync(tmp, stateFilePath());
    return true;
  } catch {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
    return false;
  }
};

/**
 * The current consolidated state. Absent or corrupt file → defaults. Never
 * throws. A pure read must not create a state file.
 */
export const readState = (): TDaemonState => {
  let raw: string;
  try {
    raw = readFileSync(stateFilePath(), "utf-8");
  } catch {
    return DEFAULT_STATE;
  }
  try {
    return coerceState(JSON.parse(raw));
  } catch {
    return DEFAULT_STATE;
  }
};

/**
 * Synchronous read-fresh → transform → atomic-write. MUST stay synchronous
 * end to end (see the module header) — that is the whole concurrency story.
 * Returns whether the transformed state actually persisted.
 */
export const mutateState = (fn: (s: TDaemonState) => TDaemonState): boolean => {
  return writeStateAtomic(fn(readState()));
};

// ── Process-lifetime fallback guards ────────────────────────────────────────
// `state.json` writes are best-effort by design: a full disk or a read-only
// mount must not crash the daemon, but it must ALSO not silently drop the
// update backoff/rejection guards — that would re-download a broken ~40 MB
// artifact every tick forever. Every recordAttempt/rejectUpdateVersion is
// therefore ALSO mirrored into these process-lifetime maps, keyed by the
// state dir they were recorded under (test isolation makes dir-scoping the
// safe shape; in production there is exactly one state dir).
const memoryAttempts = new Map<
  TUpdateSlot,
  { readonly dir: string; readonly attempt: TUpdateAttempt }
>();
/**
 * In-memory rejection mirror, keyed `"<version>\0<digest>"` per slot — a
 * proven-bad artifact stays blocked for this process even when the state
 * write fails (and triggers the auto-update suspension below).
 */
const memoryRejected = new Map<
  string,
  { daemon: Set<string>; cli: Set<string> }
>();
/**
 * State dirs whose LAST rejection write could not be persisted. While a dir
 * is listed, {@link autoUpdateSuspended} gates every converger on this host —
 * an unpersisted deterministic reject must never degrade into cross-process
 * retry loops (round-3: the in-memory mirror alone only covered THIS process).
 */
const suspendedStateDirs = new Set<string>();

const rejectedKey = (version: string, digest: string): string =>
  `${version}${digest}`;

const memoryRejectedFor = (
  dir: string,
): { daemon: Set<string>; cli: Set<string> } => {
  const existing = memoryRejected.get(dir);
  if (existing !== undefined) return existing;
  const created = { daemon: new Set<string>(), cli: new Set<string>() };
  memoryRejected.set(dir, created);
  return created;
};

/** Test-only: drop every in-memory fallback record. Never called in production. */
export const clearInMemoryUpdateGuardsForTests = (): void => {
  memoryAttempts.clear();
  memoryRejected.clear();
  suspendedStateDirs.clear();
};

/**
 * Fail-closed gate (round-3): TRUE while a deterministic-failure rejection
 * could not be persisted to `state.json` — meaning every OTHER process can
 * re-attempt the bad artifact, and this process must not add to the churn.
 * Each call while suspended probes a real write; the first successful one
 * lifts the suspension (transient full-disk / read-only windows self-heal).
 */
export const autoUpdateSuspended = (): boolean => {
  const dir = stateDir();
  if (!suspendedStateDirs.has(dir)) return false;
  if (writeStateAtomic(readState())) {
    suspendedStateDirs.delete(dir);
    return false;
  }
  return true;
};

const attemptIsRecent = (
  attempt: TUpdateAttempt | undefined,
  version: string,
  now: number,
): boolean => {
  if (attempt === undefined || attempt.version !== version) return false;
  const retryAfterMs = attempt.retryAfterMs ?? UPDATE_ATTEMPT_COOLDOWN_MS;
  return now - attempt.ts < retryAfterMs;
};

/**
 * True when `slot` must still wait before re-trying `version`: a recorded
 * try exists, targets the same version, and its jittered backoff has not
 * elapsed — so a relaunch/tick that still isn't on it (bad publish, failed
 * download/checksum/write/probe) backs off instead of re-downloading every
 * tick. Records written before per-attempt backoff fall back to the flat
 * {@link UPDATE_ATTEMPT_COOLDOWN_MS}. The persisted record OR its in-memory
 * mirror counts, so a failed state write still yields a durable backoff for
 * this process's lifetime.
 */
export const recentlyAttempted = (
  slot: TUpdateSlot,
  version: string,
  now: number = Date.now(),
): boolean => {
  const persisted = readState().updateAttempts[slot];
  const mirrored = memoryAttempts.get(slot);
  return (
    attemptIsRecent(persisted, version, now) ||
    (mirrored !== undefined &&
      mirrored.dir === stateDir() &&
      attemptIsRecent(mirrored.attempt, version, now))
  );
};

/**
 * Record `slot`'s try at `version` — a completed swap OR a failed
 * download/checksum/write/probe; neither has proven convergence yet, so both
 * share one counter. Bumps the consecutive-`failures` count (reset when the
 * target version changes) and stamps a fresh jittered `retryAfterMs` so the
 * next try backs off exponentially up to {@link UPDATE_FAILURE_MAX_DELAY_MS}.
 * Merge-preserving: the other slot's record is untouched.
 */
export const recordAttempt = (
  slot: TUpdateSlot,
  version: string,
  opts?: {
    readonly now?: number;
    readonly rng?: () => number;
    readonly digest?: string;
  },
): void => {
  const now = opts?.now ?? Date.now();
  const rng = opts?.rng ?? Math.random;
  mutateState((s) => {
    const prev = s.updateAttempts[slot];
    const failures = (prev?.version === version ? (prev.failures ?? 0) : 0) + 1;
    const attempt: TUpdateAttempt = {
      version,
      ts: now,
      failures,
      retryAfterMs: updateFailureDelayMs(failures, rng),
      ...(opts?.digest !== undefined ? { digest: opts.digest } : {}),
    };
    // Mirror unconditionally — if the write itself fails, the process-local
    // copy still enforces the backoff (see the fallback-guards note above).
    memoryAttempts.set(slot, { dir: stateDir(), attempt });
    return {
      ...s,
      updateAttempts: {
        ...s.updateAttempts,
        [slot]: attempt,
      },
    };
  });
};

/**
 * Match a stored rejection against a query. A `""` stored digest means "this
 * version whatever the bytes" (legacy/crash-loop records) and matches any
 * advertised digest; a keyed entry matches only the exact artifact. A query
 * WITHOUT a digest can only confirm the wildcard records — callers that know
 * the advertised digest must pass it so a corrected re-publish isn't blocked.
 */
const rejectionMatches = (
  entry: TRejectedUpdate,
  version: string,
  digest: string | undefined,
): boolean =>
  entry.version === version &&
  (entry.digest === "" || (digest !== undefined && entry.digest === digest));

/**
 * True when `slot`'s converger must never install `version`'s artifact
 * `digest` again — persisted rejection OR its in-memory mirror (a state-write
 * failure must not re-admit an artifact this process already proved bad).
 * Rejects are keyed by version + artifact sha256, so a corrected re-publish
 * of the same version (different advertised digest) is NOT rejected.
 */
export const isUpdateRejected = (
  slot: TUpdateSlot,
  version: string,
  digest?: string,
): boolean => {
  if (
    (readState().rejectedUpdates?.[slot] ?? []).some((e) =>
      rejectionMatches(e, version, digest),
    )
  ) {
    return true;
  }
  const memory = memoryRejected.get(stateDir())?.[slot];
  if (memory === undefined) return false;
  if (memory.has(rejectedKey(version, ""))) return true;
  return digest !== undefined && memory.has(rejectedKey(version, digest));
};

/**
 * Mark `version`'s artifact `digest` as never-installable on this host for
 * `slot`'s product — deterministic artifact failure (checksum/size/
 * decompression), a bad binary proven by the pre-swap probe, or a post-swap
 * crash loop. `digest` is the manifest-advertised sha256; pass "" when the
 * artifact identity was never captured (rejects the version regardless of
 * bytes — the fail-closed legacy shape).
 *
 * Re-recording an already-rejected (version, digest) moves it to the END of
 * the list: an artifact still being advertised can therefore never age out
 * of the {@link REJECTED_UPDATES_MAX} bound while it keeps proving bad.
 * Returns whether the record persisted; on failure the entry still lands in
 * the in-memory mirror AND the state dir is marked suspended so
 * {@link autoUpdateSuspended} fails every converger closed until a write
 * lands (the round-3 fix: an unpersisted reject must not let OTHER processes
 * keep retrying the same bad bytes).
 */
export const rejectUpdateVersion = (
  slot: TUpdateSlot,
  version: string,
  digest: string = "",
): boolean => {
  memoryRejectedFor(stateDir())[slot].add(rejectedKey(version, digest));
  const persisted = mutateState((s) => {
    const existing = s.rejectedUpdates?.[slot] ?? [];
    // Re-admitting the same entry refreshes its position (a still-advertised
    // bad artifact can never be evicted by newer rejects).
    const rest = existing.filter(
      (e) => !(e.version === version && e.digest === digest),
    );
    return {
      ...s,
      rejectedUpdates: {
        ...s.rejectedUpdates,
        [slot]: [...rest, { version, digest }].slice(-REJECTED_UPDATES_MAX),
      },
    };
  });
  if (!persisted) suspendedStateDirs.add(stateDir());
  return persisted;
};

/** Boot timestamps for the crash-loop breaker (`boot-guard.ts`). */
export const readBootHistory = (): readonly number[] => readState().bootHistory;

export const writeBootHistory = (timestamps: readonly number[]): void => {
  mutateState((s) => ({ ...s, bootHistory: [...timestamps] }));
};

// ── RTC native-crash circuit breaker ────────────────────────────────────────
// The daemon can crash NATIVELY (SIGBUS/SIGSEGV) inside the werift/Bun UDP
// stack — a runtime fault we can't catch in JS. If a host keeps doing it with
// RTC live, we degrade that host to relay-mux (one hop slower, still fully
// functional) instead of crash-looping. This is the durable half; the boot
// wiring lives in `boot-guard.ts`.

/** How far back a native crash counts toward the RTC breaker tally. */
export const RTC_CRASH_WINDOW_MS = 30 * 60 * 1000;
/** Native crashes (RTC live) within {@link RTC_CRASH_WINDOW_MS} that trip it. */
export const RTC_CRASH_LIMIT = 2;

export type TRtcBreakerDecision = {
  /** Whether THIS run should withdraw RTC (fall back to relay-mux). */
  readonly disableRtc: boolean;
  /** State to persist: fresh sentinel + trimmed crash tally + version. */
  readonly nextState: TDaemonState;
};

/**
 * PURE breaker decision (mirrors `boot-guard.ts` `shouldPark` — unit-testable
 * without a real crash). Given the persisted state, `now`, the running daemon
 * `version`, and this process's `pid`:
 *
 * - A prior `rtcRun` sentinel that SURVIVED (still present, different pid, was
 *   RTC-enabled) means the previous run died to a native signal with RTC live —
 *   append `now` to the crash tally.
 * - The tally belongs to a specific `version`; a version change (self-update)
 *   discards it, so a new binary earns a clean trial.
 * - Trip when the in-window tally reaches {@link RTC_CRASH_LIMIT}. A tripped run
 *   records `rtcEnabled:false` in its own sentinel, so a crash while degraded
 *   isn't re-attributed to RTC (the breaker can't self-perpetuate), and the
 *   tally ages out of the window on a later clean run → auto-recovery.
 *
 * HEURISTIC, not proof: a surviving sentinel means "the prior run died to a
 * signal (ran no exit hook) while RTC was live" — which is SIGSEGV/SIGBUS (the
 * target), but ALSO an OOM `SIGKILL`, a `kill -9`, a power loss, or a SIGTERM
 * that arrived before the daemon installed its handlers. Those over-count, but
 * the only consequence is a one-hop-slower relay-mux fallback, and it takes
 * {@link RTC_CRASH_LIMIT} in-window to trip — a benign bias toward safety.
 */
export const evaluateRtcBreaker = (
  state: TDaemonState,
  now: number,
  version: string,
  pid: number,
): TRtcBreakerDecision => {
  const prior = state.rtcRun ?? null;
  const priorCrashedWithRtc =
    prior !== null && prior.pid !== pid && prior.rtcEnabled === true;
  // Discard a tally from a different binary version.
  const priorTally =
    state.rtcCrashesVersion === version
      ? (state.rtcCrashes ?? []).filter(
          (t) => t <= now && now - t < RTC_CRASH_WINDOW_MS,
        )
      : [];
  const rtcCrashes = priorCrashedWithRtc ? [...priorTally, now] : priorTally;
  const disableRtc = rtcCrashes.length >= RTC_CRASH_LIMIT;
  return {
    disableRtc,
    nextState: {
      ...state,
      rtcRun: { pid, startedAt: now, rtcEnabled: !disableRtc },
      rtcCrashes,
      rtcCrashesVersion: version,
    },
  };
};

/**
 * Clear THIS process's liveness sentinel — called from a `process.on("exit")`
 * hook, so it MUST stay synchronous (`mutateState` is). Marks a GRACEFUL exit:
 * the absence of a surviving sentinel next boot is how the breaker tells a clean
 * shutdown from a native crash.
 *
 * PID-guarded: only clear a sentinel this process owns. During a self-update →
 * relaunch handoff (or a supervised fast restart) an exiting process can overlap
 * a freshly-booted one that has already written ITS sentinel; an unguarded clear
 * would erase the new run's evidence and silently defeat the breaker in exactly
 * the crash-churn it exists for. Mirrors the pid identity check in
 * {@link evaluateRtcBreaker}.
 */
export const clearRtcRun = (pid: number = process.pid): void => {
  mutateState((s) => (s.rtcRun?.pid === pid ? { ...s, rtcRun: null } : s));
};
