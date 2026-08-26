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

export type TUpdateAttempt = { readonly version: string; readonly ts: number };

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
};

/**
 * Don't retry the SAME target version within this window after a swap that
 * didn't converge (a mis-published release) — bounds restart/download loops.
 * Single source for both convergers (was duplicated in `self-update.ts` and
 * `cli-self-update.ts`).
 */
export const UPDATE_ATTEMPT_COOLDOWN_MS = 60 * 60 * 1000;

const DEFAULT_STATE: TDaemonState = { updateAttempts: {}, bootHistory: [] };

export const stateFilePath = (): string => join(stateDir(), "state.json");

const isAttempt = (v: unknown): v is TUpdateAttempt =>
  typeof v === "object" &&
  v !== null &&
  typeof (v as TUpdateAttempt).version === "string" &&
  typeof (v as TUpdateAttempt).ts === "number";

const numberList = (v: unknown): number[] =>
  Array.isArray(v) ? v.filter((n): n is number => typeof n === "number") : [];

/** Coerce parsed-unknown JSON into a valid state, field by field. */
const coerceState = (v: unknown): TDaemonState => {
  if (typeof v !== "object" || v === null) return DEFAULT_STATE;
  const raw = v as {
    updateAttempts?: unknown;
    bootHistory?: unknown;
    deviceAccessPubkey?: unknown;
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
  return {
    updateAttempts: {
      ...(isAttempt(attempts.daemon) ? { daemon: attempts.daemon } : {}),
      ...(isAttempt(attempts.cli) ? { cli: attempts.cli } : {}),
    },
    bootHistory: numberList(raw.bootHistory),
    ...(pubkey !== undefined ? { deviceAccessPubkey: pubkey } : {}),
  };
};

/** Atomic write: pid-suffixed temp + rename. Best-effort — swallows errors. */
const writeStateAtomic = (state: TDaemonState): void => {
  const tmp = join(stateDir(), `.state.json.${process.pid}.tmp`);
  try {
    mkdirSync(stateDir(), { recursive: true });
    writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    renameSync(tmp, stateFilePath());
  } catch {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
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
 */
export const mutateState = (fn: (s: TDaemonState) => TDaemonState): void => {
  writeStateAtomic(fn(readState()));
};

/**
 * True when `slot` already tried to converge to `version` recently — so a
 * relaunch/tick that still isn't on it (bad publish) backs off instead of
 * looping.
 */
export const recentlyAttempted = (
  slot: TUpdateSlot,
  version: string,
): boolean => {
  const attempt = readState().updateAttempts[slot];
  return (
    attempt !== undefined &&
    attempt.version === version &&
    Date.now() - attempt.ts < UPDATE_ATTEMPT_COOLDOWN_MS
  );
};

/** Record `slot`'s attempt, merge-preserving the other slot's record. */
export const recordAttempt = (slot: TUpdateSlot, version: string): void => {
  mutateState((s) => ({
    ...s,
    updateAttempts: {
      ...s.updateAttempts,
      [slot]: { version, ts: Date.now() },
    },
  }));
};

/** Boot timestamps for the crash-loop breaker (`boot-guard.ts`). */
export const readBootHistory = (): readonly number[] => readState().bootHistory;

export const writeBootHistory = (timestamps: readonly number[]): void => {
  mutateState((s) => ({ ...s, bootHistory: [...timestamps] }));
};
