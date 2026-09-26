import {
  accessSync,
  constants as fsConstants,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { constants as osConstants } from "node:os";
import { delimiter, isAbsolute, resolve } from "node:path";
import {
  ffiPointer,
  loadPtyBindings,
  type TPtyNativeBindings,
} from "../../pty-native";
import {
  normalizeProcessStartIdentity,
  processStartIdentity,
} from "../../pty-native/session/local-runtime";
import { WINDOWS_PTY_KILL_GRACE_MS } from "./bs-pty";
import { logWarn } from "./logger";
import { nativePtyEnv } from "./pty-env";
import type { TPtyLike, TPtySpawnArgs } from "./session-core";
import {
  spawn as admittedSpawn,
  nodeSpawnSync as spawnSync,
} from "./windows-process";

const POLL_READABLE = 1;
const POLL_WRITABLE = 2;
const POLL_HANGUP = 4;
const POLL_ERROR = 8;
const TTY_TARGET_CHILD = 1;
const TTY_TARGET_GROUP = 2;
const TTY_TARGET_FOREGROUND_GROUP = 4;
const TTY_TARGETS =
  TTY_TARGET_CHILD | TTY_TARGET_GROUP | TTY_TARGET_FOREGROUND_GROUP;
const TICK_MS = 4;
const STARTUP_DEADLINE_MS = 12_000;
const FINAL_DRAIN_DEADLINE_MS = 1_000;
const GRACEFUL_FINAL_DRAIN_MS = 250;
const DESTROY_RETRY_DELAYS_MS = [10, 25, 50, 100, 200] as const;
const DESTROY_RETRY_LIMIT = DESTROY_RETRY_DELAYS_MS.length + 1;
// P3-2: platform-aware TERM→KILL escalation. POSIX keeps the 1000 ms value;
// win32 uses the pinned retired-worker grace (WINDOWS_PTY_KILL_GRACE_MS, one
// definition in bs-pty.ts) — the ConPTY shim kills the root child on SIGTERM
// and the job tree only on the escalated SIGKILL.
const IS_WIN32_HOST = process.platform === "win32";
const TERM_ESCALATION_MS = IS_WIN32_HOST ? WINDOWS_PTY_KILL_GRACE_MS : 1_000;
const READ_BUFFER_BYTES = 64 * 1024;
/**
 * Per scheduler wake (one `tick()`), cap total child→host bytes delivered
 * through `onData`. The 4 ms tick stays load-bearing for exit reap, write
 * drain, and poll ordering; this budget only bounds how long we keep
 * poll→read looping within a single wake so a flood cannot starve the loop.
 */
const TURN_READ_BUDGET_BYTES = 1024 * 1024;
const INT32_MAX = 0x7fffffff;
const UINT32_MAX = 0xffffffff;

const PTY_EINTR = osConstants.errno.EINTR;
const TRANSIENT_READ_ERRORS = new Set([
  PTY_EINTR,
  osConstants.errno.EAGAIN,
  osConstants.errno.EWOULDBLOCK,
]);

/**
 * F4: resolve a signal number from the HOST's own table (`node:os.constants`),
 * never a hard-coded Linux table. Darwin and Linux number signals differently
 * (e.g. SIGIO/SIGPWR/SIGSYS), so a single table serving both OSes is wrong.
 * Returns undefined when the signal does not exist on this host — callers
 * reject it explicitly instead of substituting a foreign number.
 */
const hostSignalNumber = (signal: NodeJS.Signals): number | undefined => {
  const table = osConstants.signals as Record<string, number | undefined>;
  const value = table[signal];
  return typeof value === "number" ? value : undefined;
};
/** Resolve a required signal, failing closed if the host lacks it. */
const requireSignal = (signal: NodeJS.Signals): number => {
  const value = hostSignalNumber(signal);
  if (value === undefined)
    throw new Error(`signal ${signal} is not resolvable on this host`);
  return value;
};
// P3-2 (win32): SIGTERM(15)/SIGKILL(9) exist in Node's Windows signal table
// and match the ConPTY shim's accepted set. SIGHUP also resolves (to 1) on
// Windows, but pty-win.c rejects every signal except TERM/KILL with EINVAL —
// that surfaces as the shim's explicit errno (a logged kill failure), never a
// silent success. Pinned in tests/daemon/windows-pty-seam.test.ts.
const SIGKILL = requireSignal("SIGKILL");
// F5: the shim returns a STABLE lost-child sentinel (PTY_ECHILD = 10) from
// ptyWait when waitpid reports the child was reaped elsewhere. This is the
// shim's own constant, NOT the platform errno (which differs: 10 Linux, 67
// Darwin), so the TS side keys on this one value across both OSes.
const PTY_ECHILD_LOST = 10;

const asError = (value: unknown): Error =>
  value instanceof Error ? value : new Error(String(value));

type TLinuxProcessIdentity = {
  readonly parent: number;
  readonly session: number;
  readonly start: string;
};

type TLinuxSessionMemberIdentity = {
  readonly pid: number;
  readonly session: number;
  readonly start: string;
};

type TSignalPolicy = "forward" | "terminate-gracefully" | "terminate-now";

const linuxProcessIdentity = (pid: number): TLinuxProcessIdentity | null => {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(") ") + 2).split(" ");
    const start = fields[19];
    if (start === undefined) return null;
    return {
      parent: Number(fields[1]),
      session: Number(fields[3]),
      start,
    };
  } catch {
    return null;
  }
};

/** One consistent /proc read of every process on the host. */
const linuxProcessTable = (): Map<number, TLinuxProcessIdentity> => {
  const table = new Map<number, TLinuxProcessIdentity>();
  try {
    for (const name of readdirSync("/proc")) {
      if (!/^[1-9][0-9]*$/.test(name)) continue;
      const pid = Number(name);
      const identity = linuxProcessIdentity(pid);
      if (identity !== null) table.set(pid, identity);
    }
  } catch {
    // /proc can disappear or become unreadable during daemon shutdown.
  }
  return table;
};

/**
 * Snapshot session members that the native child/original/foreground-group
 * signal can miss. The leader birth check proves this is still our session;
 * every later signal also rechecks each member's birth identity so a delayed
 * escalation cannot target a reused PID after the leader has been reaped.
 *
 * Two capture classes, one snapshot (TH-1): processes still in the leader's
 * session, plus every DESCENDANT of the leader tree — a child that detached
 * (setsid / Bun `detached:true` / daemonizers) left the session and would
 * otherwise survive teardown as an orphan under ppid 1. Parentage comes from
 * the same /proc table, so a process reparented before the snapshot is simply
 * not a descendant.
 */
const linuxSessionMembers = (
  leaderPid: number,
  birth: TLinuxProcessIdentity | null,
): TLinuxSessionMemberIdentity[] => {
  if (process.platform !== "linux" || birth === null) return [];
  const table = linuxProcessTable();
  const leader = table.get(leaderPid);
  if (
    birth.parent !== process.pid ||
    leader === undefined ||
    leader.start !== birth.start ||
    leader.session !== leaderPid
  )
    return [];
  const members: TLinuxSessionMemberIdentity[] = [];
  const captured = new Set<number>([leaderPid]);
  const parents = new Set<number>([leaderPid]);
  for (const [pid, member] of table) {
    if (captured.has(pid) || member.session !== leaderPid) continue;
    captured.add(pid);
    parents.add(pid);
    members.push({ pid, session: member.session, start: member.start });
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const [pid, member] of table) {
      if (captured.has(pid) || !parents.has(member.parent)) continue;
      captured.add(pid);
      parents.add(pid);
      members.push({ pid, session: member.session, start: member.start });
      changed = true;
    }
  }
  return members;
};

const signalLinuxSessionMembers = (
  members: readonly TLinuxSessionMemberIdentity[],
  signalNumber: number,
): void => {
  for (const member of members) {
    const current = linuxProcessIdentity(member.pid);
    // The captured start identity is the PID-reuse guard. There is no
    // session re-check on purpose: captured descendants that detached are
    // exactly the members that must be signalled (TH-1).
    if (current?.start !== member.start) continue;
    try {
      process.kill(member.pid, signalNumber);
    } catch {
      // The member exited between the identity check and the signal.
    }
  }
};

type TDarwinSessionMemberIdentity = {
  readonly pid: number;
  readonly start: string;
};

export type TDarwinProcessRow = {
  readonly parent: number;
  readonly start: string;
};

/**
 * Parse `ps -axo pid=,ppid=,lstart=` output into pid → {parent, start}.
 * `start` is normalized through {@link normalizeProcessStartIdentity} — the
 * canonical parser shared with every identity compare (DR-4: BSD `ps` pads
 * days 1–9 with two spaces while a split on whitespace collapses them).
 */
export const parseDarwinProcessTable = (
  stdout: string,
): Map<number, TDarwinProcessRow> => {
  const rows = new Map<number, TDarwinProcessRow>();
  for (const line of stdout.split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 7) continue;
    const pid = Number(fields[0]);
    const parent = Number(fields[1]);
    const start = normalizeProcessStartIdentity(fields.slice(2).join(" "));
    if (
      Number.isInteger(pid) &&
      pid > 0 &&
      Number.isInteger(parent) &&
      start.length > 0
    )
      rows.set(pid, { parent, start });
  }
  return rows;
};

/** Descendants of `leaderPid` in one process-table snapshot (BFS by ppid). */
const darwinCapturedMembers = (
  rows: ReadonlyMap<number, TDarwinProcessRow>,
  leaderPid: number,
  leaderStart: string,
): TDarwinSessionMemberIdentity[] => {
  if (rows.get(leaderPid)?.start !== leaderStart) return [];
  const members: TDarwinSessionMemberIdentity[] = [];
  const parents = new Set([leaderPid]);
  const captured = new Set<number>([leaderPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [pid, row] of rows) {
      if (captured.has(pid) || !parents.has(row.parent)) continue;
      captured.add(pid);
      parents.add(pid);
      members.push({ pid, start: row.start });
      changed = true;
    }
  }
  return members;
};

/**
 * One synchronous `ps -axo pid=,ppid=,lstart=` process-table snapshot, or
 * null when the probe cannot run. The table is taken before the leader is
 * signalled, or children reparent to launchd and the descendant links are
 * gone (DR-8).
 */
const darwinProcessTableSync = (): Map<number, TDarwinProcessRow> | null => {
  if (process.platform !== "darwin") return null;
  const result = spawnSync("ps", ["-axo", "pid=,ppid=,lstart="], {
    encoding: "utf8",
    timeout: 500,
    windowsHide: true,
    env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
  });
  if (result.error || result.status !== 0) return null;
  return parseDarwinProcessTable(result.stdout);
};

/** One async `ps -axo pid=,lstart=` snapshot → pid → normalized start. */
const darwinProcessStartTimes = async (): Promise<Map<
  number,
  string
> | null> => {
  if (process.platform !== "darwin") return null;
  try {
    const proc = admittedSpawn(["ps", "-axo", "pid=,lstart="], {
      stdout: "pipe",
      stderr: "ignore",
      env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        proc.kill();
      } catch {
        // The helper may already have exited.
      }
    }, 1_500);
    try {
      const stdout = await new Response(proc.stdout).text();
      const code = await proc.exited;
      if (timedOut || code !== 0) return null;
      const starts = new Map<number, string>();
      for (const line of stdout.split(/\r?\n/)) {
        const fields = line.trim().split(/\s+/);
        if (fields.length < 6) continue;
        const pid = Number(fields[0]);
        if (!Number.isInteger(pid) || pid <= 0) continue;
        starts.set(
          pid,
          normalizeProcessStartIdentity(fields.slice(1).join(" ")),
        );
      }
      return starts;
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return null;
  }
};

/**
 * Signal captured macOS members — only those whose pid + start identity is
 * revalidated against the process-table snapshot `table`, taken at the top
 * of the same signal pass. A member that exited and had its pid reused is
 * absent (or mismatched) and is skipped; a null table means no member can
 * be verified, so nothing is signalled at all — an unverified pid is never
 * a licence to signal.
 */
export const signalDarwinSessionMembers = (
  members: readonly TDarwinSessionMemberIdentity[],
  signalNumber: number,
  table: ReadonlyMap<number, TDarwinProcessRow> | null,
): void => {
  if (table === null) return;
  for (const member of members) {
    if (table.get(member.pid)?.start !== member.start) continue;
    try {
      process.kill(member.pid, signalNumber);
    } catch {
      // The member exited between its identity check and the signal.
    }
  }
};

/** Bound for one verify-then-signal pass, including a wedged `ps` helper. */
export const DARWIN_KILL_VERIFY_TIMEOUT_MS = 2_000;

type TDarwinStartTableReader = () => Promise<Map<number, string> | null>;

/**
 * Delayed-escalation member signalling (DR-8): a single async `ps` snapshot
 * re-verifies every captured start identity, so a PID reused while the
 * escalation timer was pending is never signalled — and the daemon event
 * loop is never blocked by N synchronous `ps` spawns.
 *
 * Awaitable (DSN-7): resolves once the snapshot and the KILL sweep finish,
 * or when {@link DARWIN_KILL_VERIFY_TIMEOUT_MS} elapses — the PTY's
 * whenTerminated() must not resolve while this sweep is in flight, or a
 * host that exits first strands it.
 */
export const signalDarwinSessionMembersVerified = (
  members: readonly TDarwinSessionMemberIdentity[],
  signalNumber: number,
  readStartTable: TDarwinStartTableReader = darwinProcessStartTimes,
): Promise<void> => {
  if (members.length === 0) return Promise.resolve();
  const sweep = readStartTable()
    .then((starts) => {
      if (starts === null) return;
      for (const member of members) {
        if (starts.get(member.pid) !== member.start) continue;
        try {
          process.kill(member.pid, signalNumber);
        } catch {
          // The member exited between its identity check and the signal.
        }
      }
    })
    .catch(() => {
      // A failed verification signals nothing: it fails closed, never open.
    });
  let timer: ReturnType<typeof setTimeout> | null = null;
  const bounded = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, DARWIN_KILL_VERIFY_TIMEOUT_MS);
  });
  return Promise.race([sweep, bounded]).finally(() => {
    if (timer !== null) clearTimeout(timer);
  });
};

export class NativePtyNativeError extends Error {
  readonly errno: number;
  readonly acceptedBytes: number;

  constructor(operation: string, errno: number, acceptedBytes = 0) {
    super(`${operation} failed: errno=${errno}`);
    this.name = "NativePtyNativeError";
    this.errno = errno;
    this.acceptedBytes = acceptedBytes;
  }
}

export class NativePtyWriteOverflowError extends Error {
  readonly acceptedBytes: number;
  readonly pendingBytes: number;

  constructor(acceptedBytes: number, pendingBytes: number) {
    super(
      `native PTY input queue refused a write: accepted=${acceptedBytes} pending=${pendingBytes}`,
    );
    this.name = "NativePtyWriteOverflowError";
    this.acceptedBytes = acceptedBytes;
    this.pendingBytes = pendingBytes;
  }
}

const assertInt32Length = (length: number): void => {
  if (!Number.isSafeInteger(length) || length < 0 || length > INT32_MAX)
    throw new RangeError(`PTY byte length exceeds INT32_MAX: ${length}`);
};

const assertDimension = (name: string, value: number): void => {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65535)
    throw new RangeError(`${name} must be an integer in 1..65535`);
};

const assertCString = (name: string, value: string): Uint8Array => {
  if (value.includes("\0")) throw new TypeError(`${name} contains NUL`);
  const bytes = new TextEncoder().encode(value);
  const result = new Uint8Array(bytes.byteLength + 1);
  result.set(bytes);
  return result;
};

const absoluteExecutable = (
  executable: string,
  cwd: string,
  environment: Record<string, string>,
): string => {
  // P3-2 (win32): the ConPTY shim validates Windows-absolute paths
  // (drive-letter or UNC) itself, so the TS layer passes argv[0] through
  // unchanged — no POSIX "/" rule or PATH search may leak into the spawn.
  if (IS_WIN32_HOST) return executable;
  if (isAbsolute(executable)) return executable;
  if (executable.includes("/")) return resolve(cwd, executable);
  const pathValue = environment.PATH;
  if (pathValue !== undefined) {
    for (const directory of pathValue.split(delimiter)) {
      // PATH entries may be relative; the child resolves those against its
      // requested cwd, not the daemon's current working directory.
      const candidate = resolve(cwd, directory, executable);
      try {
        accessSync(candidate, fsConstants.X_OK);
        if (statSync(candidate).isFile()) return candidate;
      } catch {
        // Continue PATH search when an entry is missing or not executable.
      }
    }
  }
  throw new Error(`executable not found in PATH: ${executable}`);
};

const argvBlock = (argv: ReadonlyArray<string>): Uint8Array => {
  const encoded = argv.map((arg, index) =>
    assertCString(`argv[${index}]`, arg),
  );
  const bytes = encoded.reduce((total, item) => total + item.byteLength, 0);
  assertInt32Length(bytes);
  const block = new Uint8Array(bytes);
  let offset = 0;
  for (const item of encoded) {
    block.set(item, offset);
    offset += item.byteLength;
  }
  return block;
};

const checkReturn = (operation: string, result: number): number => {
  if (result < 0) throw new NativePtyNativeError(operation, -result);
  return result;
};

export type TNativePtySpawner = (args: TPtySpawnArgs) => Promise<TPtyLike>;

// Every NativePty whose native handle has not settled yet. This includes the
// internal owner NativePty.spawn creates when a launch fails after the child
// exists: the rejected caller never sees that instance, but it still owns a
// child, a handle, and timers until its own teardown settles.
const unsettledPtys = new Set<NativePty>();
// Every NativePty that has not fully terminated: not finished, or finished
// with a TERM→KILL escalation still owed to captured descendants (DSN-7).
// A host process that exits must wait for this set — a process.exit before
// the escalation fires orphans every TERM-ignoring descendant.
const unterminatedPtys = new Set<NativePty>();

/**
 * Waits, at most timeoutMs, until every NativePty that exists at call time
 * has settled its native handle (see NativePty.whenSettled), including
 * post-launch startup failures that never reached the caller. Resolves true
 * when all settled and false on timeout; it never rejects and never waits
 * unbounded, because a PTY that is still running only settles after its
 * session ends. No product path calls this; it exists for teardown checks.
 *
 * Registry lifetime: a product instance is always either unfinished and
 * held by its own scheduler interval or startup timer (spawn → waitForExec
 * → startScheduler/abortStartup; the startup-failure owner →
 * startScheduler), or finished with at most a bounded destroy-retry chain
 * pending (DESTROY_RETRY_LIMIT + 1 attempts, then settled). The registry
 * therefore never keeps alive an instance that its own timers would not.
 */
export const whenAllNativePtysSettled = async (
  timeoutMs: number,
): Promise<boolean> => {
  const pending = [...unsettledPtys].map((pty) => pty.whenSettled());
  if (pending.length === 0) return true;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timedOut = new Promise<false>((resolveTimeout) => {
    timer = setTimeout(() => resolveTimeout(false), timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([
      Promise.all(pending).then(() => true as const),
      timedOut,
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
};

/**
 * Waits, at most timeoutMs, until every NativePty that exists at call time
 * has fully terminated: finished AND with no TERM→KILL escalation still owed
 * to captured descendants (DSN-7). Resolves true when all terminated and
 * false on timeout; never rejects and never waits unbounded. Session hosts
 * await this before process.exit so a vendor tree that traps TERM is
 * SIGKILLed by the escalation instead of orphaned under ppid 1.
 */
export const whenAllNativePtysTerminated = async (
  timeoutMs: number,
): Promise<boolean> => {
  const pending = [...unterminatedPtys].map((pty) => pty.whenTerminated());
  if (pending.length === 0) return true;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timedOut = new Promise<false>((resolveTimeout) => {
    timer = setTimeout(() => resolveTimeout(false), timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([
      Promise.all(pending).then(() => true as const),
      timedOut,
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
};

export class NativePty implements TPtyLike {
  readonly pid: number;

  private readonly readBuffer = new Uint8Array(READ_BUFFER_BYTES);
  private readonly waitExitCode = new Int32Array(1);
  private readonly waitSignal = new Int32Array(1);
  private readonly acceptedBytes = new Uint32Array(1);
  private readonly bindings: TPtyNativeBindings;
  private readonly linuxBirth: TLinuxProcessIdentity | null;
  private darwinBirth: string | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private startupTimer: ReturnType<typeof setTimeout> | null = null;
  private escalationTimer: ReturnType<typeof setTimeout> | null = null;
  /** The one pending Windows destroy retry; null when none is armed. */
  private destroyRetryTimer: ReturnType<typeof setTimeout> | null = null;
  private destroyAttempts = 0;
  private destroySettled = false;
  private readonly settled: Promise<void>;
  private resolveSettled: () => void = () => {};
  private readonly terminated: Promise<void>;
  private resolveTerminated: () => void = () => {};
  private terminationComplete = false;
  private destroyEscalated = false;
  private finished = false;
  private started = false;
  private ioClosed = false;
  private childExited = false;
  private childLost = false;
  private ioFailureHandled = false;
  private outputEof = false;
  private finalDrainDeadline = 0;
  private forcedExitCode: number | null = null;
  private gracefulTerminationRequested = false;
  private linuxTerminationMembers: TLinuxSessionMemberIdentity[] = [];
  private darwinTerminationMembers: TDarwinSessionMemberIdentity[] = [];
  /** In-flight escalated verify-then-KILL sweep; blocks whenTerminated(). */
  private darwinVerification: Promise<void> | null = null;

  private constructor(
    private readonly handle: number,
    bindings: TPtyNativeBindings,
    private readonly args: TPtySpawnArgs,
    pid: number,
  ) {
    this.bindings = bindings;
    this.pid = pid;
    this.linuxBirth =
      process.platform === "linux" ? linuxProcessIdentity(pid) : null;
    this.settled = new Promise<void>((resolve) => {
      this.resolveSettled = resolve;
    });
    this.terminated = new Promise<void>((resolve) => {
      this.resolveTerminated = resolve;
    });
    unsettledPtys.add(this);
    unterminatedPtys.add(this);
  }

  /**
   * Resolves once this PTY's native handle is settled: ptyDestroy succeeded,
   * failed non-retryably, or exhausted its Windows retries (handle retained).
   * After that no destroy retry timer remains armed. onExit alone does not
   * mean this: finish() fires onExit while a destroy retry may still be
   * pending.
   */
  whenSettled(): Promise<void> {
    return this.settled;
  }

  /**
   * Resolves once this PTY is finished AND owes no pending TERM→KILL
   * escalation to captured descendants. Distinct from {@link whenSettled}:
   * the native handle settles at destroy, while a TERM-ignoring descendant
   * may still be waiting on the escalation timer.
   */
  whenTerminated(): Promise<void> {
    return this.terminated;
  }

  private markTerminated(): void {
    if (this.terminationComplete) return;
    if (
      !this.finished ||
      this.escalationTimer !== null ||
      this.darwinVerification !== null
    )
      return;
    this.terminationComplete = true;
    unterminatedPtys.delete(this);
    this.resolveTerminated();
  }

  private markSettled(): void {
    if (this.destroySettled) return;
    this.destroySettled = true;
    this.clearDestroyRetry();
    unsettledPtys.delete(this);
    this.resolveSettled();
  }

  static async spawn(args: TPtySpawnArgs): Promise<NativePty> {
    // Reject malformed keys before the allowlist drops them. An empty key or
    // a key containing "=" or NUL must not disappear into a successful spawn.
    for (const key of Object.keys(args.env)) {
      if (key.length === 0 || key.includes("=") || key.includes("\0"))
        throw new TypeError(`invalid PTY environment key: ${key}`);
    }
    // P3-2: the win32 host compiles the ConPTY shim (pty-win.c) against this
    // exact ABI (see ../../pty-native), so the same spawn path serves both
    // platforms — the platform differences live below, not behind a throw.
    const bindings = loadPtyBindings();
    const handle = checkReturn("ptyCreate", bindings.ptyCreate());
    if (handle <= 0)
      throw new Error(`ptyCreate returned invalid handle: ${handle}`);
    let launched = false;
    try {
      const environment = nativePtyEnv(args.env);
      for (const [key, value] of Object.entries(environment)) {
        if (key.length === 0 || key.includes("=") || key.includes("\0"))
          throw new TypeError(`invalid PTY environment key: ${key}`);
        const keyBuffer = assertCString("environment key", key);
        const valueBuffer = assertCString("environment value", value);
        checkReturn(
          "ptySetEnv",
          bindings.ptySetEnv(
            handle,
            ffiPointer(keyBuffer),
            ffiPointer(valueBuffer),
          ),
        );
      }
      const executableArg = args.argv[0];
      if (executableArg === undefined)
        throw new TypeError("PTY argv cannot be empty");
      // P3-2 (win32): the shim validates the Windows-absolute cwd rule
      // itself (EINVAL from ptySpawn); POSIX keeps the TS-side check so a
      // relative cwd never reaches the shim.
      if (!IS_WIN32_HOST && !isAbsolute(args.cwd))
        throw new TypeError("PTY cwd must be absolute");
      assertDimension("cols", args.cols);
      assertDimension("rows", args.rows);
      const executable = absoluteExecutable(
        executableArg,
        args.cwd,
        environment,
      );
      const executableBuffer = assertCString("executable", executable);
      const cwdBuffer = assertCString("cwd", args.cwd);
      const block = argvBlock(args.argv);
      const pid = checkReturn(
        "ptySpawn",
        bindings.ptySpawn(
          handle,
          ffiPointer(executableBuffer),
          ffiPointer(cwdBuffer),
          ffiPointer(block),
          block.byteLength,
          args.argv.length,
          args.cols,
          args.rows,
        ),
      );
      if (pid <= 0) throw new Error(`ptySpawn returned invalid pid: ${pid}`);
      launched = true;
      const pty = new NativePty(handle, bindings, args, pid);
      await pty.waitForExec();
      return pty;
    } catch (error) {
      if (!launched) {
        let childPid = 0;
        try {
          const candidate = bindings.ptyPid(handle);
          if (candidate > 0) childPid = candidate;
        } catch {
          // Fall through to descriptor cleanup when no child identity is
          // available; the original startup error remains authoritative.
        }
        if (childPid > 0) {
          // ptySpawn may have forked before reporting a parent-side setup
          // failure. Keep a NativePty owner alive to kill, reap, and destroy
          // that child instead of abandoning it with the rejected promise.
          const orphan = new NativePty(handle, bindings, args, childPid);
          orphan.forcedExitCode = 1;
          orphan.sendKill(SIGKILL, "terminate-now");
          orphan.closeIo();
          orphan.startScheduler();
        } else {
          try {
            bindings.ptyClose(handle);
          } catch {
            // The handle may have failed before the PTY was opened.
          }
          try {
            bindings.ptyDestroy(handle);
          } catch {
            // Preserve the original explicit startup failure.
          }
        }
      }
      throw asError(error);
    }
  }

  write(data: Uint8Array | string): void {
    if (this.finished || this.ioClosed) return;
    const bytes =
      typeof data === "string" ? new TextEncoder().encode(data) : data;
    assertInt32Length(bytes.byteLength);
    if (bytes.byteLength === 0) return;
    this.acceptedBytes[0] = 0;
    const result = this.bindings.ptyWrite(
      this.handle,
      ffiPointer(bytes),
      bytes.byteLength,
      ffiPointer(this.acceptedBytes),
    );
    const accepted = this.acceptedBytes[0] ?? 0;
    const pending = this.pendingBytes();
    if (result < 0)
      throw new NativePtyNativeError("ptyWrite", -result, accepted);
    if (result === 0 || accepted !== bytes.byteLength)
      throw new NativePtyWriteOverflowError(accepted, pending);
  }

  resize(cols: number, rows: number): void {
    if (this.finished || this.ioClosed) return;
    assertDimension("cols", cols);
    assertDimension("rows", rows);
    const result = this.bindings.ptyResize(this.handle, cols, rows);
    if (result < 0) {
      // A2: a viewport frame can arrive after the child has exited; the
      // slave side is gone, so TIOCSWINSZ fails with EIO/EBADF. That is not a
      // session error — log and no-op instead of throwing into the mux.
      if (this.childExited || this.childLost) {
        logWarn(
          "session",
          `native PTY resize no-op after exit: errno=${-result}`,
        );
        return;
      }
      throw new NativePtyNativeError("ptyResize", -result);
    }
  }

  kill(signal: NodeJS.Signals = "SIGTERM"): void {
    if (this.finished) return;
    const signalNumber = hostSignalNumber(signal);
    if (signalNumber === undefined)
      throw new TypeError(`unsupported signal for native PTY: ${signal}`);
    if (signal === "SIGKILL") {
      this.sendKill(signalNumber, "terminate-now");
      this.closeIo();
      return;
    }
    if (signal === "SIGTERM" || signal === "SIGHUP") {
      this.gracefulTerminationRequested = true;
      this.sendKill(signalNumber, "terminate-gracefully");
      if (this.escalationTimer === null) {
        this.escalationTimer = setTimeout(() => {
          this.escalationTimer = null;
          if (!this.finished && !this.childExited) {
            this.sendKill(SIGKILL, "terminate-now");
            this.closeIo();
          } else {
            // The leader may exit before a stubborn background group. Its
            // captured identities remain safe to signal after ptyDestroy.
            this.signalTrackedLinuxSessionMembers(SIGKILL);
            this.linuxTerminationMembers = [];
            const members = this.darwinTerminationMembers;
            this.darwinTerminationMembers = [];
            // The verify-then-KILL sweep must finish (or hit its bound)
            // before this PTY reports terminated — a host that exits first
            // would strand the ps snapshot and the kills that depend on it.
            const verification = signalDarwinSessionMembersVerified(
              members,
              SIGKILL,
            );
            this.darwinVerification = verification;
            void verification.finally(() => {
              if (this.darwinVerification === verification)
                this.darwinVerification = null;
              this.markTerminated();
            });
          }
          this.markTerminated();
        }, TERM_ESCALATION_MS);
      }
      return;
    }
    this.sendKill(signalNumber, "forward");
  }

  private pendingBytes(): number {
    const pending = this.bindings.ptyPendingBytes(this.handle);
    if (pending < 0)
      throw new NativePtyNativeError("ptyPendingBytes", -pending);
    return pending;
  }

  private rememberLinuxSessionMembers(): void {
    const remembered = new Map(
      this.linuxTerminationMembers.map((member) => [member.pid, member]),
    );
    for (const member of linuxSessionMembers(this.pid, this.linuxBirth))
      remembered.set(member.pid, member);
    this.linuxTerminationMembers = [...remembered.values()];
  }

  /**
   * Refresh the captured macOS member set from one process-table snapshot
   * and return that snapshot: the SAME table revalidates every retained
   * member before each signal in this pass (pid + canonical start — a pid
   * reused since capture is never signalled). Retained members absent from
   * the table have exited and are dropped. Returns null when the snapshot
   * cannot run or no birth identity exists — the caller then signals
   * nothing on this OS.
   */
  private rememberDarwinSessionMembers(): ReadonlyMap<
    number,
    TDarwinProcessRow
  > | null {
    if (process.platform !== "darwin" || this.darwinBirth === null) return null;
    const rows = darwinProcessTableSync();
    if (rows === null) return null;
    const remembered = new Map(
      this.darwinTerminationMembers
        // Presence alone is not identity: a pid still in the table but with
        // a different start was reused since capture — drop it so it can
        // never be signalled, here or by the escalated sweep.
        .filter((member) => rows.get(member.pid)?.start === member.start)
        .map((member) => [member.pid, member]),
    );
    for (const member of darwinCapturedMembers(
      rows,
      this.pid,
      normalizeProcessStartIdentity(this.darwinBirth),
    ))
      remembered.set(member.pid, member);
    this.darwinTerminationMembers = [...remembered.values()];
    return rows;
  }

  private signalTrackedLinuxSessionMembers(signalNumber: number): void {
    signalLinuxSessionMembers(this.linuxTerminationMembers, signalNumber);
  }

  private sendKill(signalNumber: number, policy: TSignalPolicy): void {
    // Forward-only signals (STOP/CONT/WINCH/application signals) target the
    // native child/original/foreground groups and never trigger tree cleanup.
    // TERM/HUP first reach every verified Linux session member gracefully;
    // SIGKILL and hard-failure teardown remove the same tree immediately.
    if (policy !== "forward") this.rememberLinuxSessionMembers();
    // One snapshot both captures new members and revalidates retained ones:
    // every member signal below is checked against it immediately before
    // the kill, so a pid reused since capture is never signalled.
    const darwinTable =
      policy === "forward" ? null : this.rememberDarwinSessionMembers();

    // F5: never ask the native handle to signal a possibly reused leader PID
    // once child ownership is lost. Captured Linux member identities remain
    // safe because every individual PID is birth-checked again below.
    if (!this.childLost) {
      const result = this.bindings.ptyKill(
        this.handle,
        signalNumber,
        TTY_TARGETS,
      );
      if (result < 0 && !this.childExited)
        logWarn("session", `native PTY kill failed: errno=${-result}`);
    }

    if (policy === "terminate-gracefully")
      this.signalTrackedLinuxSessionMembers(signalNumber);
    if (policy === "terminate-gracefully")
      signalDarwinSessionMembers(
        this.darwinTerminationMembers,
        signalNumber,
        darwinTable,
      );
    if (policy === "terminate-now") {
      this.signalTrackedLinuxSessionMembers(SIGKILL);
      this.linuxTerminationMembers = [];
      signalDarwinSessionMembers(
        this.darwinTerminationMembers,
        SIGKILL,
        darwinTable,
      );
      this.darwinTerminationMembers = [];
    }
  }

  private closeIo(): void {
    if (this.ioClosed) return;
    this.ioClosed = true;
    try {
      const result = this.bindings.ptyClose(this.handle);
      if (result < 0)
        logWarn("session", `native PTY close failed: errno=${-result}`);
    } catch (error) {
      logWarn("session", `native PTY close failed: ${asError(error).message}`);
    }
  }

  private waitForExec(): Promise<void> {
    return new Promise<void>((resolvePromise, rejectPromise) => {
      const deadline = Date.now() + STARTUP_DEADLINE_MS;
      const check = (): void => {
        if (this.finished) {
          rejectPromise(new Error("native PTY ended during startup"));
          return;
        }
        try {
          const status = this.bindings.ptySpawnStatus(this.handle);
          if (status === 1) {
            // A child that fails before the ready handshake has no live PTY
            // session to protect. In particular, do not probe its PID on
            // Darwin: the startup error is authoritative and the child may
            // already be gone. Once ready, retain the birth identity used to
            // guard descendant signaling against PID reuse.
            if (process.platform === "darwin")
              this.darwinBirth = processStartIdentity(this.pid) ?? null;
            this.started = true;
            this.startScheduler();
            resolvePromise();
            return;
          }
          if (status < 0) {
            const error = new NativePtyNativeError("ptySpawnStatus", -status);
            rejectPromise(error);
            this.abortStartup();
            return;
          }
          if (Date.now() >= deadline) {
            const error = new Error(
              "native PTY startup timed out after 12000ms",
            );
            rejectPromise(error);
            this.abortStartup();
            return;
          }
          this.startupTimer = setTimeout(check, TICK_MS);
        } catch (error) {
          rejectPromise(asError(error));
          this.abortStartup();
        }
      };
      check();
    });
  }

  private abortStartup(): void {
    if (this.startupTimer !== null) clearTimeout(this.startupTimer);
    this.startupTimer = null;
    this.forcedExitCode = 1;
    this.sendKill(SIGKILL, "terminate-now");
    this.closeIo();
    this.startScheduler();
  }

  private startScheduler(): void {
    if (this.timer !== null) return;
    this.tick();
    if (!this.finished) this.timer = setInterval(this.tick, TICK_MS);
  }

  private tick = (): void => {
    if (this.finished) return;
    try {
      if (!this.ioClosed) {
        const interests =
          POLL_READABLE | (this.pendingBytes() > 0 ? POLL_WRITABLE : 0);
        const events = this.bindings.ptyPoll(this.handle, interests);
        if (events < 0) {
          // F5: poll(2) can be interrupted by a signal. Retry on the next
          // scheduler tick without turning a live child into an I/O failure.
          if (TRANSIENT_READ_ERRORS.has(-events)) return;
          throw new NativePtyNativeError("ptyPoll", -events);
        }
        if ((events & POLL_WRITABLE) !== 0) {
          const drained = this.bindings.ptyDrain(this.handle);
          if (drained < 0) throw new NativePtyNativeError("ptyDrain", -drained);
        }
        if ((events & (POLL_READABLE | POLL_HANGUP | POLL_ERROR)) !== 0)
          this.readAvailable(false);
      } else if (this.childExited) {
        this.finish(this.forcedExitCode ?? this.waitExitCode[0] ?? 1);
        return;
      }
      this.reconcileExit();
      if (
        this.childExited &&
        !this.ioClosed &&
        Date.now() >= this.finalDrainDeadline
      ) {
        logWarn(
          "session",
          "native PTY final output drain truncated after 1000ms",
        );
        this.finish(this.forcedExitCode ?? this.waitExitCode[0] ?? 1);
      }
    } catch (error) {
      this.handleIoFailure(asError(error));
    }
  };

  private readAvailable(force: boolean): void {
    let readBytes = 0;
    // A transient read error (EAGAIN after a readiness race) ends this turn:
    // re-polling immediately would spin the event loop at 100% CPU. The next
    // scheduler tick is the backoff.
    let yieldTurn = false;
    while (readBytes < TURN_READ_BUDGET_BYTES && !this.finished) {
      const events = this.bindings.ptyPoll(this.handle, POLL_READABLE);
      if (events < 0) {
        if (TRANSIENT_READ_ERRORS.has(-events)) break;
        throw new NativePtyNativeError("ptyPoll", -events);
      }
      const hasReadInterest =
        (events & (POLL_READABLE | POLL_HANGUP | POLL_ERROR)) !== 0;
      if (!hasReadInterest) {
        // Post-exit drain: poll may be idle while the master still returns EOF.
        if (force && readBytes === 0) {
          /* fall through to one read attempt */
        } else {
          break;
        }
      }

      while (readBytes < TURN_READ_BUDGET_BYTES && !this.finished) {
        const result = this.bindings.ptyRead(
          this.handle,
          ffiPointer(this.readBuffer),
          READ_BUFFER_BYTES,
        );
        if (result > 0) {
          readBytes += result;
          const chunk = this.readBuffer.slice(0, result);
          if (!this.finished) this.args.onData(chunk);
          continue;
        }
        if (result === 0) {
          this.outputEof = true;
          break;
        }
        if (TRANSIENT_READ_ERRORS.has(-result)) {
          yieldTurn = true;
          break;
        }
        throw new NativePtyNativeError("ptyRead", -result);
      }
      if (this.outputEof || yieldTurn) break;
    }
    if (force && this.outputEof)
      this.finish(this.forcedExitCode ?? this.waitExitCode[0] ?? 1);
  }

  private reconcileExit(): void {
    if (this.childExited) {
      if (!this.ioClosed) this.readAvailable(true);
      if (this.outputEof || this.ioClosed) {
        this.finish(this.forcedExitCode ?? this.waitExitCode[0] ?? 1);
      }
      return;
    }
    const waited = this.bindings.ptyWait(
      this.handle,
      ffiPointer(this.waitExitCode),
      ffiPointer(this.waitSignal),
    );
    if (waited < 0) {
      if (-waited === PTY_EINTR) return;
      if (-waited === PTY_ECHILD_LOST) {
        // F5: lost child ownership (reaped elsewhere). Terminal state with a
        // forced exit code — close I/O, stop timers, deliver onExit exactly
        // once. The C handle is marked lost, so ptyDestroy is permitted and
        // any later ptyKill is rejected (no signaling a possibly reused PID).
        this.childLost = true;
        this.childExited = true;
        this.forcedExitCode = 1;
        this.closeIo();
        this.finish(1);
        return;
      }
      throw new NativePtyNativeError("ptyWait", -waited);
    }
    if (waited !== 1) return;
    this.childExited = true;
    this.finalDrainDeadline =
      Date.now() +
      (this.gracefulTerminationRequested
        ? GRACEFUL_FINAL_DRAIN_MS
        : FINAL_DRAIN_DEADLINE_MS);
    if (this.ioClosed || this.outputEof)
      this.finish(this.forcedExitCode ?? this.waitExitCode[0] ?? 1);
  }

  private handleIoFailure(error: Error): void {
    if (this.finished || this.ioFailureHandled) return;
    // F5: one-shot hard-I/O failure handling — one diagnostic, one termination
    // request, one close sequence. A live child is never falsely declared
    // exited merely because an error counter reached a limit; EINTR-class
    // transient errors are filtered upstream (TRANSIENT_READ_ERRORS).
    this.ioFailureHandled = true;
    this.forcedExitCode = 1;
    logWarn("session", `native PTY I/O failure: ${error.message}`);
    if (!this.childLost) this.sendKill(SIGKILL, "terminate-now");
    this.closeIo();
  }

  private finish(exitCode: number): void {
    if (this.finished) return;
    this.finished = true;
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
    if (this.startupTimer !== null) clearTimeout(this.startupTimer);
    this.startupTimer = null;
    // Retire the pending TERM→KILL escalation only when NOTHING captured
    // remains. Checking only the Linux list used to cancel the timer on
    // macOS (its linux list is always empty), so TERM-ignoring darwin
    // descendants were never escalated to SIGKILL.
    if (
      this.escalationTimer !== null &&
      this.linuxTerminationMembers.length === 0 &&
      this.darwinTerminationMembers.length === 0
    ) {
      clearTimeout(this.escalationTimer);
      this.escalationTimer = null;
    }
    this.markTerminated();
    this.closeIo();
    this.tryDestroy();
    if (!this.started) return;
    try {
      this.args.onExit(exitCode);
    } catch (error) {
      logWarn(
        "session",
        `native PTY exit callback failed: ${asError(error).message}`,
      );
    }
  }

  /** Retry transient Windows reap/cancellation races without blocking Bun. */
  private tryDestroy(): void {
    this.attemptDestroy();
    // An attempt that armed no retry is final: success, a non-retryable
    // failure, or exhausted retries with the handle deliberately retained.
    if (this.destroyRetryTimer === null) this.markSettled();
  }

  private attemptDestroy(): void {
    // A direct attempt supersedes any armed retry, so at most one retry timer
    // exists per handle and none survives the attempt that settles it.
    this.clearDestroyRetry();
    this.destroyAttempts += 1;
    let result: number;
    try {
      result = this.bindings.ptyDestroy(this.handle);
    } catch (error) {
      logWarn(
        "session",
        `native PTY destroy failed: ${asError(error).message}`,
      );
      return;
    }
    if (result === 0) return;

    const errno = -result;
    if (
      !IS_WIN32_HOST ||
      (errno !== osConstants.errno.EBUSY && errno !== osConstants.errno.EIO)
    ) {
      logWarn("session", `native PTY destroy failed: errno=${errno}`);
      return;
    }
    if (this.destroyAttempts >= DESTROY_RETRY_LIMIT && !this.destroyEscalated) {
      this.destroyEscalated = true;
      try {
        const killResult = this.bindings.ptyKill(
          this.handle,
          SIGKILL,
          TTY_TARGETS,
        );
        if (killResult < 0 && killResult !== -osConstants.errno.ECHILD) {
          logWarn(
            "session",
            `native PTY cleanup kill failed: errno=${-killResult}`,
          );
        }
      } catch (error) {
        logWarn(
          "session",
          `native PTY cleanup kill failed: ${asError(error).message}`,
        );
      }
      this.scheduleDestroyRetry(
        DESTROY_RETRY_DELAYS_MS[DESTROY_RETRY_DELAYS_MS.length - 1],
      );
      return;
    }
    if (this.destroyAttempts > DESTROY_RETRY_LIMIT) {
      logWarn(
        "session",
        `native PTY destroy retries exhausted: errno=${errno}; retaining native handle until process exit to protect pending I/O storage`,
      );
      return;
    }

    const delay =
      DESTROY_RETRY_DELAYS_MS[
        Math.min(this.destroyAttempts - 1, DESTROY_RETRY_DELAYS_MS.length - 1)
      ];
    if (delay === undefined) return;
    this.scheduleDestroyRetry(delay);
  }

  private scheduleDestroyRetry(delay: number): void {
    if (this.destroyRetryTimer !== null) return;
    this.destroyRetryTimer = setTimeout(() => {
      this.destroyRetryTimer = null;
      this.tryDestroy();
    }, delay);
  }

  private clearDestroyRetry(): void {
    if (this.destroyRetryTimer === null) return;
    clearTimeout(this.destroyRetryTimer);
    this.destroyRetryTimer = null;
  }
}

export const nativePtySpawner: TNativePtySpawner = (args) =>
  NativePty.spawn(args);

export const nativePtyConstants = {
  startupDeadlineMs: STARTUP_DEADLINE_MS,
  tickMs: TICK_MS,
  termEscalationMs: TERM_ESCALATION_MS,
  readBufferBytes: READ_BUFFER_BYTES,
  turnReadBudgetBytes: TURN_READ_BUDGET_BYTES,
  int32Max: INT32_MAX,
  uint32Max: UINT32_MAX,
} as const;
