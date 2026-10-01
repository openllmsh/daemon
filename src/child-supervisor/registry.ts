import { createHash } from "node:crypto";
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  legacyProcessStartIdentity,
  processIdentityStatus,
  processStartIdentity,
} from "../../../tunnel/session/local-runtime";
import { createDeadlineBudget, firstOfBudget } from "../deadline-budget";
import { stateDir } from "../env";
import { logDebug } from "../logger";
import {
  spawn as admittedSpawn,
  spawnSync as admittedSpawnSync,
} from "../windows-process";
import { processGroupExists, signalGroup } from "./posix";

export type TDisposableChildKind =
  | "probe"
  | "vendor-capture"
  | "mcp-helper"
  | "login"
  | "native-runtime";

export type TChildRegistryRecord = {
  readonly instanceId: string;
  readonly kind: TDisposableChildKind;
  readonly pid: number;
  readonly pgid: number;
  readonly processStartTime: string;
  readonly argvDigest: string;
  readonly startedAtMs: number;
};

const childrenDir = (): string => join(stateDir(), "children");

const recordPath = (pid: number): string => join(childrenDir(), `${pid}.json`);

const isKind = (value: unknown): value is TDisposableChildKind =>
  value === "probe" ||
  value === "vendor-capture" ||
  value === "mcp-helper" ||
  value === "login" ||
  value === "native-runtime";

const isRecord = (value: unknown): value is TChildRegistryRecord => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.instanceId === "string" &&
    record.instanceId.length > 0 &&
    isKind(record.kind) &&
    typeof record.pid === "number" &&
    Number.isInteger(record.pid) &&
    record.pid > 0 &&
    typeof record.pgid === "number" &&
    Number.isInteger(record.pgid) &&
    record.pgid > 0 &&
    typeof record.processStartTime === "string" &&
    record.processStartTime.length > 0 &&
    typeof record.argvDigest === "string" &&
    /^[a-f0-9]{64}$/.test(record.argvDigest) &&
    typeof record.startedAtMs === "number" &&
    Number.isFinite(record.startedAtMs)
  );
};

/**
 * `ps -o lstart=` follows LC_TIME and TZ. Installer writes and daemon reads
 * must share one pin or a live worker looks PID-reused. Keep sync + async
 * helpers on the same env.
 */
const processStartTimePsEnv = (): NodeJS.ProcessEnv => ({
  ...process.env,
  LC_ALL: "C",
  LANG: "C",
  TZ: "UTC",
});

/**
 * darwin start identity through the daemon's ADMITTED spawn path (the same
 * `ps -o lstart=` probe as before XS-2). The shared local-runtime reader runs
 * `ps` through node:child_process, which bypasses the admission seam and the
 * loader-boundary allowlist; the macmini PTY suite caught that regression.
 */
/** ESRCH from kill(pid, 0) proves the pid is gone; anything else is unknown. */
const livenessFallback = (pid: number): null | undefined => {
  try {
    process.kill(pid, 0);
    return undefined;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH" ? null : undefined;
  }
};

const darwinPsStartTime = (pid: number): string | null | undefined => {
  try {
    const output = admittedSpawnSync(
      ["ps", "-o", "lstart=", "-p", String(pid)],
      {
        stdout: "pipe",
        stderr: "ignore",
        env: processStartTimePsEnv(),
        // A stalled ps must not block the daemon (review P2): same bound as
        // the shared reader. A timeout gives a null exit code → "unknown".
        timeout: 1500,
      },
    );
    if (output.exitCode !== 0) return livenessFallback(pid);
    const value = new TextDecoder().decode(output.stdout).trim();
    return value.length > 0 ? value : undefined;
  } catch {
    // ps could not start at all (e.g. not on PATH): still prove a dead pid
    // dead instead of reporting every record as unknown (review P2).
    return livenessFallback(pid);
  }
};

/**
 * Start identity for new records. Linux: the shared in-process /proc
 * identity (XS-2, no subprocess). darwin: the admitted `ps` probe. Windows:
 * the shared identity.
 */
export const processStartTime = (pid: number): string | null | undefined =>
  process.platform === "darwin"
    ? darwinPsStartTime(pid)
    : processStartIdentity(pid);

export const childProcessIdentityStatus = (
  record: TChildRegistryRecord,
): "alive" | "dead" | "unknown" =>
  process.platform === "darwin"
    ? processIdentityStatus(
        record.pid,
        record.processStartTime,
        darwinPsStartTime,
        darwinPsStartTime,
      )
    : processIdentityStatus(
        record.pid,
        record.processStartTime,
        processStartIdentity,
        legacyProcessStartIdentity,
      );

/**
 * Named budget for the async `ps -o lstart=` helper. Failure to obtain
 * identity returns null; it must not drop in-memory tracking.
 */
export const PROCESS_START_TIME_HELPER_TIMEOUT_MS = 400;
/** After the named budget expires, wait this long for SIGTERM before SIGKILL. */
export const PROCESS_START_TIME_HELPER_KILL_WAIT_MS = 50;

type TProcessStartTimeHelperSpawn = (
  pid: number,
) => ReturnType<typeof Bun.spawn>;

let processStartTimeHelperSpawnForTests: TProcessStartTimeHelperSpawn | null =
  null;

/**
 * Test-only: replace the `ps` helper spawn. Production kill/read path still
 * runs. Do not use {@link superviseSpawn} here — that would recurse identity
 * lookup.
 */
export const setProcessStartTimeHelperSpawnForTests = (
  spawn: TProcessStartTimeHelperSpawn | null,
): void => {
  processStartTimeHelperSpawnForTests = spawn;
};

const defaultProcessStartTimeHelperSpawn: TProcessStartTimeHelperSpawn = (
  pid,
) =>
  admittedSpawn(["ps", "-o", "lstart=", "-p", String(pid)], {
    stdout: "pipe",
    stderr: "ignore",
    env: processStartTimePsEnv(),
    // Own process group so reap can SIGKILL descendants without touching
    // the daemon group. Test fakes must also set detached: true.
    detached: true,
  });

const closeHelperStdout = (proc: ReturnType<typeof Bun.spawn>): void => {
  const stdout = proc.stdout;
  if (stdout === undefined || typeof stdout === "number") return;
  try {
    void stdout.cancel().catch(() => {
      // Locked by the in-flight Response reader, or already closed.
    });
  } catch {
    // Already closed.
  }
};

const reapStartTimeHelper = async (
  proc: ReturnType<typeof Bun.spawn>,
): Promise<void> => {
  closeHelperStdout(proc);
  const pgid = proc.pid;
  // Detached helper is group leader (pgid === pid). Never signalGroup(0/1).
  signalGroup(pgid, "SIGTERM");
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    await Promise.race([
      proc.exited.then(() => undefined),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, PROCESS_START_TIME_HELPER_KILL_WAIT_MS);
      }),
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
  if (processGroupExists(pgid)) signalGroup(pgid, "SIGKILL");
};

/**
 * Read Linux and Windows identities without a subprocess.
 * On macOS, use an async ps helper with a time limit.
 * A failed read returns null. It does not prove that the child has exited.
 */
export const readProcessStartTime = async (
  pid: number,
): Promise<string | null> => {
  if (process.platform === "win32") {
    return processStartIdentity(pid) ?? null;
  }
  // An injected helper lets Linux tests exercise the macOS timeout path.
  if (
    process.platform === "linux" &&
    processStartTimeHelperSpawnForTests === null
  ) {
    return processStartIdentity(pid) ?? null;
  }
  // Owner-created helper budget — never a shared login/logout budget.
  // firstOfBudget only detaches its waiter; this finally releases the helper.
  const budget = createDeadlineBudget(PROCESS_START_TIME_HELPER_TIMEOUT_MS);
  const spawn =
    processStartTimeHelperSpawnForTests ?? defaultProcessStartTimeHelperSpawn;
  let proc: ReturnType<typeof Bun.spawn> | null = null;
  try {
    proc = spawn(pid);
    const stdout = proc.stdout;
    const read =
      stdout === undefined || typeof stdout === "number"
        ? Promise.resolve({ out: "", code: 1 })
        : Promise.all([new Response(stdout).text(), proc.exited]).then(
            ([out, code]) => ({ out, code }),
          );
    const raced = await firstOfBudget(budget, read);
    if (raced.kind === "expired") {
      await reapStartTimeHelper(proc);
      return null;
    }
    if (raced.value.code !== 0) return null;
    const value = raced.value.out.trim();
    return value.length > 0 ? value : null;
  } catch {
    if (proc !== null) await reapStartTimeHelper(proc);
    return null;
  } finally {
    budget.release();
  }
};

// The boot process must be distinguishable even on a platform where its
// creation timestamp cannot be read. The random-like startup timestamp is
// intentionally process-local rather than durable state.
const daemonInstanceId = `${process.pid}:${processStartTime(process.pid) ?? String(Date.now())}`;

export const currentDaemonInstanceId = (): string => daemonInstanceId;

export const currentChildSupervisorInstanceId = (): string => daemonInstanceId;

export const argvDigest = (argv: ReadonlyArray<string>): string =>
  createHash("sha256").update(JSON.stringify(argv)).digest("hex");

export const addChildRegistryRecord = (record: TChildRegistryRecord): void => {
  const directory = childrenDir();
  const target = recordPath(record.pid);
  const temporary = join(directory, `.${record.pid}.${process.pid}.tmp`);
  try {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    writeFileSync(temporary, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    renameSync(temporary, target);
  } catch (error) {
    logDebug("child-supervisor", "failed to persist child registry record", {
      pid: record.pid,
      kind: record.kind,
      error: error instanceof Error ? error.message : String(error),
    });
    try {
      rmSync(temporary, { force: true });
    } catch {
      // Best-effort registry cleanup.
    }
  }
};

export const removeChildRegistryRecord = (pid: number): void => {
  try {
    rmSync(recordPath(pid), { force: true });
  } catch {
    // A concurrent reaper or an already-exited child may own cleanup.
  }
};

export const listChildRegistryRecords = (): readonly TChildRegistryRecord[] => {
  let entries: string[];
  try {
    entries = readdirSync(childrenDir());
  } catch {
    return [];
  }
  const records: TChildRegistryRecord[] = [];
  for (const entry of entries) {
    if (!/^\d+\.json$/.test(entry)) continue;
    try {
      const parsed: unknown = JSON.parse(
        readFileSync(join(childrenDir(), entry), "utf8"),
      );
      if (isRecord(parsed)) records.push(parsed);
      else rmSync(join(childrenDir(), entry), { force: true });
    } catch {
      try {
        rmSync(join(childrenDir(), entry), { force: true });
      } catch {
        // Retry an unreadable record at the next boot.
      }
    }
  }
  return records;
};

export const childProcessMatchesRecord = (
  record: TChildRegistryRecord,
): boolean => childProcessIdentityStatus(record) === "alive";
