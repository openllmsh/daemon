import { linuxPdeathsigArgv } from "./linux-pdeathsig";
import { DEFAULT_TERMINATE_GRACE_MS, terminateProcessGroup } from "./posix";
import type { TChildRegistryRecord, TDisposableChildKind } from "./registry";
import {
  addChildRegistryRecord,
  argvDigest,
  childProcessMatchesRecord,
  currentChildSupervisorInstanceId,
  listChildRegistryRecords,
  processStartTime,
  removeChildRegistryRecord,
} from "./registry";
import { daemonSelfInvocation } from "./self-exec";

export type TSuperviseSpawnOptions = Omit<
  Bun.SpawnOptions.SpawnOptions<
    Bun.SpawnOptions.Writable,
    Bun.SpawnOptions.Readable,
    Bun.SpawnOptions.Readable
  >,
  "detached" | "onExit"
> & {
  readonly kind: TDisposableChildKind;
};

export type TTerminateOptions = {
  readonly graceMs?: number;
};

export type TSupervisedChild = {
  readonly subprocess: ReturnType<typeof Bun.spawn>;
  readonly pid: number;
  readonly pgid: number;
  readonly terminate: (opts?: TTerminateOptions) => Promise<void>;
  readonly beginTask: () => () => void;
};

type TTrackedChild = {
  readonly handle: TSupervisedChild;
  terminating: Promise<void> | null;
  activeTasks: number;
};

const trackedChildren = new Map<number, TTrackedChild>();

const exited = async (child: TSupervisedChild): Promise<void> => {
  try {
    await child.subprocess.exited;
  } catch {
    // Bun exposes exit status through the subprocess even for signal exits.
  }
};

const finishTrackedChild = async (child: TSupervisedChild): Promise<void> => {
  await exited(child);
  // A disposable root can exit while a forked descendant still owns stdout or
  // stderr. Its subprocess has exited, but its detached process group remains
  // alive and would otherwise evade a later timeout reaper after this handle is
  // removed. Reap the remaining group before forgetting its ownership record.
  await terminateProcessGroup(child.pgid, 0);
  removeChildRegistryRecord(child.pid);
  trackedChildren.delete(child.pid);
};

const waitForTrackedExit = async (
  tracked: TTrackedChild,
  graceMs: number,
): Promise<void> => {
  const outcome = await Promise.race([
    exited(tracked.handle).then(() => "exited" as const),
    new Promise<"grace">((resolve) =>
      setTimeout(() => resolve("grace"), graceMs),
    ),
  ]);
  if (outcome === "exited") return;
  await terminateProcessGroup(tracked.handle.pgid, 0);
  await exited(tracked.handle);
};

const signalProcessGroup = (pgid: number, signal: NodeJS.Signals): void => {
  try {
    process.kill(-pgid, signal);
  } catch (error) {
    // ESRCH (already gone) and EPERM (pgid recycled to a foreign process we
    // neither own nor may signal) both mean "stop" — never crash the reaper.
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ESRCH" || code === "EPERM") return;
    throw error;
  }
};

const sleep = (ms: number): Promise<void> =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

const processAlive = (record: TChildRegistryRecord): boolean =>
  childProcessMatchesRecord(record);

const terminateTrackedChild = (
  tracked: TTrackedChild,
  opts: TTerminateOptions,
): Promise<void> => {
  if (tracked.terminating !== null) return tracked.terminating;
  const graceMs = opts.graceMs ?? DEFAULT_TERMINATE_GRACE_MS;
  tracked.terminating = (async (): Promise<void> => {
    signalProcessGroup(tracked.handle.pgid, "SIGTERM");
    await waitForTrackedExit(tracked, Math.max(0, graceMs));
    await finishTrackedChild(tracked.handle);
  })();
  return tracked.terminating;
};

const activeTaskRelease = (tracked: TTrackedChild): (() => void) => {
  let released = false;
  return (): void => {
    if (released) return;
    released = true;
    if (tracked.activeTasks > 0) tracked.activeTasks -= 1;
    else tracked.activeTasks = 0;
  };
};

/**
 * Spawn one disposable child in an independently killable group and track its
 * root record. This supervisor deliberately excludes durable session hosts.
 * macOS has no PDEATHSIG; launchd shutdown plus process-group cleanup owns it.
 */
export const superviseSpawn = (
  argv: ReadonlyArray<string>,
  opts: TSuperviseSpawnOptions,
): TSupervisedChild => {
  if (argv.length === 0 || argv[0] === undefined || argv[0].length === 0)
    throw new Error("superviseSpawn requires a command");
  // Linux hard-crash guarantee: re-exec through the PDEATHSIG wrapper so the
  // child dies if the daemon is SIGKILLed (no macOS equivalent — Darwin relies
  // on the process group + launchd cleanup + the boot sweep). Darwin argv is
  // left byte-identical.
  const spawnArgv =
    process.platform === "linux"
      ? linuxPdeathsigArgv(argv, daemonSelfInvocation(), process.pid)
      : argv;
  const subprocess = Bun.spawn([...spawnArgv], {
    ...opts,
    // POSIX: lead an independently killable process group (pgid === pid).
    detached: true,
  });
  const pid = subprocess.pid;
  const pgid = pid;
  // A short probe (`--version`) can exit within milliseconds — before
  // `ps -o lstart=` can read its start time. A null identity therefore means
  // "already exiting", NOT a spawn failure: DON'T kill it (its stdout is still
  // the valid capture) and DON'T throw. We still return a working handle and
  // track it in-memory so terminate()/terminateAllDisposable() can group-kill a
  // descendant that outlived it this session; we just skip the PERSISTENT
  // registry record, because a boot sweep needs a verifiable identity and an
  // already-exited process is never a cross-restart orphan.
  const startTime = processStartTime(pid);
  let handle: TSupervisedChild;
  let tracked: TTrackedChild;
  const beginTask = (): (() => void) => {
    tracked.activeTasks += 1;
    return activeTaskRelease(tracked);
  };
  handle = {
    subprocess,
    pid,
    pgid,
    terminate: (terminateOptions?: TTerminateOptions): Promise<void> =>
      terminate(handle, terminateOptions),
    beginTask,
  };
  tracked = { handle, terminating: null, activeTasks: 0 };
  trackedChildren.set(pid, tracked);
  if (startTime !== null)
    addChildRegistryRecord({
      instanceId: currentChildSupervisorInstanceId(),
      kind: opts.kind,
      pid,
      pgid,
      processStartTime: startTime,
      argvDigest: argvDigest(argv),
      startedAtMs: Date.now(),
    });
  void finishTrackedChild(handle);
  return handle;
};

const isIdleTrackedChild = (tracked: TTrackedChild): boolean =>
  tracked.activeTasks === 0;

/** Idempotently stop one disposable child and remove its registry record. */
export const terminate = async (
  handle: TSupervisedChild,
  opts: TTerminateOptions = {},
): Promise<void> => {
  const tracked = trackedChildren.get(handle.pid);
  if (tracked === undefined) {
    removeChildRegistryRecord(handle.pid);
    return;
  }
  await terminateTrackedChild(tracked, opts);
};

/** TERM → grace → KILL every disposable child owned by this daemon instance. */
export const terminateAllDisposable = async (
  opts: TTerminateOptions = {},
): Promise<void> => {
  const trackedEntries = [...trackedChildren.values()];
  const idleChildren = trackedEntries.filter(isIdleTrackedChild);

  await Promise.all(
    idleChildren.map((tracked) => terminateTrackedChild(tracked, opts)),
  );
};

const terminateStaleRecord = async (
  record: TChildRegistryRecord,
  opts: TTerminateOptions,
): Promise<void> => {
  if (!childProcessMatchesRecord(record)) {
    removeChildRegistryRecord(record.pid);
    return;
  }
  signalProcessGroup(record.pgid, "SIGTERM");
  await sleep(Math.max(0, opts.graceMs ?? DEFAULT_TERMINATE_GRACE_MS));
  if (processAlive(record)) signalProcessGroup(record.pgid, "SIGKILL");
  removeChildRegistryRecord(record.pid);
};

/**
 * Kill verified disposable roots left by a prior daemon process. PID identity
 * is checked before every signal, so a recycled PID is never targeted.
 */
export const sweepStaleChildrenOnBoot = async (
  opts: TTerminateOptions = {},
): Promise<void> => {
  const instanceId = currentChildSupervisorInstanceId();
  await Promise.all(
    listChildRegistryRecords()
      .filter((record) => record.instanceId !== instanceId)
      .map((record) => terminateStaleRecord(record, opts)),
  );
};
