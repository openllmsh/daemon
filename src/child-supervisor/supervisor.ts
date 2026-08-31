import { logError } from "../logger";
import { linuxPdeathsigArgv } from "./linux-pdeathsig";
import {
  DEFAULT_TERMINATE_GRACE_MS,
  signalGroup,
  terminateProcessGroup,
} from "./posix";
import type { TChildRegistryRecord, TDisposableChildKind } from "./registry";
import {
  addChildRegistryRecord,
  argvDigest,
  childProcessMatchesRecord,
  currentChildSupervisorInstanceId,
  listChildRegistryRecords,
  readProcessStartTime,
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

const sleep = (ms: number): Promise<void> =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

const terminateTrackedChild = (
  tracked: TTrackedChild,
  opts: TTerminateOptions,
): Promise<void> => {
  if (tracked.terminating !== null) return tracked.terminating;
  const graceMs = opts.graceMs ?? DEFAULT_TERMINATE_GRACE_MS;
  tracked.terminating = (async (): Promise<void> => {
    signalGroup(tracked.handle.pgid, "SIGTERM");
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
  // Persist the cross-restart identity record OFF the spawn hot path. Reading
  // the start time is a `ps` subprocess; doing it synchronously here blocked the
  // event loop on every spawn (a status sweep fans out 5 `--version` probes at
  // once), starving unrelated async work. Defer it: resolve the identity via the
  // non-blocking reader, then write the record once it lands.
  //
  // A short probe (`--version`) can exit within milliseconds — before
  // `ps -o lstart=` can read its start time (null identity), or before this
  // deferred write runs (the child already reaped, dropped from
  // `trackedChildren`). Either way we skip the PERSISTENT registry record: a
  // boot sweep needs a verifiable identity, and an already-exited process is
  // never a cross-restart orphan. The in-memory tracking above is unaffected, so
  // terminate()/terminateAllDisposable() can still group-kill a live descendant.
  //
  // ACCEPTED macOS window: between spawn and this deferred write landing (the
  // async `ps` read, ms–tens of ms), the child has no persistent record. Linux
  // is still covered — `linuxPdeathsigArgv` SIGKILLs the child with the parent —
  // but Darwin has no PDEATHSIG and the boot sweep keys on the registry, so a
  // HARD daemon death (SIGKILL/native crash, no graceful drain) inside that
  // window can orphan a still-detached macOS child that the next boot's sweep
  // won't see. This is the deliberate trade for taking the synchronous `ps` off
  // the spawn hot path (it stalled the event loop on every spawn); the window is
  // orders of magnitude shorter than a child's lifetime, graceful drain still
  // reaps via in-memory tracking, and most probes are sub-second regardless.
  void (async () => {
    const startTime = await readProcessStartTime(pid);
    // Re-check membership AFTER the await: if the child exited during the read,
    // `finishTrackedChild` has already deleted it (and removed any record), so
    // writing now would leave a stale one. No `await` between this guard and the
    // write, so single-threaded JS keeps them atomic against that deletion.
    if (startTime === null || !trackedChildren.has(pid)) return;
    addChildRegistryRecord({
      instanceId: currentChildSupervisorInstanceId(),
      kind: opts.kind,
      pid,
      pgid,
      processStartTime: startTime,
      argvDigest: argvDigest(argv),
      startedAtMs: Date.now(),
    });
  })().catch((error) =>
    logError("child-supervisor", error, { pid, pgid, kind: opts.kind }),
  );
  void finishTrackedChild(handle).catch((error) =>
    logError("child-supervisor", error, { pid, pgid, kind: opts.kind }),
  );
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

/**
 * TERM → grace → KILL every IDLE disposable child owned by this daemon instance.
 * A child with an open task lease (`beginTask`) is deliberately SPARED so a
 * graceful reap (self-update / SIGTERM) never kills a child serving live work;
 * it self-exits when its task ends, and on a hard daemon exit Linux PDEATHSIG /
 * macOS launchd process-group cleanup stops it. Explicit `terminate(handle)` and
 * the boot sweep still stop a child unconditionally.
 */
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
  signalGroup(record.pgid, "SIGTERM");
  await sleep(Math.max(0, opts.graceMs ?? DEFAULT_TERMINATE_GRACE_MS));
  if (childProcessMatchesRecord(record)) signalGroup(record.pgid, "SIGKILL");
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
