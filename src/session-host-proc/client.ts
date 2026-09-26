import {
  spawn as admittedSpawn,
  spawnSync as admittedSpawnSync,
} from "../windows-process";

/**
 * Durable session-host discovery, spawn, and CLI-pipe attach client.
 *
 * The daemon never opens a session unix socket itself — the CLI owns that
 * path. Browser attach is a child process of `openllm sessions attach --pipe`
 * whose stdio is bridged to the relay stream. Spawn still launches the
 * detached `__session-host` sibling (same binary) so the host is ready before
 * the attach child dials it.
 */

import { randomUUID } from "node:crypto";
import {
  existsSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import type {
  TDeviceSessionCli,
  TSessionStreamOpenPayload,
} from "@openllmsh/protocol";
import { DeviceSessionCli, SESSION_ID_PATTERN } from "@openllmsh/protocol";
import { decodeJsonPayload, encodeJsonPayload } from "@openllmsh/tunnel/codec";
import { Schema as S } from "effect";
import {
  executableName,
  localSessionEndpointPresent,
  normalizeProcessStartIdentity,
  processIdentityStatus,
  processStartCommand,
  processStartIdentity,
  SESSION_HOST_STARTUP_GRACE_MS,
  sessionHostSupported,
  sourceEntrypoint,
} from "../../../pty-native/session/local-runtime";
import {
  verifyWindowsSessionDirectory,
  verifyWindowsSessionFile,
} from "../../../pty-native/session/windows-session-pipe";
import { requestedPtyBackend } from "../bs-pty";
import { resolveOpenllmCli } from "../cli-self-update";
import { spawnCommand } from "../command";
import type { TDeadlineBudget } from "../deadline-budget";
import {
  budgetFromSignal,
  createDeadlineBudget,
  firstOfBudget,
} from "../deadline-budget";
import { isDevMode, stateDir } from "../env";
import { withoutCommandReplayContext } from "../op-context";
import type { TSessionStream } from "../session-core";
import { MAX_LIVE_SESSIONS } from "../session-core";
import {
  inServiceCgroup,
  planSessionHostLaunch,
  type SessionHostLaunch,
} from "./linux-scope";
import type { TSessionHostMeta } from "./main";

const SPAWN_SOCKET_TIMEOUT_MS = 2_000;
// Native PTY compilation + exec-status reconciliation has a bounded 12s
// startup deadline; leave a small process/socket margin for the host sibling.
const NATIVE_SPAWN_SOCKET_TIMEOUT_MS = 15_000;
/** Per-pid `ps` identity read. Expiry is unknown, never dead. */
const PROCESS_IDENTITY_TIMEOUT_MS = process.platform === "win32" ? 1500 : 250;
const DISCOVERY_CONCURRENCY = 4;
/**
 * Outer bound for one registry scan (and attach-path slot wait). Per-pid checks
 * stay at {@link PROCESS_IDENTITY_TIMEOUT_MS}; this caps N slow probes so status
 * and boot cannot wait N/concurrency waves. Shared with boot reconcile — the
 * scan honors the budget (no abandoned post-expiry reap).
 */
const DISCOVERY_TIMEOUT_MS = process.platform === "win32" ? 5000 : 1000;
/** RS (0x1e) prefixes a JSON control line on the pipe-mode attach stdio. */
const PIPE_CTRL = 0x1e;
const PIPE_CTRL_MAX_BYTES = 512;
/** Grace for a timed-out session host's process group before SIGKILL (PL-D1). */
const ORPHANED_HOST_TERM_GRACE_MS = 1_000;

/**
 * DSN-2: launches in flight — counted alongside registry-live hosts so two
 * simultaneous opens cannot both pass a live-count check and both spawn.
 */
let sessionHostSpawnsInFlight = 0;

/**
 * Reserve one global session-host slot. `liveHostCount` is the caller's
 * latest discovery count; the reservation closes the check→spawn race.
 * Returns the release callback (invoke once the spawned host is discoverable
 * or the launch has failed) or null when the cap is already reached.
 */
export const reserveSessionHostSpawn = (
  liveHostCount: number,
): (() => void) | null => {
  if (liveHostCount + sessionHostSpawnsInFlight >= MAX_LIVE_SESSIONS)
    return null;
  sessionHostSpawnsInFlight += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    sessionHostSpawnsInFlight = Math.max(0, sessionHostSpawnsInFlight - 1);
  };
};

/** Test seam: pending-launch counter for global-cap coverage. */
export const sessionHostSpawnsInFlightForTests = (): number =>
  sessionHostSpawnsInFlight;

export type TLiveSessionHost = TSessionHostMeta & {
  readonly socketPath: string;
  /**
   * Whether pid + start identity was verified against the recorded meta.
   * False means attach may still be safe (the socket answers), but the
   * registry entry alone does not prove a live host.
   */
  readonly identityVerified: boolean;
  /**
   * Whether this entry counts toward the global session cap. Unverified
   * entries count only while a bounded liveness handshake over their socket
   * succeeds — a dead host whose pid was reused by an unprobeable process
   * cannot hold a cap slot forever.
   */
  readonly countsTowardCap: boolean;
};

export type TSpawnSessionHostProc = {
  readonly id: string;
  readonly cli: TDeviceSessionCli;
  readonly cols: number;
  readonly rows: number;
  readonly cwd?: string;
  readonly title?: string;
  readonly dangerous?: boolean;
  readonly resume?: string;
  readonly vendorArgs?: readonly string[];
};

const isCli: (value: unknown) => value is TDeviceSessionCli =
  S.is(DeviceSessionCli);

const sessionHostsRoot = (): string => join(stateDir(), "sessions");
const sessionHostDir = (id: string): string => join(sessionHostsRoot(), id);
const sessionHostSocketPath = (id: string): string =>
  join(sessionHostDir(id), "ctl.sock");

const isSessionHostMeta = (value: unknown): value is TSessionHostMeta => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const meta = value as Record<string, unknown>;
  return (
    typeof meta.id === "string" &&
    SESSION_ID_PATTERN.test(meta.id) &&
    isCli(meta.cli) &&
    typeof meta.cwd === "string" &&
    meta.cwd.length > 0 &&
    typeof meta.pid === "number" &&
    Number.isInteger(meta.pid) &&
    meta.pid > 0 &&
    (meta.vendorSessionId === null ||
      typeof meta.vendorSessionId === "string") &&
    (meta.title === null || typeof meta.title === "string") &&
    typeof meta.startedAtMs === "number" &&
    Number.isFinite(meta.startedAtMs) &&
    typeof meta.processStartTime === "string" &&
    meta.processStartTime.length > 0 &&
    typeof meta.generation === "number" &&
    Number.isInteger(meta.generation) &&
    meta.generation >= 1
  );
};

export type TProcessIdentity = "alive" | "dead" | "unknown" | "unsupported";

type TProcessIdentityReader = (
  meta: Pick<TSessionHostMeta, "pid" | "processStartTime">,
  budget: TDeadlineBudget,
) => Promise<TProcessIdentity>;

let processIdentityReaderForTests: TProcessIdentityReader | null = null;

/** Test seam: replace the bounded `ps` identity probe. */
export const setSessionHostProcessIdentityReaderForTests = (
  reader: TProcessIdentityReader | null,
): void => {
  processIdentityReaderForTests = reader;
};

/**
 * Bounded async `lstart` read. `undefined` means the deadline expired or the
 * helper could not be observed — never treat that as a dead pid.
 */
const readProcessStartTime = async (
  pid: number,
  budget: TDeadlineBudget,
): Promise<string | null | undefined> => {
  if (budget.expired()) return undefined;
  if (process.platform === "win32") return processStartIdentity(pid);
  try {
    const proc = admittedSpawn(processStartCommand(pid), {
      stdout: "pipe",
      stderr: "ignore",
      env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
    });
    const raced = await firstOfBudget(
      budget,
      Promise.all([new Response(proc.stdout).text(), proc.exited]).then(
        ([out, code]) => ({ out, code }),
      ),
    );
    if (raced.kind === "expired") {
      try {
        proc.kill();
      } catch {
        // The helper may already have exited.
      }
      return undefined;
    }
    if (raced.value.code !== 0) {
      try {
        process.kill(pid, 0);
        return undefined;
      } catch (error) {
        if (
          error !== null &&
          typeof error === "object" &&
          "code" in error &&
          (error as { readonly code?: unknown }).code === "ESRCH"
        )
          return null;
        return undefined;
      }
    }
    return parseProcessIdentityOutput(raced.value.out);
  } catch {
    return undefined;
  }
};

/** A successful but empty `ps` result cannot establish process identity. */
export const parseProcessIdentityOutput = (
  stdout: string,
): string | undefined => {
  const value = stdout.trim();
  return value.length > 0 ? value : undefined;
};

const defaultProcessIdentity: TProcessIdentityReader = async (meta, budget) => {
  if (!sessionHostSupported()) return "unsupported";
  const startTime = await readProcessStartTime(meta.pid, budget);
  return processIdentityStatus(
    meta.pid,
    meta.processStartTime,
    () => startTime,
  );
};

const sessionHostProcessIdentity = async (
  meta: Pick<TSessionHostMeta, "pid" | "processStartTime">,
  parent?: AbortSignal,
): Promise<TProcessIdentity> => {
  const budget = createDeadlineBudget(PROCESS_IDENTITY_TIMEOUT_MS, parent);
  const reader = processIdentityReaderForTests ?? defaultProcessIdentity;
  return reader(meta, budget);
};

const forEachLimited = async <T>(
  values: readonly T[],
  limit: number,
  visit: (value: T) => Promise<void>,
  shouldStop?: () => boolean,
): Promise<void> => {
  if (values.length === 0) return;
  const maxConcurrency = Math.max(1, Math.min(limit, values.length));
  let cursor = 0;
  await Promise.all(
    Array.from({ length: maxConcurrency }, async () => {
      for (;;) {
        if (shouldStop?.()) return;
        const index = cursor;
        cursor += 1;
        if (index >= values.length) return;
        await visit(values[index] as T);
      }
    }),
  );
};

type TProbeWaiter = {
  granted: boolean;
  settle: (granted: boolean) => void;
};

let probeActive = 0;
const probeWaiters: TProbeWaiter[] = [];

const acquireProbeSlot = async (budget: TDeadlineBudget): Promise<boolean> => {
  if (budget.expired()) return false;
  if (probeActive < DISCOVERY_CONCURRENCY) {
    probeActive += 1;
    return true;
  }
  const waiter: TProbeWaiter = {
    granted: false,
    settle: () => {},
  };
  const slot = new Promise<boolean>((resolve) => {
    let settled = false;
    waiter.settle = (granted) => {
      if (settled) return;
      settled = true;
      waiter.granted = granted;
      resolve(granted);
    };
    probeWaiters.push(waiter);
  });
  const waited = await firstOfBudget(budget, slot);
  if (waited.kind === "value") {
    if (!waited.value || budget.expired()) {
      if (waited.value) releaseProbeSlot();
      return false;
    }
    return true;
  }
  // Expired won the race. If release already granted this waiter (shifted it
  // off the queue), the slot is held until we give it back.
  const index = probeWaiters.indexOf(waiter);
  if (index >= 0) {
    probeWaiters.splice(index, 1);
    return false;
  }
  releaseProbeSlot();
  return false;
};

const releaseProbeSlot = (): void => {
  const next = probeWaiters.shift();
  if (next !== undefined) {
    next.granted = true;
    next.settle(true);
    return;
  }
  probeActive = Math.max(0, probeActive - 1);
};

const boundedProcessIdentity = async (
  meta: Pick<TSessionHostMeta, "pid" | "processStartTime">,
  parent: AbortSignal,
): Promise<TProcessIdentity> => {
  const budget = budgetFromSignal(parent) ?? createDeadlineBudget(0, parent);
  const acquired = await acquireProbeSlot(budget);
  if (!acquired) return "unknown";
  try {
    if (parent.aborted) return "unknown";
    return await sessionHostProcessIdentity(meta, parent);
  } finally {
    releaseProbeSlot();
  }
};

const socketPresent = (path: string): boolean => {
  return localSessionEndpointPresent(path);
};

/** Bound for one socket liveness handshake during admission counting. */
const SESSION_HOST_SOCKET_LIVENESS_MS = 1_000;

/**
 * Liveness handshake for admission counting: a host that LISTENS on its
 * control socket proves a live owning process even when the pid identity
 * probe cannot run (the registry entry stays attachable either way — this
 * only decides whether it consumes a global cap slot). Bounded; a refused
 * or stalled connect counts as not-live.
 */
const sessionHostSocketLiveness = (
  socketPath: string,
  timeoutMs: number,
): Promise<boolean> =>
  new Promise<boolean>((resolve) => {
    if (timeoutMs <= 0) {
      resolve(false);
      return;
    }
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let socket: ReturnType<typeof connect> | null = null;
    const finish = (live: boolean): void => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      try {
        socket?.destroy();
      } catch {
        // The socket is already gone.
      }
      resolve(live);
    };
    try {
      socket = connect(socketPath);
    } catch {
      resolve(false);
      return;
    }
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    timer = setTimeout(() => finish(false), timeoutMs);
    timer.unref?.();
  });

type TDiscoveryCandidate = {
  readonly id: string;
  readonly directory: string;
  readonly socketPath: string;
  readonly meta: TSessionHostMeta;
  readonly socketReady: boolean;
};

const reapSessionHostDir = (directory: string): void => {
  try {
    if (process.platform === "win32") {
      verifyWindowsSessionDirectory(sessionHostsRoot());
      verifyWindowsSessionDirectory(directory);
    }
    rmSync(directory, { recursive: true, force: true });
  } catch {
    // A concurrently exiting host owns final cleanup.
  }
};

type TDiscoveryOutcome = {
  readonly hosts: readonly TLiveSessionHost[];
  readonly complete: boolean;
};

let discoveryInFlight: Promise<TDiscoveryOutcome> | null = null;
/**
 * The last COMPLETE scan's hosts, each stamped with when it was verified.
 * A timed-out scan serves this cache for attach/status, but an entry that
 * has not been re-verified within one scan interval must not keep holding a
 * global cap slot — otherwise a dead host with an unprobeable pid blocks
 * every new session forever.
 */
let lastKnownLiveHosts: readonly {
  readonly host: TLiveSessionHost;
  readonly verifiedAtMs: number;
}[] = [];

const readSessionHostMeta = (id: string): TSessionHostMeta | null => {
  if (!SESSION_ID_PATTERN.test(id)) return null;
  const directory = sessionHostDir(id);
  try {
    if (process.platform === "win32") {
      verifyWindowsSessionDirectory(sessionHostsRoot());
      verifyWindowsSessionDirectory(directory);
      verifyWindowsSessionFile(join(directory, "meta.json"));
    }
    const parsed: unknown = JSON.parse(
      readFileSync(join(directory, "meta.json"), "utf8"),
    );
    return isSessionHostMeta(parsed) && parsed.id === id ? parsed : null;
  } catch {
    return null;
  }
};

const sessionHostDirectoryAgeMs = (directory: string): number => {
  try {
    return Math.max(0, Date.now() - statSync(directory).mtimeMs);
  } catch {
    return Number.POSITIVE_INFINITY;
  }
};

const liveHostIfAttachable = (
  meta: TSessionHostMeta,
  identity: TProcessIdentity,
  socketPath: string,
  socketReady: boolean,
  socketLive: boolean,
): TLiveSessionHost | null => {
  if (!socketReady) return null;
  if (identity === "dead" || identity === "unsupported") return null;
  const verified = identity === "alive";
  return {
    ...meta,
    socketPath,
    identityVerified: verified,
    // Attach safety stays separate from admission counting: an unverified
    // entry is still attachable, but it holds a cap slot only while its
    // socket answers the liveness handshake.
    countsTowardCap: verified || socketLive,
  };
};

const discoverSessionHostsOnce = async (): Promise<TDiscoveryOutcome> => {
  const budget = createDeadlineBudget(DISCOVERY_TIMEOUT_MS);
  let entries: string[];
  try {
    if (process.platform === "win32")
      verifyWindowsSessionDirectory(sessionHostsRoot());
    entries = readdirSync(sessionHostsRoot());
  } catch {
    lastKnownLiveHosts = [];
    return { hosts: [], complete: true };
  }
  const candidates: TDiscoveryCandidate[] = [];
  for (const id of entries) {
    if (!SESSION_ID_PATTERN.test(id)) continue;
    const directory = sessionHostDir(id);
    if (process.platform === "win32") {
      try {
        verifyWindowsSessionDirectory(directory);
      } catch {
        continue;
      }
    }
    const socketPath = sessionHostSocketPath(id);
    const meta = readSessionHostMeta(id);
    if (meta === null) {
      // Startup metadata is published atomically, but an interrupted rename,
      // transient read error, or active staging transition must not make the
      // first registry scan destructive. Reap only after the normal startup
      // grace has elapsed.
      if (sessionHostDirectoryAgeMs(directory) > SESSION_HOST_STARTUP_GRACE_MS)
        reapSessionHostDir(directory);
      continue;
    }
    candidates.push({
      id,
      directory,
      socketPath,
      meta,
      socketReady: socketPresent(socketPath),
    });
  }

  const hosts: TLiveSessionHost[] = [];
  await forEachLimited(
    candidates,
    DISCOVERY_CONCURRENCY,
    async (candidate) => {
      if (budget.expired()) return;
      const identity = await boundedProcessIdentity(
        candidate.meta,
        budget.signal,
      );
      if (budget.expired()) return;
      if (identity === "unknown" || identity === "unsupported") {
        // Uncertainty never authorizes deletion. Surface a socket-ready host so
        // attach/status keep the session; otherwise leave the directory.
        // Admission counting is stricter than attach: an unverified entry
        // holds a cap slot only while its socket answers a bounded liveness
        // handshake — a dead host with a recycled, unprobeable pid cannot
        // block every new session forever.
        const socketLive = candidate.socketReady
          ? await sessionHostSocketLiveness(
              candidate.socketPath,
              Math.min(SESSION_HOST_SOCKET_LIVENESS_MS, budget.remainingMs()),
            )
          : false;
        if (budget.expired()) return;
        const host = liveHostIfAttachable(
          candidate.meta,
          identity,
          candidate.socketPath,
          candidate.socketReady,
          socketLive,
        );
        if (host !== null) hosts.push(host);
        return;
      }
      if (identity === "dead") {
        reapSessionHostDir(candidate.directory);
        return;
      }
      // Alive process: never reap. A missing socket is not attachable yet
      // (bind lag or a later recreate); keep the registry until the socket
      // appears or identity later proves dead.
      const host = liveHostIfAttachable(
        candidate.meta,
        identity,
        candidate.socketPath,
        candidate.socketReady,
        true,
      );
      if (host !== null) hosts.push(host);
    },
    () => budget.expired(),
  );
  if (budget.expired()) {
    const now = Date.now();
    return {
      // Stale cache entries stay attachable (attach rechecks the socket),
      // but only entries re-verified within the last scan interval still
      // consume a global cap slot.
      hosts: lastKnownLiveHosts.map((entry) =>
        now - entry.verifiedAtMs <= DISCOVERY_TIMEOUT_MS
          ? entry.host
          : { ...entry.host, countsTowardCap: false },
      ),
      complete: false,
    };
  }
  const verifiedAtMs = Date.now();
  lastKnownLiveHosts = hosts
    .sort((a, b) => b.startedAtMs - a.startedAtMs)
    .map((host) => ({ host, verifiedAtMs }));
  return { hosts, complete: true };
};

const discoverSessionHostOutcome = async (): Promise<TDiscoveryOutcome> => {
  if (discoveryInFlight !== null) return discoveryInFlight;
  const run = withoutCommandReplayContext(discoverSessionHostsOnce);
  discoveryInFlight = run;
  void run.finally(() => {
    if (discoveryInFlight === run) discoveryInFlight = null;
  });
  return run;
};

/** Scan, validate, and reap stale durable session-host registry entries. */
export const discoverSessionHosts = async (): Promise<
  readonly TLiveSessionHost[]
> => (await discoverSessionHostOutcome()).hosts;

/**
 * Targeted attach lookup. A coalesced scan's last-known list never authorizes
 * attach. A complete-scan hit still requires a live socket; a miss (or stale
 * socket) rechecks only this id against identity + socket.
 */
export const findSessionHost = async (
  id: string,
): Promise<TLiveSessionHost | null> => {
  const outcome = await discoverSessionHostOutcome();
  if (outcome.complete) {
    const hit = outcome.hosts.find((host) => host.id === id);
    if (hit !== undefined && socketPresent(hit.socketPath)) return hit;
  }
  return lookupSessionHost(id);
};

const lookupSessionHost = async (
  id: string,
): Promise<TLiveSessionHost | null> => {
  const budget = createDeadlineBudget(DISCOVERY_TIMEOUT_MS);
  const meta = readSessionHostMeta(id);
  if (meta === null) return null;
  const socketPath = sessionHostSocketPath(id);
  const socketReady = socketPresent(socketPath);
  const identity = await boundedProcessIdentity(meta, budget.signal);
  if (budget.expired()) return null;
  const socketLive =
    socketReady && identity !== "alive" && identity !== "dead"
      ? await sessionHostSocketLiveness(
          socketPath,
          Math.min(SESSION_HOST_SOCKET_LIVENESS_MS, budget.remainingMs()),
        )
      : identity === "alive";
  if (budget.expired()) return null;
  // Attach never reaps. Unknown stays unknown; dead is a negative attach.
  return liveHostIfAttachable(
    meta,
    identity,
    socketPath,
    socketReady,
    socketLive,
  );
};

/** Test seam: drop a coalesced scan so the next call starts a fresh one. */
export const resetSessionHostDiscoveryForTests = (): void => {
  discoveryInFlight = null;
  processIdentityReaderForTests = null;
  lastKnownLiveHosts = [];
  probeActive = 0;
  probeWaiters.length = 0;
};

/** Test seam: identity-probe semaphore used by discovery and targeted lookup. */
export const acquireSessionHostProbeSlotForTests = acquireProbeSlot;
export const releaseSessionHostProbeSlotForTests = releaseProbeSlot;

type TSessionHostSpawnHarness = {
  /** Full replacement launch command — bypasses daemonBinary()/argv. */
  readonly command?: readonly string[];
  /** Bound for the socket-publish wait (ms). */
  readonly socketTimeoutMs?: number;
};

let spawnHarnessForTests: TSessionHostSpawnHarness | null = null;

/** Test seam: fake the detached host launch and its socket wait (PL-D1). */
export const setSessionHostSpawnHarnessForTests = (
  harness: TSessionHostSpawnHarness | null,
): void => {
  spawnHarnessForTests = harness;
};

const waitForSessionHostSocket = async (id: string): Promise<string | null> => {
  const socketPath = sessionHostSocketPath(id);
  const timeoutMs =
    spawnHarnessForTests?.socketTimeoutMs ??
    (requestedPtyBackend() === "native"
      ? NATIVE_SPAWN_SOCKET_TIMEOUT_MS
      : SPAWN_SOCKET_TIMEOUT_MS);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (socketPresent(socketPath)) return socketPath;
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
  return socketPresent(socketPath) ? socketPath : null;
};

const daemonBinary = (): readonly string[] => {
  // The detached session host is what actually owns the PTY and spawns the
  // openllm CLI. Re-exec THIS daemon's own entrypoint so it inherits our code
  // (and, in dev, the CLI override). In dev we run from source under
  // `bun --watch src/main.ts`, so `process.argv[1]` is that script — re-exec it
  // rather than the INSTALLED `~/.openllm/bin/openllmd`, which would otherwise
  // run shipped code with none of the dev overrides (and can protocol-skew the
  // source daemon, surfacing as `spawn_failed` in the browser).
  const sourceRunner = sourceEntrypoint(process.argv[1]);
  if (isDevMode()) {
    return sourceRunner === null
      ? [process.execPath]
      : [process.execPath, sourceRunner];
  }
  const installed = join(stateDir(), "bin", executableName("openllmd"));
  if (existsSync(installed)) return [installed];
  return sourceRunner === null
    ? [process.execPath]
    : [process.execPath, sourceRunner];
};

const systemdVersions = new Map<string, number | null>();
const sessionHostLaunch = (command: readonly string[]): SessionHostLaunch => {
  let cgroup = "";
  if (process.platform === "linux") {
    try {
      cgroup = readFileSync("/proc/self/cgroup", "utf8");
    } catch {
      if (process.env.INVOCATION_ID)
        throw new Error("Cannot establish service ownership");
    }
  }
  const managed = process.platform === "linux" && inServiceCgroup(cgroup);
  const runner = managed ? Bun.which("systemd-run") : null;
  if (runner && !systemdVersions.has(runner)) {
    const probe = admittedSpawnSync([runner, "--version"], {
      stdout: "pipe",
      stderr: "ignore",
      timeout: 1000,
    });
    const match = /^systemd (\d+)\b/.exec(probe.stdout.toString());
    systemdVersions.set(
      runner,
      probe.exitCode === 0 && match ? Number(match[1]) : null,
    );
  }
  return planSessionHostLaunch(command, {
    platform: process.platform,
    cgroup,
    runner,
    major: runner ? (systemdVersions.get(runner) ?? null) : null,
    nonce: randomUUID().replaceAll("-", ""),
  });
};

const stopFailedSessionScope = async (scopeName: string): Promise<void> => {
  const ctl = Bun.which("systemctl");
  if (!ctl) return;
  // The name is generated locally for this attempt; never stop a caller's unit.
  const stop = admittedSpawn([ctl, "--user", "stop", scopeName], {
    stdio: ["ignore", "ignore", "ignore"],
  });
  const timer = setTimeout(() => stop.kill(), 5000);
  try {
    await stop.exited;
  } finally {
    clearTimeout(timer);
  }
};

const processAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as { readonly code?: unknown }).code !== "ESRCH";
  }
};

/**
 * What the pid behind a timed-out launch is RIGHT NOW, revalidated just
 * before each signal — never a bare liveness bit. "foreign" is the dangerous
 * verdict: the orphan died and its pid was recycled onto an unrelated
 * process, which must never eat our signals.
 */
type TOrphanPidVerdict = "ours" | "foreign" | "dead" | "unknown";

/**
 * PL-D1: a detached host that never publishes its socket is an orphan — the
 * daemon used to leave it (and its vendor CLI) alive until the 60-minute
 * idle reap. The detached spawn is its own process-group leader on POSIX,
 * so TERM the whole group, give it a bounded grace, then SIGKILL it. On
 * Windows there are no POSIX process groups: kill the direct child only.
 *
 * Every signal is gated on identity revalidation against the start identity
 * captured AT LAUNCH: between the socket wait timing out and each signal the
 * orphan may have exited and had its pid recycled, and a recycled pid (or a
 * stranger group that formed under it) must never be signalled. While the
 * direct child still runs it is provably this launch's — a live pid cannot
 * be reused — so an unverifiable probe only withholds signals once the child
 * is gone.
 */
const killOrphanedSessionHost = async (
  proc: ReturnType<typeof admittedSpawn>,
  expectedStart: string | null,
): Promise<void> => {
  const pid = proc.pid;
  const orphanPidVerdict = (): TOrphanPidVerdict => {
    if (typeof pid !== "number" || pid <= 0) return "dead";
    let current: string | null | undefined;
    try {
      current = processStartIdentity(pid);
    } catch {
      current = undefined;
    }
    if (current === null) return "dead";
    if (current !== undefined && expectedStart !== null) {
      return normalizeProcessStartIdentity(current) ===
        normalizeProcessStartIdentity(expectedStart)
        ? "ours"
        : "foreign";
    }
    // No start identity was captured at launch, or the probe cannot answer
    // now: the child's own exit bookkeeping is the only proof left. A still
    // -running direct child is provably ours; after its exit a live pid is
    // suspect but unprovable.
    if (proc.exitCode === null && !proc.killed) return "ours";
    return "unknown";
  };
  const signalGroup = (signal: "SIGTERM" | "SIGKILL"): void => {
    if (process.platform === "win32") {
      try {
        proc.kill(signal);
      } catch {
        // Already gone.
      }
      return;
    }
    const verdict = orphanPidVerdict();
    // A proven-recycled pid is never signalled — not the group a stranger
    // may have formed under it, and not the bare pid.
    if (verdict === "foreign") return;
    // An unverifiable pid is never signalled either: the group could be a
    // stranger's, and this is the only gate between us and kill(-pid).
    if (verdict === "unknown") return;
    try {
      // Prefer the group recorded at launch: the detached spawn is its own
      // process-group leader, so -pid is exactly this launch's group. A dead
      // leader leaves the group to its descendants — signalling it is still
      // correct (or a caught ESRCH when empty).
      process.kill(-pid, signal);
      return;
    } catch {
      // Group already gone — fall through to the direct pid in case setsid
      // never ran (race between spawn and group leadership).
    }
    // The bare-pid fallback requires positive proof the pid is still this
    // launch's leader — a dead pid is ESRCH, but a live one could be anyone.
    if (verdict === "ours") {
      try {
        process.kill(pid, signal);
      } catch {
        // Already gone.
      }
    }
  };
  signalGroup("SIGTERM");
  const deadline = Date.now() + ORPHANED_HOST_TERM_GRACE_MS;
  // Prefer proc.exited over kill(pid,0): a direct child stays a zombie
  // (kill(0)-visible) until it is reaped, so liveness alone cannot tell a
  // dead leader from a stubborn one.
  while (Date.now() < deadline) {
    const exited = await Promise.race([
      proc.exited.then(() => true as const),
      new Promise<false>((resolve) => setTimeout(() => resolve(false), 50)),
    ]);
    if (exited) break;
  }
  // Always KILL the group after grace: the leader may have died on TERM while
  // a descendant ignores it, and an empty group is just a caught ESRCH. The
  // verdict is revalidated — the pid may have been recycled during the grace.
  signalGroup("SIGKILL");
  // Reap the leader so callers testing liveness never see a zombie.
  await Promise.race([
    proc.exited,
    new Promise<void>((resolve) => setTimeout(() => resolve(undefined), 200)),
  ]);
};

/** Test seam: the orphaned-host killer, identity-revalidated per signal. */
export const killOrphanedSessionHostForTests = killOrphanedSessionHost;

/**
 * One launch's ownership identity. `token` is minted per spawn and carried
 * to the host in its environment (recorded in owner.json/meta.json), so it
 * binds state to exactly one launch even when the pid is reused — or hidden
 * behind a systemd scope. `start` is the pid's start identity captured at
 * spawn; it may be null when no probe could run, in which case the token is
 * the only proof. `launchedAtMs` bounds the fallback that accepts a staging
 * dir carrying no record at all.
 */
export type TFailedLaunchOwnership = {
  readonly pid: number;
  readonly start: string | null;
  readonly token: string;
  readonly launchedAtMs: number;
};

type TOwnerRecord = {
  readonly pid: number | null;
  readonly processStartTime: string | null;
  readonly launchToken: string | null;
};

const readOwnerRecord = (file: string): TOwnerRecord | null => {
  try {
    const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
    if (typeof parsed !== "object" || parsed === null) return null;
    const record = parsed as Record<string, unknown>;
    return {
      pid:
        typeof record.pid === "number" &&
        Number.isInteger(record.pid) &&
        record.pid > 0
          ? record.pid
          : null,
      processStartTime:
        typeof record.processStartTime === "string" &&
        record.processStartTime.length > 0
          ? record.processStartTime
          : null,
      launchToken:
        typeof record.launchToken === "string" && record.launchToken.length > 0
          ? record.launchToken
          : null,
    };
  } catch {
    return null;
  }
};

type TOwnerVerdict = "ours" | "foreign-dead" | "unproven";

/**
 * Classify a recorded owner against this launch. "ours" requires the launch
 * token or pid + start — never a bare pid, which PID reuse can counterfeit.
 * "foreign-dead" is a recorded owner proven gone (dead pid, or a live pid
 * whose start mismatches the record): its leftover state is orphaned and
 * removable. Anything else is unproven and stays.
 */
const ownerRecordVerdict = (
  record: TOwnerRecord,
  launch: TFailedLaunchOwnership,
): TOwnerVerdict => {
  if (record.launchToken !== null && record.launchToken === launch.token)
    return "ours";
  if (
    record.pid === launch.pid &&
    launch.start !== null &&
    record.processStartTime !== null &&
    normalizeProcessStartIdentity(record.processStartTime) ===
      normalizeProcessStartIdentity(launch.start)
  )
    return "ours";
  if (record.pid !== null) {
    if (record.processStartTime !== null) {
      if (processIdentityStatus(record.pid, record.processStartTime) === "dead")
        return "foreign-dead";
    } else if (!processAlive(record.pid)) {
      // Legacy records without a start identity can only age out by liveness.
      return "foreign-dead";
    }
  }
  return "unproven";
};

/**
 * Remove `directory` only while `removable` proves it — and bind the removal
 * to the verified contents: the dir is first renamed to a unique quarantine
 * sibling, re-verified inside, and only then deleted. A racing re-publish at
 * the original path makes the second check fail, and the dir is put back
 * instead of being deleted.
 */
const removeProvenSessionHostDir = (
  directory: string,
  removable: (dir: string) => boolean,
): void => {
  if (!removable(directory)) return;
  const quarantine = `${directory}.reaping-${randomUUID()}`;
  try {
    renameSync(directory, quarantine);
  } catch {
    return; // Already gone, or being removed by a racing cleanup.
  }
  if (removable(quarantine)) {
    reapSessionHostDir(quarantine);
    return;
  }
  try {
    renameSync(quarantine, directory);
  } catch {
    // Restore failed — leave it quarantined under its unique name; the
    // generic unrecognized-dir path blocks on it but never deletes it.
  }
};

/**
 * Remove only the state that is PROVABLY owned by the timed-out launch
 * (PL-D1). A concurrent or later launch of the same session id may hold the
 * claim, the staging dir, or the published dir — deleting those would orphan
 * a live host, so every removal requires a launch-token or pid + start match
 * (a bare pid can be reused), and the delete itself goes through a
 * re-verified quarantine rename:
 *  - `.{id}.{pid}.staging` carries the pid in its name plus owner.json inside;
 *  - `.{id}.claim/owner.json` records the claiming host's identity + token;
 *  - `<id>/meta.json` records the publishing host's identity + token.
 * A recorded owner proven dead (foreign-dead) is orphaned state and is also
 * removed. Unverifiable leftovers are kept for the startup-grace reaper.
 */
export const removeFailedSessionHostDirs = (
  id: string,
  launch: TFailedLaunchOwnership,
): void => {
  const root = sessionHostsRoot();
  const removable = (verdict: TOwnerVerdict): boolean =>
    verdict === "ours" || verdict === "foreign-dead";
  const verdictFromFile = (dir: string, file: string): TOwnerVerdict => {
    const record = readOwnerRecord(join(dir, file));
    return record === null ? "unproven" : ownerRecordVerdict(record, launch);
  };

  removeProvenSessionHostDir(
    join(root, `.${id}.${launch.pid}.staging`),
    (dir) => {
      const record =
        readOwnerRecord(join(dir, "owner.json")) ??
        readOwnerRecord(join(dir, "meta.json"));
      if (record !== null) return removable(ownerRecordVerdict(record, launch));
      // No identity record at all: the pid in the name can only bind this
      // launch if the dir was created during it — a reused pid names an
      // older launch's leftover, which stays for the grace reaper.
      try {
        return statSync(dir).mtimeMs >= launch.launchedAtMs - 1_000;
      } catch {
        return false;
      }
    },
  );
  removeProvenSessionHostDir(join(root, `.${id}.claim`), (dir) =>
    removable(verdictFromFile(dir, "owner.json")),
  );
  removeProvenSessionHostDir(sessionHostDir(id), (dir) =>
    removable(verdictFromFile(dir, "meta.json")),
  );
};

/** Spawn a detached sibling session host and wait for its private control socket. */
export const spawnSessionHostProc = async (
  args: TSpawnSessionHostProc,
): Promise<string | null> => {
  if (!sessionHostSupported()) return null;
  if (!SESSION_ID_PATTERN.test(args.id)) return null;
  const argv = [
    "__session-host",
    "--id",
    args.id,
    "--cli",
    args.cli,
    ...(args.cwd === undefined ? [] : ["--cwd", args.cwd]),
    ...(args.title === undefined ? [] : ["--title", args.title]),
    ...(args.dangerous === true ? ["--dangerous"] : []),
    ...(args.resume === undefined ? [] : ["--resume", args.resume]),
    ...(args.vendorArgs ?? []).flatMap((arg) => ["--vendor-arg", arg]),
    "--cols",
    String(args.cols),
    "--rows",
    String(args.rows),
  ];
  let launch: SessionHostLaunch | undefined;
  try {
    launch = sessionHostLaunch(
      spawnHarnessForTests?.command ?? [...daemonBinary(), ...argv],
    );
    // Minted per launch and carried to the host in its environment; the host
    // records it in owner.json/meta.json so failed-launch cleanup removes
    // only state provably written by THIS launch (pid reuse cannot forge it).
    const launchToken = randomUUID();
    const launchedAtMs = Date.now();
    const proc = admittedSpawn(launch.command, {
      detached: true,
      // Preserve runtime-loaded state selectors in the durable sibling too.
      env: {
        ...process.env,
        OPENLLM_SESSION_HOST_LAUNCH_TOKEN: launchToken,
      },
      stdio: ["ignore", "ignore", "ignore"],
    });
    proc.unref();
    // Capture the child's start identity NOW, while the pid is provably this
    // launch's — a later read could observe a reused pid.
    const hostStart =
      typeof proc.pid === "number"
        ? (processStartIdentity(proc.pid) ?? null)
        : null;
    const socket = await waitForSessionHostSocket(args.id);
    if (socket === null) {
      // PL-D1: never leave the timed-out host (and its vendor CLI) orphaned.
      // A systemd scope owns its own cgroup teardown; without one the
      // detached process group must be signalled directly.
      if (launch.scopeName) await stopFailedSessionScope(launch.scopeName);
      else await killOrphanedSessionHost(proc, hostStart);
      removeFailedSessionHostDirs(args.id, {
        pid: proc.pid,
        start: hostStart,
        token: launchToken,
        launchedAtMs,
      });
    }
    return socket;
  } catch {
    if (launch?.scopeName)
      await stopFailedSessionScope(launch.scopeName).catch(() => {});
    return null;
  }
};

const openllmCliBinary = (): string | null => resolveOpenllmCli();

/**
 * A TSessionStream that pipes to `openllm sessions attach --pipe`.
 *
 * The CLI child owns the unix-socket dial; the daemon only owns this process
 * and the bridge. Binary frames go to the child's stdin; RS-prefixed JSON
 * lines carry resize/close controls. The child's stdout is PTY output.
 */
export class CliPipeSessionStream implements TSessionStream {
  private readonly dataHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly ctrlHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly resetHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly endHandlers = new Set<() => void>();
  private closed = false;

  constructor(
    private readonly proc: ReturnType<typeof Bun.spawn>,
    private readonly stdin: {
      write: (data: Uint8Array | string) => number | Promise<number>;
      flush: () => number | Promise<number>;
    },
  ) {
    const stdout = proc.stdout;
    if (stdout !== null && typeof stdout !== "number") {
      void (async () => {
        const reader = (stdout as ReadableStream<Uint8Array>).getReader();
        const ctrlDecoder = new TextDecoder();
        let ctrlBytes: number[] = [];
        let ctrlOverflow = false;
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done || value === undefined) break;
            let index = 0;
            while (index < value.length) {
              if (
                ctrlBytes.length > 0 ||
                ctrlOverflow ||
                value[index] === PIPE_CTRL
              ) {
                if (ctrlBytes.length === 0 && !ctrlOverflow) index += 1;
                while (index < value.length) {
                  const byte = value[index] ?? 0;
                  index += 1;
                  if (byte === 0x0a) {
                    if (!ctrlOverflow) {
                      try {
                        const decoded: unknown = JSON.parse(
                          ctrlDecoder.decode(new Uint8Array(ctrlBytes)),
                        );
                        if (
                          typeof decoded === "object" &&
                          decoded !== null &&
                          !Array.isArray(decoded)
                        ) {
                          const control = decoded as Record<string, unknown>;
                          if (control.t === "reset") {
                            const { t: _tag, ...reset } = control;
                            const payload = encodeJsonPayload(reset);
                            for (const handler of this.resetHandlers)
                              handler(payload);
                          } else {
                            const payload = encodeJsonPayload(control);
                            for (const handler of this.ctrlHandlers)
                              handler(payload);
                          }
                        }
                      } catch {
                        // Malformed control — drop and keep streaming.
                      }
                    }
                    ctrlBytes = [];
                    ctrlOverflow = false;
                    break;
                  }
                  ctrlBytes.push(byte);
                  if (ctrlBytes.length > PIPE_CTRL_MAX_BYTES) {
                    // Keep consuming through newline so a malformed frame tail
                    // cannot be emitted as raw terminal output.
                    ctrlBytes = [];
                    ctrlOverflow = true;
                  }
                }
                continue;
              }
              const start = index;
              while (index < value.length && value[index] !== PIPE_CTRL)
                index += 1;
              if (index > start) {
                const bytes = value.subarray(start, index);
                for (const handler of this.dataHandlers) handler(bytes);
              }
            }
          }
        } catch {
          // Child closed stdout.
        } finally {
          this.fireEnd();
        }
      })();
    } else {
      void proc.exited.then(() => this.fireEnd());
    }
    // With a stdout pipe, EOF owns completion. Reaping the child can happen
    // before buffered output/control frames have reached this reader.
  }

  private fireEnd = (): void => {
    if (this.closed) return;
    this.closed = true;
    for (const handler of this.endHandlers) handler();
  };

  write = async (bytes: Uint8Array): Promise<void> => {
    if (this.closed) throw new Error("session pipe closed");
    await this.stdin.write(bytes);
    await this.stdin.flush();
  };

  private writeControl = (control: object): void => {
    void Promise.resolve(
      this.stdin.write(
        `${String.fromCharCode(PIPE_CTRL)}${JSON.stringify(control)}\n`,
      ),
    )
      .then(() => this.stdin.flush())
      .catch(() => this.fireEnd());
  };

  sendCtrl = (payload: Uint8Array): void => {
    if (this.closed) return;
    const decoded = decodeJsonPayload(payload);
    if (
      decoded === undefined ||
      typeof decoded !== "object" ||
      decoded === null
    )
      return;
    const ctrl = decoded as {
      t?: string;
      cols?: number;
      rows?: number;
      intent?: string;
    };
    if (
      ctrl.t === "resize" &&
      typeof ctrl.cols === "number" &&
      typeof ctrl.rows === "number"
    ) {
      this.writeControl({ t: "resize", cols: ctrl.cols, rows: ctrl.rows });
      return;
    }
    if (ctrl.t === "focus") {
      // Forward opaque focus claims so a browser tab can claim primary through
      // the pipe-bridged attach child without typing.
      this.writeControl({ t: "focus" });
      return;
    }
    if (ctrl.t === "close") {
      this.writeControl({ t: "close", intent: ctrl.intent ?? "detach" });
    }
  };

  reset = (_payload?: Uint8Array): void => {
    // Parent-side teardown: kill the attach child. The durable host is untouched.
    try {
      this.proc.kill();
    } catch {
      /* already gone */
    }
    this.fireEnd();
  };

  end = (): void => {
    this.sendCtrl(encodeJsonPayload({ t: "close", intent: "detach" }));
    try {
      this.proc.kill();
    } catch {
      /* already gone */
    }
    this.fireEnd();
  };

  onData = (handler: (payload: Uint8Array) => unknown): (() => void) => {
    this.dataHandlers.add(handler);
    return () => this.dataHandlers.delete(handler);
  };
  onCtrl = (handler: (payload: Uint8Array) => unknown): (() => void) => {
    this.ctrlHandlers.add(handler);
    return () => this.ctrlHandlers.delete(handler);
  };
  onReset = (handler: (payload: Uint8Array) => unknown): (() => void) => {
    this.resetHandlers.add(handler);
    return () => this.resetHandlers.delete(handler);
  };
  onEnd = (handler: () => void): (() => void) => {
    this.endHandlers.add(handler);
    return () => this.endHandlers.delete(handler);
  };
}

/**
 * Attach to a durable session by spawning `openllm sessions attach --pipe`.
 * The CLI owns the unix-socket dial; this returns a TSessionStream over the
 * child's stdio so the daemon can bridge a relay mux stream without opening
 * any session socket itself.
 */
export const attachSessionHostViaCli = (
  open: TSessionStreamOpenPayload,
): TSessionStream | null => {
  const bin = openllmCliBinary();
  if (bin === null) return null;
  const proc = admittedSpawn(
    spawnCommand(process.platform, bin, [
      "sessions",
      "attach",
      open.session_id,
      "--pipe",
      "--cols",
      String(open.cols),
      "--rows",
      String(open.rows),
    ]),
    {
      env: { ...process.env },
      stdin: "pipe",
      stdout: "pipe",
      stderr: "ignore",
    },
  );
  if (proc.stdin === null || typeof proc.stdin === "number") {
    try {
      proc.kill();
    } catch {
      /* already gone */
    }
    return null;
  }
  return new CliPipeSessionStream(proc, proc.stdin);
};
