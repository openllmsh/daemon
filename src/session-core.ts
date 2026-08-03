/**
 * Transport-neutral device-session state machine.
 *
 * Owns PTY session state, stream fan-out, scrollback, replay, lag control, and
 * idle reaping. Transport adapters turn their own protocol into TSessionStream
 * or call openSession; this module never imports relay frame types.
 */

import { existsSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import type {
  TDeviceSessionCli,
  TSessionStreamOpenPayload,
} from "@openllmsh/protocol";
import {
  DANGEROUS_SESSION_CLIS,
  parseStreamCtrlPayload,
  SESSION_ID_PATTERN,
} from "@openllmsh/protocol";
import { decodeJsonPayload, encodeJsonPayload } from "@openllmsh/tunnel/codec";
import { hostCliCandidates, sessionEnv } from "./cli-paths";
import { cliBinaryPath, legacyCliBinaryPath } from "./cli-self-update";
import { spawnEnv } from "./delegation/spawn";
import { loadEnvFile } from "./env";
import { logInfo, logWarn } from "./logger";

/** Max concurrently-LIVE PTYs in one session-host process. */
const MAX_LIVE_SESSIONS = 4;

/** Retained dead (resumable) session records cap — evict oldest beyond this. */
const MAX_RETAINED_SESSIONS = 32;

/** Vendor session ids accepted for cold resume: url-safe, no leading dash. */
export const RESUME_ID_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,127}$/;

/** Scrollback ring cap — enough to repaint a screenful+history on attach
 *  without unbounded memory. */
const SCROLLBACK_MAX_BYTES = 1024 * 1024;

/** One stalled viewer must not retain unbounded PTY output. */
const CONSUMER_MAX_QUEUED_BYTES = 2 * 1024 * 1024;

/** Reaped children get time to flush their transcript before forcible exit. */
const REAP_KILL_GRACE_MS = 10_000;

/** Detached idle timeout. Zero deliberately restores never-reap behavior. */
const DEFAULT_SESSION_IDLE_TIMEOUT_MIN = 60;

const sessionIdleTimeoutMs = (): number => {
  loadEnvFile();
  const raw = process.env.OPENLLM_SESSION_IDLE_TIMEOUT_MIN;
  if (raw === undefined) return DEFAULT_SESSION_IDLE_TIMEOUT_MIN * 60_000;
  const minutes = Number(raw.trim());
  return Number.isFinite(minutes) && minutes >= 0
    ? Math.floor(minutes * 60_000)
    : DEFAULT_SESSION_IDLE_TIMEOUT_MIN * 60_000;
};

// ─── PTY abstraction (injectable for CI — no PTY there) ──────────────

export type TPtyLike = {
  write(data: Uint8Array | string): void;
  resize(cols: number, rows: number): void;
  kill(signal?: NodeJS.Signals): void;
  readonly pid?: number;
};

export type TPtySpawnArgs = {
  readonly argv: ReadonlyArray<string>;
  readonly cwd: string;
  readonly env: Record<string, string>;
  readonly cols: number;
  readonly rows: number;
  readonly onData: (chunk: Uint8Array) => void;
  readonly onExit: (exitCode?: number) => void;
};

export type TPtySpawner = (args: TPtySpawnArgs) => TPtyLike;

/**
 * Transport-neutral endpoint of a device session. Keeping this structural means
 * the local broker can reuse the exact mux lifecycle without becoming mux wire.
 */
export type TSessionStream = {
  readonly write: (bytes: Uint8Array) => Promise<void>;
  readonly sendCtrl: (payload: Uint8Array) => void;
  readonly reset: (payload?: Uint8Array) => void;
  readonly end: () => void;
  readonly onData: (handler: (payload: Uint8Array) => unknown) => () => void;
  readonly onCtrl: (handler: (payload: Uint8Array) => unknown) => () => void;
  readonly onReset: (handler: (payload: Uint8Array) => unknown) => () => void;
  readonly onEnd: (handler: () => void) => () => void;
};

/** Production spawner over Bun's built-in PTY. */
const bunPtySpawner: TPtySpawner = (args) => {
  const terminal = new Bun.Terminal({
    cols: args.cols,
    rows: args.rows,
    data: (_t, chunk) => args.onData(chunk),
  });
  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = Bun.spawn([...args.argv], {
      cwd: args.cwd,
      env: spawnEnv(args.env),
      terminal,
    });
  } catch (err) {
    // Spawn threw (ENOENT etc.) — the terminal was already created above;
    // close it so the failed attempt doesn't leak a PTY fd.
    terminal.close();
    throw err;
  }
  void proc.exited.then((exitCode) => {
    try {
      args.onExit(exitCode);
    } finally {
      // A throwing exit handler must never leak the PTY fd.
      terminal.close();
    }
  });
  return {
    write: (data) => terminal.write(data),
    resize: (cols, rows) => terminal.resize(cols, rows),
    kill: (signal = "SIGTERM") => {
      try {
        proc.kill(signal);
      } catch {
        /* already gone */
      }
    },
    pid: proc.pid,
  };
};

let spawner: TPtySpawner = bunPtySpawner;
export const setPtySpawner = (fn: TPtySpawner | null): void => {
  spawner = fn ?? bunPtySpawner;
};

export const ptySupported = (): boolean => process.platform !== "win32";

// ─── session state ───────────────────────────────────────────────────

type TAttachedConsumer = {
  readonly stream: TSessionStream;
  /** Removes this consumer's transport event bindings on detach. */
  readonly unsubscribe: Array<() => void>;
  writeTail: Promise<void>;
  queuedBytes: number;
  exitHandler: ((code: number) => void) | null;
};

export type TSession = {
  readonly id: string;
  readonly cli: TDeviceSessionCli;
  /** Absolute cwd the CLI was (last) spawned in. */
  cwd: string;
  /** Vendor resume id when known (cold resume / continue). */
  vendorSessionId: string | null;
  pty: TPtyLike | null; // null = dead (continue-able)
  scrollback: Uint8Array[];
  scrollbackBytes: number;
  /** Every active mux or broker consumer. */
  consumers: Set<TAttachedConsumer>;
  outSeq: number;
  startedAtMs: number;
  detachedAtMs: number | null;
  lastOutputAtMs: number;
  lastBusyAtMs: number;
  busy: boolean;
  title: string | null;
  pid: number | null;
  /** Daemon-minted monotonically increasing value for successful opens. */
  generation: number;
  /** Terminal state retained so a later attach can explain why it cannot resume. */
  lastExitReason: "evicted" | "reaped" | "done" | "killed" | null;
  /** Child status, when Bun's PTY-backed process supplied one. */
  exitCode: number | null;
  /** Optional adapter for output/close when no stream is attached. */
  fallback: TSessionFallback | null;
};

const sessions = new Map<string, TSession>();
let nextSessionGeneration = 0;

type TSessionLifecycleHooks = {
  readonly onSpawn: (session: TSession) => void;
  readonly onEnd: (session: TSession) => void;
};

let lifecycleHooks: TSessionLifecycleHooks = {
  onSpawn: () => {},
  onEnd: () => {},
};

/** Adapter seam for daemon pidfiles or standalone-host persistence. */
export const setSessionLifecycleHooks = (
  hooks: TSessionLifecycleHooks | null,
): void => {
  lifecycleHooks = hooks ?? { onSpawn: () => {}, onEnd: () => {} };
};

type TActivityProbe = (rootPids: ReadonlySet<number>) => Promise<Set<number>>;
let activityProbe: TActivityProbe | null = null;
let activityHook: (() => void) | null = null;

export const setActivityProbe = (probe: TActivityProbe | null): void => {
  activityProbe = probe;
};

/** Optional hook fired when a detached session transitions busy → quiet.
 *  Used for status push refresh. */
export const setSessionActivityHook = (hook: (() => void) | null): void => {
  activityHook = hook;
};

const probeActivity = async (
  rootPids: ReadonlySet<number>,
): Promise<Set<number>> => {
  if (activityProbe !== null) return activityProbe(rootPids);
  const proc = Bun.spawn(["ps", "-Ao", "pid=,ppid=,pcpu="], {
    stdout: "pipe",
    stderr: "ignore",
  });
  const text = await new Response(proc.stdout).text();
  if ((await proc.exited) !== 0) throw new Error("ps exited nonzero");
  const rows = text
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => line.trim().split(/\s+/));
  const parent = new Map<number, number>();
  const cpu = new Map<number, number>();
  for (const row of rows) {
    const [pidText, parentText, cpuText] = row;
    const pid = Number(pidText);
    const ppid = Number(parentText);
    const percent = Number(cpuText);
    if (
      !Number.isInteger(pid) ||
      !Number.isInteger(ppid) ||
      !Number.isFinite(percent)
    )
      throw new Error("unparseable ps output");
    parent.set(pid, ppid);
    cpu.set(pid, percent);
  }
  const busy = new Set<number>();
  for (const root of rootPids) {
    let total = 0;
    for (const [pid, percent] of cpu) {
      let current: number | undefined = pid;
      let hops = 0;
      const visited = new Set<number>();
      while (
        current !== undefined &&
        current !== 0 &&
        hops < 4_096 &&
        !visited.has(current)
      ) {
        if (current === root) {
          total += percent;
          break;
        }
        visited.add(current);
        const next = parent.get(current);
        if (next === current) break;
        current = next;
        hops += 1;
      }
    }
    if (total > 1) busy.add(root);
  }
  return busy;
};

const isAttached = (session: TSession): boolean => session.consumers.size > 0;

const scheduleReapKill = (session: TSession, pty: TPtyLike): void => {
  const timer = setTimeout(() => {
    if (session.pty !== pty) return;
    try {
      pty.kill("SIGKILL");
    } catch {
      // The child generally exits after SIGTERM; escalation is best-effort.
    }
  }, REAP_KILL_GRACE_MS);
  timer.unref?.();
};

const reapIdleSession = (session: TSession): void => {
  const pty = session.pty;
  if (
    pty === null ||
    isAttached(session) ||
    session.lastExitReason === "reaped"
  )
    return;
  session.lastExitReason = "reaped";
  try {
    pty.kill("SIGTERM");
  } catch {
    // A raced exit will be reconciled by its onExit callback.
  }
  scheduleReapKill(session, pty);
  logInfo("session", "session reaped after detached idle timeout", {
    id: session.id,
  });
};

/** Poll detached process trees and reap only detached, output-quiet, non-busy sessions. */
export const pollSessionActivity = async (now = Date.now()): Promise<void> => {
  const dormant = [...sessions.values()].filter(
    (session) => session.pty !== null && !isAttached(session),
  );
  if (dormant.length === 0) return;
  const pids = new Set<number>();
  for (const session of dormant) {
    // A dormant session without a known pid can't be probed — mark it busy
    // (conservative: never reaped on unknown) but keep probing the rest.
    if (session.pid === null) {
      session.busy = true;
      session.lastBusyAtMs = now;
      continue;
    }
    pids.add(session.pid);
  }
  if (pids.size === 0) return;
  let busyPids: Set<number>;
  try {
    busyPids = await probeActivity(pids);
  } catch (error) {
    logWarn(
      "session",
      `activity probe failed; retaining sessions: ${error instanceof Error ? error.message : String(error)}`,
    );
    for (const session of dormant) {
      session.busy = true;
      session.lastBusyAtMs = now;
    }
    return;
  }
  const timeoutMs = sessionIdleTimeoutMs();
  for (const session of dormant) {
    if (session.pid === null) continue; // already marked busy above
    const isBusy = busyPids.has(session.pid);
    if (isBusy) session.lastBusyAtMs = now;
    if (session.busy && !isBusy) activityHook?.();
    session.busy = isBusy;
    if (
      timeoutMs > 0 &&
      !isBusy &&
      !isAttached(session) &&
      now - session.lastOutputAtMs > timeoutMs &&
      now - session.lastBusyAtMs > timeoutMs
    ) {
      reapIdleSession(session);
    }
  }
};

/** Status report for `DaemonStatus.sessions`. */
export const sessionStatusReport = (): Array<{
  id: string;
  cli: TDeviceSessionCli;
  started_at_ms: number;
  attached: boolean;
  live: boolean;
  busy: boolean;
  title?: string;
  last_exit_reason?: "evicted" | "reaped" | "done" | "killed";
  vendor_session_id?: string | null;
}> =>
  [...sessions.values()]
    .sort((a, b) => b.startedAtMs - a.startedAtMs)
    .slice(0, 12)
    .map((s) => ({
      id: s.id,
      cli: s.cli,
      started_at_ms: s.startedAtMs,
      attached: isAttached(s),
      live: s.pty !== null,
      busy: s.busy,
      ...(s.title === null ? {} : { title: s.title.slice(0, 80) }),
      ...(s.lastExitReason === null
        ? {}
        : { last_exit_reason: s.lastExitReason }),
      ...(s.vendorSessionId === null
        ? {}
        : { vendor_session_id: s.vendorSessionId }),
    }));

/**
 * Snapshot of in-memory device PTYs for `list_local_sessions` merge.
 * Exported so the control command can join vendor history with live PTYs.
 */
export const deviceSessionsForList = (): ReadonlyArray<{
  readonly id: string;
  readonly cli: TDeviceSessionCli;
  readonly live: boolean;
  readonly title: string | null;
  readonly vendor_session_id: string | null;
  readonly cwd: string;
  readonly started_at_ms: number;
}> =>
  [...sessions.values()].map((s) => ({
    id: s.id,
    cli: s.cli,
    live: s.pty !== null,
    title: s.title,
    vendor_session_id: s.vendorSessionId,
    cwd: s.cwd,
    started_at_ms: s.startedAtMs,
  }));

const liveCount = (): number =>
  [...sessions.values()].filter((s) => s.pty !== null).length;

/**
 * Device CLI → `openllm <client>` id. Only clients the openllm CLI hosts
 * are mappable; others fall back to the host vendor binary.
 */
const openllmClientId = (cli: TDeviceSessionCli): string => {
  switch (cli) {
    case "claude_code":
      return "claude";
    case "chatgpt":
      return "codex";
    case "grok":
      return "grok";
    case "opencode":
      return "opencode";
  }
};

/**
 * Whether `openllm -d <client>` is meaningful. Reuses the canonical
 * `DANGEROUS_SESSION_CLIS` set from protocol so the daemon and picker share
 * ONE membership list (claude/codex/grok — not opencode).
 */
export const sessionSupportsDangerous = (cli: TDeviceSessionCli): boolean =>
  DANGEROUS_SESSION_CLIS.has(cli);

/** Resolve the installed openllm CLI binary (current name, then legacy). */
const openllmBin = (): string | null => {
  for (const path of [cliBinaryPath(), legacyCliBinaryPath()]) {
    if (existsSync(path)) return path;
  }
  return null;
};

/** Host binary candidates for device CLIs (opencode is not a TCliProvider). */
const hostBinCandidates = (cli: TDeviceSessionCli): string[] => {
  if (cli === "opencode") {
    const home = homedir();
    return [
      join(home, ".opencode", "bin", "opencode"),
      join(home, ".local", "bin", "opencode"),
    ];
  }
  // Subscription-backed device CLIs share the isolated-CLI candidate list.
  return hostCliCandidates(cli);
};

/**
 * Resolve the host-installed vendor binary. Used only as a last-resort
 * fallback when the openllm CLI is not installed on this box.
 */
const hostCliBin = (cli: TDeviceSessionCli): string => {
  for (const candidate of hostBinCandidates(cli)) {
    if (existsSync(candidate)) return candidate;
  }
  const first = hostBinCandidates(cli)[0];
  if (first !== undefined) return first;
  // Last resort: the command name — Bun.spawn resolves it against PATH.
  switch (cli) {
    case "claude_code":
      return "claude";
    case "chatgpt":
      return "codex";
    case "grok":
      return "grok";
    case "opencode":
      return "opencode";
  }
};

/** Append vendor cold-resume flags for a known session id. */
const pushResumeArgs = (
  args: string[],
  cli: TDeviceSessionCli,
  vendorSessionId: string,
): void => {
  switch (cli) {
    case "claude_code":
    case "grok":
      args.push("--resume", vendorSessionId);
      break;
    case "chatgpt":
      args.push("resume", vendorSessionId);
      break;
    case "opencode":
      args.push("--session", vendorSessionId);
      break;
    default:
      break;
  }
};

/**
 * The CLI's argv for a session start.
 *
 * Preferred path: `openllm [-d] <client> [resume flags]` so device sessions
 * get the same overlay/gateway wiring as a local `openllm claude` launch.
 * Cold resume uses vendor resume-by-id; continue without a known id falls
 * back to claude `--continue` only.
 */
const argvFor = (
  cli: TDeviceSessionCli,
  mode: "spawn" | "continue",
  dangerous: boolean,
  vendorSessionId: string | null,
  vendorArgs: readonly string[] = [],
): ReadonlyArray<string> => {
  const clientId = openllmClientId(cli);
  const bin = openllmBin();
  const canDangerous = dangerous && sessionSupportsDangerous(cli);
  // Preferred path: openllm wrapper when installed.
  if (bin !== null) {
    const args: string[] = [bin];
    if (canDangerous) args.push("-d");
    args.push(clientId);
    if (vendorSessionId !== null) {
      pushResumeArgs(args, cli, vendorSessionId);
    } else if (mode === "continue" && cli === "claude_code") {
      args.push("--continue");
    }
    args.push(...vendorArgs);
    return args;
  }
  // Fallback: host vendor binary (no openllm wrapper).
  const host = hostCliBin(cli);
  const flags: string[] = [];
  if (cli === "claude_code" && canDangerous) {
    flags.push("--dangerously-skip-permissions");
  }
  if (vendorSessionId !== null) {
    const withResume = [host, ...flags];
    pushResumeArgs(withResume, cli, vendorSessionId);
    withResume.push(...vendorArgs);
    return withResume;
  }
  if (mode === "continue" && cli === "claude_code") {
    flags.push("--continue");
  }
  return [host, ...flags, ...vendorArgs];
};

/**
 * Resolve the spawn cwd. New sessions → `$HOME`. Resume may pass an absolute
 * existing directory; relative / missing / non-dir paths fall back to `$HOME`.
 */
export const resolveSessionCwd = (requested: string | undefined): string => {
  const home = homedir();
  if (requested === undefined || requested.length === 0) return home;
  if (!isAbsolute(requested)) return home;
  // Reject path traversal / non-directories without following untrusted
  // symlink escapes outside what realpath reports.
  try {
    const abs = resolve(requested);
    const real = realpathSync(abs);
    if (!statSync(real).isDirectory()) return home;
    return real;
  } catch {
    return home;
  }
};

/** Env for a device PTY: real HOME + device-session markers for live.json.
 *  Provider-agnostic — every device CLI (incl. opencode) shares one env. */
const deviceSessionEnv = (
  _cli: TDeviceSessionCli,
  openllmSessionId: string,
  title: string | null,
): Record<string, string> => {
  const base = sessionEnv();
  return {
    ...base,
    OPENLLM_DEVICE_SESSION_ID: openllmSessionId,
    ...(title !== null && title.length > 0
      ? { OPENLLM_DEVICE_TITLE: title.slice(0, 80) }
      : {}),
  };
};

const pushScrollback = (s: TSession, chunk: Uint8Array): void => {
  s.scrollback.push(chunk);
  s.scrollbackBytes += chunk.length;
  while (s.scrollbackBytes > SCROLLBACK_MAX_BYTES && s.scrollback.length > 1) {
    const dropped = s.scrollback.shift();
    if (dropped !== undefined) s.scrollbackBytes -= dropped.length;
  }
};

const detachConsumer = (
  session: TSession,
  consumer: TAttachedConsumer,
): void => {
  if (!session.consumers.delete(consumer)) return;
  consumer.exitHandler = null;
  consumer.queuedBytes = 0;
  for (const unsubscribe of consumer.unsubscribe) unsubscribe();
  if (!isAttached(session)) {
    session.detachedAtMs = Date.now();
    logInfo("session", "session detached", { id: session.id });
  }
};

const resetLaggingConsumer = (
  session: TSession,
  consumer: TAttachedConsumer,
): void => {
  if (!session.consumers.has(consumer)) return;
  detachConsumer(session, consumer);
  try {
    consumer.stream.reset(
      encodeJsonPayload({
        code: "lagging",
        message: "session output exceeded the consumer queue limit",
      }),
    );
  } catch {
    // A failed reset is still safely detached from the PTY fan-out.
  }
};

/** Queue output on one consumer without making peers wait for it. */
const writeConsumer = (
  session: TSession,
  consumer: TAttachedConsumer,
  chunk: Uint8Array,
): void => {
  if (!session.consumers.has(consumer)) return;
  if (consumer.queuedBytes + chunk.length > CONSUMER_MAX_QUEUED_BYTES) {
    resetLaggingConsumer(session, consumer);
    return;
  }
  consumer.queuedBytes += chunk.length;
  consumer.writeTail = consumer.writeTail
    .then(() => consumer.stream.write(chunk))
    .then(
      () => {
        if (session.consumers.has(consumer))
          consumer.queuedBytes -= chunk.length;
      },
      () => {
        resetLaggingConsumer(session, consumer);
      },
    )
    .catch(() => {});
};

const writeConsumers = (session: TSession, chunk: Uint8Array): void => {
  for (const consumer of session.consumers)
    writeConsumer(session, consumer, chunk);
};

/** Fan out one out-direction chunk to every attached transport-neutral consumer. */
const sendOut = (session: TSession, chunk: Uint8Array): void => {
  if (isAttached(session)) {
    writeConsumers(session, chunk);
    return;
  }
  session.fallback?.onOutput(session, chunk);
};

const terminalClose = (session: TSession, reason: "done" | "killed"): void => {
  const consumers = [...session.consumers];
  if (consumers.length === 0) session.fallback?.onClose(session, reason);
  // Exit codes are delivered on natural exits before each local broker stream
  // closes. An explicit kill intentionally has no late exit envelope.
  for (const consumer of consumers) {
    if (session.exitCode !== null) {
      try {
        consumer.exitHandler?.(session.exitCode);
      } catch {
        // The local socket may already be gone; close remains terminal.
      }
    }
    detachConsumer(session, consumer);
    try {
      consumer.stream.end();
    } catch {
      // Closing one broken stream must not prevent peers from closing.
    }
  }
};

const endPty = (
  s: TSession,
  reason: "evicted" | "reaped" | "done" | "killed",
  kill = true,
): void => {
  s.lastExitReason = reason;
  if (kill) s.pty?.kill();
  s.pty = null;
  s.pid = null;
  // Release the scrollback ring — a dead session can't be attached, so its
  // buffered output is dead weight until the row itself is evicted.
  s.scrollback.length = 0;
  s.scrollbackBytes = 0;
  lifecycleHooks.onEnd(s);
};

/** Bound retained dead session rows: evict the oldest non-live records beyond
 *  MAX_RETAINED_SESSIONS so a long-lived daemon can't accumulate them without
 *  limit. Live and attached sessions are never evicted. */
const evictStaleDeadSessions = (): void => {
  const dead = [...sessions.values()]
    .filter((s) => s.pty === null && !isAttached(s))
    .sort((a, b) => a.startedAtMs - b.startedAtMs);
  const excess = dead.length - MAX_RETAINED_SESSIONS;
  for (let i = 0; i < excess; i += 1) {
    const victim = dead[i];
    if (victim !== undefined) sessions.delete(victim.id);
  }
};

export const detachSession = (id: string): void => {
  const session = sessions.get(id);
  if (session === undefined) return;
  for (const consumer of [...session.consumers])
    detachConsumer(session, consumer);
  if (!isAttached(session)) session.detachedAtMs = Date.now();
};

/** Kill a live device PTY by its OpenLLM session id for the local broker. */
export const killSession = (id: string): boolean => {
  const session = sessions.get(id);
  if (session === undefined || session.pty === null) return false;
  endPty(session, "killed");
  logInfo("session", "session closed", { id, reason: "kill" });
  return true;
};

/** Kill all local PTYs and close their transport-neutral consumers. */
export const killAllSessions = (): void => {
  for (const session of sessions.values()) {
    if (session.pty !== null) {
      try {
        session.pty.kill();
      } catch {
        /* already gone */
      }
      session.pty = null;
      session.pid = null;
    }
    for (const consumer of [...session.consumers]) {
      session.consumers.delete(consumer);
      try {
        consumer.stream.end();
      } catch {
        /* already gone */
      }
    }
    lifecycleHooks.onEnd(session);
  }
};

/** Write input bytes from a transport-neutral session attachment. */
export const writeSessionInput = (id: string, bytes: Uint8Array): void => {
  sessions.get(id)?.pty?.write(bytes);
};

/** Resize the PTY from a transport-neutral session attachment. */
export const resizeSession = (id: string, cols: number, rows: number): void => {
  sessions.get(id)?.pty?.resize(cols, rows);
};

/** End a session now and close any attached transport-neutral consumers. */
export const closeSession = (id: string): boolean => {
  const session = sessions.get(id);
  if (session === undefined) return false;
  endPty(session, "killed");
  terminalClose(session, "killed");
  logInfo("session", "session closed", { id, reason: "close" });
  return true;
};

/** Per-client dangerous bypass flags (mirrors the CLI registry's
 *  `dangerousFlag` values). Vendor args may not smuggle these — the dangerous
 *  grant travels ONLY on `frame.dangerous`, which the picker/CLI gate. */
const DANGEROUS_VENDOR_FLAGS: ReadonlySet<string> = new Set([
  "--dangerously-skip-permissions",
  "--dangerously-bypass-approvals-and-sandbox",
  "--always-approve",
]);

const validVendorArgs = (
  vendorArgs: readonly string[] | undefined,
  dangerousGranted: boolean,
): boolean =>
  vendorArgs === undefined ||
  (vendorArgs.length <= 64 &&
    vendorArgs.every(
      (arg) =>
        typeof arg === "string" &&
        arg.length >= 1 &&
        arg.length <= 512 &&
        !arg.includes("\0") &&
        (dangerousGranted || !DANGEROUS_VENDOR_FLAGS.has(arg)),
    ));

export type TSessionOpen = {
  readonly session_id: string;
  readonly cli: TDeviceSessionCli;
  readonly cols: number;
  readonly rows: number;
  readonly mode: "spawn" | "attach" | "continue";
  readonly title?: string;
  readonly dangerous?: boolean;
  readonly resume_session_id?: string;
  readonly cwd?: string;
};

export type TSessionOpenAck =
  | {
      readonly ok: true;
      readonly live: boolean;
      readonly generation: number;
    }
  | {
      readonly ok: false;
      readonly error:
        | "pty_unsupported"
        | "cli_not_installed"
        | "session_not_found"
        | "session_busy"
        | "overloaded"
        | "spawn_failed";
      readonly lastExitReason?: "evicted" | "reaped" | "done" | "killed";
    };

export type TSessionFallback = {
  readonly onOutput: (session: TSession, chunk: Uint8Array) => void;
  readonly onClose: (session: TSession, reason: "done" | "killed") => void;
};

export type TOpenSessionOptions = {
  readonly vendorArgs?: readonly string[];
  readonly fallback?: TSessionFallback;
  readonly onSessionReady?: (session: TSession) => void;
  readonly onAck: (ack: TSessionOpenAck) => void;
};

export const openSession = (
  frame: TSessionOpen,
  options: TOpenSessionOptions,
): void => {
  const { vendorArgs, fallback, onSessionReady, onAck } = options;
  const nack = (
    error:
      | "pty_unsupported"
      | "cli_not_installed"
      | "session_not_found"
      | "session_busy"
      | "overloaded"
      | "spawn_failed",
    lastExitReason?: "evicted" | "reaped" | "done" | "killed" | null,
  ): void => {
    // Every refusal surfaces as user-facing copy in the browser, so it must be
    // greppable here too — a nack used to return before the first log line,
    // which made "couldn't open this session" invisible daemon-side.
    logInfo("session", "session open refused", {
      id: frame.session_id,
      mode: frame.mode,
      error,
      ...(lastExitReason === undefined || lastExitReason === null
        ? {}
        : { last_exit_reason: lastExitReason }),
    });
    onAck({
      ok: false,
      error,
      ...(lastExitReason === undefined || lastExitReason === null
        ? {}
        : { lastExitReason }),
    });
  };
  // Outer guard: pre-spawn helpers (cwd resolution, binary lookup, …) used
  // to sit outside the spawn try/catch. An unexpected throw there left the
  // browser waiting on open_ack until its 15s timeout. Always nack.
  try {
    if (
      !validVendorArgs(
        vendorArgs,
        frame.dangerous === true && sessionSupportsDangerous(frame.cli),
      )
    ) {
      nack("spawn_failed");
      return;
    }
    if (!ptySupported()) {
      nack("pty_unsupported");
      return;
    }
    if (!SESSION_ID_PATTERN.test(frame.session_id)) {
      nack("spawn_failed");
      return;
    }
    const cli: TDeviceSessionCli = frame.cli;
    const existing = sessions.get(frame.session_id);
    // The relay adapter supplies a new fallback for every legacy attachment;
    // stream attachments deliberately clear it because output has consumers.
    if (existing !== undefined) existing.fallback = fallback ?? null;
    const rawResumeId =
      typeof frame.resume_session_id === "string" &&
      frame.resume_session_id.length > 0
        ? frame.resume_session_id
        : null;
    // Only accept a vendor session id that is a plain url-safe token: never a
    // value that could be read as a flag (leading "-") when appended to argv.
    if (rawResumeId !== null && !RESUME_ID_PATTERN.test(rawResumeId)) {
      nack("spawn_failed");
      return;
    }
    const resumeId = rawResumeId;

    // ── attach: re-bind a live PTY ────────────────────────────────────
    if (frame.mode === "attach") {
      if (existing === undefined) {
        nack("session_not_found");
        return;
      }
      if (existing.pty === null) {
        // Dead — the consumer should re-open with mode:"continue".
        nack("session_not_found", existing.lastExitReason);
        return;
      }
      existing.detachedAtMs = null;
      existing.generation = ++nextSessionGeneration;
      onSessionReady?.(existing);
      existing.pty.resize(frame.cols, frame.rows);
      onAck({ ok: true, live: true, generation: existing.generation });
      // Legacy JSON has no stream object to add to the consumer set, so it
      // replays only while no mux or broker stream is attached.
      if (!isAttached(existing)) {
        sendOut(existing, new TextEncoder().encode("\x1b[2J\x1b[H"));
        for (const chunk of existing.scrollback) sendOut(existing, chunk);
      }
      logInfo("session", "session re-attached", { id: existing.id });
      return;
    }

    // ── spawn / continue: start a CLI process ─────────────────────────
    if (existing !== undefined && existing.pty !== null) {
      nack("session_busy");
      return;
    }
    // At capacity: refuse the new spawn. Detached sessions stay alive until
    // the user explicitly ends them — never silently evict under pressure.
    if (liveCount() >= MAX_LIVE_SESSIONS) {
      nack("overloaded");
      return;
    }

    // Prefer openllm CLI presence (preferred launch path). Fall back to the
    // host vendor binary when openllm is missing. Only enforced for the REAL
    // spawner — an injected test spawner never execs, and CI boxes don't
    // carry the vendor CLIs. Every DeviceSessionCli maps to an openllm client.
    if (spawner === bunPtySpawner) {
      const hasOpenllm = openllmBin() !== null;
      const hasHostVendor = hostBinCandidates(cli).some((candidate) =>
        existsSync(candidate),
      );
      if (!hasOpenllm && !hasHostVendor) {
        nack("cli_not_installed");
        return;
      }
    }

    // cwd: resume frame / prior session cwd / $HOME. No ~/.openllm/sessions.
    const cwd = resolveSessionCwd(
      frame.cwd ??
        (existing !== undefined ? existing.cwd : undefined) ??
        undefined,
    );
    const vendorSessionId =
      resumeId ?? (existing !== undefined ? existing.vendorSessionId : null);

    // `continue` after a daemon restart: no in-memory record — recreate it.
    const s: TSession = existing ?? {
      id: frame.session_id,
      cli,
      cwd,
      vendorSessionId,
      pty: null,
      scrollback: [],
      scrollbackBytes: 0,
      consumers: new Set(),
      outSeq: 0,
      startedAtMs: Date.now(),
      detachedAtMs: null,
      lastOutputAtMs: Date.now(),
      lastBusyAtMs: Date.now(),
      busy: true,
      title: frame.title ?? null,
      pid: null,
      generation: 0,
      lastExitReason: null,
      exitCode: null,
      fallback: fallback ?? null,
    };
    // Refresh resume metadata on every spawn/continue.
    s.cwd = cwd;
    s.vendorSessionId = vendorSessionId;
    if (frame.title !== undefined) s.title = frame.title;
    s.fallback = fallback ?? null;
    sessions.set(s.id, s);
    evictStaleDeadSessions();

    try {
      const argv = argvFor(
        cli,
        frame.mode === "continue" ? "continue" : "spawn",
        frame.dangerous === true,
        vendorSessionId,
        vendorArgs,
      );
      logInfo("session", "session open started", {
        id: s.id,
        cli,
        mode: frame.mode,
        cwd,
        argv: argv.join(" "),
      });
      const pendingOutput: Uint8Array[] = [];
      let ptyReady = false;
      const onData = (chunk: Uint8Array): void => {
        s.lastOutputAtMs = Date.now();
        pushScrollback(s, chunk);
        if (!ptyReady) {
          pendingOutput.push(chunk);
          return;
        }
        sendOut(s, chunk);
      };
      const pty = spawner({
        argv,
        cwd,
        // Real user HOME + PATH (via spawnEnv). Device markers let the
        // openllm CLI write host=device into ~/.openllm/run/.../live.json.
        env: deviceSessionEnv(cli, s.id, s.title),
        cols: frame.cols,
        rows: frame.rows,
        onData,
        onExit: (exitCode) => {
          s.exitCode = typeof exitCode === "number" ? exitCode : null;
          const reason = s.lastExitReason ?? "done";
          endPty(s, reason, false);
          terminalClose(s, reason === "done" ? "done" : "killed");
          logInfo("session", "session CLI exited", { id: s.id });
        },
      });
      s.pty = pty;
      onSessionReady?.(s);
      ptyReady = true;
      for (const chunk of pendingOutput) sendOut(s, chunk);
      pendingOutput.length = 0;
      s.pid = pty.pid ?? null;
      s.busy = true;
      s.lastBusyAtMs = Date.now();
      s.detachedAtMs = null;
      s.generation = ++nextSessionGeneration;
      s.lastExitReason = null;
      // A reused row may retain the prior child status. The newly spawned PTY
      // must not report that old exit code when it later closes.
      s.exitCode = null;
      // Lifecycle ownership stays injectable: the current daemon writes its
      // pidfile adapter, while the standalone host supplies its own persistence.
      // Run it only after all persisted metadata has its final spawn values.
      lifecycleHooks.onSpawn(s);
      onAck({ ok: true, live: false, generation: s.generation });
      logInfo("session", "session started", {
        id: s.id,
        cli,
        mode: frame.mode,
      });
    } catch (err) {
      sessions.delete(s.id);
      logWarn(
        "session",
        `session spawn failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      nack("spawn_failed");
    }
  } catch (err) {
    logWarn(
      "session",
      `session open failed: ${err instanceof Error ? err.message : String(err)}`,
      { id: frame.session_id, mode: frame.mode },
    );
    nack("spawn_failed");
  }
};

/** Bind a transport-neutral session stream without changing the legacy JSON state machine. */
export const bindSessionStream = (
  stream: TSessionStream,
  open: TSessionStreamOpenPayload,
  opts: {
    readonly vendorArgs?: readonly string[];
    readonly onExit?: (code: number) => void;
  } = {},
): void => {
  const consumer: TAttachedConsumer = {
    stream,
    unsubscribe: [],
    writeTail: Promise.resolve(),
    queuedBytes: 0,
    exitHandler: opts.onExit ?? null,
  };
  const registerConsumer = (session: TSession): void => {
    if (session.consumers.has(consumer)) return;
    session.consumers.add(consumer);
    session.detachedAtMs = null;
  };
  const onAck = (ack: TSessionOpenAck): void => {
    if (!ack.ok) {
      stream.reset(
        encodeJsonPayload({
          code: ack.error,
          ...(ack.lastExitReason === undefined
            ? {}
            : { last_exit_reason: ack.lastExitReason }),
        }),
      );
      return;
    }
    const session = sessions.get(open.session_id);
    if (session === undefined) {
      // No record for a successful open ack (raced teardown) — reset the
      // stream so the consumer settles instead of hanging on the channel.
      stream.reset(encodeJsonPayload({ code: "session_not_found" }));
      return;
    }
    registerConsumer(session);
    stream.sendCtrl(
      encodeJsonPayload({
        t: "open_ack",
        ok: true,
        live: ack.live,
        generation: ack.generation,
      }),
    );
    if (open.mode !== "attach") return;
    // Snapshot before yielding. This consumer's private tail orders its
    // repaint before subsequent live output without delaying other viewers.
    const scrollback = [...session.scrollback];
    writeConsumer(session, consumer, new TextEncoder().encode("\x1b[2J\x1b[H"));
    for (const chunk of scrollback) writeConsumer(session, consumer, chunk);
    consumer.writeTail = consumer.writeTail
      .then(() => stream.sendCtrl(encodeJsonPayload({ t: "replay_done" })))
      .catch(() => detachConsumer(session, consumer));
  };

  let boundSession: TSession | undefined;
  openSession(open, {
    vendorArgs: opts.vendorArgs,
    onAck,
    onSessionReady: (session) => {
      boundSession = session;
      registerConsumer(session);
    },
  });
  const session = boundSession;
  // A refused open never became a consumer, so it must not leave four dormant
  // transport handlers behind. For accepted streams, keep every unsubscribe on
  // the consumer and release them together on reset/end/lagging/PTY teardown.
  if (session === undefined || consumer === undefined) return;
  consumer.unsubscribe.push(
    stream.onData((bytes) => {
      if (!session.consumers.has(consumer)) return;
      session.pty?.write(bytes);
    }),
    stream.onCtrl((payload) => {
      if (!session.consumers.has(consumer)) return;
      const ctrl = parseStreamCtrlPayload(decodeJsonPayload(payload));
      if (ctrl?.t === "resize") session.pty?.resize(ctrl.cols, ctrl.rows);
      if (ctrl?.t === "close" && ctrl.intent === "kill") {
        endPty(session, "killed");
        // END is a clean terminal close to sessionStream.closed ("done").
        terminalClose(session, "killed");
      }
    }),
    stream.onReset(() => detachConsumer(session, consumer)),
    stream.onEnd(() => detachConsumer(session, consumer)),
  );
  // A stream can synchronously end while a transport registers a handler.
  // Avoid retaining subscriptions in that raced, already-detached consumer.
  if (!session.consumers.has(consumer)) {
    for (const unsubscribe of consumer.unsubscribe) unsubscribe();
  }
};

/** Test-only: reset all session state. */
export const resetSessionsForTest = (): void => {
  for (const s of sessions.values()) {
    s.pty?.kill();
    lifecycleHooks.onEnd(s);
  }
  sessions.clear();
};
