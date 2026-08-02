/**
 * Device chat sessions — the daemon end
 * (`docs/features/sub-tunnel-and-chat-sessions.md` §2.2). A browser
 * consumer opens a `session_*` channel over the relay; this module spawns
 * the chosen vendor CLI under a PTY (Bun's built-in `Bun.Terminal` — no
 * native deps, POSIX only) with the user's **real `$HOME`** and streams
 * the TUI both ways.
 *
 * Lifecycle:
 *  - `spawn`   — fresh CLI process (cwd `$HOME`, or a validated resume cwd).
 *  - `attach`  — re-bind a LIVE PTY (tab reload / another day): ack
 *                `live:true`, replay the scrollback ring after a resize.
 *  - `continue`— the PTY died (or daemon restarted): respawn with the
 *                vendor's resume-by-id flag when known, else claude
 *                `--continue` / plain.
 *  - `detach`  — the consumer went away: the PTY LIVES ON indefinitely
 *                until an explicit kill/end. No quiet reaper.
 *
 * Isolation: the CLI runs the user's REAL binary with real `$HOME` / PATH
 * so credentials and vendor session stores work. There is no
 * `~/.openllm/sessions/<id>/` workspace — vendor history lives under
 * `~/.claude` / `~/.codex` / … Live processes are indexed via the openllm
 * CLI's `~/.openllm/run/<client>/<pid>/live.json` (device env
 * `OPENLLM_DEVICE_SESSION_ID`). The `cliEnv()` isolated-HOME rewrite is NOT
 * applied (sessions keep the real `$HOME`), and the PTY spawn is deliberately
 * NOT routed through the per-child sandbox shim (`sandbox/exec.ts`) — the
 * session IS the user's real CLI over their real files, so OS confinement
 * would break it by design (`docs/audits/daemon-sandbox-scoping.md`).
 * Each session is its own async task — never the control channel's
 * commandTail.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import type {
  TDeviceSessionCli,
  TRelayFrame,
  TRelaySessionCloseFrame,
  TRelaySessionIoFrame,
  TRelaySessionOpenFrame,
  TRelaySessionResizeFrame,
  TSessionStreamOpenPayload,
} from "@openllmsh/protocol";
import {
  DANGEROUS_SESSION_CLIS,
  parseStreamCtrlPayload,
  SESSION_ID_PATTERN,
  TUNNEL_CHUNK_MAX,
} from "@openllmsh/protocol";
import { decodeJsonPayload, encodeJsonPayload } from "@openllmsh/tunnel/codec";
import type { TMuxStream } from "@openllmsh/tunnel/mux";
import { hostCliCandidates, sessionEnv } from "./cli-paths";
import { cliBinaryPath, legacyCliBinaryPath } from "./cli-self-update";
import { spawnEnv } from "./delegation/spawn";
import { stateDir } from "./env";
import { logInfo, logWarn } from "./logger";
import { isVendorSessionCommand } from "./vendor-commands";

// Re-exported for the daemon-session-host test's command-recognition cases.
export { isVendorSessionCommand } from "./vendor-commands";

/** Max concurrently-LIVE PTYs on one daemon. */
const MAX_LIVE_SESSIONS = 4;

/** Retained dead (resumable) session records cap — evict oldest beyond this. */
const MAX_RETAINED_SESSIONS = 32;

/** Vendor session ids accepted for cold resume: url-safe, no leading dash so
 *  the value can never be parsed as a CLI flag when appended to argv. */
const RESUME_ID_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,127}$/;

// ── Atomic PTY lifecycle: no session process ever outlives its daemon ──
//
// A PTY is a child process; if the daemon dies without killing it, it leaks
// (memory + a held session slot) until the machine reboots. Two escape hatches
// are closed:
//   1. CATCHABLE exit (SIGTERM from auto-update/launchd, SIGINT, uncaught
//      error) → `killAllSessions()` runs from main.ts's exit paths.
//   2. UNCATCHABLE exit (SIGKILL, crash, power loss) → cleanup can't run, so
//      each live PTY records a pidfile; the NEXT daemon start sweeps stale
//      pidfiles and kills any survivor whose command still looks like ours.
// Together these guarantee the machine never accumulates orphaned session PTYs.

/** Directory holding one `<sessionId>.pid` file per live PTY. */
// Sibling of sessionRoot (not nested under it) so a client-minted
// session id of "pids" can never collide with the pidfile directory.
const pidDir = (): string => join(stateDir(), "session-pids");

const pidFile = (sessionId: string): string =>
  join(pidDir(), `${sessionId}.pid`);

const writePidFile = (sessionId: string, pid: number): void => {
  try {
    mkdirSync(pidDir(), { recursive: true });
    writeFileSync(pidFile(sessionId), String(pid), "utf8");
  } catch (err) {
    logWarn(
      "session",
      `pidfile write failed for ${sessionId}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
};

const removePidFile = (sessionId: string): void => {
  try {
    rmSync(pidFile(sessionId), { force: true });
  } catch {
    /* best-effort */
  }
};

/** Whether a live process with `pid` is (still) one of our session CLIs.
 *  Conservative: only kill when the executable is a known vendor CLI, so a
 *  reused PID with a vendor name in an argument can never be SIGKILLed. */
const looksLikeSessionProc = (pid: number): boolean => {
  try {
    const out = Bun.spawnSync(["ps", "-p", String(pid), "-o", "command="], {
      stdout: "pipe",
    }).stdout.toString();
    return isVendorSessionCommand(out);
  } catch {
    return false;
  }
};

/** Startup sweep: kill any orphan PTY a PRIOR daemon instance left behind
 *  (uncatchable exit), then clear its pidfile. Idempotent; call once at boot
 *  BEFORE accepting sessions. */
export const reapOrphanSessionProcs = (): void => {
  let entries: string[];
  try {
    entries = readdirSync(pidDir());
  } catch {
    return; // no pid dir yet — nothing to sweep
  }
  for (const entry of entries) {
    if (!entry.endsWith(".pid")) continue;
    const path = join(pidDir(), entry);
    let pid = 0;
    try {
      pid = Number.parseInt(readFileSync(path, "utf8").trim(), 10);
    } catch {
      pid = 0;
    }
    if (Number.isInteger(pid) && pid > 0 && looksLikeSessionProc(pid)) {
      try {
        process.kill(pid, "SIGKILL");
        logInfo("session", "reaped orphan session process from prior daemon", {
          pid,
          file: entry,
        });
      } catch {
        /* already gone */
      }
    }
    try {
      rmSync(path, { force: true });
    } catch {
      /* best-effort */
    }
  }
};

/** Kill EVERY live session PTY now (catchable-exit cleanup). Synchronous so it
 *  completes inside a signal handler before `process.exit`. Clears pidfiles. */
export const killAllSessions = (): void => {
  for (const s of sessions.values()) {
    if (s.pty !== null) {
      try {
        s.pty.kill();
      } catch {
        /* already gone */
      }
      s.pty = null;
      s.pid = null;
    }
    removePidFile(s.id);
  }
};

/** Scrollback ring cap — enough to repaint a screenful+history on attach
 *  without unbounded memory. */
const SCROLLBACK_MAX_BYTES = 1024 * 1024;

// ─── PTY abstraction (injectable for CI — no PTY there) ──────────────

export type TPtyLike = {
  write(data: Uint8Array | string): void;
  resize(cols: number, rows: number): void;
  kill(): void;
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
    args.onExit(exitCode);
    terminal.close();
  });
  return {
    write: (data) => terminal.write(data),
    resize: (cols, rows) => terminal.resize(cols, rows),
    kill: () => {
      try {
        proc.kill();
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

type TSession = {
  readonly id: string;
  readonly cli: TDeviceSessionCli;
  /** Absolute cwd the CLI was (last) spawned in. */
  cwd: string;
  /** Vendor resume id when known (cold resume / continue). */
  vendorSessionId: string | null;
  pty: TPtyLike | null; // null = dead (continue-able)
  scrollback: Uint8Array[];
  scrollbackBytes: number;
  /** A consumer channel is currently bound (frames flow). */
  attached: boolean;
  outSeq: number;
  startedAtMs: number;
  detachedAtMs: number | null;
  lastOutputAtMs: number;
  lastBusyAtMs: number;
  busy: boolean;
  title: string | null;
  pid: number | null;
  muxStream: TSessionStream | null;
  /** Serializes replay, replay_done, and live mux output in wire order. */
  muxWriteTail: Promise<void>;
  /** Daemon-minted monotonically increasing value for successful opens. */
  generation: number;
  /** Terminal state retained so a later attach can explain why it cannot resume. */
  lastExitReason: "evicted" | "reaped" | "done" | "killed" | null;
  /** Child status, when Bun's PTY-backed process supplied one. */
  exitCode: number | null;
  /** Local broker-only exit notification; mux has no equivalent envelope. */
  exitHandler: ((code: number) => void) | null;
};

const sessions = new Map<string, TSession>();
let nextSessionGeneration = 0;

type TActivityProbe = (rootPids: ReadonlySet<number>) => Promise<Set<number>>;
let activityProbe: TActivityProbe | null = null;
let activityHook: (() => void) | null = null;

export const setActivityProbe = (probe: TActivityProbe | null): void => {
  activityProbe = probe;
};

/** Optional hook fired when a detached session transitions busy → quiet.
 *  Used for status push refresh; never kills the PTY. */
export const setSessionActivityHook = (hook: (() => void) | null): void => {
  activityHook = hook;
};

/** @deprecated Prefer {@link setSessionActivityHook}; quiet reaping is disabled. */
export const setSessionQuietHook = (hook: (() => void) | null): void => {
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

/** Poll detached process trees. Probe failures deliberately mark every session busy. */
export const pollSessionActivity = async (now = Date.now()): Promise<void> => {
  const dormant = [...sessions.values()].filter(
    (session) => session.pty !== null && !session.attached,
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
  for (const session of dormant) {
    if (session.pid === null) continue; // already marked busy above
    const isBusy = busyPids.has(session.pid);
    if (isBusy) session.lastBusyAtMs = now;
    if (session.busy && !isBusy) activityHook?.();
    session.busy = isBusy;
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
      attached: s.attached,
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

const b64 = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64");

/** Send one out-direction chunk, split at the wire cap. */
const detachMuxStream = (s: TSession, stream?: TSessionStream): void => {
  if (stream !== undefined && s.muxStream !== stream) return;
  s.muxStream = null;
  s.exitHandler = null;
  s.muxWriteTail = Promise.resolve();
  if (s.attached) detachSession(s.id);
};

/** Queue a mux write after all prior replay/live output. */
const writeMux = (
  s: TSession,
  stream: TSessionStream,
  chunk: Uint8Array,
): void => {
  s.muxWriteTail = s.muxWriteTail
    .then(() => stream.write(chunk))
    .catch(() => detachMuxStream(s, stream));
};

const writeCurrentMux = (s: TSession, chunk: Uint8Array): void => {
  if (s.muxStream !== null) writeMux(s, s.muxStream, chunk);
};

/** Send one out-direction chunk, preserving mux writes and failures in order. */
const sendOut = (
  s: TSession,
  chunk: Uint8Array,
  send: (frame: TRelayFrame) => void,
): void => {
  if (s.muxStream !== null) {
    writeCurrentMux(s, chunk);
    return;
  }
  for (let i = 0; i < chunk.length; i += TUNNEL_CHUNK_MAX) {
    send({
      type: "session_io",
      session_id: s.id,
      dir: "out",
      seq: s.outSeq,
      data_b64: b64(chunk.subarray(i, i + TUNNEL_CHUNK_MAX)),
    });
    s.outSeq += 1;
  }
};

const terminalClose = (
  s: TSession,
  send: (frame: TRelayFrame) => void,
  reason: "done" | "killed",
): void => {
  const muxStream = s.muxStream;
  if (s.attached) {
    s.attached = false;
    if (muxStream === null) {
      send({
        type: "session_close",
        session_id: s.id,
        reason,
        generation: s.generation,
      });
    }
  }
  if (s.exitCode !== null) {
    try {
      s.exitHandler?.(s.exitCode);
    } catch {
      // The local socket may already be gone; close remains terminal.
    }
  }
  s.exitHandler = null;
  muxStream?.end();
  // Do not wait for the peer's END callback to clear replay state: a restart
  // may bind the same row before that callback runs. Otherwise its first PTY
  // chunks remain queued behind a replay_done that only attach emits.
  s.muxStream = null;
  s.muxWriteTail = Promise.resolve();
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
  removePidFile(s.id);
};

/** Bound retained dead session rows: evict the oldest non-live records beyond
 *  MAX_RETAINED_SESSIONS so a long-lived daemon can't accumulate them without
 *  limit. Live and attached sessions are never evicted. */
const evictStaleDeadSessions = (): void => {
  const dead = [...sessions.values()]
    .filter((s) => s.pty === null && !s.attached)
    .sort((a, b) => a.startedAtMs - b.startedAtMs);
  const excess = dead.length - MAX_RETAINED_SESSIONS;
  for (let i = 0; i < excess; i += 1) {
    const victim = dead[i];
    if (victim !== undefined) sessions.delete(victim.id);
  }
};

// ─── frame handling ──────────────────────────────────────────────────

export const isSessionFrame = (
  frame: TRelayFrame,
): frame is
  | TRelaySessionOpenFrame
  | TRelaySessionIoFrame
  | TRelaySessionResizeFrame
  | TRelaySessionCloseFrame =>
  frame.type === "session_open" ||
  frame.type === "session_io" ||
  frame.type === "session_resize" ||
  frame.type === "session_close";

/** Handle one inbound session frame from the relay. `send` is the control
 *  channel's frame sender. */
export const handleSessionFrame = (
  frame:
    | TRelaySessionOpenFrame
    | TRelaySessionIoFrame
    | TRelaySessionResizeFrame
    | TRelaySessionCloseFrame,
  send: (frame: TRelayFrame) => void,
): void => {
  switch (frame.type) {
    case "session_open":
      handleOpen(frame, send);
      return;
    case "session_io": {
      const s = sessions.get(frame.session_id);
      if (s === undefined || frame.dir !== "in" || s.pty === null) return;
      s.pty.write(new Uint8Array(Buffer.from(frame.data_b64, "base64")));
      return;
    }
    case "session_resize": {
      const s = sessions.get(frame.session_id);
      s?.pty?.resize(frame.cols, frame.rows);
      return;
    }
    case "session_close": {
      const s = sessions.get(frame.session_id);
      if (s === undefined) return;
      if (frame.reason === "detach" || frame.reason === "consumer_gone") {
        detachSession(s.id);
        return;
      }
      // Explicit kill / terminal teardown.
      endPty(s, "killed");
      terminalClose(s, send, "killed");
      logInfo("session", "session closed", {
        id: s.id,
        reason: frame.reason ?? "unknown",
      });
      return;
    }
  }
};

export const detachSession = (id: string): void => {
  const session = sessions.get(id);
  if (session === undefined || !session.attached) return;
  session.attached = false;
  session.muxStream = null;
  session.detachedAtMs = Date.now();
  logInfo("session", "session detached", { id: session.id });
};

/** Kill a live device PTY by its OpenLLM session id for the local broker. */
export const killSession = (id: string): boolean => {
  const session = sessions.get(id);
  if (session === undefined || session.pty === null) return false;
  endPty(session, "killed");
  terminalClose(session, () => {}, "killed");
  logInfo("session", "session closed", { id, reason: "kill" });
  return true;
};

/**
 * Hand an already-attached PTY to a new consumer.
 *
 * `attached` is not falsifiable from here: a closed browser tab never sends a
 * detach, the relay's `channel_close` used to be dropped on the floor, and an
 * RTC peer is only declared dead once ICE gives up (observed minutes later).
 * Refusing the new consumer with `session_busy` therefore stranded the session
 * for as long as the stale binding survived — the common case being "close the
 * tab, re-open the same chat URL". A live rival consumer is the rare case, and
 * it is told to stand down (`superseded`) rather than reconnect, so the two
 * cannot trade the PTY back and forth.
 */
const supersedeConsumer = (s: TSession): void => {
  const previous = s.muxStream;
  // Clear BEFORE resetting: a local reset fires this stream's own reset
  // handlers synchronously, and `detachMuxStream` must see a stream that is no
  // longer current so it cannot undo the attach that follows.
  s.muxStream = null;
  s.muxWriteTail = Promise.resolve();
  s.attached = false;
  s.detachedAtMs = Date.now();
  try {
    previous?.reset(
      encodeJsonPayload({
        code: "superseded",
        message: "this session was opened by a newer consumer",
      }),
    );
  } catch {
    // The prior transport is already gone — which is the usual reason we are here.
  }
  logInfo("session", "session consumer superseded", { id: s.id });
};

const validVendorArgs = (vendorArgs: readonly string[] | undefined): boolean =>
  vendorArgs === undefined ||
  (vendorArgs.length <= 64 &&
    vendorArgs.every(
      (arg) =>
        typeof arg === "string" &&
        arg.length >= 1 &&
        arg.length <= 512 &&
        !arg.includes("\0"),
    ));

const handleOpen = (
  frame: TRelaySessionOpenFrame,
  send: (frame: TRelayFrame) => void,
  vendorArgs?: readonly string[],
): void => {
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
    send({
      type: "session_open_ack",
      session_id: frame.session_id,
      ok: false,
      error,
      ...(lastExitReason === undefined || lastExitReason === null
        ? {}
        : { last_exit_reason: lastExitReason }),
    });
  };
  // Outer guard: pre-spawn helpers (cwd resolution, binary lookup, …) used
  // to sit outside the spawn try/catch. An unexpected throw there left the
  // browser waiting on open_ack until its 15s timeout. Always nack.
  try {
    if (!validVendorArgs(vendorArgs)) {
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
        // Dead — the consumer should re-open with mode:"continue". Checked
        // before the takeover so a refusal never disturbs a bound consumer.
        nack("session_not_found", existing.lastExitReason);
        return;
      }
      // A stale binding is the norm, not the exception — take the PTY over
      // rather than refusing (see {@link supersedeConsumer}).
      if (existing.attached) supersedeConsumer(existing);
      existing.attached = true;
      existing.detachedAtMs = null;
      existing.generation = ++nextSessionGeneration;
      existing.pty.resize(frame.cols, frame.rows);
      send({
        type: "session_open_ack",
        session_id: frame.session_id,
        ok: true,
        live: true,
        generation: existing.generation,
      });
      // The legacy JSON caller needs its repaint frames here. Mux callers set
      // `muxStream` in bindMuxSessionStream's ack handler and replay directly
      // to that binary stream instead.
      if (existing.muxStream === null) {
        sendOut(existing, new TextEncoder().encode("\x1b[2J\x1b[H"), send);
        for (const chunk of existing.scrollback) sendOut(existing, chunk, send);
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
      attached: false,
      outSeq: 0,
      startedAtMs: Date.now(),
      detachedAtMs: null,
      lastOutputAtMs: Date.now(),
      lastBusyAtMs: Date.now(),
      busy: true,
      title: frame.title ?? null,
      pid: null,
      muxStream: null,
      muxWriteTail: Promise.resolve(),
      generation: 0,
      lastExitReason: null,
      exitCode: null,
      exitHandler: null,
    };
    // Refresh resume metadata on every spawn/continue.
    s.cwd = cwd;
    s.vendorSessionId = vendorSessionId;
    if (frame.title !== undefined) s.title = frame.title;
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
      const pty = spawner({
        argv,
        cwd,
        // Real user HOME + PATH (via spawnEnv). Device markers let the
        // openllm CLI write host=device into ~/.openllm/run/.../live.json.
        env: deviceSessionEnv(cli, s.id, s.title),
        cols: frame.cols,
        rows: frame.rows,
        onData: (chunk) => {
          s.lastOutputAtMs = Date.now();
          pushScrollback(s, chunk);
          if (s.attached) sendOut(s, chunk, send);
        },
        onExit: (exitCode) => {
          s.exitCode = typeof exitCode === "number" ? exitCode : null;
          const reason = s.lastExitReason ?? "done";
          endPty(s, reason, false);
          terminalClose(s, send, reason === "done" ? "done" : "killed");
          logInfo("session", "session CLI exited", { id: s.id });
        },
      });
      s.pty = pty;
      s.pid = pty.pid ?? null;
      // Record the live PID so a crash-killed daemon's successor can reap it.
      // Best-effort and non-critical — do not block open_ack on a slow state FS.
      if (s.pid !== null) {
        try {
          writePidFile(s.id, s.pid);
        } catch {
          /* writePidFile already logs; never block ack */
        }
      }
      s.busy = true;
      s.lastBusyAtMs = Date.now();
      s.attached = true;
      s.detachedAtMs = null;
      s.generation = ++nextSessionGeneration;
      s.lastExitReason = null;
      send({
        type: "session_open_ack",
        session_id: s.id,
        ok: true,
        live: false,
        generation: s.generation,
      });
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
  const send = (frame: TRelayFrame): void => {
    if (frame.type === "session_open_ack") {
      if (!frame.ok) {
        stream.reset(
          encodeJsonPayload({
            code: frame.error ?? "spawn_failed",
            ...(frame.last_exit_reason === undefined
              ? {}
              : { last_exit_reason: frame.last_exit_reason }),
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
      session.muxStream = stream;
      session.exitHandler = opts.onExit ?? null;
      stream.sendCtrl(
        encodeJsonPayload({
          t: "open_ack",
          ok: true,
          live: frame.live,
          generation: frame.generation,
        }),
      );
      if (open.mode !== "attach") return;
      // Snapshot before yielding. The shared tail makes later PTY output wait
      // behind the repaint and replay_done without a separate live-output buffer.
      const scrollback = [...session.scrollback];
      session.muxWriteTail = session.muxWriteTail
        .then(async () => {
          await stream.write(new TextEncoder().encode("\x1b[2J\x1b[H"));
          for (const chunk of scrollback) await stream.write(chunk);
          stream.sendCtrl(encodeJsonPayload({ t: "replay_done" }));
        })
        .catch(() => detachMuxStream(session, stream));
      return;
    }
    if (frame.type === "session_close") stream.end();
  };
  handleOpen(
    {
      type: "session_open",
      session_id: open.session_id,
      key_id: "mux",
      cli: open.cli,
      cols: open.cols,
      rows: open.rows,
      mode: open.mode,
      ...(open.title === undefined ? {} : { title: open.title }),
      ...(open.dangerous === true ? { dangerous: true } : {}),
      ...(open.resume_session_id === undefined
        ? {}
        : { resume_session_id: open.resume_session_id }),
      ...(open.cwd === undefined ? {} : { cwd: open.cwd }),
    },
    send,
    opts.vendorArgs,
  );
  stream.onData((bytes) => {
    const session = sessions.get(open.session_id);
    // Stale stream after re-attach: only the current muxStream may write.
    if (session === undefined || session.muxStream !== stream) return;
    session.pty?.write(bytes);
  });
  stream.onCtrl((payload) => {
    const ctrl = parseStreamCtrlPayload(decodeJsonPayload(payload));
    const session = sessions.get(open.session_id);
    // Reject delayed controls from a prior attachment generation so a
    // detached stream cannot kill/resize a PTY re-bound to a new consumer.
    if (session === undefined || session.muxStream !== stream) return;
    if (ctrl?.t === "resize") session.pty?.resize(ctrl.cols, ctrl.rows);
    if (ctrl?.t === "close" && ctrl.intent === "kill") {
      endPty(session, "killed");
      // END is a clean terminal close to sessionStream.closed ("done").
      terminalClose(session, send, "killed");
    }
  });
  stream.onReset(() => {
    const session = sessions.get(open.session_id);
    if (session !== undefined) detachMuxStream(session, stream);
  });
  stream.onEnd(() => {
    const session = sessions.get(open.session_id);
    if (session !== undefined) detachMuxStream(session, stream);
  });
};

/** Mux compatibility wrapper; the generic binder is intentionally structural. */
export const bindMuxSessionStream = (
  stream: TMuxStream,
  open: TSessionStreamOpenPayload,
): void => bindSessionStream(stream, open);

/** Control-channel reconnect: the relay swept every channel — DETACH all
 *  attached sessions (PTYs survive relay cycling; the browser re-attaches
 *  on its own reconnect). */
export const detachAllSessions = (): void => {
  for (const s of sessions.values()) {
    if (s.attached) detachSession(s.id);
  }
};

/**
 * @deprecated Quiet reaping is disabled — detach keeps the PTY alive
 * indefinitely. Kept as a no-op so older call sites/tests can still invoke it.
 * Slot-pressure eviction is also disabled: at MAX_LIVE_SESSIONS new spawns
 * nack `overloaded` rather than killing a detached peer.
 */
export const reapDetachedSessions = (_now = Date.now()): void => {
  // Intentionally empty: design rule — detach never auto-kills for quietness.
};

/** Test-only: reset all session state. */
export const resetSessionsForTest = (): void => {
  for (const s of sessions.values()) {
    s.pty?.kill();
    removePidFile(s.id);
  }
  sessions.clear();
};
