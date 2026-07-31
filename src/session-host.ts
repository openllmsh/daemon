/**
 * Device chat sessions — the daemon end
 * (`docs/features/sub-tunnel-and-chat-sessions.md` §2.2). A browser
 * consumer opens a `session_*` channel over the relay; this module spawns
 * the chosen vendor CLI under a PTY (Bun's built-in `Bun.Terminal` — no
 * native deps, POSIX only) in `~/.openllm/sessions/<id>/` and streams
 * the TUI both ways.
 *
 * Lifecycle:
 *  - `spawn`   — fresh workspace + fresh CLI process.
 *  - `attach`  — re-bind a LIVE PTY (tab reload / another day): ack
 *                `live:true`, replay the scrollback ring after a resize.
 *  - `continue`— the PTY died (or daemon restarted): respawn in the SAME
 *                workspace with the CLI's native continue flag where the
 *                daemon knows one (`claude --continue`), else plain.
 *  - `detach`  — the consumer went away: the PTY LIVES ON indefinitely
 *                until an explicit kill/end. No quiet reaper.
 *
 * Isolation: the CLI runs the user's REAL binary (`hostCliBin`) with the
 * real `$HOME` / PATH so credentials work without re-login. Only the cwd
 * is a per-session workspace under `~/.openllm/sessions/<id>/`. Sandbox
 * HOME rewrite and seatbelt grants are NOT applied — those stay for
 * auto-update and login/auth triggers only. Each session is its own
 * async task — never the control channel's commandTail.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";
import type {
  TRelayFrame,
  TRelaySessionCloseFrame,
  TRelaySessionIoFrame,
  TRelaySessionOpenFrame,
  TRelaySessionResizeFrame,
  TSubscriptionProviderSlug,
} from "@openllmsh/protocol";
import {
  parseStreamCtrlPayload,
  SESSION_ID_PATTERN,
  TUNNEL_CHUNK_MAX,
} from "@openllmsh/protocol";
import { decodeJsonPayload, encodeJsonPayload } from "@openllmsh/tunnel/codec";
import type { TMuxStream } from "@openllmsh/tunnel/mux";
import type { TCliProvider } from "./cli-paths";
import {
  hostCliCandidates,
  sessionEnv,
  sessionWorkspace,
} from "./cli-paths";
import { spawnEnv } from "./delegation/spawn";
import { stateDir } from "./env";
import { logInfo, logWarn } from "./logger";

/** Max concurrently-LIVE PTYs on one daemon. */
const MAX_LIVE_SESSIONS = 4;

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

const vendorCliNames = ["claude", "codex", "kimi", "grok", "cursor-agent"];

/** Extract and validate the executable token from `ps -o command=` output. */
export const isVendorSessionCommand = (command: string): boolean => {
  const executable = command.trim().split(/\s+/, 1)[0];
  if (executable === undefined || executable === "") return false;
  const name = basename(executable).toLowerCase();
  return vendorCliNames.some(
    (vendor) => name === vendor || name.startsWith(`${vendor}-`),
  );
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
  readonly onExit: () => void;
};

export type TPtySpawner = (args: TPtySpawnArgs) => TPtyLike;

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
  void proc.exited.then(() => {
    args.onExit();
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
  readonly cli: TCliProvider;
  readonly workspace: string;
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
  muxStream: TMuxStream | null;
  /** Serializes replay, replay_done, and live mux output in wire order. */
  muxWriteTail: Promise<void>;
  /** Daemon-minted monotonically increasing value for successful opens. */
  generation: number;
  /** Terminal state retained so a later attach can explain why it cannot resume. */
  lastExitReason: "evicted" | "reaped" | "done" | "killed" | null;
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
      while (current !== undefined && current !== 0) {
        if (current === root) {
          total += percent;
          break;
        }
        current = parent.get(current);
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
    if (session.pid === null) {
      for (const candidate of dormant) {
        candidate.busy = true;
        candidate.lastBusyAtMs = now;
      }
      return;
    }
    pids.add(session.pid);
  }
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
    const isBusy = session.pid !== null && busyPids.has(session.pid);
    if (isBusy) session.lastBusyAtMs = now;
    if (session.busy && !isBusy) activityHook?.();
    session.busy = isBusy;
  }
};

/** Status report for `DaemonStatus.sessions`. */
export const sessionStatusReport = (): Array<{
  id: string;
  cli: TCliProvider;
  started_at_ms: number;
  attached: boolean;
  live: boolean;
  busy: boolean;
  title?: string;
  last_exit_reason?: "evicted" | "reaped" | "done" | "killed";
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
    }));

const liveCount = (): number =>
  [...sessions.values()].filter((s) => s.pty !== null).length;

/**
 * The user's REAL CLI binary — NOT the isolated `cliBin()` under
 * `~/.openllm/cli/<provider>/`. A device session is the user driving
 * their OWN interactive CLI. Falls back to the bare command name
 * (PATH resolves it) when no known install path exists. */
const hostCliBin = (cli: TCliProvider): string => {
  for (const candidate of hostCliCandidates(cli)) {
    if (existsSync(candidate)) return candidate;
  }
  // Last resort: the command name — Bun.spawn resolves it against PATH.
  const first = hostCliCandidates(cli)[0];
  return first ?? cli;
};

/** The CLI's argv for a session start. `continue` uses the vendor's own
 *  same-directory resume where the daemon knows one. */
const argvFor = (
  cli: TCliProvider,
  mode: "spawn" | "continue",
): ReadonlyArray<string> => {
  const bin = hostCliBin(cli);
  if (cli === "claude_code") {
    // The session workspace is a throwaway dir the user is driving
    // interactively — skip the per-tool permission prompts that would
    // otherwise block every action in a fresh cwd.
    const flags = ["--dangerously-skip-permissions"];
    // Claude persists sessions per-cwd; --continue reopens the most
    // recent conversation in this workspace.
    if (mode === "continue") flags.push("--continue");
    return [bin, ...flags];
  }
  return [bin];
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
const detachMuxStream = (s: TSession, stream?: TMuxStream): void => {
  if (stream !== undefined && s.muxStream !== stream) return;
  s.muxStream = null;
  s.muxWriteTail = Promise.resolve();
  if (s.attached) detachSession(s.id);
};

/** Queue a mux write after all prior replay/live output. */
const writeMux = (s: TSession, stream: TMuxStream, chunk: Uint8Array): void => {
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
  removePidFile(s.id);
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

const handleOpen = (
  frame: TRelaySessionOpenFrame,
  send: (frame: TRelayFrame) => void,
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
  if (!ptySupported()) {
    nack("pty_unsupported");
    return;
  }
  if (!SESSION_ID_PATTERN.test(frame.session_id)) {
    nack("spawn_failed");
    return;
  }
  const cli: TSubscriptionProviderSlug = frame.cli;
  const existing = sessions.get(frame.session_id);

  // ── attach: re-bind a live PTY ────────────────────────────────────
  if (frame.mode === "attach") {
    if (existing === undefined) {
      nack("session_not_found");
      return;
    }
    if (existing.attached) {
      nack("session_busy");
      return;
    }
    if (existing.pty === null) {
      // Dead — the consumer should re-open with mode:"continue".
      nack("session_not_found", existing.lastExitReason);
      return;
    }
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
  const workspace = sessionWorkspace(frame.session_id);
  try {
    mkdirSync(workspace, { recursive: true });
  } catch (err) {
    logWarn(
      "session",
      `workspace mkdir failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    nack("spawn_failed");
    return;
  }

  // The CLI must actually be installed on this box — `hostCliCandidates`
  // already folds in a PATH scan (`resolveOnPath`), so no candidate on
  // disk means the spawn could only ENOENT. Nack the precise error so the
  // browser can say "install it" instead of a generic spawn failure.
  // Only enforced for the REAL spawner — an injected test spawner never
  // execs, and CI boxes don't carry the vendor CLIs.
  if (
    spawner === bunPtySpawner &&
    !hostCliCandidates(cli).some((candidate) => existsSync(candidate))
  ) {
    nack("cli_not_installed");
    return;
  }

  // `continue` after a daemon restart: no in-memory record, but the
  // workspace may still exist on disk — recreate the record (the `??`
  // fallback) and continue in place.
  const s: TSession = existing ?? {
    id: frame.session_id,
    cli,
    workspace,
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
  };
  sessions.set(s.id, s);

  try {
    const pty = spawner({
      argv: argvFor(cli, frame.mode === "continue" ? "continue" : "spawn"),
      cwd: workspace,
      // Real user HOME + PATH (via spawnEnv). Session cwd is isolated under
      // ~/.openllm/sessions/<id>/ without rewriting HOME or sandboxing.
      env: sessionEnv(cli),
      cols: frame.cols,
      rows: frame.rows,
      onData: (chunk) => {
        s.lastOutputAtMs = Date.now();
        pushScrollback(s, chunk);
        if (s.attached) sendOut(s, chunk, send);
      },
      onExit: () => {
        const reason = s.lastExitReason ?? "done";
        endPty(s, reason, false);
        terminalClose(s, send, reason === "done" ? "done" : "killed");
        logInfo("session", "session CLI exited", { id: s.id });
      },
    });
    s.pty = pty;
    s.pid = pty.pid ?? null;
    // Record the live PID so a crash-killed daemon's successor can reap it.
    if (s.pid !== null) writePidFile(s.id, s.pid);
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
};

/** Bind a mux session stream without changing the legacy JSON state machine. */
export const bindMuxSessionStream = (
  stream: TMuxStream,
  open: {
    readonly session_id: string;
    readonly cli: TSubscriptionProviderSlug;
    readonly cols: number;
    readonly rows: number;
    readonly mode: "spawn" | "attach" | "continue";
    readonly title?: string;
  },
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
      if (session === undefined) return;
      session.muxStream = stream;
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
  handleSessionFrame(
    {
      type: "session_open",
      session_id: open.session_id,
      key_id: "mux",
      cli: open.cli,
      cols: open.cols,
      rows: open.rows,
      mode: open.mode,
      ...(open.title === undefined ? {} : { title: open.title }),
    },
    send,
  );
  stream.onData((bytes) => {
    const session = sessions.get(open.session_id);
    session?.pty?.write(bytes);
  });
  stream.onCtrl((payload) => {
    const ctrl = parseStreamCtrlPayload(decodeJsonPayload(payload));
    const session = sessions.get(open.session_id);
    if (session === undefined) return;
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
