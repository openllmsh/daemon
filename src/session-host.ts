/**
 * Device chat sessions — the daemon end
 * (`docs/features/sub-tunnel-and-chat-sessions.md` §2.2). A browser
 * consumer opens a `session_*` channel over the relay; this module spawns
 * the chosen vendor CLI under a PTY (Bun's built-in `Bun.Terminal` — no
 * native deps, POSIX only) in `~/.openllm/sessions/<id>/` and streams the
 * TUI both ways.
 *
 * Lifecycle:
 *  - `spawn`   — fresh workspace + fresh CLI process.
 *  - `attach`  — re-bind a LIVE PTY (tab reload / another day): ack
 *                `live:true`, replay the scrollback ring after a resize.
 *  - `continue`— the PTY died (or daemon restarted): respawn in the SAME
 *                workspace with the CLI's native continue flag where the
 *                daemon knows one (`claude --continue`), else plain.
 *  - `detach`  — the consumer went away: the PTY LIVES ON (dormant) until
 *                the detached-TTL reaper fires (SESSION_DETACHED_TTL_MS).
 *
 * Isolation: the CLI runs as the USER's real tool — real `HOME`, real
 * binary (`hostCliBin`), real config — because a device session is the
 * user driving their own CLI, already OpenLLM-configured by the
 * integration install (`.claude/settings.json` etc., which the daemon
 * sandbox already grants). NOT the isolated `~/.openllm/cli/<provider>/`
 * home (that's the headless subscription-delegation plane). cwd is
 * pinned to the session workspace. Each session is its own async task —
 * never the control channel's commandTail.
 */

import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type {
  TRelayFrame,
  TRelaySessionCloseFrame,
  TRelaySessionIoFrame,
  TRelaySessionOpenFrame,
  TRelaySessionResizeFrame,
  TSubscriptionProviderSlug,
} from "@openllmsh/protocol";
import {
  SESSION_DETACHED_TTL_MS,
  SESSION_ID_PATTERN,
  TUNNEL_CHUNK_MAX,
} from "@openllmsh/protocol";
import type { TCliProvider } from "./cli-paths";
import { hostCliCandidates } from "./cli-paths";
import { spawnEnv } from "./delegation/spawn";
import { stateDir } from "./env";
import { logInfo, logWarn } from "./logger";

/** Max concurrently-LIVE PTYs on one daemon. */
const MAX_LIVE_SESSIONS = 4;

/** Scrollback ring cap — enough to repaint a screenful+history on attach
 *  without unbounded memory. */
const SCROLLBACK_MAX_BYTES = 256 * 1024;

// ─── PTY abstraction (injectable for CI — no PTY there) ──────────────

export type TPtyLike = {
  write(data: Uint8Array | string): void;
  resize(cols: number, rows: number): void;
  kill(): void;
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
  const proc = Bun.spawn([...args.argv], {
    cwd: args.cwd,
    env: spawnEnv(args.env),
    terminal,
  });
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
};

const sessions = new Map<string, TSession>();

/** Status report for `DaemonStatus.sessions`. */
export const sessionStatusReport = (): Array<{
  id: string;
  cli: string;
  started_at_ms: number;
  attached: boolean;
  live: boolean;
}> =>
  [...sessions.values()].map((s) => ({
    id: s.id,
    cli: s.cli,
    started_at_ms: s.startedAtMs,
    attached: s.attached,
    live: s.pty !== null,
  }));

const liveCount = (): number =>
  [...sessions.values()].filter((s) => s.pty !== null).length;

const sessionsRoot = (): string => join(stateDir(), "sessions");

/**
 * The user's REAL CLI binary — NOT the isolated `cliBin()` under
 * `~/.openllm/cli/<provider>/`. A device session is the user driving
 * their OWN interactive CLI, which is already configured for OpenLLM by
 * the integration install (its real `~/.claude` / `~/.codex` config +
 * login). The isolated home exists only for the SUBSCRIPTION-delegation
 * data plane (a headless credential runner); a live terminal must use
 * the user's actual tool + settings. Falls back to the bare command name
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
    // The session workspace is a throwaway sandboxed dir the user is
    // driving interactively — skip the per-tool permission prompts that
    // would otherwise block every action in a fresh cwd.
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
const sendOut = (
  s: TSession,
  chunk: Uint8Array,
  send: (frame: TRelayFrame) => void,
): void => {
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
        // The consumer went away — keep the PTY (dormant) for re-attach.
        s.attached = false;
        s.detachedAtMs = Date.now();
        logInfo("session", "session detached", { id: s.id });
        return;
      }
      // Explicit kill / terminal teardown.
      s.pty?.kill();
      s.pty = null;
      s.attached = false;
      logInfo("session", "session closed", {
        id: s.id,
        reason: frame.reason ?? "unknown",
      });
      return;
    }
  }
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
  ): void => {
    send({
      type: "session_open_ack",
      session_id: frame.session_id,
      ok: false,
      error,
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
      nack("session_not_found");
      return;
    }
    existing.attached = true;
    existing.detachedAtMs = null;
    existing.pty.resize(frame.cols, frame.rows);
    send({
      type: "session_open_ack",
      session_id: frame.session_id,
      ok: true,
      live: true,
    });
    // Repaint: clear, then replay the ring (already sized to the new
    // dims by the resize above).
    sendOut(existing, new TextEncoder().encode("\x1b[2J\x1b[H"), send);
    for (const chunk of existing.scrollback) sendOut(existing, chunk, send);
    logInfo("session", "session re-attached", { id: existing.id });
    return;
  }

  // ── spawn / continue: start a CLI process ─────────────────────────
  if (existing !== undefined && existing.pty !== null) {
    nack("session_busy");
    return;
  }
  if (frame.mode === "continue" && existing === undefined) {
    // Daemon restarted since — the workspace may still exist on disk;
    // recreate the record and continue in place.
  }
  if (liveCount() >= MAX_LIVE_SESSIONS) {
    nack("overloaded");
    return;
  }
  const workspace = join(sessionsRoot(), frame.session_id);
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
  };
  sessions.set(s.id, s);

  try {
    const pty = spawner({
      argv: argvFor(cli, frame.mode === "continue" ? "continue" : "spawn"),
      cwd: workspace,
      // The user's REAL environment — NOT the isolated `cliEnv()`. A
      // device session drives the user's own CLI with its own config +
      // login (already OpenLLM-configured by the integration install);
      // `spawnEnv` layers this over `process.env`, so the real HOME/PATH
      // carry through. HOME is pinned explicitly (defensive — the CLI
      // must read the user's real ~/.claude etc.) and TERM is forced for
      // the PTY.
      env: { HOME: homedir(), TERM: "xterm-256color" },
      cols: frame.cols,
      rows: frame.rows,
      onData: (chunk) => {
        pushScrollback(s, chunk);
        if (s.attached) sendOut(s, chunk, send);
      },
      onExit: () => {
        s.pty = null;
        if (s.attached) {
          s.attached = false;
          send({
            type: "session_close",
            session_id: s.id,
            reason: "done",
          });
        }
        logInfo("session", "session CLI exited", { id: s.id });
      },
    });
    s.pty = pty;
    s.attached = true;
    s.detachedAtMs = null;
    send({
      type: "session_open_ack",
      session_id: s.id,
      ok: true,
      live: false,
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

/** Control-channel reconnect: the relay swept every channel — DETACH all
 *  attached sessions (PTYs survive relay cycling; the browser re-attaches
 *  on its own reconnect). */
export const detachAllSessions = (): void => {
  const now = Date.now();
  for (const s of sessions.values()) {
    if (s.attached) {
      s.attached = false;
      s.detachedAtMs = now;
    }
  }
};

/** Reap DETACHED live PTYs past the TTL. Called on a timer from main. */
export const reapDetachedSessions = (now = Date.now()): void => {
  for (const s of sessions.values()) {
    if (
      s.pty !== null &&
      !s.attached &&
      s.detachedAtMs !== null &&
      now - s.detachedAtMs > SESSION_DETACHED_TTL_MS
    ) {
      logInfo("session", "reaping detached session", { id: s.id });
      s.pty.kill();
      s.pty = null;
    }
  }
};

/** Test-only: reset all session state. */
export const resetSessionsForTest = (): void => {
  for (const s of sessions.values()) s.pty?.kill();
  sessions.clear();
};
