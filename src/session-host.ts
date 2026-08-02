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
 *  - `detach`  — one consumer went away: the PTY remains available to other
 *                consumers and is reaped only after it is unattached and idle.
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
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type {
  TRelayFrame,
  TRelaySessionCloseFrame,
  TRelaySessionIoFrame,
  TRelaySessionOpenFrame,
  TRelaySessionResizeFrame,
} from "@openllmsh/protocol";
import { TUNNEL_CHUNK_MAX } from "@openllmsh/protocol";
import { stateDir } from "./env";
import { logInfo, logWarn } from "./logger";
import type { TSessionFallback } from "./session-core";
import {
  closeSession,
  detachSession,
  killAllSessions as killAllCoreSessions,
  openSession,
  resizeSession,
  setSessionLifecycleHooks,
  writeSessionInput,
} from "./session-core";
import { isVendorSessionCommand } from "./vendor-commands";

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

// ── daemon relay-frame adapter ───────────────────────────────────────
//
// The state machine lives in session-core.ts. This module deliberately owns
// only legacy TRelayFrame shaping plus the daemon pidfile lifecycle until
// Phase 1d replaces those files with the durable session-host registry.

const legacyFallback = (
  send: (frame: TRelayFrame) => void,
): TSessionFallback => ({
  onOutput: (session, chunk) => {
    for (let i = 0; i < chunk.length; i += TUNNEL_CHUNK_MAX) {
      send({
        type: "session_io",
        session_id: session.id,
        dir: "out",
        seq: session.outSeq,
        data_b64: Buffer.from(chunk.subarray(i, i + TUNNEL_CHUNK_MAX)).toString(
          "base64",
        ),
      });
      session.outSeq += 1;
    }
  },
  onClose: (session, reason) => {
    send({
      type: "session_close",
      session_id: session.id,
      reason,
      generation: session.generation,
    });
  },
});

setSessionLifecycleHooks({
  onSpawn: (session) => {
    if (session.pid !== null) writePidFile(session.id, session.pid);
  },
  onEnd: (session) => removePidFile(session.id),
});

/** Kill EVERY live session PTY now (catchable-exit cleanup). Synchronous so it
 *  completes inside a signal handler before `process.exit`. Clears pidfiles. */
export const killAllSessions = (): void => {
  killAllCoreSessions();
};

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

/** Handle one inbound legacy relay session frame. */
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
      openSession(frame, {
        fallback: legacyFallback(send),
        onAck: (ack) => {
          send({
            type: "session_open_ack",
            session_id: frame.session_id,
            ...(!ack.ok && ack.lastExitReason !== undefined
              ? { last_exit_reason: ack.lastExitReason }
              : {}),
            ...(ack.ok
              ? {
                  ok: true,
                  live: ack.live,
                  generation: ack.generation,
                }
              : { ok: false, error: ack.error }),
          });
        },
      });
      return;
    case "session_io":
      if (frame.dir === "in") {
        writeSessionInput(
          frame.session_id,
          new Uint8Array(Buffer.from(frame.data_b64, "base64")),
        );
      }
      return;
    case "session_resize":
      resizeSession(frame.session_id, frame.cols, frame.rows);
      return;
    case "session_close":
      if (frame.reason === "detach" || frame.reason === "consumer_gone") {
        detachSession(frame.session_id);
        return;
      }
      closeSession(frame.session_id);
      logInfo("session", "session closed", {
        id: frame.session_id,
        reason: frame.reason ?? "unknown",
      });
      return;
  }
};

export * from "./session-core";
export { isVendorSessionCommand } from "./vendor-commands";
