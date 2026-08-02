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
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type {
  TDeviceSessionCli,
  TRelayFrame,
  TRelaySessionCloseFrame,
  TRelaySessionIoFrame,
  TRelaySessionOpenFrame,
  TRelaySessionResizeFrame,
} from "@openllmsh/protocol";
import { SESSION_ID_PATTERN, TUNNEL_CHUNK_MAX } from "@openllmsh/protocol";
import { stateDir } from "./env";
import { logInfo } from "./logger";
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
import type { TSessionHostMeta } from "./session-host-proc";
import { isVendorSessionCommand } from "./vendor-commands";

// ── Durable local session registry + legacy browser PTY ownership ─────
//
// Local sessions are independent `openllmd __session-host` processes. Their
// socket directories are the source of truth: a daemon restart adopts a valid
// live entry and removes only an incomplete/dead one. It must never signal a
// process discovered there.
//
// The pidfile mechanism below is intentionally retained only for the legacy
// browser/relay PTYs that still run in this daemon during Phase 1. Phase 2 will
// replace that adapter with a socket client. Durable hosts never write pidfiles.

const sessionRoot = (): string => join(stateDir(), "sessions");

/** Directory holding one `<sessionId>.pid` file per legacy browser PTY. */
const pidDir = (): string => join(stateDir(), "session-pids");

const pidFile = (sessionId: string): string =>
  join(pidDir(), `${sessionId}.pid`);

const writePidFile = (sessionId: string, pid: number): void => {
  try {
    mkdirSync(pidDir(), { recursive: true });
    writeFileSync(pidFile(sessionId), String(pid), "utf8");
  } catch {
    // The legacy adapter remains usable if its best-effort crash cleanup cannot
    // persist a pidfile. Durable session-host processes do not use this path.
  }
};

const removePidFile = (sessionId: string): void => {
  try {
    rmSync(pidFile(sessionId), { force: true });
  } catch {
    /* best-effort */
  }
};

const isDeviceSessionCli = (value: unknown): value is TDeviceSessionCli =>
  value === "claude_code" ||
  value === "chatgpt" ||
  value === "grok" ||
  value === "opencode";

const parseSessionHostMeta = (
  raw: string,
  id: string,
): TSessionHostMeta | null => {
  try {
    const value: unknown = JSON.parse(raw);
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return null;
    const meta = value as Record<string, unknown>;
    if (
      meta.id !== id ||
      !isDeviceSessionCli(meta.cli) ||
      typeof meta.cwd !== "string" ||
      meta.cwd.length === 0 ||
      typeof meta.pid !== "number" ||
      !Number.isInteger(meta.pid) ||
      meta.pid <= 0 ||
      (meta.vendorSessionId !== null &&
        typeof meta.vendorSessionId !== "string") ||
      (meta.title !== null && typeof meta.title !== "string") ||
      typeof meta.startedAtMs !== "number" ||
      !Number.isFinite(meta.startedAtMs) ||
      typeof meta.generation !== "number" ||
      !Number.isInteger(meta.generation)
    )
      return null;
    return {
      id,
      cli: meta.cli,
      cwd: meta.cwd,
      pid: meta.pid,
      vendorSessionId: meta.vendorSessionId,
      title: meta.title,
      startedAtMs: meta.startedAtMs,
      generation: meta.generation,
    };
  } catch {
    return null;
  }
};

const pidAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (
      error !== null &&
      typeof error === "object" &&
      "code" in error &&
      (error as { readonly code?: unknown }).code === "EPERM"
    );
  }
};

const socketPresent = (path: string): boolean => {
  try {
    return statSync(path).isSocket();
  } catch {
    return false;
  }
};

export type TSessionHostReconcilerDeps = {
  readonly isPidAlive?: (pid: number) => boolean;
  readonly isSocketPresent?: (path: string) => boolean;
};

/**
 * Adopt live durable session-host directories and reap stale registry entries.
 * A directory survives only with valid metadata, a live host pid, and ctl.sock;
 * this daemon never sends it a signal. Kept entries are discovery state for
 * status now and the Phase 2 browser socket proxy later.
 */
export const reapOrphanSessionProcs = (
  deps: TSessionHostReconcilerDeps = {},
): void => {
  let entries: string[];
  try {
    entries = readdirSync(sessionRoot());
  } catch {
    return;
  }
  const isPidAlive = deps.isPidAlive ?? pidAlive;
  const isSocketPresent = deps.isSocketPresent ?? socketPresent;
  for (const id of entries) {
    if (!SESSION_ID_PATTERN.test(id)) continue;
    const directory = join(sessionRoot(), id);
    let meta: TSessionHostMeta | null = null;
    try {
      if (!statSync(directory).isDirectory()) continue;
      meta = parseSessionHostMeta(
        readFileSync(join(directory, "meta.json"), "utf8"),
        id,
      );
    } catch {
      meta = null;
    }
    const live =
      meta !== null &&
      isPidAlive(meta.pid) &&
      isSocketPresent(join(directory, "ctl.sock"));
    if (live && meta !== null) {
      logInfo("session", "adopted durable session host", { id, pid: meta.pid });
      continue;
    }
    try {
      rmSync(directory, { recursive: true, force: true });
      logInfo("session", "reaped stale durable session registry entry", { id });
    } catch {
      /* best-effort */
    }
  }
};

/** Whether a live process with `pid` is (still) one legacy browser session CLI. */
const looksLikeLegacyBrowserSessionProc = (pid: number): boolean => {
  try {
    const out = Bun.spawnSync(["ps", "-p", String(pid), "-o", "command="], {
      stdout: "pipe",
    }).stdout.toString();
    return isVendorSessionCommand(out);
  } catch {
    return false;
  }
};

/** Reap only legacy in-daemon browser PTYs after an uncatchable daemon exit. */
export const reapLegacyBrowserSessionProcs = (): void => {
  let entries: string[];
  try {
    entries = readdirSync(pidDir());
  } catch {
    return;
  }
  for (const entry of entries) {
    if (!entry.endsWith(".pid")) continue;
    const path = join(pidDir(), entry);
    let pid = 0;
    try {
      pid = Number.parseInt(readFileSync(path, "utf8").trim(), 10);
    } catch {
      // A partial pidfile is stale; remove it below without signalling anyone.
    }
    if (
      Number.isInteger(pid) &&
      pid > 0 &&
      looksLikeLegacyBrowserSessionProc(pid)
    ) {
      try {
        process.kill(pid, "SIGKILL");
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

/** Reconcile durable hosts, then retain pre-Phase-2 browser PTY protection. */
export const reconcileSessionHostsAtBoot = (): void => {
  reapOrphanSessionProcs();
  reapLegacyBrowserSessionProcs();
};

// ── daemon relay-frame adapter ───────────────────────────────────────
//
// The state machine lives in session-core.ts. This module deliberately owns
// only legacy TRelayFrame shaping plus temporary browser-PTY pidfiles. Durable
// local sessions are discovered through their socket-directory registry.

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
