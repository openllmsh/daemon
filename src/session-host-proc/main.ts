/**
 * Durable, per-session PTY host.
 *
 * This is deliberately independent of the daemon control plane: one invocation
 * owns one PTY and serves attached terminal consumers over a private Unix
 * WebSocket on POSIX or an owner-ACL named pipe on Windows. Both carry the
 * same local broker envelope.
 */

import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  renameSync,
  rmSync,
} from "node:fs";
import { isAbsolute, join } from "node:path";
import type {
  TDeviceSessionCli,
  TSessionStreamOpenPayload,
} from "@openllmsh/protocol";
import {
  DeviceSessionCli,
  SESSION_ID_PATTERN,
  TerminalDimension,
} from "@openllmsh/protocol";
import {
  encodeSessionPipeFrame,
  SESSION_PIPE_DRAIN_ACK,
  SessionPipeFrameDecoder,
} from "@openllmsh/protocol/session-pipe";
import { decodeJsonPayload, encodeJsonPayload } from "@openllmsh/tunnel/codec";
import { Schema as S } from "effect";
import {
  createSessionDirectory,
  createSessionFile,
  localSessionEndpoint,
  processStartIdentity,
  secureSessionDirectory,
  sessionHostSupported,
  WINDOWS_SESSION_HOST_UNAVAILABLE,
} from "../../../pty-native/session/local-runtime";
import type { TWindowsSessionPipeServer } from "../../../pty-native/session/windows-session-pipe";
import {
  createWindowsSessionPipeServer,
  verifyWindowsSessionFile,
} from "../../../pty-native/session/windows-session-pipe";
import { stateDir } from "../env";
import { whenAllNativePtysTerminated } from "../native-pty";
import type { TSessionStream } from "../session-core";
import {
  bindSessionStream,
  closeSession,
  openSession,
  pollSessionActivity,
  RESUME_ID_PATTERN,
  setSessionLifecycleHooks,
} from "../session-core";
import { ensureWindowsProcessAdmission } from "../windows-process";

const SESSION_DIR_MODE = 0o700;
const ACTIVITY_POLL_MS = 15_000;
const EXIT_DRAIN_TIMEOUT_MS = 1_000;
/**
 * Bound on waiting for every PTY to finish TERM→KILL escalation before the
 * host exits (PL-D7/DSN-7): escalation is 1 s, then the awaitable darwin
 * verify-then-KILL sweep runs up to DARWIN_KILL_VERIFY_TIMEOUT_MS (2 s), so
 * the wait needs strictly more than 3 s to never truncate a finishing sweep.
 */
const PTY_TERMINATE_BUDGET_MS = 4_000;

export type TSessionHostStartupNack = {
  readonly ok: false;
  readonly reason: typeof WINDOWS_SESSION_HOST_UNAVAILABLE;
  readonly detail: string;
};

export const SESSION_HOST_STARTUP_RECEIPT_PREFIX =
  "openllm-session-host-startup:";

export const formatSessionHostStartupNack = (
  detail: string,
): TSessionHostStartupNack => ({
  ok: false,
  reason: WINDOWS_SESSION_HOST_UNAVAILABLE,
  detail,
});

const writeSessionHostStartupNack = (detail: string): void => {
  process.stderr.write(
    `${SESSION_HOST_STARTUP_RECEIPT_PREFIX}${JSON.stringify(formatSessionHostStartupNack(detail))}\n`,
  );
};

/**
 * Per-launch token the spawning daemon sets on this host's environment. It
 * is recorded in owner.json (claim + staging) and meta.json so failed-launch
 * cleanup removes only state provably written by THIS launch — a pid alone
 * can be reused.
 */
export const SESSION_HOST_LAUNCH_TOKEN_ENV =
  "OPENLLM_SESSION_HOST_LAUNCH_TOKEN";

const sessionHostLaunchToken = (): string | null => {
  const value = process.env[SESSION_HOST_LAUNCH_TOKEN_ENV];
  return typeof value === "string" && value.length >= 1 && value.length <= 128
    ? value
    : null;
};

const processStartTime = (): string | null => {
  const identity = processStartIdentity(process.pid);
  if (identity === undefined || identity === null) return null;
  return identity;
};

/**
 * Publish this host's ownership record atomically into `dir`: write a temp
 * sibling, then rename over `owner.json`. A concurrent discovery scan can
 * only ever see the file absent (unproven — kept) or complete (verifiable),
 * never torn.
 */
const writeSessionHostOwnerRecord = (
  dir: string,
  cli: TDeviceSessionCli,
  start: string,
): void => {
  const temp = join(dir, `.owner.json.${process.pid}.tmp`);
  const token = sessionHostLaunchToken();
  createSessionFile(
    temp,
    `${JSON.stringify({
      pid: process.pid,
      processStartTime: start,
      cli,
      ...(token === null ? {} : { launchToken: token }),
    })}\n`,
  );
  renameSync(temp, join(dir, "owner.json"));
};

export type TSessionHostArgs = {
  readonly id: string;
  readonly cli: TDeviceSessionCli;
  readonly cols?: number;
  readonly rows?: number;
  readonly cwd?: string;
  readonly title?: string;
  readonly dangerous: boolean;
  readonly resumeSessionId?: string;
  readonly vendorArgs: readonly string[];
};

export type TSessionHostMeta = {
  readonly id: string;
  readonly cli: TDeviceSessionCli;
  readonly cwd: string;
  readonly pid: number;
  readonly vendorSessionId: string | null;
  readonly title: string | null;
  readonly startedAtMs: number;
  readonly processStartTime: string;
  readonly generation: number;
  /** Per-launch token from the spawning daemon; binds this host's state to
   *  exactly one launch so failed-launch cleanup can prove ownership. */
  readonly launchToken?: string;
  /** Optional for discovery compatibility with already-running older hosts. */
  readonly attached?: boolean;
};

type TSocketData = {
  stream: SessionHostStream | null;
  opened: boolean;
  drainWaiters: Set<{ resolve: () => void; reject: (error: Error) => void }>;
};

type TSocket = {
  readonly data: TSocketData;
  sendBinary(bytes: Uint8Array): number;
  sendText(text: string): number;
  close(): void;
};

type TEnvelope = {
  readonly t?: unknown;
  readonly open?: unknown;
  readonly p?: unknown;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Empty / unparseable RESET → `peer_gone` (channel teardown), not protocol_error. */
export const sessionHostResetPayload = (
  payload?: Uint8Array,
): Record<string, unknown> => {
  if (payload === undefined || payload.byteLength === 0) {
    return { code: "peer_gone" };
  }
  const decoded = decodeJsonPayload(payload);
  return isRecord(decoded) ? decoded : { code: "peer_gone" };
};

const isCli: (value: unknown) => value is TDeviceSessionCli =
  S.is(DeviceSessionCli);

const parseDimension = (value: string | undefined): number | null => {
  if (value === undefined) return null;
  const parsed = Number.parseInt(value, 10);
  if (value !== `${parsed}`) return null;
  return S.is(TerminalDimension)(parsed) ? parsed : null;
};

const isDimension = (value: unknown): value is number =>
  S.is(TerminalDimension)(value);

const validVendorArg = (value: string): boolean =>
  value.length >= 1 && value.length <= 512 && !value.includes("\0");

/** Parse hidden-process arguments without accepting option-like injection. */
export const parseSessionHostArgs = (
  argv: readonly string[],
): TSessionHostArgs | null => {
  let id: string | undefined;
  let cli: TDeviceSessionCli | undefined;
  let cols: number | undefined;
  let rows: number | undefined;
  let cwd: string | undefined;
  let title: string | undefined;
  let dangerous = false;
  let resumeSessionId: string | undefined;
  const vendorArgs: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const value = argv[index + 1];
    switch (option) {
      case "--id":
        if (id !== undefined || value === undefined) return null;
        id = value;
        index += 1;
        break;
      case "--cli":
        if (cli !== undefined || value === undefined || !isCli(value))
          return null;
        cli = value;
        index += 1;
        break;
      case "--cols": {
        if (cols !== undefined) return null;
        const parsedCols = parseDimension(value);
        if (parsedCols === null) return null;
        cols = parsedCols;
        index += 1;
        break;
      }
      case "--rows": {
        if (rows !== undefined) return null;
        const parsedRows = parseDimension(value);
        if (parsedRows === null) return null;
        rows = parsedRows;
        index += 1;
        break;
      }
      case "--cwd":
        if (
          cwd !== undefined ||
          value === undefined ||
          value.length < 1 ||
          value.length > 1024 ||
          value.includes("\0") ||
          !isAbsolute(value)
        )
          return null;
        cwd = value;
        index += 1;
        break;
      case "--title":
        if (
          title !== undefined ||
          value === undefined ||
          value.length > 80 ||
          value.includes("\0")
        )
          return null;
        title = value;
        index += 1;
        break;
      case "--dangerous":
        if (dangerous) return null;
        dangerous = true;
        break;
      case "--resume":
        if (
          resumeSessionId !== undefined ||
          value === undefined ||
          !RESUME_ID_PATTERN.test(value)
        )
          return null;
        resumeSessionId = value;
        index += 1;
        break;
      case "--vendor-arg":
        if (
          value === undefined ||
          vendorArgs.length >= 64 ||
          !validVendorArg(value)
        )
          return null;
        vendorArgs.push(value);
        index += 1;
        break;
      default:
        return null;
    }
  }
  if (id === undefined || !SESSION_ID_PATTERN.test(id) || cli === undefined)
    return null;
  return {
    id,
    cli,
    ...(cols === undefined ? {} : { cols }),
    ...(rows === undefined ? {} : { rows }),
    ...(cwd === undefined ? {} : { cwd }),
    ...(title === undefined ? {} : { title }),
    dangerous,
    ...(resumeSessionId === undefined ? {} : { resumeSessionId }),
    vendorArgs,
  };
};

export const sessionHostDir = (id: string): string =>
  join(stateDir(), "sessions", id);
export const sessionHostSocketPath = (id: string): string =>
  join(sessionHostDir(id), "ctl.sock");

class SessionHostStream implements TSessionStream {
  private readonly dataHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly ctrlHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly resetHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly endHandlers = new Set<() => void>();
  private resetSent = false;

  constructor(private readonly socket: TSocket) {}

  write = (bytes: Uint8Array): Promise<void> => {
    const status = this.socket.sendBinary(bytes);
    if (status > 0) return Promise.resolve();
    if (status === 0)
      return Promise.reject(new Error("session host socket send failed"));
    return new Promise<void>((resolve, reject) => {
      this.socket.data.drainWaiters.add({ resolve, reject });
    });
  };

  sendCtrl = (payload: Uint8Array): void => {
    const decoded = decodeJsonPayload(payload);
    if (decoded !== undefined)
      this.socket.sendText(JSON.stringify({ t: "ctrl", p: decoded }));
  };

  reset = (payload?: Uint8Array): void => {
    if (this.resetSent) return;
    this.resetSent = true;
    this.socket.sendText(
      JSON.stringify({
        t: "reset",
        p: sessionHostResetPayload(payload),
      }),
    );
    this.socket.close();
  };

  end = (): void => this.socket.close();
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
  receiveData = (payload: Uint8Array): void => {
    for (const handler of this.dataHandlers) handler(payload);
  };
  receiveCtrl = (payload: unknown): void => {
    for (const handler of this.ctrlHandlers)
      handler(encodeJsonPayload(payload));
  };
  closed = (): void => {
    if (this.resetSent) {
      for (const handler of this.resetHandlers) handler(new Uint8Array());
      return;
    }
    for (const handler of this.endHandlers) handler();
  };
}

const protocolError = (socket: TSocket): void => {
  const stream = socket.data.stream ?? new SessionHostStream(socket);
  socket.data.stream = stream;
  stream.reset(encodeJsonPayload({ code: "protocol_error" }));
};

const parseAttachOpen = (
  value: unknown,
  expected: TSessionHostArgs,
): TSessionStreamOpenPayload | null => {
  if (!isRecord(value)) return null;
  if (
    value.session_id !== expected.id ||
    value.cli !== expected.cli ||
    !isDimension(value.cols) ||
    !isDimension(value.rows) ||
    value.mode !== "attach"
  )
    return null;
  return {
    kind: "session",
    session_id: expected.id,
    cli: expected.cli,
    cols: value.cols,
    rows: value.rows,
    mode: "attach",
  };
};

export type TSessionHostOptions = {
  /** Test seam: production exits after cleanup, tests retain the process. */
  readonly exit?: (code: number) => void;
};

/** Start one durable session host. Kept exportable so tests can use its fake PTY seam. */
export const runSessionHost = async (
  args: TSessionHostArgs,
  options: TSessionHostOptions = {},
): Promise<void> => {
  const directory = sessionHostDir(args.id);
  const root = join(stateDir(), "sessions");
  const claim = join(root, `.${args.id}.claim`);
  const stagingDirectory = join(root, `.${args.id}.${process.pid}.staging`);
  const socketPath = join(stagingDirectory, "ctl.sock");

  let server: Bun.Server<TSocketData> | null = null;
  let pipeServer: TWindowsSessionPipeServer | null = null;
  let activityTimer: ReturnType<typeof setInterval> | null = null;
  let ownerTimer: ReturnType<typeof setInterval> | null = null;
  let cleaned = false;
  let exiting = false;
  let ownsClaim = false;
  let meta: TSessionHostMeta | null = null;
  let published = false;
  const attachedSockets = new Set<TSocket>();

  const fail = (): void => {
    setSessionLifecycleHooks(null);
    closeSession(args.id);
    // A PTY may still owe captured descendants a pending SIGKILL escalation;
    // give it the same bounded settle the clean exit path gets (DSN-7).
    void (async () => {
      await whenAllNativePtysTerminated(PTY_TERMINATE_BUDGET_MS);
      cleanup();
      if (options.exit === undefined) process.exitCode = 1;
      else options.exit(1);
    })();
  };

  const failUnavailable = (detail: string): void => {
    writeSessionHostStartupNack(detail);
    fail();
  };

  const cleanup = (): void => {
    if (cleaned) return;
    cleaned = true;
    if (activityTimer !== null) clearInterval(activityTimer);
    if (ownerTimer !== null) clearInterval(ownerTimer);
    server?.stop(true);
    if (pipeServer !== null) void pipeServer.close(0);
    if (published) rmSync(directory, { recursive: true, force: true });
    rmSync(stagingDirectory, { recursive: true, force: true });
    if (ownsClaim) rmSync(claim, { recursive: true, force: true });
  };

  if (!sessionHostSupported()) {
    failUnavailable(
      "durable session-host is unavailable on this platform or architecture",
    );
    return;
  }
  // Direct broker callers also precede protocol-owned identity/ACL helpers.
  ensureWindowsProcessAdmission();

  // PL-D7/DSN-7: process.exit used to fire before the PTY's 1 s TERM→KILL
  // escalation, so a vendor that traps TERM survived under ppid 1. Every exit
  // path waits — with a bound — for all NativePtys to fully terminate first.
  const settleThenExit = async (code: number): Promise<void> => {
    await whenAllNativePtysTerminated(PTY_TERMINATE_BUDGET_MS);
    cleanup();
    (options.exit ?? process.exit)(code);
  };

  const exit = (): void => {
    if (exiting || cleaned) return;
    exiting = true;
    if (server === null && pipeServer === null) {
      void settleThenExit(0);
      return;
    }
    if (server === null && pipeServer !== null) {
      const currentPipeServer = pipeServer;
      queueMicrotask(async () => {
        try {
          await currentPipeServer.close(EXIT_DRAIN_TIMEOUT_MS);
        } finally {
          await settleThenExit(0);
        }
      });
      return;
    }
    const current = server;
    if (current === null) return;
    // The core calls onEnd before terminalClose sends the exit envelope.
    // Yield that stack, then let the broker sockets flush and close. A forced
    // stop here drops the real shell status and makes the CLI report success.
    queueMicrotask(async () => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          current.stop(false),
          new Promise<void>((resolve) => {
            timer = setTimeout(resolve, EXIT_DRAIN_TIMEOUT_MS);
          }),
        ]);
      } catch {
        // A failed graceful stop still reaches the bounded forced cleanup.
      } finally {
        if (timer !== undefined) clearTimeout(timer);
        await settleThenExit(0);
      }
    });
  };

  const publish = (): void => {
    if (published) return;
    try {
      renameSync(stagingDirectory, directory);
      published = true;
    } catch (error) {
      cleanup();
      throw error;
    }
    rmSync(claim, { recursive: true, force: true });
    ownsClaim = false;
  };

  const writeMeta = (): void => {
    if (meta === null) return;
    const targetDirectory = published ? directory : stagingDirectory;
    const temp = join(targetDirectory, `.meta.json.${process.pid}.tmp`);
    const target = join(targetDirectory, "meta.json");
    try {
      createSessionFile(temp, `${JSON.stringify(meta)}\n`);
      if (process.platform === "win32") {
        let targetExists = false;
        try {
          lstatSync(target);
          targetExists = true;
        } catch (error) {
          if (
            error === null ||
            typeof error !== "object" ||
            !("code" in error) ||
            error.code !== "ENOENT"
          )
            throw error;
        }
        if (targetExists) verifyWindowsSessionFile(target);
      }
      renameSync(temp, target);
    } catch (error) {
      try {
        rmSync(temp, { force: true });
      } catch {
        // Best-effort temp cleanup.
      }
      throw error;
    }
  };

  const recordAttachment = (socket: TSocket, attached: boolean): void => {
    if (attached) attachedSockets.add(socket);
    else attachedSockets.delete(socket);
    if (cleaned || meta === null || meta.attached === attachedSockets.size > 0)
      return;
    meta = { ...meta, attached: attachedSockets.size > 0 };
    try {
      writeMeta();
    } catch {
      // Telemetry persistence must not terminate an otherwise working terminal.
      process.stderr.write("session-host: attachment metadata update failed\n");
    }
  };

  const handleMessage = (
    socket: TSocket,
    message: string | Uint8Array,
  ): void => {
    try {
      const stream = socket.data.stream;
      if (typeof message !== "string") {
        if (!socket.data.opened || stream === null) {
          protocolError(socket);
          return;
        }
        stream.receiveData(message);
        return;
      }
      const envelope: TEnvelope = JSON.parse(message) as TEnvelope;
      if (!socket.data.opened) {
        if (envelope.t !== "open") {
          protocolError(socket);
          return;
        }
        const open = parseAttachOpen(envelope.open, args);
        if (open === null) {
          protocolError(socket);
          return;
        }
        const next = new SessionHostStream(socket);
        socket.data.stream = next;
        socket.data.opened = true;
        bindSessionStream(next, open, {
          onExit: (code) =>
            socket.sendText(JSON.stringify({ t: "exit", code })),
        });
        recordAttachment(socket, true);
        return;
      }
      if (envelope.t === "ctrl" && stream !== null)
        stream.receiveCtrl(envelope.p);
    } catch {
      protocolError(socket);
    }
  };

  const handleClosed = (socket: TSocket): void => {
    const waiters = [...socket.data.drainWaiters];
    socket.data.drainWaiters.clear();
    for (const waiter of waiters)
      waiter.reject(new Error("session host socket closed"));
    socket.data.stream?.closed();
    recordAttachment(socket, false);
  };

  // Own identity must be known BEFORE claiming: the claim records it so a
  // crashed host's leftover claim is provably dead and reapable by the CLI.
  let ownProcessStartTime: string;
  try {
    const identity = processStartTime();
    if (identity === null) {
      fail();
      return;
    }
    ownProcessStartTime = identity;
  } catch (error) {
    failUnavailable(error instanceof Error ? error.message : String(error));
    return;
  }

  try {
    if (process.platform === "win32") {
      if (existsSync(root)) secureSessionDirectory(root);
      else createSessionDirectory(root);
      createSessionDirectory(claim);
    } else {
      mkdirSync(root, { recursive: true, mode: SESSION_DIR_MODE });
      mkdirSync(claim, { mode: SESSION_DIR_MODE });
    }
    ownsClaim = true;
    // Claim ownership record (S7 contract): the CLI reaps a stale claim only
    // when this owner is provably dead by pid + start identity. Published
    // atomically — temp + rename INSIDE the claim dir — so a scan never
    // observes a torn owner.json, and the claim is only "owned" once the
    // record has fully landed.
    writeSessionHostOwnerRecord(claim, args.cli, ownProcessStartTime);
  } catch (error) {
    if (process.platform === "win32") {
      failUnavailable(error instanceof Error ? error.message : String(error));
      return;
    }
    fail();
    return;
  }

  if (existsSync(directory)) {
    fail();
    return;
  }

  try {
    rmSync(stagingDirectory, { recursive: true, force: true });
    if (process.platform === "win32") createSessionDirectory(stagingDirectory);
    else {
      mkdirSync(stagingDirectory, { mode: SESSION_DIR_MODE });
      chmodSync(stagingDirectory, SESSION_DIR_MODE);
    }
    // The staging dir carries the same ownership record the claim does, so a
    // pid reused mid-launch cannot pass for this host. It travels into the
    // published dir with the atomic rename.
    writeSessionHostOwnerRecord(
      stagingDirectory,
      args.cli,
      ownProcessStartTime,
    );
  } catch (error) {
    if (!sessionHostSupported()) {
      failUnavailable(error instanceof Error ? error.message : String(error));
      return;
    }
    fail();
    return;
  }

  setSessionLifecycleHooks({
    onSpawn: (session) => {
      const token = sessionHostLaunchToken();
      meta = {
        id: args.id,
        cli: args.cli,
        cwd: session.cwd,
        pid: process.pid,
        vendorSessionId: session.vendorSessionId,
        title: session.title,
        startedAtMs: session.startedAtMs,
        processStartTime: ownProcessStartTime,
        generation: session.generation,
        ...(token === null ? {} : { launchToken: token }),
        attached: attachedSockets.size > 0,
      };
      writeMeta();
    },
    onEnd: () => exit(),
  });

  let spawnFailed = false;
  // Native PTY startup yields before onSpawn writes metadata. Keep our
  // claim and staging directory until the spawn has actually settled.
  await openSession(
    {
      session_id: args.id,
      cli: args.cli,
      cols: args.cols ?? 80,
      rows: args.rows ?? 24,
      mode: "spawn",
      ...(args.cwd === undefined ? {} : { cwd: args.cwd }),
      ...(args.title === undefined ? {} : { title: args.title }),
      ...(args.dangerous ? { dangerous: true } : {}),
      ...(args.resumeSessionId === undefined
        ? {}
        : { resume_session_id: args.resumeSessionId }),
    },
    {
      vendorArgs: args.vendorArgs,
      onAck: (ack) => {
        if (!ack.ok) spawnFailed = true;
      },
    },
  );
  // A short-lived PTY can call onEnd while openSession is still settling.
  if (cleaned) return;
  if (spawnFailed || meta === null) {
    fail();
    return;
  }

  try {
    if (process.platform === "win32") {
      const endpoint = localSessionEndpoint(
        join(directory, "ctl.sock"),
        "win32",
      );
      pipeServer = createWindowsSessionPipeServer(
        endpoint,
        (connection): void => {
          let closeTimer: ReturnType<typeof setTimeout> | null = null;
          let closeRequested = false;
          const data: TSocketData = {
            stream: null,
            opened: false,
            drainWaiters: new Set(),
          };
          const socket: TSocket = {
            data,
            sendBinary: (bytes): number => {
              try {
                return connection.write(
                  encodeSessionPipeFrame({ kind: "binary", payload: bytes }),
                );
              } catch {
                return 0;
              }
            },
            sendText: (text): number => {
              try {
                return connection.write(
                  encodeSessionPipeFrame({ kind: "text", payload: text }),
                );
              } catch {
                return 0;
              }
            },
            close: (): void => {
              if (closeRequested) return;
              closeRequested = true;
              closeTimer = setTimeout(
                () => connection.close(),
                EXIT_DRAIN_TIMEOUT_MS,
              );
              closeTimer.unref?.();
            },
          };
          connection.onDrain(() => {
            const waiters = [...socket.data.drainWaiters];
            socket.data.drainWaiters.clear();
            for (const waiter of waiters) waiter.resolve();
          });
          const decoder = new SessionPipeFrameDecoder();
          connection.onData((chunk): void => {
            try {
              for (const frame of decoder.push(chunk)) {
                if (
                  frame.kind === "text" &&
                  frame.payload === SESSION_PIPE_DRAIN_ACK
                ) {
                  if (closeTimer !== null) clearTimeout(closeTimer);
                  connection.close();
                  continue;
                }
                handleMessage(socket, frame.payload);
              }
            } catch {
              protocolError(socket);
            }
          });
          connection.onClose(() => handleClosed(socket));
        },
      );
      createSessionFile(socketPath, `${endpoint}\n`);
    } else {
      server = Bun.serve({
        unix: socketPath,
        fetch: (request, current): Response | undefined => {
          if (request.method !== "GET")
            return new Response("not found", { status: 404 });
          return current.upgrade(request, {
            data: { stream: null, opened: false, drainWaiters: new Set() },
          })
            ? undefined
            : new Response("websocket upgrade failed", { status: 400 });
        },
        websocket: {
          open: (socket): void => {
            socket.binaryType = "uint8array";
          },
          drain: (socket): void => {
            const waiters = [...socket.data.drainWaiters];
            socket.data.drainWaiters.clear();
            for (const waiter of waiters) waiter.resolve();
          },
          message: (socket, message): void =>
            handleMessage(
              socket,
              typeof message === "string" ? message : new Uint8Array(message),
            ),
          close: (socket): void => {
            handleClosed(socket);
          },
        },
      });
    }
    publish();
  } catch (error) {
    process.stderr.write(
      `session-host: control endpoint startup failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    fail();
    return;
  }

  activityTimer = setInterval(
    () => void pollSessionActivity(),
    ACTIVITY_POLL_MS,
  );
  activityTimer.unref?.();
  const shutdown = (): void => {
    closeSession(args.id);
    exit();
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  // The trace harness marks only its source-client children. A host launched
  // from that client may be detached, so it must reap itself when that exact
  // owner exits rather than relying on broad session-directory cleanup.
  const ownerPid = Number.parseInt(
    process.env.OPENLLM_SESSION_HOST_OWNER_PID ?? "",
    10,
  );
  if (Number.isSafeInteger(ownerPid) && ownerPid > 1) {
    ownerTimer = setInterval((): void => {
      try {
        process.kill(ownerPid, 0);
      } catch {
        shutdown();
      }
    }, 100);
    ownerTimer.unref?.();
  }
};

/** Entry for the hidden `openllmd __session-host` subcommand. */
export const runSessionHostProcess = (argv: readonly string[]): boolean => {
  const args = parseSessionHostArgs(argv);
  if (args === null) {
    process.stderr.write(
      "usage: openllmd __session-host --id <id> --cli <cli> [--cols <n> --rows <n> --cwd <dir> --title <title> --dangerous --resume <vendorId> --vendor-arg <arg>]\n",
    );
    process.exitCode = 2;
    // `runCli` false means "boot the daemon". This internal command was
    // handled even when malformed, so it must never fall through to that path.
    return true;
  }
  void runSessionHost(args).catch((error: unknown) => {
    process.stderr.write(
      `__session-host: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exit(1);
  });
  return true;
};
