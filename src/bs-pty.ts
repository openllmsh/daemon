import { spawn as admittedSpawn } from "./windows-process";
/**
 * Host PTY backend over a BridgeSessions session-worker.
 *
 * Replaces in-process `Bun.Terminal` with the same worker the `bs` mesh uses:
 * a detached process that owns forkpty, named reattach, and scrollback.
 * Browser mux still attaches through session-host; only the PTY owner changes.
 *
 * POSIX-only — `bridgesessions session-worker` is not built on Windows.
 */

import { nodeSpawnSync as spawnSync, ensureWindowsProcessAdmission } from "./windows-process";
import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { executableName } from "@openllmsh/protocol/local-runtime";
import { createConnection, type Socket } from "node:net";
import { Schema } from "effect";
import { DAEMON_VERSION as build } from "./version";
import {
  WMSG,
  WORKER_PROTOCOL_VERSION,
  commandFromArgv,
  decodeWorkerFrames,
  encodeResizePayload,
  encodeWorkerFrame,
  parseDiedPayload,
  parseReadyPayload,
  parseWorkerHello,
} from "./bs-pty-codec";
import { stateDir } from "./env";
import { logInfo, logWarn } from "./logger";

/** Mirrored from `@openllmsh/protocol` `BS_CAP` until that tag is published. */
export const BS_CAP = "bs1";

type TPtySpawnArgs = {
  readonly argv: ReadonlyArray<string>;
  readonly cwd: string;
  readonly env: Record<string, string>;
  readonly cols: number;
  readonly rows: number;
  readonly onData: (chunk: Uint8Array) => void;
  readonly onExit: (exitCode?: number) => void;
};

export type TPtyBackend = "bun" | "bridgesessions" | "conpty";

/** Match BridgeSessions create_session_hosted: 12s adaptive budget. */
const SOCKET_WAIT_MS = 12_000;
/** macOS `sun_path` is 104 bytes, including the trailing NUL. */
const UNIX_PATH_MAX = 104;
const INPUT_MAX_BYTES = 64 * 1024;
const INPUT_MAX_AGE_MS = 5_000;
const STDERR_MAX_BYTES = 8 * 1024;

let binaryCache: string | null | undefined;

const which = (name: string): string | null => {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (dir.length === 0) continue;
    const candidate = resolve(dir, executableName(name));
    if (existsSync(candidate)) return candidate;
  }
  return null;
};

export const bundledBsPath = (executable: string = process.execPath): string =>
  join(dirname(executable), executableName("bridgesessions"));

const candidateBinaries = (): readonly string[] => {
  const override = process.env.OPENLLM_BS_BIN?.trim();
  const home = process.env.HOME?.trim() || homedir();
  return [
    ...(override !== undefined && override.length > 0 && isAbsolute(override)
      ? [override]
      : []),
    bundledBsPath(),
    ...[which("bs"), which("bridgesessions")].filter(
      (value): value is string => value !== null,
    ),
    join(home, ".local", "bin", "bs"),
    join(home, ".local", "bin", "bridgesessions"),
  ];
};

const probeBinary = (bin: string): string | null => {
  try {
    const result = spawnSync(bin, ["--version"], {
      timeout: 500,
      killSignal: "SIGKILL",
      maxBuffer: 4096,
      encoding: "utf8",
      // Node accepts a minimal environment; Next adds NODE_ENV to ProcessEnv.
      env: workerEnv({}) as NodeJS.ProcessEnv,
    });
    return result.status === 0 && result.error === undefined
      ? `${result.stdout}\n${result.stderr}`
      : null;
  } catch {
    return null;
  }
};

type TBinaryProbe = (bin: string) => string | null;
let binaryProbe: TBinaryProbe = probeBinary;

/** Absolute path of a version-probed `bs` / `bridgesessions` binary, or null. */
export const resolveBsBinary = (): string | null => {
  if (binaryCache !== undefined) return binaryCache;
  for (const candidate of new Set(candidateBinaries())) {
    if (!existsSync(candidate)) continue;
    const output = binaryProbe(candidate);
    if (
      output !== null &&
      output.length <= 8192 &&
      /(?:^|\s)v?\d{1,4}\.\d{1,3}\.\d{1,3}(?:[-+][A-Za-z0-9.-]+)?(?=\s|$)/m.test(
        output,
      )
    ) {
      binaryCache = candidate;
      return candidate;
    }
  }
  binaryCache = null;
  return null;
};

/** Test seam: inject the version probe without executing a host binary. */
export const setBsBinaryProbeForTest = (probe: TBinaryProbe | null): void => {
  binaryProbe = probe ?? probeBinary;
  resetBsBinaryCache();
};

/** Test seam: drop the resolved-binary memo. */
export const resetBsBinaryCache = (): void => {
  binaryCache = undefined;
};

export const bridgesessionsAvailable = (): boolean =>
  process.platform !== "win32" && resolveBsBinary() !== null;

/** Unset / auto prefers BridgeSessions; an explicit request fails closed. */
export const requestedPtyBackend = (): TPtyBackend => {
  const raw = process.env.OPENLLM_PTY_BACKEND?.trim().toLowerCase();
  if (raw === "conpty") return "conpty";
  if (raw === "bun") return "bun";
  if (raw === "bridgesessions") return "bridgesessions";
  if (process.platform === "win32") return "conpty";
  return bridgesessionsAvailable() ? "bridgesessions" : "bun";
};

const sanitizeSessionName = (id: string): string =>
  id.replace(/[^A-Za-z0-9._-]/g, "_");

/** Reject pre-existing permissive directories and symlinks instead of repairing them. */
const privateDirectory = (path: string): string => {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (
    !stat.isDirectory() ||
    (stat.mode & 0o777) !== 0o700 ||
    stat.uid !== process.geteuid?.()
  ) {
    throw new Error(`unsafe bridgesessions socket directory: ${path}`);
  }
  return realpathSync(path);
};

const fitsSocketPath = (path: string): boolean =>
  Buffer.byteLength(path) < UNIX_PATH_MAX;

export const workerSocketPath = (sessionId: string): string => {
  const root = join(stateDir(), "run", "bs-pty");
  const safe = sanitizeSessionName(sessionId);
  const digest = createHash("sha256")
    .update(`${resolve(root)}\0${sessionId}`)
    .digest("hex")
    .slice(0, 16);
  const preferred = join(root, `${safe}.sock`);
  if (fitsSocketPath(preferred)) {
    const path = join(privateDirectory(root), `${safe}.sock`);
    if (fitsSocketPath(path)) return path;
  }
  // A short name often suffices without changing the runtime root.
  if (fitsSocketPath(join(root, `${digest}.sock`))) {
    const path = join(privateDirectory(root), `${digest}.sock`);
    if (fitsSocketPath(path)) return path;
  }
  // Never place fallback sockets in a shared temporary directory. XDG runtime
  // roots and the real HOME must be owned by this user and not writable by peers.
  for (const base of [
    process.env.XDG_RUNTIME_DIR,
    process.env.HOME || homedir(),
  ]) {
    if (base === undefined || !isAbsolute(base)) continue;
    try {
      const canonical = realpathSync(base);
      if (/^\/(?:private\/)?(?:tmp|var\/tmp)(?:\/|$)/.test(canonical)) continue;
      const stat = lstatSync(base);
      if (
        !stat.isDirectory() ||
        stat.uid !== process.geteuid?.() ||
        (stat.mode & 0o022) !== 0
      )
        continue;
      const dir = join(canonical, ".ollm-bs");
      if (!fitsSocketPath(join(dir, `${digest}.sock`))) continue;
      const path = join(privateDirectory(dir), `${digest}.sock`);
      if (fitsSocketPath(path)) return path;
    } catch {
      // Try the next private root; the caller falls back to Bun if none fit.
    }
  }
  throw new Error("no safe bridgesessions socket path fits sun_path");
};

const pidIsAlive = (pid: number): boolean => {
  if (!Number.isSafeInteger(pid) || pid <= 0 || pid > 0x7fffffff) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
};

const readWorkerPid = (socketPath: string): number | null => {
  try {
    const raw = readFileSync(`${socketPath}.pid`, "utf8").trim();
    const pid = /^\d+$/.test(raw) ? Number(raw) : NaN;
    return Number.isSafeInteger(pid) && pid > 0 && pid <= 0x7fffffff
      ? pid
      : null;
  } catch {
    return null;
  }
};

const WorkerCommand = Schema.Struct({
  pid: Schema.Number,
  command: Schema.String,
});

const recordedCommand = (socketPath: string, pid: number): string | null => {
  try {
    const path = `${socketPath}.pid.json`;
    if (lstatSync(path).size > 64 * 1024) return null;
    const record = Schema.decodeUnknownSync(WorkerCommand)(
      JSON.parse(readFileSync(path, "utf8")),
    );
    return record.pid === pid ? record.command : null;
  } catch {
    return null;
  }
};

const unlinkStale = (socketPath: string): void => {
  for (const path of [
    socketPath,
    `${socketPath}.pid`,
    `${socketPath}.pid.json`,
  ]) {
    try {
      unlinkSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
};

/**
 * The worker inherits this environment into its shell: terminal/locale basics
 * plus the two explicit device-session markers needed for CLI live.json.
 * Daemon credentials, provider keys, and runtime loader variables stay out.
 */
export const workerEnv = (
  overrides: Record<string, string>,
  platform: NodeJS.Platform = process.platform,
  inherited: NodeJS.ProcessEnv = process.env,
): Record<string, string> => {
  const env: Record<string, string> = {};
  // Windows environment blocks are case-insensitive. Enumerating ComSpec and
  // COMSPEC through process.env can return the same value twice; emitting both
  // breaks .NET/PowerShell child creation. Normalize each source before merging
  // so an override also wins across casing, without widening the allowlist.
  const normalize = (source: Record<string, string | undefined>): Record<string, string | undefined> => platform === "win32"
    ? Object.fromEntries(Object.entries(source).map(([key, value]) => [key.toUpperCase(), value]))
    : source;
  const base = normalize(inherited), selected = normalize(overrides);
  for (const key of [
    "PATH",
    "HOME",
    "TMPDIR",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SHELL",
    "USER",
    "LOGNAME",
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
  ]) {
    const name = platform === "win32" ? key.toUpperCase() : key;
    const value = selected[name] ?? base[name];
    if (value !== undefined) env[name] = value;
  }
  for (const key of ["OPENLLM_DEVICE_SESSION_ID", "OPENLLM_DEVICE_TITLE"]) {
    if (selected[key] !== undefined) env[key] = selected[key];
  }
  return env;
};

type TWorkerProcess = {
  readonly pid: number;
  readonly stderr: ReadableStream<Uint8Array>;
  unref(): void;
  kill(signal?: NodeJS.Signals): unknown;
};

type TBsPtyOptions = {
  readonly connect: (path: string) => Socket;
  readonly spawn: (
    argv: string[],
    options: {
      cwd: string;
      env: Record<string, string>;
      stdin: "ignore";
      stdout: "ignore";
      stderr: "pipe";
      detached: true;
    },
  ) => TWorkerProcess;
  readonly isAlive: (pid: number) => boolean;
  readonly warn: (message: string) => void;
  readonly now: () => number;
  readonly helloMs: number;
  readonly connectMs: number;
  readonly retryDelays: readonly number[];
  readonly startupMs: number;
};

const defaultOptions: TBsPtyOptions = {
  connect: (path) => createConnection({ path }),
  spawn: (argv, options) => admittedSpawn(argv, options),
  isAlive: pidIsAlive,
  warn: (message) => logWarn("session", message),
  now: Date.now,
  helloMs: 1500,
  connectMs: 300,
  retryDelays: [100, 250, 500],
  startupMs: SOCKET_WAIT_MS,
};

/** One async owner per resolved path; cross-process owners also take O_EXCL. */
const spawning = new Map<string, Promise<void>>();

const serializeSpawn = async <T>(
  path: string,
  action: () => Promise<T>,
): Promise<T> => {
  const previous = spawning.get(path) ?? Promise.resolve();
  let release!: () => void;
  const tail = new Promise<void>((resolve) => {
    release = resolve;
  });
  spawning.set(path, tail);
  await previous;
  try {
    return await action();
  } finally {
    release();
    if (spawning.get(path) === tail) spawning.delete(path);
  }
};

const lockWorker = async (
  path: string,
  deadline: number,
): Promise<() => void> => {
  const lock = `${path}.lock`;
  while (true) {
    let fd: number;
    try {
      fd = openSync(lock, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (Date.now() >= deadline)
        throw new Error(`bridgesessions spawn lock timed out: ${lock}`);
      // Do not steal stale locks: unlink/recreate has a cross-process ABA race.
      await Bun.sleep(25);
      continue;
    }
    try {
      writeFileSync(fd, `${process.pid}\n`);
    } catch (error) {
      closeSync(fd);
      unlinkSync(lock);
      throw error;
    }
    const owned = fstatSync(fd);
    return () => {
      try {
        const current = lstatSync(lock);
        if (current.dev === owned.dev && current.ino === owned.ino)
          unlinkSync(lock);
      } finally {
        closeSync(fd);
      }
    };
  }
};

export class BsPty {
  private socket: Socket | null = null;
  private buffer: Uint8Array = new Uint8Array(0);
  private pending: { frame: Uint8Array; at: number }[] = [];
  private pendingBytes = 0;
  private pendingTimer: ReturnType<typeof setTimeout> | null = null;
  private helloTimer: ReturnType<typeof setTimeout> | null = null;
  private lastResize: { cols: number; rows: number } | null = null;
  private closed = false;
  private connected = false;
  private handshaken = false;
  private blocked = false;
  private recovering = false;
  private childPid: number | null = null;
  private stderr = new Uint8Array(0);
  transportDetached = false;
  legacy = false;
  commandMismatch = false;

  constructor(
    private readonly args: TPtySpawnArgs,
    private readonly socketPath: string,
    private readonly sessionName: string,
    private workerPid: number | null,
    private readonly options: TBsPtyOptions,
  ) {}

  get pid(): number | undefined {
    return this.childPid ?? this.workerPid ?? undefined;
  }

  lastStderr(): string {
    return new TextDecoder().decode(this.stderr);
  }

  /** Drain throughout startup and after detach; never wait for a full pipe. */
  async drainStderr(stream: ReadableStream<Uint8Array>): Promise<void> {
    const reader = stream.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const tail = value.subarray(
          Math.max(0, value.byteLength - STDERR_MAX_BYTES),
        );
        const keep = Math.min(
          this.stderr.byteLength,
          STDERR_MAX_BYTES - tail.byteLength,
        );
        const next = new Uint8Array(keep + tail.byteLength);
        next.set(this.stderr.subarray(this.stderr.byteLength - keep));
        next.set(tail, keep);
        this.stderr = next;
      }
    } catch (error) {
      this.options.warn(`bridgesessions stderr reader error: ${String(error)}`);
    } finally {
      reader.releaseLock();
    }
  }

  write(data: Uint8Array | string): void {
    if (this.closed || this.transportDetached) return;
    const bytes =
      typeof data === "string" ? new TextEncoder().encode(data) : data;
    // Queue complete frames so overflow cannot replay a truncated command.
    if (bytes.byteLength + 5 > INPUT_MAX_BYTES) {
      this.clearPending();
      return;
    }
    this.prunePending();
    const frame = encodeWorkerFrame(WMSG.INPUT, bytes);
    while (this.pendingBytes + frame.byteLength > INPUT_MAX_BYTES)
      this.dropOldest();
    this.pending.push({ frame, at: this.options.now() });
    this.pendingBytes += frame.byteLength;
    this.flushPending();
    this.armPendingTimer();
  }

  resize(cols: number, rows: number): void {
    this.lastResize = { cols, rows };
    if (this.connected && this.handshaken && !this.closed) {
      this.socket?.write(
        encodeWorkerFrame(WMSG.RESIZE, encodeResizePayload(cols, rows)),
      );
    }
  }

  kill(signal: NodeJS.Signals = "SIGTERM"): void {
    if (this.closed) return;
    this.clearPending();
    if (this.connected) this.socket?.write(encodeWorkerFrame(WMSG.SHUTDOWN));
    if (this.workerPid !== null) {
      try {
        process.kill(this.workerPid, signal);
      } catch {
        /* already gone */
      }
    }
    this.socket?.end();
  }

  /** Intentional detach leaves the worker alive and disables automatic reattach. */
  detach(): void {
    if (this.closed) return;
    if (this.connected) this.socket?.write(encodeWorkerFrame(WMSG.DETACH));
    this.closed = true;
    this.transportDetached = true;
    this.clearPending();
    this.clearHello();
    this.socket?.destroy();
    this.socket = null;
  }

  private dropOldest(): void {
    const entry = this.pending.shift();
    if (entry !== undefined) this.pendingBytes -= entry.frame.byteLength;
  }

  private prunePending(): void {
    while (
      this.pending.length > 0 &&
      this.options.now() - this.pending[0]!.at >= INPUT_MAX_AGE_MS
    )
      this.dropOldest();
  }

  private armPendingTimer(): void {
    if (this.pendingTimer !== null) clearTimeout(this.pendingTimer);
    this.pendingTimer = null;
    if (this.pending.length === 0) return;
    this.pendingTimer = setTimeout(
      () => {
        this.pendingTimer = null;
        this.prunePending();
        this.armPendingTimer();
      },
      Math.max(
        1,
        INPUT_MAX_AGE_MS - (this.options.now() - this.pending[0]!.at),
      ),
    );
    this.pendingTimer.unref();
  }

  private clearPending(): void {
    this.pending = [];
    this.pendingBytes = 0;
    if (this.pendingTimer !== null) clearTimeout(this.pendingTimer);
    this.pendingTimer = null;
  }

  private flushPending(): void {
    this.prunePending();
    const socket = this.socket;
    if (
      socket === null ||
      !this.connected ||
      !this.handshaken ||
      !socket.writable ||
      this.blocked ||
      this.closed
    )
      return;
    while (this.pending.length > 0) {
      const entry = this.pending[0]!;
      this.dropOldest();
      if (!socket.write(entry.frame)) {
        this.blocked = true;
        break;
      }
    }
    this.armPendingTimer();
  }

  private clearHello(): void {
    if (this.helloTimer !== null) clearTimeout(this.helloTimer);
    this.helloTimer = null;
    this.handshaken = false;
  }

  private acceptHello(legacy: boolean): void {
    this.clearHello();
    this.legacy = legacy;
    this.handshaken = true;
    if (this.lastResize !== null)
      this.resize(this.lastResize.cols, this.lastResize.rows);
    this.flushPending();
  }

  /** Resolve only after the actual socket connects so spawnHostPty can catch refusals. */
  connect(): Promise<void> {
    privateDirectory(dirname(this.socketPath));
    return new Promise((resolve, reject) => {
      const socket = this.options.connect(this.socketPath);
      this.socket = socket;
      let connected = false;
      const timer = setTimeout(
        () => fail(new Error("bridgesessions connect timed out")),
        this.options.connectMs,
      );
      const fail = (error: Error): void => {
        if (this.socket !== socket) return;
        clearTimeout(timer);
        this.socket = null;
        this.connected = false;
        this.buffer = new Uint8Array(0);
        this.clearHello();
        this.clearPending();
        socket.destroy();
        if (!connected) reject(error);
        else this.transportLost(error);
      };
      socket.on("connect", () => {
        if (this.socket !== socket || this.closed) return;
        clearTimeout(timer);
        connected = true;
        this.connected = true;
        this.blocked = false;
        this.transportDetached = false;
        this.workerPid = readWorkerPid(this.socketPath) ?? this.workerPid;
        this.helloTimer = setTimeout(() => {
          this.options.warn(
            `bridgesessions worker ${this.sessionName} has no HELLO_ACK; using legacy protocol`,
          );
          this.acceptHello(true);
        }, this.options.helloMs);
        socket.write(
          encodeWorkerFrame(
            WMSG.HELLO,
            JSON.stringify({
              version: WORKER_PROTOCOL_VERSION,
              build,
              features: ["reattach", "command-sidecar"],
            }),
          ),
        );
        resolve();
      });
      socket.on("data", (chunk: Buffer) => {
        if (this.socket === socket && !this.closed) this.onChunk(chunk);
      });
      socket.on("drain", () => {
        if (this.socket !== socket) return;
        this.blocked = false;
        this.flushPending();
      });
      socket.on("error", fail);
      socket.on("close", () =>
        fail(new Error("bridgesessions worker socket closed without DIED")),
      );
    });
  }

  private workerIsAlive(): boolean {
    const recorded = readWorkerPid(this.socketPath);
    if (recorded !== null && recorded !== this.workerPid) {
      this.workerPid = recorded;
      // A replacement worker will announce its own child in READY.
      this.childPid = null;
    }
    const pid = recorded ?? this.workerPid ?? this.childPid;
    return (
      pid !== null &&
      this.options.isAlive(pid) &&
      (this.childPid === null || this.options.isAlive(this.childPid))
    );
  }

  private transportLost(error: Error): void {
    if (this.closed) return;
    this.transportDetached = true;
    this.options.warn(error.message);
    if (!this.workerIsAlive()) {
      this.finish(1);
      return;
    }
    if (!this.recovering) void this.reattach();
  }

  private async reattach(): Promise<void> {
    this.recovering = true;
    try {
      for (const delay of this.options.retryDelays) {
        await Bun.sleep(delay);
        if (this.closed) return;
        if (!this.workerIsAlive()) break;
        try {
          await this.connect();
          if (this.connected) return;
        } catch {
          // A live PID alone cannot establish a usable transport; retries are bounded.
        }
      }
      this.finish(1);
    } finally {
      this.recovering = false;
    }
  }

  private onChunk(chunk: Buffer): void {
    const next = new Uint8Array(this.buffer.byteLength + chunk.byteLength);
    next.set(this.buffer);
    next.set(chunk, this.buffer.byteLength);
    try {
      const decoded = decodeWorkerFrames(next);
      this.buffer = decoded.rest;
      for (const message of decoded.messages) {
        if (this.closed) break;
        switch (message.type) {
          case WMSG.OUTPUT:
          case WMSG.SCROLLBACK:
            if (message.data.byteLength > 0) this.args.onData(message.data);
            break;
          case WMSG.READY: {
            const ready = parseReadyPayload(message.data, this.sessionName);
            this.childPid =
              ready.childPid !== null && ready.childPid > 0
                ? ready.childPid
                : null;
            break;
          }
          case WMSG.HELLO_ACK:
            parseWorkerHello(message.data);
            this.acceptHello(false);
            break;
          case WMSG.DIED:
            this.finish(parseDiedPayload(message.data).exitCode);
            break;
          case WMSG.ERROR:
            this.options.warn(
              `bridgesessions worker error: ${new TextDecoder().decode(message.data)}`,
            );
            this.finish(1);
            break;
        }
      }
    } catch (error) {
      this.options.warn(`bridgesessions worker frame error: ${String(error)}`);
      this.finish(1);
    }
  }

  private finish(exitCode: number): void {
    if (this.closed) return;
    this.closed = true;
    this.clearPending();
    this.clearHello();
    this.socket?.destroy();
    this.socket = null;
    this.args.onExit(exitCode);
  }
}

/** Per-call I/O seams keep regression tests independent of a real worker binary. */
export const bsPtySpawner = async (
  args: TPtySpawnArgs,
  overrides: Partial<TBsPtyOptions> = {},
): Promise<BsPty> => {
  const options = { ...defaultOptions, ...overrides };
  const bin = resolveBsBinary();
  if (bin === null)
    throw new Error("BridgeSessions binary not found or failed version probe");
  const name = sanitizeSessionName(
    args.env.OPENLLM_DEVICE_SESSION_ID ||
      `pty-${args.cols}x${args.rows}-${randomUUID()}`,
  );
  const socketPath = workerSocketPath(name);
  const command = commandFromArgv(args.argv);
  return serializeSpawn(socketPath, async () => {
    const deadline = Date.now() + options.startupMs;
    const unlock = await lockWorker(socketPath, deadline);
    let proc: TWorkerProcess | null = null;
    let pty: BsPty | null = null;
    try {
      privateDirectory(dirname(socketPath));
      let workerPid = readWorkerPid(socketPath);
      const attach = workerPid !== null && options.isAlive(workerPid);
      if (!attach) {
        unlinkStale(socketPath);
        ensureWindowsProcessAdmission();
        proc = options.spawn(
          [
            bin,
            "session-worker",
            "--socket",
            socketPath,
            "--name",
            name,
            "--command",
            command,
            "--cols",
            String(args.cols),
            "--rows",
            String(args.rows),
            "--term",
            "xterm-256color",
            "--app-home",
            stateDir(),
          ],
          {
            cwd: args.cwd,
            env: workerEnv(args.env),
            stdin: "ignore",
            stdout: "ignore",
            stderr: "pipe",
            detached: true,
          },
        );
        workerPid = proc.pid;
      }
      pty = new BsPty(args, socketPath, name, workerPid, options);
      if (proc !== null) {
        void pty.drainStderr(proc.stderr);
        proc.unref();
        let delay = 25;
        while (!existsSync(socketPath) || readWorkerPid(socketPath) === null) {
          if (Date.now() >= deadline || !options.isAlive(proc.pid)) {
            throw new Error(
              `bridgesessions session-worker did not bind ${socketPath}`,
            );
          }
          await Bun.sleep(delay);
          delay = Math.min(delay * 2, 500);
        }
        workerPid = readWorkerPid(socketPath);
        // The C++ worker owns the numeric .pid file. Pair adapter metadata with
        // that PID so an old record cannot describe a replacement worker.
        writeFileSync(
          `${socketPath}.pid.json`,
          JSON.stringify({ pid: workerPid, command }),
          { mode: 0o600 },
        );
      } else if (workerPid !== null) {
        const recorded = recordedCommand(socketPath, workerPid);
        pty.commandMismatch = recorded !== null && recorded !== command;
        if (pty.commandMismatch) {
          options.warn(
            `bridgesessions command mismatch on attach to ${name}; preserving existing worker`,
          );
        } else if (recorded === null) {
          options.warn(
            `bridgesessions command unknown on legacy attach to ${name}`,
          );
        }
      }
      await pty.connect();
      logInfo(
        "session",
        attach
          ? "bridgesessions session-worker reattached"
          : "bridgesessions session-worker started",
        {
          name,
          socket: socketPath,
        },
      );
      return pty;
    } catch (error) {
      pty?.detach();
      try {
        proc?.kill("SIGTERM");
      } catch {
        /* already gone */
      }
      throw error;
    } finally {
      unlock();
    }
  });
};
