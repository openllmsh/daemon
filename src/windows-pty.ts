import { spawn as admittedSpawn } from "./windows-process";
import { windowsWorkerPath } from "@openllmsh/protocol/local-runtime";
import { stateDir } from "./env";
import { workerEnv } from "./bs-pty";
import { DAEMON_VERSION } from "./version";
import { validWindowsAdmission, signedWindowsExitCode } from "./windows-process";

const WINDOWS_PTY_KILL_GRACE_MS = 250;

type Args = {
  argv: readonly string[]; cwd: string; env: Record<string, string>;
  cols: number; rows: number;
  onData: (bytes: Uint8Array) => void; onExit: (code?: number) => void;
};

/** A durable session host owns this ConPTY worker across daemon/CLI reconnects. */
export const windowsPtySpawner = async (args: Args) => {
  const bin = windowsWorkerPath(stateDir());
  if (!bin) throw new Error("Native Windows ConPTY worker is not installed");
  const proc = admittedSpawn([bin, "--pty", String(args.cols), String(args.rows), ...args.argv], {
    cwd: args.cwd, env: workerEnv(args.env), stdin: "pipe", stdout: "pipe", stderr: "pipe",
    windowsHide: true,
  });
  let ready = false, ended = false, childPid = 0;
  let workerExited = false, killRequested = false, forceKillRequested = false;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const clearKillTimer = (): void => {
    if (killTimer === undefined) return;
    clearTimeout(killTimer);
    killTimer = undefined;
  };
  const forceKill = (): void => {
    if (workerExited || forceKillRequested) return;
    forceKillRequested = true;
    clearKillTimer();
    try {
      proc.kill("SIGKILL");
    } catch {
      // The worker may have exited between the promise and this escalation.
    }
  };
  let accept!: () => void, reject!: (error: Error) => void;
  const started = new Promise<void>((resolve, fail) => { accept = resolve; reject = fail; });
  const finish = (code: number) => {
    if (ended) return;
    ended = true;
    if (!ready) reject(new Error(`ConPTY worker exited before ready (${code})`));
    else args.onExit(code);
  };
  // Drain diagnostics without retaining command/environment text in the daemon.
  void (async () => { for await (const _chunk of proc.stderr) { /* bounded by pipe consumption */ } })();
  const outputDone = (async () => {
    let buffer = "";
    for await (const chunk of proc.stdout) {
      buffer += new TextDecoder().decode(chunk);
      if (buffer.length > 1024 * 1024) throw new Error("ConPTY output frame exceeds limit");
      for (;;) {
        const end = buffer.indexOf("\n"); if (end < 0) break;
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        const msg = JSON.parse(line);
        if (msg.t === "ready") {
          if (ready || msg.version !== DAEMON_VERSION || !Number.isInteger(msg.pid) || msg.pid <= 0 || !validWindowsAdmission(msg.admission))
            throw new Error("ConPTY worker identity/version mismatch");
          childPid = msg.pid; ready = true; accept();
        } else if (msg.t === "output" && ready && typeof msg.data === "string") {
          args.onData(Buffer.from(msg.data, "base64"));
        } else if (msg.t === "exit" && ready && Number.isInteger(msg.code) && msg.code >= -0x80000000 && msg.code <= 0x7fffffff) {
          finish(msg.code);
        } else throw new Error("Invalid ConPTY worker frame");
      }
    }
  })();
  void outputDone.catch(() => { forceKill(); finish(1); });
  void proc.exited.then(async (code) => {
    workerExited = true;
    clearKillTimer();
    await outputDone.catch(() => {});
    finish(signedWindowsExitCode(code) || 1);
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([started, new Promise<never>((_, fail) => {
      timer = setTimeout(() => fail(new Error("ConPTY worker startup timed out")), 10000);
    })]);
  } catch (error) { forceKill(); throw error; }
  finally { if (timer) clearTimeout(timer); }
  const send = (value: unknown) => {
    if (ended) return;
    proc.stdin.write(`${JSON.stringify(value)}\n`);
    proc.stdin.flush();
  };
  const kill = (signal: NodeJS.Signals = "SIGTERM"): void => {
    if (workerExited || forceKillRequested) return;
    if (signal === "SIGKILL") {
      forceKill();
      return;
    }
    if (ended || killRequested) return;
    killRequested = true;
    try {
      send({ t: "kill" });
    } catch {
      forceKill();
      return;
    }
    if (workerExited || forceKillRequested) return;
    killTimer = setTimeout(forceKill, WINDOWS_PTY_KILL_GRACE_MS);
    killTimer.unref?.();
  };
  return {
    pid: childPid,
    write: (data: string | Uint8Array) => {
      const bytes = Buffer.from(data);
      for (let offset = 0; offset < bytes.length; offset += 65536)
        send({ t: "input", data: bytes.subarray(offset, offset + 65536).toString("base64") });
    },
    resize: (cols: number, rows: number) => send({ t: "resize", cols, rows }),
    kill,
  };
};
