import { dirname, join } from "node:path";
import { DAEMON_VERSION } from "../version";
import { spawn, signedWindowsExitCode, validWindowsAdmission } from "../windows-process";

const WINDOWS_TASK_INPUT_LIMIT = 65536;
// C# returns a signed int; Windows/Bun can expose its DWORD unsigned. Validate
// before conversion: JS bitwise coercion would accept malformed status aliases.
const validWindowsStatus = (code: unknown): code is number =>
  typeof code === "number" && Number.isInteger(code) && code >= -0x80000000 && code <= 0xffffffff;

const confinedTaskExit = (
  failed: boolean,
  exit: number | undefined,
  workerExit: number | null | undefined,
): number => {
  if (failed || !validWindowsStatus(exit) || !validWindowsStatus(workerExit)) return 78;
  if ((workerExit >>> 0) !== (exit >>> 0)) return 78;
  // Canonical signed form: NTSTATUS semantics, matching signedWindowsExitCode.
  return exit | 0;
};

export const validWindowsTaskDesktop = (frame: { desktop_mode?: unknown; win32k_disabled?: unknown }): boolean =>
  (frame.desktop_mode === "private" && frame.win32k_disabled === false) ||
  (frame.desktop_mode === "headless" && frame.win32k_disabled === true);

export const validWindowsTaskReady = (frame: {
  version?: unknown; profile?: unknown; appcontainer?: unknown; network?: unknown;
  declared_handles?: unknown; pid?: unknown; creation_job?: unknown;
  active_process_limit?: unknown; stdin_kind?: unknown;
  desktop_mode?: unknown; win32k_disabled?: unknown;
}, version: string): boolean =>
  frame.version === version &&
  frame.profile === "windows-cmd-v1" &&
  frame.appcontainer === true &&
  frame.network === "none" &&
  frame.declared_handles === 3 &&
  Number.isInteger(frame.pid) && Number(frame.pid) > 0 &&
  validWindowsTaskDesktop(frame) &&
  frame.creation_job === true &&
  frame.active_process_limit === 16 &&
  frame.stdin_kind === "pipe";

const validateWindowsTaskInput = (script: Uint8Array): void => {
  if (!script.length || script.length > WINDOWS_TASK_INPUT_LIMIT || script.some(byte => byte === 0 || byte > 127))
    throw new Error("windows-cmd-v1 requires nonempty ASCII command input");
};

/** Fixed uncredentialed native operation. No inherited credential environment,
 * host-path grants, tool selector or network capability enters the workload. */
export async function runWindowsConfinedTask(): Promise<number> {
  if (process.platform !== "win32") throw new Error("Windows AppContainer is required");
  const chunks: Uint8Array[] = []; let size = 0;
  for await (const chunk of Bun.stdin.stream()) {
    size += chunk.length;
    if (size > WINDOWS_TASK_INPUT_LIMIT) throw new Error("Task input exceeds 64 KiB");
    chunks.push(chunk);
  }
  const script = Buffer.concat(chunks);
  validateWindowsTaskInput(script);
  // Compiled package sibling only. Vendor/probe worker overrides cannot choose
  // the required-confinement backend. Missing packaging fails closed.
  const worker = join(dirname(process.execPath), "openllm-windows-worker.exe");
  const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
  if (!systemRoot) throw new Error("Windows system root unavailable");
  const proc = spawn([worker, "--appcontainer-cmd"], {
    env: { SystemRoot: systemRoot, WINDIR: systemRoot },
    // Keep the native cleanup controller out of the caller's console/process
    // group. Its private control pipe still observes caller death as EOF.
    stdin: "pipe", stdout: "pipe", stderr: "pipe", windowsHide: true, detached: true,
  });
  let ready = false, exit: number | undefined, failed = false, outputBytes = 0;
  const cancel = () => { try { proc.stdin.write('{"t":"cancel"}\n'); proc.stdin.flush(); } catch {} };
  const signals = ["SIGTERM", "SIGINT", "SIGHUP"] as const;
  for (const signal of signals) process.on(signal, cancel);
  const hardStop = setTimeout(() => { failed = true; proc.stdin.end(); setTimeout(() => proc.kill(), 6000).unref(); }, 70_000);
  proc.stdin.write(JSON.stringify({ v: 1, profile: "windows-cmd-v1", script: script.toString("base64") }) + "\n");
  proc.stdin.flush();
  // Worker diagnostics are bounded and never include the input command.
  const diagnostics = (async () => { let bytes = 0; for await (const chunk of proc.stderr) { bytes += chunk.length; if (bytes > 65536) { failed = true; cancel(); } } })();
  try {
    let pending = ""; const decoder = new TextDecoder();
    for await (const chunk of proc.stdout) {
      pending += decoder.decode(chunk, {stream:true});
      if (pending.length > 131072) throw new Error("Task protocol frame too large");
      for (;;) {
        const end = pending.indexOf("\n"); if (end < 0) break;
        const frame = JSON.parse(pending.slice(0,end)); pending = pending.slice(end+1);
        if (frame.t === "ready" && !ready && exit === undefined) {
          if (!validWindowsTaskReady(frame, DAEMON_VERSION) || !validWindowsAdmission(frame.admission))
            throw new Error("AppContainer worker attestation/version mismatch");
          ready = true; process.stderr.write(`openllmd confined-task: ${JSON.stringify(frame)}\n`);
        } else if (frame.t === "output" && ready && exit === undefined && ["stdout","stderr"].includes(frame.stream) && typeof frame.data === "string") {
          const bytes = Buffer.from(frame.data,"base64"); outputBytes += bytes.length;
          if (bytes.toString("base64") !== frame.data || outputBytes > 1048576) throw new Error("Invalid task output bound/encoding");
          (frame.stream === "stdout" ? process.stdout : process.stderr).write(bytes);
        // The Job's associated-PID inventory can retain exiting processes.
        // Match native JobPids' bounded inventory, not the kernel's separate
        // active-process limit of 16 (which remains enforced by the worker).
        } else if (frame.t === "members" && ready && exit === undefined && frame.appcontainer === true && frame.same_package === true && Array.isArray(frame.pids) && frame.pids.length <= 64 && frame.pids.every((pid: unknown) => Number.isInteger(pid) && Number(pid) > 0)) {
          process.stderr.write(`openllmd confined-task: ${JSON.stringify(frame)}\n`);
        } else if (frame.t === "exit" && exit === undefined && validWindowsStatus(frame.code)) {
          if (!ready || frame.cleanup !== true || frame.remaining !== 0) failed = true;
          exit = frame.code; process.stderr.write(`openllmd confined-task: ${JSON.stringify(frame)}\n`);
        } else if (frame.t === "error") {
          failed = true;
          // The shipped worker emits fixed operation labels/exception types,
          // never the command or environment. Keep bounded setup diagnostics
          // so an installed-path failure can be repaired without a bypass.
          const operation = typeof frame.operation === "string" && /^[A-Za-z0-9 .:()_-]{1,160}$/.test(frame.operation) ? `: ${frame.operation}` : "";
          process.stderr.write(`AppContainer worker rejected the task${operation}\n`);
        }
        else throw new Error("Invalid task protocol sequence");
      }
    }
    if (pending.trim()) throw new Error("Truncated task protocol frame");
  } catch { failed = true; cancel(); }
  finally { proc.stdin.end(); }
  const workerExit = await proc.exited;
  await diagnostics;
  clearTimeout(hardStop);
  for (const signal of signals) process.off(signal, cancel);
  return confinedTaskExit(failed, exit, workerExit);
}
