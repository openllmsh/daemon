// Runs in an isolated test process: no Windows host or real Windows child.
import { spyOn } from "bun:test";
const ffi = require("bun:ffi") as typeof import("bun:ffi");
import { runWindowsConfinedTask } from "../windows-task";
import { DAEMON_VERSION } from "../../version";
import { spawn as admittedSpawn, spawnSync as admittedSpawnSync } from "../../windows-process";
import { sandboxSpawnArgs, runSandboxExec } from "../exec";
import * as localRuntime from "@openllmsh/protocol/local-runtime";
import { windowsPtySpawner } from "../../windows-pty";

const mode = process.argv[2];
const events: Array<{ t: "start" | "stop"; pid: number; role: string }> = [];
const live = new Map<number, string>();
let nextPid = 1, limit = Infinity, assigned = false, launches = 0;
const calls: string[] = [];
const argvs: unknown[] = [];
const workerFrames: any[] = [];
const start = (role: string): number | undefined => {
  if (assigned && live.size >= limit) return undefined;
  const pid = nextPid++; live.set(pid, role); events.push({ t: "start", pid, role }); return pid;
};
const stop = (pid: number) => { const role = live.get(pid)!; live.delete(pid); events.push({ t: "stop", pid, role }); };
start("caller");
const view = (p: number, bytes: number) => new DataView(ffi.toArrayBuffer(p, 0, bytes));
spyOn(ffi, "dlopen").mockImplementation((() => ({ symbols: {
  GetCurrentProcess: () => 0xffffffffffffffffn,
  GetLastError: () => 5,
  CreateJobObjectW: () => { calls.push("create"); return mode.endsWith("create-failure") ? 0n : 42n; },
  SetInformationJobObject: (_job: bigint, kind: number, p: number, bytes: number) => {
    calls.push("limit");
    if (mode === "limit-failure") return 0;
    if (kind !== 9 || bytes !== 144) throw new Error("invalid Windows x64 Job ABI");
    const b = view(p, bytes), flags = b.getUint32(16, true);
    if (!(flags & 8) || flags & 0x1800) throw new Error("missing active limit or breakaway enabled");
    limit = b.getUint32(40, true); return 1;
  },
  AssignProcessToJobObject: () => { calls.push("assign-caller"); if (mode === "assign-failure") return 0; assigned = true; return 1; },
  IsProcessInJob: (_p: bigint, _j: bigint, out: number) => { view(out, 4).setInt32(0, assigned && mode !== "membership-failure" ? 1 : 0, true); return 1; },
  QueryInformationJobObject: (_j: bigint, kind: number, out: number, bytes: number) => {
    if (kind !== 9 || bytes !== 144) throw new Error("invalid Job query ABI");
    const b = view(out, bytes); b.setUint32(16, mode === "breakaway-policy" ? 0x808 : 8, true); b.setUint32(40, mode === "weakened-policy" ? 17 : limit, true); return mode === "query-failure" ? 0 : 1;
  },
  CloseHandle: () => { calls.push("close"); return 1; },
}, close() {} })) as unknown as typeof ffi.dlopen);

Object.defineProperty(process, "platform", { value: "win32" });
Object.defineProperty(process, "arch", { value: "x64" });
process.env.SystemRoot = "C:\\Windows";
delete process.env.OPENLLM_DAEMON_NO_SANDBOX;
spyOn(Bun.stdin, "stream").mockImplementation(() => new ReadableStream({ start(c) { c.enqueue(Buffer.from("exit 7\r\n")); c.close(); } }) as any);
const receipts: any[] = [];
spyOn(process.stderr, "write").mockImplementation(((s: string) => {
  if (s.startsWith("openllmd confined-task: ")) receipts.push(JSON.parse(s.slice("openllmd confined-task: ".length)));
  return true;
}) as any);
const status = mode.endsWith("loader") ? 0xc0000142 : mode === "access-violation" ? 0xc0000005 : 7;
const launch = (argv: unknown) => {
  argvs.push(argv);
  launches++; calls.push("spawn-worker");
  const worker = start("worker"); if (!worker) throw new Error("ERROR_NOT_ENOUGH_QUOTA");
  const owned = [worker];
  // A burst from the direct caller, without a dispatcher or semaphore. Every
  // birth goes through the mocked kernel boundary, including helper births.
  for (let i = 0; i < 17; i++) { const pid = start(["task", "broker", "formatter", "os-helper"][i % 4]!); if (pid) owned.push(pid); }
  const ready = { t: "ready", version: DAEMON_VERSION, profile: "windows-cmd-v1", pid: 3,
    controller_pid: worker, appcontainer: true, network: "none", declared_handles: 3,
    creation_job: true, active_process_limit: 16, stdin_kind: "pipe",
    desktop_mode: "headless", win32k_disabled: true,
    admission: { limit: 16, scope: "process-tree", prebirth: true, breakaway: false } };
  if (mode.endsWith("missing-receipt")) delete (ready as any).admission;
  if (mode === "weak-receipt") ready.admission.limit = 17;
  const frameCode = mode === "out-of-range" ? 0x100000007 : mode === "unsigned-receipt" ? 0xc0000142 : status | 0;
  const frames = mode === "pty-worker-loader" ? [] : [ready, { t: "exit", code: frameCode, cleanup: true, remaining: 0 }];
  workerFrames.push(...frames);
  const stream = (data: string) => new ReadableStream({ start(c) { if (data) c.enqueue(Buffer.from(data)); c.close(); } });
  const cleanup = () => { for (const pid of owned) stop(pid); };
  const exited = mode === "concurrent" ? new Promise<number>(resolve => setTimeout(() => { cleanup(); resolve(status); }, 10))
    : (cleanup(), Promise.resolve(mode === "exit-mismatch" ? 0 : status));
  return { pid: worker, stdin: { write() {}, flush() {}, end() {} }, stdout: stream(frames.length ? frames.map(f => JSON.stringify(f)).join("\n") + "\n" : ""),
    stderr: stream(""), exited, kill() {},
    // The broker fixture stops at the launch boundary, before socket discovery.
    unref() { throw new Error("mock broker launch observed"); } };
};
spyOn(Bun, "spawn").mockImplementation(launch as any);
spyOn(Bun, "spawnSync").mockImplementation(((argv: unknown) => { launch(argv); return { exitCode: 7 }; }) as any);

let result: number | undefined, error: string | undefined;
let concurrent: PromiseSettledResult<number>[] | undefined;
const exitMarker = new Error("mock process exit");
spyOn(process, "exit").mockImplementation(((code: number) => { result = code; throw exitMarker; }) as any);
try {
  if (mode.startsWith("pty")) {
    spyOn(localRuntime, "windowsWorkerPath").mockReturnValue("C:\\native\\openllm-windows-worker.exe");
    let onExit!: (code: number | undefined) => void;
    const ended = new Promise<number | undefined>(resolve => { onExit = resolve; });
    await windowsPtySpawner({ argv: ["cmd.exe"], cwd: process.cwd(), env: {}, cols: 80, rows: 24, onData() {}, onExit });
    result = await ended;
  } else if (mode === "concurrent") {
    concurrent = await Promise.allSettled([runWindowsConfinedTask(), runWindowsConfinedTask()]);
    result = await runWindowsConfinedTask(); // Stops release capacity, not JS task completion alone.
  } else if (mode.startsWith("public")) {
    result = await admittedSpawn(sandboxSpawnArgs(["windows-cmd-v1"], { profile: "windows-cmd-v1" })).exited;
  } else if (mode.startsWith("sync")) {
    result = admittedSpawnSync(["fixed-probe.exe", "--version"]).exitCode;
  } else if (mode.startsWith("dispatcher")) {
    await runSandboxExec(["windows-cmd-v1"], { profile: "windows-cmd-v1" });
  } else if (mode.startsWith("broker")) {
    const { spawnSessionHostProc } = await import("../../session-host-proc/client");
    await spawnSessionHostProc({ id: "test-admission", cli: "claude", cols: 80, rows: 24 } as any);
  } else {
    result = await runWindowsConfinedTask();
  }
} catch (e) { if (e !== exitMarker) error = String(e); }
process.stdout.write(JSON.stringify({ result, error, events, receipts, calls, launches, argvs, concurrent, workerFrames }) + "\n");
