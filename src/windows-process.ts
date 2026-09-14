/** Mandatory Windows process-tree admission, independent of task routing.
 * The caller occupies a slot before its first launch. Every descendant inherits
 * this Job, including detached workers and nested broker/dispatcher Jobs.
 * There is no breakaway flag, environment opt-out, or launch-then-assign path.
 */
import * as childProcess from "node:child_process";

export const WINDOWS_PROCESS_LIMIT = 16;

type Admission = { handle: bigint; library: ReturnType<typeof bindKernel> };
let admission: Admission | undefined;
let rejected: Error | undefined;

const bindKernel = () => {
  // Synchronous and Windows-only: admission must complete before any spawn,
  // including a synchronous helper or a direct library caller's first child.
  const { dlopen, ptr } = require("bun:ffi") as typeof import("bun:ffi");
  const library = dlopen("kernel32.dll", {
    CreateJobObjectW: { args: ["ptr", "ptr"], returns: "u64" },
    SetInformationJobObject: { args: ["u64", "i32", "ptr", "u32"], returns: "i32" },
    AssignProcessToJobObject: { args: ["u64", "u64"], returns: "i32" },
    IsProcessInJob: { args: ["u64", "u64", "ptr"], returns: "i32" },
    QueryInformationJobObject: { args: ["u64", "i32", "ptr", "u32", "ptr"], returns: "i32" },
    GetCurrentProcess: { args: [], returns: "u64" },
    GetLastError: { args: [], returns: "u32" },
    CloseHandle: { args: ["u64"], returns: "i32" },
  });
  // `symbols` is a NON-ENUMERABLE property on the dlopen result: a spread
  // (`{ ...library, ptr }`) silently drops it, leaving `library.symbols`
  // undefined on real Windows and killing admission at boot with
  // "undefined is not an object (evaluating 'k.CreateJobObjectW')".
  // Return the library itself and attach `ptr` as an own property instead.
  return Object.assign(library, { ptr });
};

// Test seam: admission is real kernel FFI on Windows; tests may substitute a
// deterministic receipt source. Production paths never set this.
export let admissionForTest: (() => void) | undefined;
export const setAdmissionForTest = (fn: (() => void) | undefined) => { admissionForTest = fn; };

export const ensureWindowsProcessAdmission = (): void => {
  if (admissionForTest) { admissionForTest(); return; }
  if (process.platform !== "win32") return;
  if (rejected) throw rejected;
  try {
    // Packaged Windows workers and their Job structures are x64 only.
    if (process.arch !== "x64") throw new Error("unsupported Windows admission ABI");
    if (!admission) {
      const library = bindKernel(), k = library.symbols;
      const check = (ok: unknown, operation: string) => {
        if (!ok) throw new Error(`Windows process admission ${operation} failed (${k.GetLastError()})`);
      };
      const handle = k.CreateJobObjectW(null, null);
      if (!handle) {
        const code = k.GetLastError(); library.close();
        throw new Error(`Windows process admission create failed (${code})`);
      }
      try {
        // JOBOBJECT_EXTENDED_LIMIT_INFORMATION, Windows x64: BasicLimit flags
        // at 16, ActiveProcessLimit at 40, sizeof = 144. HANDLE uses u64, not
        // FFI ptr (a Windows handle is not a virtual memory address).
        const limits = new BigUint64Array(18), bytes = new DataView(limits.buffer);
        bytes.setUint32(16, 0x8, true); // JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        bytes.setUint32(40, WINDOWS_PROCESS_LIMIT, true);
        check(k.SetInformationJobObject(handle, 9, library.ptr(limits), limits.byteLength), "limit");
        check(k.AssignProcessToJobObject(handle, k.GetCurrentProcess()), "assign caller");
        // Retain for the process lifetime. No KILL_ON_JOB_CLOSE here: durable
        // session hosts survive daemon exit; their inherited limits persist.
        // Nested callers may add a stricter Job but cannot reset ancestor caps.
        admission = { handle, library };
      } catch (error) { k.CloseHandle(handle); library.close(); throw error; }
    }
    const { handle, library } = admission, k = library.symbols;
    const member = new Int32Array(1), limits = new BigUint64Array(18);
    if (!k.IsProcessInJob(k.GetCurrentProcess(), handle, library.ptr(member)) || member[0] !== 1 ||
        !k.QueryInformationJobObject(handle, 9, library.ptr(limits), limits.byteLength, null))
      throw new Error("Windows process admission membership/query failed");
    const bytes = new DataView(limits.buffer), flags = bytes.getUint32(16, true);
    if (!(flags & 0x8) || (flags & 0x1800) || bytes.getUint32(40, true) !== WINDOWS_PROCESS_LIMIT)
      throw new Error("Windows process admission policy mismatch");
  } catch (error) {
    rejected = new Error(`Windows process admission unavailable: ${error instanceof Error ? error.message : String(error)}`);
    throw rejected;
  }
};

/** Keep Bun's overloads and POSIX behavior; admission is never optional. */
export const spawn: typeof Bun.spawn = ((...args: unknown[]) => {
  ensureWindowsProcessAdmission();
  return Reflect.apply(Bun.spawn, Bun, args);
}) as typeof Bun.spawn;

export const spawnSync: typeof Bun.spawnSync = ((...args: unknown[]) => {
  ensureWindowsProcessAdmission();
  return Reflect.apply(Bun.spawnSync, Bun, args);
}) as typeof Bun.spawnSync;

export const nodeSpawn: typeof childProcess.spawn = ((...args: unknown[]) => {
  ensureWindowsProcessAdmission();
  return Reflect.apply(childProcess.spawn, childProcess, args);
}) as typeof childProcess.spawn;

export const nodeSpawnSync: typeof childProcess.spawnSync = ((...args: unknown[]) => {
  ensureWindowsProcessAdmission();
  return Reflect.apply(childProcess.spawnSync, childProcess, args);
}) as typeof childProcess.spawnSync;

export const nodeExecFileSync: typeof childProcess.execFileSync = ((...args: unknown[]) => {
  ensureWindowsProcessAdmission();
  return Reflect.apply(childProcess.execFileSync, childProcess, args);
}) as typeof childProcess.execFileSync;

/** Worker protocol codes are signed int32; Bun can return either signed int32
 * or unsigned DWORD. Validate before coercion so malformed values cannot wrap
 * into success (including NaN, fractions, and multiples of 2**32).
 */
export const signedWindowsExitCode = (code: unknown): number | undefined =>
  typeof code === "number" && Number.isInteger(code) && code >= -0x80000000 && code <= 0xffffffff
    ? code | 0 : undefined;

export const validWindowsAdmission = (value: unknown): boolean => {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return v.limit === WINDOWS_PROCESS_LIMIT && v.scope === "process-tree" && v.prebirth === true && v.breakaway === false;
};
