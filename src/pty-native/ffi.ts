import { cc, FFIType, ptr } from "bun:ffi";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import * as compilerConfig from "./cc-options";
import cSource from "./pty.c" with { type: "text" };
import cSourceWindows from "./pty-win.c" with { type: "text" };

/**
 * Host platform selects the embedded shim source: win32 compiles the
 * freestanding ConPTY translation unit (pty-win.c, kernel32/msvcrt externs);
 * every other platform keeps the POSIX shim (pty.c). process.platform is
 * immutable for the process lifetime, so the choice is made once here and
 * the per-process binding cache below never straddles both.
 */
const isWindowsHost = process.platform === "win32";
const activeCSource = isWindowsHost ? cSourceWindows : cSource;

type TSymbolDescriptor = {
  readonly args: readonly FFIType[];
  readonly returns: FFIType;
};

/** The single ABI-v1 descriptor table used by every native PTY call. */
export const PTY_SYMBOLS = {
  ptyAbiVersion: { args: [], returns: FFIType.i32 },
  ptyQueueLimits: { args: [FFIType.ptr], returns: FFIType.i32 },
  ptyCreate: { args: [], returns: FFIType.i32 },
  ptySetEnv: {
    args: [FFIType.i32, FFIType.ptr, FFIType.ptr],
    returns: FFIType.i32,
  },
  ptySpawn: {
    args: [
      FFIType.i32,
      FFIType.ptr,
      FFIType.ptr,
      FFIType.ptr,
      FFIType.u32,
      FFIType.u32,
      FFIType.u32,
      FFIType.u32,
    ],
    returns: FFIType.i32,
  },
  ptySpawnStatus: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyPid: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyPoll: { args: [FFIType.i32, FFIType.u32], returns: FFIType.i32 },
  ptyRead: {
    args: [FFIType.i32, FFIType.ptr, FFIType.u32],
    returns: FFIType.i32,
  },
  ptyWrite: {
    args: [FFIType.i32, FFIType.ptr, FFIType.u32, FFIType.ptr],
    returns: FFIType.i32,
  },
  ptyDrain: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyPendingBytes: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyBackpressured: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyResize: {
    args: [FFIType.i32, FFIType.u32, FFIType.u32],
    returns: FFIType.i32,
  },
  ptyKill: {
    args: [FFIType.i32, FFIType.i32, FFIType.u32],
    returns: FFIType.i32,
  },
  ptyWait: {
    args: [FFIType.i32, FFIType.ptr, FFIType.ptr],
    returns: FFIType.i32,
  },
  ptyClose: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyDestroy: { args: [FFIType.i32], returns: FFIType.i32 },
} satisfies Record<string, TSymbolDescriptor>;

const PTY_TEST_SYMBOLS = {
  ptyTestAdoptFd: {
    args: [FFIType.i32, FFIType.i32],
    returns: FFIType.i32,
  },
  ptyTestSetInput: {
    args: [FFIType.i32, FFIType.ptr, FFIType.u32, FFIType.i32],
    returns: FFIType.i32,
  },
  ptyTestCopyInput: {
    args: [FFIType.i32, FFIType.ptr, FFIType.u32],
    returns: FFIType.i32,
  },
  ptyTestWriteCalls: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyTestFailWrites: {
    args: [FFIType.i32, FFIType.i32, FFIType.u32],
    returns: FFIType.i32,
  },
  // P4-6: Darwin handshake-fault injection (pre-ready errno preservation).
  // Defined by pty.c only under PTY_TESTING on PTY_TARGET_DARWIN; loading is
  // gated the same way, so non-testing compiles never reference them.
  ptyTestSetDarwinHandshakeFault: {
    args: [FFIType.i32, FFIType.i32],
    returns: FFIType.i32,
  },
  ptyTestSetDarwinChildErrno: {
    args: [FFIType.i32, FFIType.i32],
    returns: FFIType.i32,
  },
} satisfies Record<string, TSymbolDescriptor>;

const PTY_WINDOWS_TEST_SYMBOLS = {
  ptyTestWriteInFlight: { args: [FFIType.i32], returns: FFIType.i32 },
  ptyTestSetCompletionPending: {
    args: [FFIType.i32, FFIType.u32],
    returns: FFIType.i32,
  },
  ptyTestSetCancelError: {
    args: [FFIType.i32, FFIType.u32],
    returns: FFIType.i32,
  },
} satisfies Record<string, TSymbolDescriptor>;

const allSymbols = (testing: boolean): Record<string, TSymbolDescriptor> =>
  testing
    ? {
        ...PTY_SYMBOLS,
        ...(isWindowsHost ? PTY_WINDOWS_TEST_SYMBOLS : PTY_TEST_SYMBOLS),
      }
    : { ...PTY_SYMBOLS };

export type TPtyNativeBindings = {
  readonly ptyAbiVersion: () => number;
  readonly ptyQueueLimits: (out3: number) => number;
  readonly ptyCreate: () => number;
  readonly ptySetEnv: (handle: number, name: number, value: number) => number;
  readonly ptySpawn: (
    handle: number,
    executable: number,
    cwd: number,
    argvBlock: number,
    argvBytes: number,
    argc: number,
    cols: number,
    rows: number,
  ) => number;
  readonly ptySpawnStatus: (handle: number) => number;
  readonly ptyPid: (handle: number) => number;
  readonly ptyPoll: (handle: number, interests: number) => number;
  readonly ptyRead: (
    handle: number,
    buffer: number,
    capacity: number,
  ) => number;
  readonly ptyWrite: (
    handle: number,
    data: number,
    length: number,
    acceptedBytes: number,
  ) => number;
  readonly ptyDrain: (handle: number) => number;
  readonly ptyPendingBytes: (handle: number) => number;
  readonly ptyBackpressured: (handle: number) => number;
  readonly ptyResize: (handle: number, cols: number, rows: number) => number;
  readonly ptyKill: (
    handle: number,
    signalNumber: number,
    targets: number,
  ) => number;
  readonly ptyWait: (
    handle: number,
    exitCode: number,
    signalNumber: number,
  ) => number;
  readonly ptyClose: (handle: number) => number;
  readonly ptyDestroy: (handle: number) => number;
  readonly ptyTestAdoptFd?: (handle: number, fd: number) => number;
  readonly ptyTestSetInput?: (
    handle: number,
    data: number,
    length: number,
    backpressured: number,
  ) => number;
  readonly ptyTestCopyInput?: (
    handle: number,
    buffer: number,
    capacity: number,
  ) => number;
  readonly ptyTestWriteCalls?: (handle: number) => number;
  readonly ptyTestFailWrites?: (
    handle: number,
    errorNumber: number,
    count: number,
  ) => number;
  readonly ptyTestSetDarwinHandshakeFault?: (
    handle: number,
    fault: number,
  ) => number;
  readonly ptyTestSetDarwinChildErrno?: (
    handle: number,
    errorNumber: number,
  ) => number;
  readonly ptyTestWriteInFlight?: (handle: number) => number;
  readonly ptyTestSetCompletionPending?: (
    handle: number,
    count: number,
  ) => number;
  readonly ptyTestSetCancelError?: (
    handle: number,
    errorCode: number,
  ) => number;
};

type TCompiledLibrary = {
  readonly symbols: unknown;
  readonly close: () => void;
};

export type TPtyLoadOptions = {
  /** Compile the shim with test-only hooks enabled. */
  readonly testing?: boolean;
};

let loadedBindings: TPtyNativeBindings | null = null;
let loadedLibrary: TCompiledLibrary | null = null;
let loadFailure: Error | null = null;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const configuredCompilerOptions = (): Record<string, unknown> => {
  const exports = compilerConfig as unknown as Record<string, unknown>;
  const candidate =
    exports.ccOptions ??
    exports.compilerOptions ??
    exports.CC_OPTIONS ??
    exports.default;
  if (typeof candidate === "function") {
    const value = (candidate as () => unknown)();
    if (isRecord(value)) return value;
  }
  if (isRecord(candidate)) return candidate;
  throw new Error("pty-native compiler options are missing");
};

const isPathWithin = (candidate: string, root: string): boolean =>
  candidate === root || candidate.startsWith(`${root}${sep}`);

const expandHome = (value: string): string => {
  if (value === "~") return homedir();
  if (value.startsWith("~/")) return join(homedir(), value.slice(2));
  return value;
};

const nearestExistingPath = (path: string): string => {
  let current = path;
  while (!existsSync(current)) {
    const parent = dirname(current);
    if (parent === current) return current;
    current = parent;
  }
  return current;
};

const assertNotProductionStatePath = (candidate: string): void => {
  const productionRoot = resolve(homedir(), ".openllm");
  if (isPathWithin(candidate, productionRoot))
    throw new Error(
      "pty-native cache directory (OPENLLM_PTY_NATIVE_CACHE_DIR) must not be ~/.openllm or any child path",
    );

  // Also reject an existing symlink whose target lands in the production tree.
  // This check is read-only; it runs before mkdirSync can materialize anything.
  const existing = nearestExistingPath(candidate);
  const realExisting = realpathSync(existing);
  if (isPathWithin(realExisting, productionRoot))
    throw new Error(
      "pty-native cache directory (OPENLLM_PTY_NATIVE_CACHE_DIR) must not resolve into ~/.openllm",
    );
};

/**
 * Native materialization roots ONLY at OPENLLM_PTY_NATIVE_CACHE_DIR (explicit
 * value, `~`-expanded) or, when that is unset/empty, at a private temp-tree
 * parent. It is intentionally decoupled from the daemon state directory
 * (`OPENLLM_DAEMON_STATE_DIR`, default ~/.openllm): this loader never reads
 * that variable and never falls back to the production state tree (G4).
 */
let cachedDefaultRoot: string | null = null;

/**
 * The shared `/tmp/openllm-pty-native` name is world-visible: another local
 * user can pre-create it, and the fail-closed owner check then denies THIS
 * user a PTY (FS-14 — a denial only, never a privilege issue). Prefer the
 * fixed name when it is absent or already ours; otherwise fall back to a
 * unique sibling under the same sticky temp parent.
 */
const defaultPtyNativeRoot = (): string => {
  if (cachedDefaultRoot !== null) return cachedDefaultRoot;
  const preferred = join(tmpdir(), "openllm-pty-native");
  let usable = false;
  try {
    const preferredStat = lstatSync(preferred);
    usable =
      preferredStat.isDirectory() &&
      !preferredStat.isSymbolicLink() &&
      (typeof process.getuid !== "function" ||
        preferredStat.uid === process.getuid());
  } catch (error) {
    usable = (error as { readonly code?: unknown }).code === "ENOENT";
  }
  cachedDefaultRoot = usable
    ? preferred
    : mkdtempSync(join(tmpdir(), "openllm-pty-native-"));
  return cachedDefaultRoot;
};

const ptyNativeCacheRoot = (): string => {
  const configured = process.env.OPENLLM_PTY_NATIVE_CACHE_DIR?.trim();
  const root = resolve(
    configured !== undefined && configured.length > 0
      ? expandHome(configured)
      : defaultPtyNativeRoot(),
  );
  assertNotProductionStatePath(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink())
    throw new Error(
      "pty-native cache root must be a real directory, not a symlink",
    );
  if (typeof process.getuid === "function" && rootStat.uid !== process.getuid())
    throw new Error("pty-native cache root must be owned by the daemon user");
  if (process.platform !== "win32") {
    // mkdtempSync's child is protected only while its parent cannot be
    // replaced by another user. A sticky shared temp directory is safe; an
    // ordinary group/world-writable parent permits a symlink swap between
    // validation and source materialization.
    const parent = statSync(realpathSync(dirname(root)));
    const parentMode = parent.mode & 0o7777;
    if ((parentMode & 0o022) !== 0 && (parentMode & 0o1000) === 0)
      throw new Error(
        "pty-native cache root parent must not be group/world-writable without the sticky bit",
      );
  }
  chmodSync(root, 0o700);
  return root;
};

const compilerOptionsFor = (testing: boolean): Record<string, unknown> => {
  if (isWindowsHost) {
    /* The ConPTY shim is freestanding (zero includes) and links kernel32 /
     * msvcrt through TinyCC's default Windows libraries; cc-options.ts stays
     * POSIX-only by design. Explicit testing builds register only the
     * Windows-specific test hooks; ordinary loads use the production table. */
    const define: Record<string, string> = { PTY_WINDOWS: "1" };
    if (testing) define.PTY_TESTING = "1";
    return { define, library: [] };
  }
  const options = configuredCompilerOptions();
  const configuredDefine = options.define;
  if (!testing && !isRecord(configuredDefine)) return options;

  const define: Record<string, unknown> = {};
  if (isRecord(configuredDefine)) {
    for (const [name, value] of Object.entries(configuredDefine)) {
      if (name !== "PTY_TESTING") define[name] = value;
    }
  }
  if (testing) define.PTY_TESTING = "1";
  return { ...options, define };
};

const testingRequested = (options?: TPtyLoadOptions): boolean =>
  options?.testing === true;

const compilePty = (testing: boolean): TPtyNativeBindings => {
  const directory = mkdtempSync(join(ptyNativeCacheRoot(), ".pty-native-"));
  chmodSync(directory, 0o700);
  const sourceName = isWindowsHost ? "pty-win.c" : "pty.c";
  const sourcePath = resolve(join(directory, sourceName));
  writeFileSync(sourcePath, activeCSource, { mode: 0o600 });
  chmodSync(sourcePath, 0o600);
  try {
    const options = {
      ...compilerOptionsFor(testing),
      source: sourcePath,
      symbols: allSymbols(testing),
    } as Parameters<typeof cc>[0];
    const library = cc(options) as unknown as TCompiledLibrary;
    // Keep the whole library rooted for the process lifetime. FFI function
    // pointers remain live after a NativePty is detached from session-core.
    loadedLibrary = library;
    return library.symbols as TPtyNativeBindings;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

/** Compile/load the embedded shim once per process; failures remain explicit. */
export const loadPtyBindings = (
  options?: TPtyLoadOptions,
): TPtyNativeBindings => {
  if (loadedBindings !== null) {
    if (loadedLibrary === null)
      throw new Error("pty-native bindings lost their compiled library");
    return loadedBindings;
  }
  if (loadFailure !== null) throw loadFailure;
  try {
    const bindings = compilePty(testingRequested(options));
    if (bindings.ptyAbiVersion() !== 1)
      throw new Error("pty-native ABI version mismatch");
    loadedBindings = bindings;
    return bindings;
  } catch (error) {
    loadFailure =
      error instanceof Error
        ? new Error(`pty-native compile/load failed: ${error.message}`, {
            cause: error,
          })
        : new Error(`pty-native compile/load failed: ${String(error)}`);
    throw loadFailure;
  }
};

export const ffiPointer = (
  buffer: NodeJS.TypedArray | ArrayBufferLike | DataView,
): number => ptr(buffer);
