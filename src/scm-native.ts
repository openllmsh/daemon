import { cc, FFIType } from "bun:ffi";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import scmSource from "../../pty-native/scm-win.c" with { type: "text" };

export const SCM_SYMBOLS = {
  scmAbiVersion: { args: [], returns: FFIType.i32 },
  scmErrorNotServiceController: { args: [], returns: FFIType.u32 },
  scmBindCallbacks: {
    args: [FFIType.function, FFIType.function],
    returns: FFIType.void,
  },
  scmDispatch: { args: [], returns: FFIType.i32 },
  scmReportRunning: { args: [], returns: FFIType.void },
  scmReportStartFailed: { args: [FFIType.u32], returns: FFIType.void },
  scmReportStopped: { args: [FFIType.u32], returns: FFIType.void },
} satisfies Record<
  string,
  { readonly args: readonly FFIType[]; readonly returns: FFIType }
>;

export type TScmNativeBindings = {
  readonly scmAbiVersion: () => number;
  readonly scmErrorNotServiceController: () => number;
  readonly scmBindCallbacks: (onStart: () => void, onStop: () => void) => void;
  readonly scmDispatch: () => number;
  readonly scmReportRunning: () => void;
  readonly scmReportStartFailed: (exitCode: number) => void;
  readonly scmReportStopped: (exitCode: number) => void;
};

type TCompiledLibrary = {
  readonly symbols: unknown;
  readonly close: () => void;
};

let loadedBindings: TScmNativeBindings | null = null;
let loadedLibrary: TCompiledLibrary | null = null;

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
      "scm-native cache directory must not be ~/.openllm or any child path",
    );
  const existing = nearestExistingPath(candidate);
  const realExisting = realpathSync(existing);
  if (isPathWithin(realExisting, productionRoot))
    throw new Error(
      "scm-native cache directory must not resolve into ~/.openllm",
    );
};

const scmNativeCacheRoot = (): string => {
  const configured = process.env.OPENLLM_SCM_NATIVE_CACHE_DIR?.trim();
  const root = resolve(
    configured !== undefined && configured.length > 0
      ? expandHome(configured)
      : join(tmpdir(), "openllm-scm-native"),
  );
  assertNotProductionStatePath(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  return root;
};

const compileScm = (): TScmNativeBindings => {
  const directory = mkdtempSync(join(scmNativeCacheRoot(), ".scm-native-"));
  chmodSync(directory, 0o700);
  const sourcePath = resolve(join(directory, "scm-win.c"));
  writeFileSync(sourcePath, scmSource, { mode: 0o600 });
  chmodSync(sourcePath, 0o600);
  try {
    const library = cc({
      source: sourcePath,
      define: { PTY_WINDOWS: "1" },
      library: [],
      symbols: SCM_SYMBOLS,
    }) as unknown as TCompiledLibrary;
    loadedLibrary = library;
    return library.symbols as TScmNativeBindings;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

/** Compile/load the embedded SCM shim once per process (win32 only). */
export const loadScmBindings = (): TScmNativeBindings => {
  if (process.platform !== "win32") {
    throw new Error("scm-native is only available on win32");
  }
  if (loadedBindings !== null) {
    if (loadedLibrary === null)
      throw new Error("scm-native bindings lost their compiled library");
    return loadedBindings;
  }
  const bindings = compileScm();
  if (bindings.scmAbiVersion() !== 1)
    throw new Error("scm-native ABI version mismatch");
  loadedBindings = bindings;
  return bindings;
};
