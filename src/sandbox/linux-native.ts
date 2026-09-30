/// <reference path="../pty-native/c-source.d.ts" />
import { cc, dlopen, FFIType, ptr } from "bun:ffi";
import { closeSync, writeFileSync } from "node:fs";
import source from "./linux-native.c" with { type: "text" };

const symbols = {
  sandboxOuter: { args: [FFIType.ptr, FFIType.u32], returns: FFIType.i32 },
  sandboxInternal: { args: [FFIType.i32], returns: FFIType.i32 },
  sandboxExecutableIdentity: {
    args: [FFIType.ptr, FFIType.ptr],
    returns: FFIType.i32,
  },
  sandboxFileCapabilities: { args: [FFIType.ptr], returns: FFIType.i32 },
  sandboxListen: { args: [FFIType.ptr], returns: FFIType.i32 },
  sandboxAccept: { args: [FFIType.i32], returns: FFIType.i32 },
  sandboxRegister: {
    args: [FFIType.i32, FFIType.ptr, FFIType.ptr, FFIType.i32],
    returns: FFIType.i32,
  },
  sandboxDescriptorsExited: { args: [FFIType.ptr], returns: FFIType.i32 },
  sandboxSignal: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
  sandboxClose: { args: [FFIType.i32], returns: FFIType.i32 },
  sandboxWatch: {
    args: [FFIType.ptr, FFIType.i32, FFIType.i32],
    returns: FFIType.i32,
  },
  sandboxAlive: { args: [FFIType.i32], returns: FFIType.i32 },
  sandboxWatchCancel: { args: [FFIType.i32], returns: FFIType.i32 },
  sandboxLeaseLock: { args: [FFIType.ptr, FFIType.i32], returns: FFIType.i32 },
  sandboxCompletion: {
    args: [FFIType.i32, FFIType.i32, FFIType.ptr],
    returns: FFIType.i32,
  },
} as const;

type TNative = ReturnType<typeof cc<typeof symbols>>["symbols"];
const libraries = new Map<boolean, ReturnType<typeof cc<typeof symbols>>>();

/** Compile the embedded source without a disk cache or system headers. */
export const linuxNative = (testing: boolean = false): TNative => {
  if (process.platform !== "linux" || !["x64", "arm64"].includes(process.arch))
    throw new Error("HELPER_RUNTIME_UNAVAILABLE");
  const loaded = libraries.get(testing);
  if (loaded) return loaded.symbols;
  const exports = {
    memfd_create: { args: [FFIType.ptr, FFIType.u32], returns: FFIType.i32 },
  } as const;
  const libc = (() => {
    for (const name of [
      "libc.so.6",
      `libc.musl-${process.arch === "arm64" ? "aarch64" : "x86_64"}.so.1`,
      "libc.so",
    ]) {
      try {
        return dlopen(name, exports);
      } catch {
        /* Try the next libc name. */
      }
    }
    throw new Error("HELPER_RUNTIME_UNAVAILABLE");
  })();
  const name = Buffer.from("openllm-sandbox-source\0");
  let fd = -1;
  try {
    fd = libc.symbols.memfd_create(ptr(name), 1);
    if (fd < 0) throw new Error("HELPER_RUNTIME_UNAVAILABLE");
    writeFileSync(fd, source);
    const library = cc({
      source: `/proc/self/fd/${fd}`,
      symbols,
      ...(testing ? { define: { SBX_TESTING: "1" } } : {}),
    });
    libraries.set(testing, library);
    return library.symbols;
  } finally {
    if (fd >= 0) closeSync(fd);
    libc.close();
  }
};

export const runLinuxInternal = (
  guardian: boolean,
  testing: boolean = false,
): never => {
  try {
    process.exit(linuxNative(testing).sandboxInternal(guardian ? 1 : 0));
  } catch {
    process.stderr.write("SANDBOX_UNAVAILABLE: HELPER_RUNTIME_UNAVAILABLE\n");
    process.exit(78);
  }
};
