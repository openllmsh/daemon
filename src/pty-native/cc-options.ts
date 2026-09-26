export type TPtyCcOptions = {
  define: Record<string, string>;
  library: string[];
};

/**
 * Per-target cc() options for the header-free POSIX PTY shim.
 *
 * v2.8 (contract §5): all four POSIX release targets are supported —
 * darwin/arm64, darwin/x64, linux/x64, linux/arm64. Darwin is ABI-identical
 * across arm64/x64 for the shim's surface (one `PTY_DARWIN` define); Linux
 * branches its arch-dependent syscall/ioctl numbers internally on
 * `__x86_64__`/`__aarch64__` (one `PTY_LINUX` define). Windows is NOT a
 * POSIX shim target — it is the Phase 3 in-process ConPTY route.
 *
 * A successful Bun executable build alone does not qualify native support;
 * the target must also pass its runtime PTY suite (see the phase gate).
 */
export const getPtyCcOptions = (
  platform: string = process.platform,
  architecture: string = process.arch,
): TPtyCcOptions => {
  if (
    platform === "darwin" &&
    (architecture === "arm64" || architecture === "x64")
  ) {
    return {
      define: { PTY_DARWIN: "1" },
      library: [],
    };
  }

  if (
    platform === "linux" &&
    (architecture === "x64" || architecture === "arm64")
  ) {
    return {
      define: { PTY_LINUX: "1" },
      library: ["util"],
    };
  }

  throw new Error(
    `Unsupported native PTY target: ${platform}/${architecture}; ` +
      "supported targets are darwin/arm64, darwin/x64, linux/x64, linux/arm64",
  );
};

/** Compiler configuration consumed by the native loader. */
export const ccOptions = getPtyCcOptions;
