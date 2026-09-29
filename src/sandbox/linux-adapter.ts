import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { SandboxLaunchError } from "./exec";

export type TLinuxLaunchHandle = {
  readonly ready: Promise<void>;
  readonly cleanup: Promise<void>;
  readonly signal: (signal: 1 | 2 | 9 | 15) => void;
};
const launches = new Map<string, TLinuxLaunchHandle>();

/** Create a private registration channel before the caller starts the shim. */
export const prepareLinuxLaunch = (): string[] => {
  if (launches.size >= 256)
    throw new SandboxLaunchError("SANDBOX_UNAVAILABLE", "launch limit reached");
  if (process.platform !== "linux")
    throw new SandboxLaunchError("SANDBOX_UNAVAILABLE", "Linux host required");
  const { ptr } = require("bun:ffi") as typeof import("bun:ffi");
  const { recordLinuxSandboxRejection } =
    require("./linux-status") as typeof import("./linux-status");
  const native = (() => {
    try {
      const { linuxNative } =
        require("./linux-native") as typeof import("./linux-native");
      return linuxNative();
    } catch {
      recordLinuxSandboxRejection("HELPER_RUNTIME_UNAVAILABLE");
      throw new SandboxLaunchError(
        "SANDBOX_UNAVAILABLE",
        "helper runtime unavailable",
      );
    }
  })();
  const name = `openllm-sbx-${randomBytes(32).toString("hex")}`;
  const encoded = Buffer.from(`${name}\0`);
  const listener = native.sandboxListen(ptr(encoded));
  if (listener < 0)
    throw new SandboxLaunchError(
      "SANDBOX_UNAVAILABLE",
      "registration unavailable",
    );
  let resolveReady: () => void = () => {};
  let rejectReady: (error: Error) => void = () => {};
  let resolveCleanup: () => void = () => {};
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  void ready.catch(() => {});
  const cleanup = new Promise<void>((resolve) => {
    resolveCleanup = resolve;
  });
  let socket = -1;
  let registered = false;
  let completed = false;
  const out = new Int32Array(8);
  let ownerFd = -1;
  let admitted = false;
  let rejected = false;
  const fds = new Int32Array(3);
  const ownership = Buffer.alloc(4161);
  let leasePath = "";
  let launchId = "";
  let lostOuter = false;
  const deadline = performance.now() + 10000;
  const finish = (): void => {
    clearInterval(timer);
    native.sandboxClose(listener);
    if (socket >= 0) native.sandboxClose(socket);
    if (registered) for (const fd of fds) native.sandboxClose(fd);
    if (ownerFd >= 0) native.sandboxClose(ownerFd);
    launches.delete(name);
    resolveCleanup();
  };
  const fail = (): void => {
    recordLinuxSandboxRejection("SETUP_FAILED");
    rejectReady(
      new SandboxLaunchError("SANDBOX_UNAVAILABLE", "Linux setup rejected"),
    );
    if (!admitted) finish();
    else {
      rejected = true;
      native.sandboxSignal(ownerFd, 15);
    }
  };
  const signal = (value: 1 | 2 | 9 | 15): void => {
    if (!registered) {
      if (ownerFd >= 0) native.sandboxSignal(ownerFd, value);
      return;
    }
    if (value === 9) {
      native.sandboxSignal(fds[2] as number, 9);
      native.sandboxSignal(fds[0] as number, 9);
    } else native.sandboxSignal(fds[1] as number, value);
  };
  const timer = setInterval(() => {
    if (rejected) {
      try {
        const lease: unknown = JSON.parse(readFileSync(leasePath, "utf8"));
        const owner = new Int32Array([ownerFd, ownerFd, ownerFd]);
        if (
          typeof lease === "object" &&
          lease !== null &&
          "launchId" in lease &&
          lease.launchId === launchId &&
          "cleanupComplete" in lease &&
          lease.cleanupComplete === true &&
          native.sandboxDescriptorsExited(ptr(owner))
        )
          finish();
      } catch {
        /* Keep ownership until the outer shim confirms cleanup. */
      }
      return;
    }
    if (!registered) {
      if (performance.now() >= deadline) {
        fail();
        return;
      }
      if (socket < 0) {
        const accepted = native.sandboxAccept(listener);
        if (accepted === -2) return;
        if (accepted < 0) {
          fail();
          return;
        }
        socket = accepted;
      }
      const result = native.sandboxRegister(socket, ptr(out), ptr(ownership));
      if (result < 0) {
        fail();
        return;
      }
      if (result === 1) {
        fds.set(out.subarray(1, 4));
        registered = true;
        leasePath = ownership.subarray(0, ownership.indexOf(0)).toString();
        launchId = ownership.subarray(4096, 4160).toString();
        resolveReady();
      } else if (result === 2) {
        admitted = true;
        ownerFd = out[7] as number;
        leasePath = ownership.subarray(0, ownership.indexOf(0)).toString();
        launchId = ownership.subarray(4096, 4160).toString();
      }
    } else {
      if (!completed && !lostOuter) {
        const result = native.sandboxCompletion(socket, out[0] as number);
        if (result === 1) completed = true;
        if (result < 0) {
          lostOuter = true;
          signal(9);
        }
      }
      if (lostOuter && !completed) {
        try {
          const lease: unknown = JSON.parse(readFileSync(leasePath, "utf8"));
          completed =
            typeof lease === "object" &&
            lease !== null &&
            "launchId" in lease &&
            lease.launchId === launchId &&
            "cleanupComplete" in lease &&
            lease.cleanupComplete === true;
        } catch {
          /* Keep the descriptors until cleanup is confirmed. */
        }
      }
      if (completed && native.sandboxDescriptorsExited(ptr(fds)) === 1)
        finish();
    }
  }, 10);
  timer.unref();
  launches.set(name, { ready, cleanup, signal });
  return ["--sandbox-control", name];
};

export const linuxLaunchHandle = (
  argv: readonly string[],
): TLinuxLaunchHandle | undefined => {
  const index = argv.indexOf("--sandbox-control");
  const separator = argv.indexOf("--");
  if (index < 0 || (separator >= 0 && index > separator)) return undefined;
  return launches.get(argv[index + 1] ?? "");
};
