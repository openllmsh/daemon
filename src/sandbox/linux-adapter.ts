import type { FSWatcher, ReadStream } from "node:fs";
import {
  chmodSync,
  createReadStream,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  watch,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { SandboxLaunchError } from "./exec";

export type TLinuxLaunchOutcome =
  | { readonly kind: "setup_rejected"; readonly code: 78 }
  | { readonly kind: "exec_failed"; readonly code: 127 }
  | { readonly kind: "exited"; readonly code: number }
  | { readonly kind: "reap_unconfirmed"; readonly code: null }
  | { readonly kind: "owner_lost"; readonly code: null };

export type TLinuxLaunchHandle = {
  readonly completion: Promise<TLinuxLaunchOutcome>;
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
  const {
    recordLinuxSandboxRejection,
    getLinuxNamespaceFallbackReason,
    recordLinuxNamespaceFallback,
  } = require("./linux-status") as typeof import("./linux-status");
  const fallback = getLinuxNamespaceFallbackReason();
  if (fallback) return ["--sandbox-landlock-only", fallback];
  try {
    const { qualifyBubblewrap } =
      require("./linux-launch") as typeof import("./linux-launch");
    qualifyBubblewrap();
  } catch (error) {
    return ["--sandbox-landlock-only", recordLinuxNamespaceFallback(error)];
  }
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
  const directory = mkdtempSync(join(tmpdir(), "sbx-"));
  chmodSync(directory, 0o700);
  const name = join(directory, "control");
  const encoded = Buffer.from(`${name}\0`);
  const listener = native.sandboxListen(ptr(encoded));
  if (listener < 0) {
    rmSync(directory, { recursive: true, force: true });
    throw new SandboxLaunchError(
      "SANDBOX_UNAVAILABLE",
      "registration unavailable",
    );
  }
  let resolveReady: () => void = () => {};
  let rejectReady: (error: Error) => void = () => {};
  let resolveCleanup: () => void = () => {};
  let resolveCompletion: (outcome: TLinuxLaunchOutcome) => void = () => {};
  const completion = new Promise<TLinuxLaunchOutcome>((resolve) => {
    resolveCompletion = resolve;
  });
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
  let pendingSignal = 0;
  let admitted = false;
  let rejected = false;
  const fds = new Int32Array(3);
  const ownership = Buffer.alloc(4161);
  let leasePath = "";
  let launchId = "";
  let lostOuter = false;
  let execFailed = false;
  let exitCode: number | null = null;
  const status = new Int32Array(1);
  const deadline = performance.now() + 10000;
  let cleanupDeadline = Number.POSITIVE_INFINITY;
  let stopped = false;
  let readiness: ReadStream | undefined;
  let readinessFd = -1;
  const cancelWait = (): void => {
    if (readinessFd >= 0) native.sandboxWatchCancel(readinessFd);
    readinessFd = -1;
    readiness?.destroy();
    readiness = undefined;
  };
  let leaseWatcher: FSWatcher | undefined;
  const finish = (confirmed: boolean = true): void => {
    if (stopped) return;
    stopped = true;
    cancelWait();
    leaseWatcher?.close();
    native.sandboxClose(listener);
    rmSync(directory, { recursive: true, force: true });
    if (socket >= 0) native.sandboxClose(socket);
    if (registered) for (const fd of fds) native.sandboxClose(fd);
    if (ownerFd >= 0) native.sandboxClose(ownerFd);
    launches.delete(name);
    if (confirmed) resolveCleanup();
    resolveCompletion(
      !confirmed
        ? { kind: "reap_unconfirmed", code: null }
        : !registered
          ? { kind: "setup_rejected", code: 78 }
          : execFailed
            ? { kind: "exec_failed", code: 127 }
            : exitCode === null
              ? { kind: "owner_lost", code: null }
              : { kind: "exited", code: exitCode },
    );
  };
  const fail = (): void => {
    recordLinuxSandboxRejection("SETUP_FAILED");
    rejectReady(
      new SandboxLaunchError("SANDBOX_UNAVAILABLE", "Linux setup rejected"),
    );
    if (!admitted) finish();
    else {
      rejected = true;
      cleanupDeadline = Math.min(cleanupDeadline, performance.now() + 5000);
      native.sandboxSignal(ownerFd, 15);
      queueMicrotask(drive);
    }
  };
  const signal = (value: 1 | 2 | 9 | 15): void => {
    if (stopped) return;
    cleanupDeadline = Math.min(cleanupDeadline, performance.now() + 5000);
    queueMicrotask(drive);
    if (!registered) {
      if (pendingSignal !== 9) pendingSignal = value;
      if (ownerFd >= 0) native.sandboxSignal(ownerFd, 15);
      return;
    }
    if (value === 9) {
      native.sandboxSignal(fds[2] as number, 9);
      native.sandboxSignal(fds[0] as number, 9);
    } else native.sandboxSignal(fds[1] as number, value);
  };
  const step = (): void => {
    if (performance.now() >= cleanupDeadline) {
      process.stderr.write("SANDBOX_UNAVAILABLE: reap_unconfirmed\n");
      finish(false);
      return;
    }
    if (rejected) {
      try {
        const owner = new Int32Array([ownerFd, ownerFd, ownerFd]);
        if (native.sandboxDescriptorsExited(ptr(owner))) {
          const lock = native.sandboxLeaseLock(
            ptr(Buffer.from(`${leasePath}\0`)),
            0,
          );
          if (lock >= 0) {
            try {
              const lease: unknown = JSON.parse(
                readFileSync(leasePath, "utf8"),
              );
              if (
                typeof lease === "object" &&
                lease !== null &&
                "launchId" in lease &&
                lease.launchId === launchId &&
                "guardianPid" in lease &&
                lease.guardianPid === 0
              ) {
                const temp = `${leasePath}.recover`;
                writeFileSync(
                  temp,
                  JSON.stringify({ ...lease, cleanupComplete: true }),
                  { mode: 0o600 },
                );
                renameSync(temp, leasePath);
              }
            } finally {
              native.sandboxClose(lock);
            }
          }
        }
        const lease: unknown = JSON.parse(readFileSync(leasePath, "utf8"));
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
      const result = native.sandboxRegister(
        socket,
        ptr(out),
        ptr(ownership),
        pendingSignal,
      );
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
        const result = native.sandboxCompletion(
          socket,
          out[0] as number,
          ptr(status),
        );
        if (result === 1) {
          completed = true;
          exitCode = status[0] ?? null;
        }
        if (result === 2) execFailed = true;
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
  };
  const drive = (): void => {
    if (stopped) return;
    cancelWait();
    step();
    if (stopped) return;
    if (leasePath && !leaseWatcher) {
      try {
        leaseWatcher = watch(dirname(leasePath), { persistent: false }, drive);
        leaseWatcher.on("error", () => {
          leaseWatcher?.close();
        });
      } catch {
        fail();
      }
    }
    if (stopped) return;
    const targets: number[] = [];
    if (!rejected && !lostOuter && !completed)
      targets.push(socket < 0 ? listener : socket);
    for (const fd of registered ? [ownerFd, ...fds] : [ownerFd])
      if (fd >= 0 && native.sandboxAlive(fd)) targets.push(fd);
    const until = Math.min(
      registered || rejected ? Infinity : deadline,
      cleanupDeadline,
    );
    const timeout = Number.isFinite(until)
      ? Math.max(0, Math.ceil(until - performance.now()))
      : -1;
    const descriptors = new Int32Array(targets.length ? targets : [-1]);
    const fd = native.sandboxWatch(ptr(descriptors), targets.length, timeout);
    if (fd < 0) {
      recordLinuxSandboxRejection("SETUP_FAILED");
      finish(false);
      return;
    }
    readinessFd = fd;
    readiness = createReadStream("", { fd, autoClose: true, highWaterMark: 1 });
    readiness.once("data", drive);
    readiness.once("error", () => {
      if (!stopped) {
        fail();
        drive();
      }
    });
  };
  launches.set(name, { ready, cleanup, signal, completion });
  drive();
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
