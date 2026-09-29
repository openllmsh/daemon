import { dlopen, FFIType } from "bun:ffi";
import { resolve } from "node:path";
import type { TDaemonSandboxDetails } from "@openllmsh/protocol";
import { DAEMON_VERSION } from "../version";
import { spawn as admittedSpawn } from "../windows-process";
import { LinuxSandboxError, qualifyBubblewrap } from "./linux-launch";

const LANDLOCK_CREATE_RULESET = 444;
const LANDLOCK_CREATE_RULESET_VERSION = 1;
const SELF_TEST_TIMEOUT_MS = 10_000;
const EXPECTED_PROBE_RECORD =
  '{"sandboxProbe":true,"pid":2,"maps":true,"globalProcAbsent":true,"capabilitiesEmpty":true}\n';

export type TLinuxSandboxProbeOutcome = {
  readonly stdout: string;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly timedOut: boolean;
};

type TReason = TDaemonSandboxDetails["reason"];
type TSelfTestResult = {
  readonly passed: boolean;
  readonly reason: TReason;
};
export type TLinuxSandboxSelfTestOutcome = TLinuxSandboxProbeOutcome & {
  readonly stderr: string;
};
export type TLinuxSandboxSelfTestRunner = (
  args: readonly string[],
  timeoutMs: number,
) => Promise<TLinuxSandboxSelfTestOutcome>;

const initialDetails = (): TDaemonSandboxDetails => ({
  backend: "linux-bubblewrap",
  bubblewrapVersion: null,
  landlockAbi: null,
  helperAvailable: false,
  guardian: "not_run",
  userNamespace: "not_run",
  selfTest: "not_run",
  lastRejection: null,
  reason: "SETUP_FAILED",
});

let details = initialDetails();
let lastRejection: TReason | null = null;

export const getLinuxSandboxDetails = (): TDaemonSandboxDetails => ({
  ...details,
  lastRejection,
});

/** Record a fixed launch rejection without exposing error text or paths. */
export const recordLinuxSandboxRejection = (reason: TReason): void => {
  lastRejection = reason;
  details = { ...details, lastRejection: reason };
};

/** Require every expected probe field, a zero exit, and no signal or timeout. */
export const classifyLinuxSandboxProbe = (
  outcome: TLinuxSandboxProbeOutcome,
): boolean =>
  outcome.stdout === EXPECTED_PROBE_RECORD &&
  outcome.exitCode === 0 &&
  outcome.signal === null &&
  !outcome.timedOut;

export const buildLinuxSandboxSelfTestArgs = (
  executable: string,
  sourceEntry?: string,
): string[] => {
  const selfArgs = sourceEntry === undefined ? [] : [resolve(sourceEntry)];
  return [
    executable,
    ...selfArgs,
    "--sandbox-exec",
    "--",
    executable,
    ...selfArgs,
    "--sandbox-probe",
  ];
};

const landlockAbi = (): number | null => {
  if (process.platform !== "linux" || !["x64", "arm64"].includes(process.arch))
    return null;
  const syscall = {
    args: [FFIType.i64, FFIType.i64, FFIType.i64, FFIType.i64],
    returns: FFIType.i64,
  } as const;
  const libraryNames = [
    "libc.so.6",
    `libc.musl-${process.arch === "arm64" ? "aarch64" : "x86_64"}.so.1`,
    "libc.so",
  ];
  for (const name of libraryNames) {
    try {
      const libc = dlopen(name, { syscall });
      try {
        const abi = Number(
          libc.symbols.syscall(
            BigInt(LANDLOCK_CREATE_RULESET),
            0n,
            0n,
            BigInt(LANDLOCK_CREATE_RULESET_VERSION),
          ),
        );
        return abi > 0 ? abi : null;
      } finally {
        libc.close();
      }
    } catch {
      // Try the next supported libc name.
    }
  }
  return null;
};

const readBounded = async (
  stream: ReadableStream<Uint8Array> | number | null | undefined,
  limit: number,
  onOverflow: () => void,
): Promise<string> => {
  if (stream === null || stream === undefined || typeof stream === "number")
    return "";
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      size += result.value.byteLength;
      if (size > limit) {
        onOverflow();
        await reader.cancel();
        return "";
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(output);
};

const spawnSelfTest: TLinuxSandboxSelfTestRunner = async (
  args,
  timeoutMs,
): Promise<TLinuxSandboxSelfTestOutcome> => {
  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = admittedSpawn([...args], {
      cwd: "/",
      env: process.env,
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    });
  } catch {
    return {
      stdout: "",
      stderr: "",
      exitCode: null,
      signal: null,
      timedOut: false,
    };
  }

  let timedOut = false;
  let overflow = false;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill("SIGTERM");
    killTimer = setTimeout(() => proc.kill("SIGKILL"), 500);
  }, timeoutMs);
  const [stdout, stderr, exitCode] = await Promise.all([
    readBounded(proc.stdout, 4096, () => {
      overflow = true;
      proc.kill("SIGKILL");
    }),
    readBounded(proc.stderr, 4096, () => {
      overflow = true;
      proc.kill("SIGKILL");
    }),
    proc.exited,
  ]);
  clearTimeout(timer);
  if (killTimer !== undefined) clearTimeout(killTimer);
  return {
    stdout: overflow ? "" : stdout,
    stderr: overflow ? "" : stderr,
    exitCode,
    signal: proc.signalCode,
    timedOut,
  };
};

/** Run the same daemon entry through its normal Linux confinement shim. */
export const runLinuxSandboxSelfTest = async (
  runner: TLinuxSandboxSelfTestRunner = spawnSelfTest,
): Promise<TSelfTestResult> => {
  const sourceEntry =
    DAEMON_VERSION === "0.0.0-dev" ? process.argv[1] : undefined;
  if (DAEMON_VERSION === "0.0.0-dev" && !sourceEntry)
    return { passed: false, reason: "SELF_TEST_FAILED" };
  const args = buildLinuxSandboxSelfTestArgs(process.execPath, sourceEntry);
  let outcome: TLinuxSandboxSelfTestOutcome;
  try {
    outcome = await runner(args, SELF_TEST_TIMEOUT_MS);
  } catch {
    return { passed: false, reason: "SELF_TEST_FAILED" };
  }
  if (classifyLinuxSandboxProbe(outcome))
    return { passed: true, reason: "READY" };
  const reason = outcome.stderr.match(/SANDBOX_UNAVAILABLE: ([A-Z_]+)\n?/)?.[1];
  if (
    reason === "USERNS_UNAVAILABLE" ||
    reason === "BWRAP_UNAVAILABLE" ||
    reason === "BWRAP_PRIVILEGED_INSTALL_UNSUPPORTED" ||
    reason === "HELPER_RUNTIME_UNAVAILABLE" ||
    reason === "GUARDIAN_UNAVAILABLE" ||
    reason === "POLICY_INVALID" ||
    reason === "SETUP_FAILED"
  ) {
    return { passed: false, reason };
  }
  return { passed: false, reason: "SELF_TEST_FAILED" };
};

const reasonFrom = (error: unknown): TReason => {
  if (error instanceof LinuxSandboxError) return error.reason;
  const message = error instanceof Error ? error.message : "";
  if (message.includes("HELPER_RUNTIME_UNAVAILABLE"))
    return "HELPER_RUNTIME_UNAVAILABLE";
  if (message.includes("GUARDIAN_UNAVAILABLE")) return "GUARDIAN_UNAVAILABLE";
  if (message.includes("POLICY_INVALID")) return "POLICY_INVALID";
  return "SETUP_FAILED";
};

/** Probe the launch admission and the complete confined self-test once. */
export const probeLinuxSandboxCapability = async (): Promise<
  "enforced" | "off" | "unsupported" | "error"
> => {
  details = initialDetails();
  lastRejection = null;
  if (process.platform !== "linux") return "unsupported";
  if (process.env.OPENLLM_DAEMON_NO_SANDBOX === "1") {
    details = { ...details, reason: "DISABLED" };
    return "off";
  }
  if (
    DAEMON_VERSION === "0.0.0-dev" &&
    process.env.OPENLLM_DAEMON_SANDBOX !== "1"
  ) {
    details = { ...details, reason: "SOURCE_RUN_OPT_IN_REQUIRED" };
    return "off";
  }

  try {
    qualifyBubblewrap();
  } catch (error) {
    const reason = reasonFrom(error);
    details = {
      ...details,
      reason,
      ...(reason === "USERNS_UNAVAILABLE"
        ? { userNamespace: "unavailable" as const }
        : {}),
      lastRejection: reason,
    };
    lastRejection = reason;
    return reason === "HELPER_RUNTIME_UNAVAILABLE" ? "error" : "unsupported";
  }
  details = {
    ...details,
    bubblewrapVersion: "bubblewrap 0.13.0",
    helperAvailable: true,
    userNamespace: "available",
  };

  const abi = landlockAbi();
  details = { ...details, landlockAbi: abi };
  if (abi === null) {
    details = { ...details, reason: "LANDLOCK_UNAVAILABLE" };
    return "unsupported";
  }

  const result = await runLinuxSandboxSelfTest();
  if (result.passed) {
    details = {
      ...details,
      guardian: "passed",
      selfTest: "passed",
      reason: "READY",
    };
    return "enforced";
  }
  details = {
    ...details,
    guardian: "failed",
    selfTest: "failed",
    reason: result.reason,
    lastRejection: result.reason,
  };
  lastRejection = result.reason;
  if (result.reason === "USERNS_UNAVAILABLE") return "unsupported";
  if (result.reason === "BWRAP_UNAVAILABLE") return "unsupported";
  if (result.reason === "BWRAP_PRIVILEGED_INSTALL_UNSUPPORTED")
    return "unsupported";
  if (result.reason === "HELPER_RUNTIME_UNAVAILABLE") return "error";
  if (result.reason === "GUARDIAN_UNAVAILABLE") return "error";
  return "error";
};
