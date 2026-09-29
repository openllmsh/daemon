import { ptr } from "bun:ffi";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
import { CLI_PROVIDERS, cliEnv, cliHome } from "../cli-paths";
import { cleanNativeSpawnEnv } from "../native-runtime/types";
import { DAEMON_VERSION } from "../version";
import { spawnSync as admittedSpawn } from "../windows-process";
import { childWorkingSet } from "./child-policy";
import { linuxNative } from "./linux-native";
import { daemonTempDir } from "./working-set";

export const LINUX_SETUP_ENV = {
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  PWD: "/",
} as const;

export type TLinuxSandboxReason =
  | "READY"
  | "BWRAP_UNAVAILABLE"
  | "BWRAP_PRIVILEGED_INSTALL_UNSUPPORTED"
  | "USERNS_UNAVAILABLE"
  | "HELPER_RUNTIME_UNAVAILABLE"
  | "POLICY_INVALID"
  | "SETUP_FAILED";

export class LinuxSandboxError extends Error {
  constructor(readonly reason: TLinuxSandboxReason) {
    super(`SANDBOX_UNAVAILABLE: ${reason}`);
    this.name = "LinuxSandboxError";
  }
}

export type TLinuxSandboxTestHooks = {
  readonly phase: "guardian-spawn" | "descriptor-transfer" | "none";
  readonly barrier: string;
  readonly info: string;
  readonly usernsBarrier?: string;
  readonly initLock?: string;
  readonly suppressAdoptedKill?: boolean;
  readonly fault?: string;
};

const checkedPath = (path: string): string => {
  if (!isAbsolute(path) || path.includes("\0"))
    throw new LinuxSandboxError("POLICY_INVALID");
  return realpathSync(path);
};

/** List imported process mounts before the namespace setup starts. */
export const hostProcfsAliases = (mountInfo: string): string[] => {
  if (mountInfo.length > 1024 * 1024)
    throw new LinuxSandboxError("POLICY_INVALID");
  const aliases: string[] = [];
  for (const line of mountInfo.trim().split("\n")) {
    const parts = line.split(" - ");
    if (parts.length !== 2) throw new LinuxSandboxError("POLICY_INVALID");
    if (!parts[1]?.startsWith("proc ")) continue;
    const encoded = parts[0]?.split(" ")[4];
    if (!encoded) throw new LinuxSandboxError("POLICY_INVALID");
    const path = encoded.replace(
      /\\(040|011|012|134)/g,
      (_, octal: string): string =>
        String.fromCharCode(Number.parseInt(octal, 8)),
    );
    if (!isAbsolute(path) || path.includes("\0") || path.includes("\n"))
      throw new LinuxSandboxError("POLICY_INVALID");
    if (path === "/proc") continue;
    if (["/proc/", "/dev/", "/tmp/"].some((root) => path.startsWith(root)))
      continue;
    aliases.push(path);
  }
  return aliases.sort((a, b) => b.length - a.length);
};

export const linuxProcessStart = (pid: number): string => {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  const start = fields[19];
  if (!start || !/^\d+$/.test(start))
    throw new LinuxSandboxError("SETUP_FAILED");
  return start;
};

export const qualifyBubblewrap = (): string => {
  const path = ["/usr/bin/bwrap", "/bin/bwrap"].find(existsSync);
  if (!path) throw new LinuxSandboxError("BWRAP_UNAVAILABLE");
  const binary = realpathSync(path);
  for (let item = binary; ; item = dirname(item)) {
    const stat = statSync(item);
    if (stat.uid !== 0 || (stat.mode & 0o022) !== 0)
      throw new LinuxSandboxError("BWRAP_UNAVAILABLE");
    if (item === binary && ((stat.mode & 0o6000) !== 0 || !stat.isFile()))
      throw new LinuxSandboxError("BWRAP_PRIVILEGED_INSTALL_UNSUPPORTED");
    if (item === "/") break;
  }
  const encoded = Buffer.from(`${binary}\0`);
  if (linuxNative().sandboxFileCapabilities(ptr(encoded)) !== 0)
    throw new LinuxSandboxError("BWRAP_PRIVILEGED_INSTALL_UNSUPPORTED");
  const version = admittedSpawn([binary, "--version"], {
    env: LINUX_SETUP_ENV,
    cwd: "/",
    stdout: "pipe",
    stderr: "pipe",
    timeout: 1000,
  });
  if (
    version.exitCode !== 0 ||
    version.signalCode != null ||
    version.stdout.toString().trim() !== "bubblewrap 0.13.0"
  )
    throw new LinuxSandboxError("BWRAP_UNAVAILABLE");
  for (const name of [
    "/proc/sys/kernel/unprivileged_userns_clone",
    "/proc/sys/user/max_user_namespaces",
  ]) {
    if (existsSync(name) && Number(readFileSync(name, "utf8")) === 0)
      throw new LinuxSandboxError("USERNS_UNAVAILABLE");
  }
  return binary;
};

export const linuxVendorEnvironment = (
  scratch: string,
  home?: string,
): Record<string, string> => {
  const selected = process.env.HOME;
  const provider = CLI_PROVIDERS.find(
    (name) => selected === cliHome(name, home),
  );
  const overlay: Record<string, string> = {};
  if (provider)
    for (const key of Object.keys(cliEnv(provider))) {
      const value = process.env[key];
      if (value !== undefined) overlay[key] = value;
    }
  const env = cleanNativeSpawnEnv(overlay);
  for (const key of Object.keys(env)) {
    if (/^(?:OPENLLM_|PRIVATE_PLANE_|RELAY_|DEVICE_GRANT_)/i.test(key))
      delete env[key];
    if (key.includes("=") || key.includes("\0") || env[key]?.includes("\0"))
      throw new LinuxSandboxError("POLICY_INVALID");
  }
  env.TMPDIR = scratch;
  env.PWD = checkedPath(process.cwd());
  return env;
};

/** Build the policy in the host namespace. The helper must not build it again. */
export const buildChildPolicy = (
  tail: readonly string[],
  home?: string,
  hooks?: TLinuxSandboxTestHooks,
): Buffer => {
  const bwrap = qualifyBubblewrap();
  const executable = tail[0] && Bun.which(tail[0]);
  if (!executable) throw new LinuxSandboxError("POLICY_INVALID");
  const executablePath = checkedPath(executable);
  const executableIdentity = Buffer.alloc(96);
  if (
    linuxNative().sandboxExecutableIdentity(
      ptr(Buffer.from(`${executablePath}\0`)),
      ptr(executableIdentity),
    ) !== 0
  )
    throw new LinuxSandboxError("POLICY_INVALID");
  const ws = childWorkingSet(home);
  const root = checkedPath(daemonTempDir(home));
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const scratch = mkdtempSync(join(root, `linux-${process.pid}-`));
  const leaseRoot = join(dirname(root), "sandbox-leases");
  const lease = join(leaseRoot, `${basename(scratch)}.json`);
  try {
    mkdirSync(leaseRoot, { recursive: true, mode: 0o700 });
    const outerStart = linuxProcessStart(process.pid);
    const boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    const id = randomBytes(32).toString("hex");
    writeFileSync(
      lease,
      JSON.stringify({
        v: 2,
        pid: process.pid,
        startIdentity: `boot:${boot}:${outerStart}`,
        launchId: id,
        cleanupComplete: false,
      }),
      { mode: 0o600 },
    );
    const ro = [...new Set(ws.readOnly.filter(existsSync).map(checkedPath))];
    const rw = [...new Set(ws.readWrite.filter(existsSync).map(checkedPath))];
    const env = linuxVendorEnvironment(scratch, home);
    const self = [
      process.execPath,
      ...(DAEMON_VERSION === "0.0.0-dev"
        ? [checkedPath(process.argv[1] ?? "")]
        : []),
    ];
    const options = [
      bwrap,
      "--unshare-user",
      "--unshare-pid",
      "--die-with-parent",
      "--cap-drop",
      "ALL",
      "--cap-add",
      "CAP_SYS_ADMIN",
      "--cap-add",
      "CAP_SETPCAP",
      "--ro-bind",
      "/",
      "/",
      ...(hooks?.fault === "planned_alias"
        ? ["--ro-bind", "/proc", hooks.barrier]
        : []),
      ...rw.flatMap((path) => ["--bind", path, path]),
      "--proc",
      "/proc",
      "--tmpfs",
      "/dev",
      ...["null", "zero", "random", "urandom"].flatMap((name) => [
        "--dev-bind",
        `/dev/${name}`,
        `/dev/${name}`,
      ]),
      "--symlink",
      "/proc/self/fd",
      "/dev/fd",
      "--symlink",
      "/proc/self/fd/0",
      "/dev/stdin",
      "--symlink",
      "/proc/self/fd/1",
      "/dev/stdout",
      "--symlink",
      "/proc/self/fd/2",
      "/dev/stderr",
      "--tmpfs",
      "/tmp",
      "--chdir",
      "/",
      "--clearenv",
      ...Object.entries(LINUX_SETUP_ENV)
        .filter(([key]) => key !== "PWD")
        .flatMap(([key, value]) => ["--setenv", key, value]),
      "--json-status-fd",
      "6",
      ...(hooks?.usernsBarrier
        ? ["--userns-block-fd", "7", "--info-fd", "8"]
        : []),
      ...(hooks?.initLock ? ["--lock-file", hooks.initLock] : []),
    ];
    const vectors = [
      self,
      [executablePath, ...tail.slice(1)],
      Object.entries(env).map(([key, value]) => `${key}=${value}`),
      ro,
      rw,
      options,
      [
        ...hostProcfsAliases(readFileSync("/proc/self/mountinfo", "utf8")),
        ...(hooks?.fault === "planned_alias" ? [hooks.barrier] : []),
      ],
    ];
    const testFields = hooks
      ? [
          hooks.phase,
          hooks.barrier,
          hooks.info,
          hooks.usernsBarrier ?? "",
          hooks.suppressAdoptedKill ? "1" : "0",
          hooks.fault ?? "",
        ]
      : [];
    vectors.push(testFields);
    const body = vectors.flatMap((items) => [String(items.length), ...items]);
    const digest = createHash("sha256").update(body.join("\0")).digest("hex");
    const controlFlag = process.argv.indexOf("--sandbox-control");
    const control =
      controlFlag >= 0 && controlFlag < process.argv.indexOf("--")
        ? (process.argv[controlFlag + 1] ?? "")
        : "";
    const fields = [
      "SBX1",
      id,
      digest,
      String(process.ppid),
      linuxProcessStart(process.ppid),
      String(process.pid),
      outerStart,
      checkedPath(process.cwd()),
      lease,
      boot,
      control,
      executableIdentity.subarray(0, executableIdentity.indexOf(0)).toString(),
      ...body,
    ];
    if (fields.some((field) => field.includes("\0")))
      throw new LinuxSandboxError("POLICY_INVALID");
    const record = Buffer.from(`${fields.join("\0")}\0`);
    if (record.length > 1024 * 1024)
      throw new LinuxSandboxError("POLICY_INVALID");
    return record;
  } catch (error) {
    rmSync(lease, { force: true });
    rmdirSync(scratch);
    throw error;
  }
};

export const runLinuxSandbox = (
  tail: readonly string[],
  home?: string,
): never => {
  try {
    const record = buildChildPolicy(tail, home);
    process.exit(linuxNative().sandboxOuter(ptr(record), record.length));
  } catch (error) {
    const reason =
      error instanceof LinuxSandboxError
        ? error.reason
        : "HELPER_RUNTIME_UNAVAILABLE";
    process.stderr.write(`SANDBOX_UNAVAILABLE: ${reason}\n`);
    process.exit(78);
  }
};
