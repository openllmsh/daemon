import { spawn as admittedSpawn } from "../windows-process";
import { childEnvironment } from "./child-policy";
/**
 * Per-child OS sandboxing — the ONE module that knows about the
 * `openllmd --sandbox-exec -- <argv…>` self-re-exec shim
 * (`docs/audits/daemon-sandbox-scoping.md` §2). It owns three things:
 *
 *   - `sandboxSpawnArgs()` — the call-site entry point: wrap a child argv so
 *     the child runs confined. Pure argv-in/argv-out; call sites contain no
 *     platform checks, no gate checks, no verb knowledge.
 *   - `runSandboxExec()` — the `--sandbox-exec` verb handler (`cli.ts`
 *     delegates here): apply the working-set sandbox to THIS re-exec'd
 *     process (`applyDaemonSandbox({ force: true })` — inherited by the tail
 *     command), spawn the tail with inherited stdio, and mirror its exit.
 *   - the env-gate logic (kill switch + dev-source opt-in), resolved in one
 *     place.
 *
 * The daemon process itself is NOT sandboxed (device-session PTYs must run
 * the user's real CLI over their real files); each risky child is confined at
 * spawn time instead. Windows risky spawns and explicitly required policies
 * fail closed before launch. The explicit shim always requires enforcement.
 * Existing POSIX development/exemption routing is retained.
 */
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { logWarn, safeDiagnosticMessage } from "../logger";
import { DAEMON_VERSION } from "../version";
import type { TSandboxState } from "./landlock";
import { runWindowsConfinedTask } from "./windows-task";
import {
  applyDaemonSandbox,
  probeLandlockSupport,
  sandboxAppliedInProcess,
} from "./landlock";

export type TSandboxSpawnOpts = {
  /** Explicit uncredentialed operation; never inferred for vendor launches. */
  readonly profile?: "windows-cmd-v1";
  /** Require confinement even in POSIX source/development runs. Windows
   *  non-probe launches always require it; false cannot weaken that rule. */
  readonly required?: boolean;
  /** Per-child grants are not implemented; nonempty requests are rejected. */
  readonly extraReadWrite?: readonly string[];
  readonly extraReadOnly?: readonly string[];
  /** Per-child network policy is not implemented; requests are rejected. */
  readonly network?: boolean;
  /** Fixed-argv read-only probe (`<bin> --version`, keychain `security`
   *  reads): skip the shim. The shim re-execs the whole daemon binary and
   *  rebuilds the working set PER SPAWN, and probes run on the 30s status hot
   *  path — that cost dwarfs any risk from a no-untrusted-input probe. Risky
   *  children (vendor scripts, login flows, anything fed remote data) must
   *  never set this. */
  readonly probe?: boolean;
};

export class SandboxLaunchError extends Error {
  constructor(readonly code: "SANDBOX_UNAVAILABLE" | "POLICY_INVALID" | "PROFILE_UNSUPPORTED", reason: string) {
    super(`${code}: ${reason}`);
    this.name = "SandboxLaunchError";
  }
}

// An internal identity, not a client-controlled header. The walker must surface
// these responses without cooldown, retry, manual transport or fleet fallback.
const terminalRejections = new WeakSet<Response>();
export const sandboxUnavailableResponse = (): Response => {
  const response = Response.json({ error: { code: "SANDBOX_UNAVAILABLE", message: "Required Windows vendor confinement is unavailable" } }, { status: 503 });
  terminalRejections.add(response);
  return response;
};
export const isSandboxRejectionResponse = (response: Response): boolean => terminalRejections.has(response);

/** Whether per-child sandboxing is enabled for this process — the two env
 *  gates plus the platform support check, resolved in ONE place. */
const sandboxingEnabled = (): boolean => {
  // Kill switch: children spawn unwrapped.
  if (process.env.OPENLLM_DAEMON_NO_SANDBOX === "1") return false;
  // Already confined in-process (the shim's own re-exec, or a test probe that
  // applied directly): children INHERIT the confinement — re-wrapping would
  // double-apply and, in a probe, re-exec the wrong entry script.
  if (sandboxAppliedInProcess()) return false;
  // No backend on this platform (win32 etc.) — identity passthrough.
  if (process.platform !== "darwin" && process.platform !== "linux")
    return false;
  return true;
};

/** A from-source run (`bun src/main.ts`) — `process.execPath` is `bun`, which
 *  would swallow `--sandbox-exec`, so the wrap must re-insert the entry
 *  script (`process.argv[1]` in both run forms — see `cli.ts` `userArgs`). */
const isDevSourceRun = (): boolean => DAEMON_VERSION === "0.0.0-dev";

/** The dev entry script as an ABSOLUTE path, captured at module load while
 *  `process.cwd()` is still the repo root (`bun run dev:sb` launches there).
 *  `sandboxSpawnArgs` call sites spawn the shim with the CHILD's cwd (the
 *  isolated CLI home — `spawnCwd`), where a relative
 *  `packages/daemon/src/main.ts` no longer resolves: every wrapped dev spawn
 *  died with "Module not found" instead of running confined, silently
 *  diverging `dev:sb` from the shipped binary's sandbox behaviour. */
const DEV_ENTRY: string | undefined =
  process.argv[1] !== undefined
    ? isAbsolute(process.argv[1])
      ? process.argv[1]
      : resolve(process.argv[1])
    : undefined;

/**
 * Wrap a child argv for sandboxed execution via the `--sandbox-exec` shim.
 * INVARIANTS:
 *  - Windows non-probe and explicitly required policies throw on unavailable
 *    enforcement; callers must not downgrade a security rejection;
 *  - POSIX legacy development gates and fixed probe exemptions are retained;
 *  - pure argv-in/argv-out: no spawn, no I/O — callers keep their own
 *    `Bun.spawn` options (cwd, env, stdio) unchanged.
 *
 * Unsupported per-child grants/network policy are rejected, never ignored.
 */
export const sandboxSpawnArgs = (
  argv: readonly string[],
  opts?: TSandboxSpawnOpts,
): string[] => {
  if (opts?.profile !== undefined) {
    if (opts.profile !== "windows-cmd-v1" || argv.length !== 1 || argv[0] !== opts.profile || opts.probe === true)
      throw new SandboxLaunchError("POLICY_INVALID", "invalid uncredentialed task operation");
    if (opts.network !== undefined || (opts.extraReadWrite?.length ?? 0) > 0 || (opts.extraReadOnly?.length ?? 0) > 0)
      throw new SandboxLaunchError("PROFILE_UNSUPPORTED", "task profile grants cannot be overridden");
    if (process.platform !== "win32" || process.env.OPENLLM_DAEMON_NO_SANDBOX === "1")
      throw new SandboxLaunchError("SANDBOX_UNAVAILABLE", "Windows task confinement is unavailable or disabled");
    return [process.execPath, ...(isDevSourceRun() && DEV_ENTRY ? [DEV_ENTRY] : []), "--sandbox-exec", "--profile", opts.profile, "--", ...argv];
  }
  if (opts?.required === true && opts.probe === true) {
    throw new SandboxLaunchError("POLICY_INVALID", "required confinement conflicts with a probe exemption");
  }
  if (opts?.network !== undefined || (opts?.extraReadWrite?.length ?? 0) > 0 || (opts?.extraReadOnly?.length ?? 0) > 0) {
    throw new SandboxLaunchError("PROFILE_UNSUPPORTED", "per-child path and network policy is not implemented");
  }
  if (opts?.probe === true) return [...argv];
  const required = process.platform === "win32" || opts?.required === true;
  if (required && process.platform !== "darwin" && process.platform !== "linux") {
    throw new SandboxLaunchError("SANDBOX_UNAVAILABLE", "no qualified confinement backend on this platform");
  }
  if (sandboxAppliedInProcess()) return [...argv];
  if (required && process.env.OPENLLM_DAEMON_NO_SANDBOX === "1") {
    throw new SandboxLaunchError("SANDBOX_UNAVAILABLE", "required confinement is disabled");
  }
  if (!sandboxingEnabled()) return [...argv];
  if (isDevSourceRun()) {
    // Dev source runs are OPT-IN (`OPENLLM_DAEMON_SANDBOX=1`), and the wrap
    // must go through `bun <entry>` since execPath is the bun runtime.
    if (process.env.OPENLLM_DAEMON_SANDBOX !== "1" && !required) return [...argv];
    if (DEV_ENTRY === undefined) {
      if (required) throw new SandboxLaunchError("SANDBOX_UNAVAILABLE", "missing sandbox entry point");
      return [...argv];
    }
    return [
      process.execPath,
      DEV_ENTRY,
      "--sandbox-exec",
      ...HOME_FLAG(),
      "--",
      ...argv,
    ];
  }
  return [process.execPath, "--sandbox-exec", ...HOME_FLAG(), "--", ...argv];
};

/**
 * `--home <realHome>` — the DAEMON's real home, pinned into the shim's argv.
 *
 * Load-bearing: most call sites spawn the shim with the CHILD's env, which
 * points `HOME` at the isolated CLI home (`cli-paths.ts` `cliEnv`). The shim
 * would then build its working set against THAT home — `stateDir()` resolves to
 * a nonexistent `<isolated>/.openllm` (so the real state dir is never granted)
 * and Seatbelt's deny-`$HOME`-by-default read rule lands on the isolated home
 * itself, EPERM-ing the very credential stores the child was spawned to read
 * (`~/.openllm/cli/<p>/home/.codex`, `.kimi-code`, `.grok/auth.json`). The
 * daemon process IS unconfined and has the real `HOME`, so it captures the
 * value at wrap time and the shim threads it into the working set — the tail
 * still runs with the isolated `HOME` it was given.
 *
 * It must travel in ARGV, not the env: the child owns `HOME` in the shared env,
 * and re-setting `process.env.HOME` inside the shim would not help anyway —
 * Bun caches `os.homedir()` on its first call, which module-load code has
 * already made.
 */
const HOME_FLAG = (): string[] => ["--home", homedir()];

/**
 * The `--sandbox-exec` verb: apply the working-set sandbox to this process
 * (inherited by the child), spawn the tail argv with inherited stdio, and
 * exit with the child's code (or `128 + signal` on a signal death — shell
 * convention, so `logIfKilled` still detects sandbox kills upstream).
 * If application does not return enforced, reject with exit 78 and no child.
 * Spawn failure of the inner
 * command (ENOENT etc.) exits 127 with a stderr line.
 */
export const runSandboxExec = async (
  tail: readonly string[],
  opts?: { readonly home?: string; readonly profile?: string },
): Promise<never> => {
  if (opts?.profile !== undefined) {
    // Revalidate in the actual child: no caller can bypass policy using the
    // explicit shim or a disable switch. Unsupported vendor paths stay closed.
    sandboxSpawnArgs(tail, { required: true, profile: opts.profile as "windows-cmd-v1" });
    return process.exit(await runWindowsConfinedTask());
  }
  // Build the working set from the DAEMON's home (see `HOME_FLAG`), NOT this
  // process's `HOME` — the shim inherits the child's isolated one. The tail's
  // env is untouched, so the child still gets its isolated `HOME`.
  const state = await applyDaemonSandbox({
    force: true,
    child: true,
    ...(opts?.home !== undefined ? { home: opts.home } : {}),
  });
  if (state !== "enforced") {
    process.stderr.write(
      `openllmd --sandbox-exec: SANDBOX_UNAVAILABLE: confinement not applied (${state}); child rejected\n`,
    );
    return process.exit(78);
  }
  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = admittedSpawn([...tail], {
      stdio: ["inherit", "inherit", "inherit"],
      env: childEnvironment(process.env),
      cwd: process.cwd(),
    });
  } catch (err) {
    process.stderr.write(
      `openllmd --sandbox-exec: failed to spawn ${tail[0] ?? "?"}: ${
        err instanceof Error ? err.message : String(err)
      }\n`,
    );
    return process.exit(127);
  }
  // Forward termination signals to the tail: the daemon kills the SHIM
  // (`proc.kill()` at the call site reaches the wrapper, not the child), so
  // without forwarding the sandboxed tail would outlive its parent. The shim
  // then exits via the child's `128 + signal` mirror below.
  //
  // RESIDUAL GAP (documented, accepted): a SIGKILL of the shim cannot be
  // forwarded (uncatchable), so a kill -9 of the wrapper can orphan the tail.
  // Bun does support detached process groups (`detached: true` performs
  // POSIX setsid) and the durable session host uses that deliberately; it does
  // not supply `PR_SET_PDEATHSIG`, however, nor can an FFI prctl run in the
  // child between fork and exec. Every daemon-side kill path uses catchable
  // signals (`proc.kill()` = SIGTERM, spawnLogin's reaper uses SIGKILL on the
  // SHIM only after the `until`/timeout capture). Revisit if Bun adds a
  // parent-death signal spawn option.
  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    process.on(signal, () => {
      try {
        proc.kill(signal);
      } catch {
        // child already gone — the exit mirror below finishes up
      }
    });
  }
  await proc.exited;
  if (proc.signalCode !== null) {
    // The shim's exit-code mirror means the DAEMON-side caller sees
    // `128 + N`, not a signalCode — so `logIfKilled` can't fire there. Log
    // the kill HERE (the shim shares the daemon's log file), preserving the
    // "child killed by a signal — likely a sandbox denial" breadcrumb.
    logWarn("sandbox", `--sandbox-exec child killed by ${proc.signalCode}`, {
      command: tail[0] ?? "?",
      signal: proc.signalCode,
    });
    return process.exit(128 + (signalNumber(proc.signalCode) ?? 15));
  }
  return process.exit(proc.exitCode ?? 1);
};

/** Map a signal NAME to its conventional number for the `128 + N` exit. */
const signalNumber = (signal: string): number | null => {
  const table: Record<string, number> = {
    SIGHUP: 1,
    SIGINT: 2,
    SIGQUIT: 3,
    SIGILL: 4,
    SIGTRAP: 5,
    SIGABRT: 6,
    SIGBUS: 7,
    SIGFPE: 8,
    SIGKILL: 9,
    SIGUSR1: 10,
    SIGSEGV: 11,
    SIGUSR2: 12,
    SIGPIPE: 13,
    SIGALRM: 14,
    SIGTERM: 15,
  };
  return table[signal] ?? null;
};

/**
 * Boot-time capability probe for `DaemonStatus.sandbox` / `/health` — the
 * posture-reporting replacement for the removed process-wide boot apply.
 * Computes what a wrapped child WILL get without restricting anything:
 * platform supported, kill switch off, dev gate satisfied — and on Linux the
 * cheap Landlock ABI probe so `"unsupported"` stays accurate. `"enforced"`
 * now means "risky children are wrapped", not "this process is confined".
 */
export const probeSandboxCapability = async (): Promise<TSandboxState> => {
  if (process.env.OPENLLM_DAEMON_NO_SANDBOX === "1") {
    logWarn(
      "sandbox",
      safeDiagnosticMessage`OPENLLM_DAEMON_NO_SANDBOX=1 — children run unconfined`,
    );
    return "off";
  }
  if (isDevSourceRun() && process.env.OPENLLM_DAEMON_SANDBOX !== "1") {
    return "off";
  }
  if (process.platform === "darwin") return "enforced";
  if (process.platform !== "linux") return "unsupported";
  return probeLandlockSupport();
};
