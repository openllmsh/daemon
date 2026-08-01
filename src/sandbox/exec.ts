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
 * spawn time instead. Fail-open lives HERE and in the shim, nowhere else:
 * when sandboxing is off/unsupported the wrap is an identity passthrough and
 * a shim whose apply degrades still runs the child — surfaced loudly
 * per-spawn (stderr + `logWarn` in `runSandboxExec`) on top of the boot-time
 * capability posture (`probeSandboxCapability`).
 */
import { logWarn } from "../logger";
import { DAEMON_VERSION } from "../version";
import type { TSandboxState } from "./landlock";
import {
  applyDaemonSandbox,
  probeLandlockSupport,
  sandboxAppliedInProcess,
} from "./landlock";

export type TSandboxSpawnOpts = {
  /** Extra allow-list paths for THIS child (v1: ignored; future: appended to
   *  the child's profile via a working-set extension the shim applies). */
  readonly extraReadWrite?: readonly string[];
  readonly extraReadOnly?: readonly string[];
  /** Future network on/off knob (v1: ignored — network policy stays with
   *  systemd / (allow default)). */
  readonly network?: boolean;
};

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

/**
 * Wrap a child argv for sandboxed execution via the `--sandbox-exec` shim.
 * INVARIANTS:
 *  - identity passthrough (`[...argv]`) when sandboxing is disabled
 *    (`OPENLLM_DAEMON_NO_SANDBOX=1`), unsupported (win32), or an ungated dev
 *    source run — callers never branch on posture;
 *  - never throws (fail-open lives HERE and in the shim, nowhere else);
 *  - pure argv-in/argv-out: no spawn, no I/O — callers keep their own
 *    `Bun.spawn` options (cwd, env, stdio) unchanged.
 *
 * `opts` is reserved (v1: ignored) so future per-child grants / network
 * policy never churn call sites.
 */
export const sandboxSpawnArgs = (
  argv: readonly string[],
  _opts?: TSandboxSpawnOpts,
): string[] => {
  if (!sandboxingEnabled()) return [...argv];
  if (isDevSourceRun()) {
    // Dev source runs are OPT-IN (`OPENLLM_DAEMON_SANDBOX=1`), and the wrap
    // must go through `bun <entry>` since execPath is the bun runtime.
    if (process.env.OPENLLM_DAEMON_SANDBOX !== "1") return [...argv];
    const entry = process.argv[1];
    if (entry === undefined) return [...argv];
    return [process.execPath, entry, "--sandbox-exec", "--", ...argv];
  }
  return [process.execPath, "--sandbox-exec", "--", ...argv];
};

/**
 * The `--sandbox-exec` verb: apply the working-set sandbox to this process
 * (inherited by the child), spawn the tail argv with inherited stdio, and
 * exit with the child's code (or `128 + signal` on a signal death — shell
 * convention, so `logIfKilled` still detects sandbox kills upstream).
 * Fail-open: if the apply degrades (`error`/`unsupported`) the child STILL
 * runs — parity with the old boot posture. Spawn failure of the inner
 * command (ENOENT etc.) exits 127 with a stderr line.
 */
export const runSandboxExec = async (
  tail: readonly string[],
): Promise<never> => {
  const state = await applyDaemonSandbox({ force: true });
  if (state === "error" || state === "unsupported") {
    // Loud on BOTH channels: stderr for the immediate caller, and the shared
    // daemon log so per-spawn degradation is visible next to the boot-time
    // capability probe's posture (the probe can say "enforced" while an
    // individual apply later degrades — fail-open, but never silent).
    process.stderr.write(
      `openllmd --sandbox-exec: sandbox not applied (${state}) — running unconfined\n`,
    );
    logWarn("sandbox", `--sandbox-exec apply degraded (${state})`, {
      command: tail[0] ?? "?",
    });
  }
  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = Bun.spawn([...tail], {
      stdio: ["inherit", "inherit", "inherit"],
      env: process.env,
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
  // forwarded (uncatchable), so a kill -9 of the wrapper orphans the tail.
  // Bun exposes neither `PR_SET_PDEATHSIG` for a spawned child nor
  // detached/process-group spawn semantics, and an FFI prctl can't run in the
  // child between fork and exec. Every daemon-side kill path uses catchable
  // signals (`proc.kill()` = SIGTERM, spawnLogin's reaper uses SIGKILL on the
  // SHIM only after the `until`/timeout capture — at which point an orphaned
  // login child is the same wedge class the pre-shim code already tolerated
  // and the orphan-reaper handles at next boot). Revisit if Bun grows
  // pdeathsig/process-group support.
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
    logWarn("sandbox", "OPENLLM_DAEMON_NO_SANDBOX=1 — children run unconfined");
    return "off";
  }
  if (isDevSourceRun() && process.env.OPENLLM_DAEMON_SANDBOX !== "1") {
    return "off";
  }
  if (process.platform === "darwin") return "enforced";
  if (process.platform !== "linux") return "unsupported";
  return probeLandlockSupport();
};
