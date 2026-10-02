/**
 * Sandboxed, supervised spawn for the Agent SDK's `claude` child — the
 * `spawnClaudeCodeProcess` hook of `query()` options, shared by
 * `claude-tool-session.ts` and `claude-tool-capture.ts` through
 * `claude-tool-sdk-options.ts`.
 *
 * Left to itself the SDK starts `claude` with a bare `child_process.spawn`: no
 * sandbox, no process-group supervision. This module owns that start instead
 * and mirrors `claude-spawn.ts`'s `spawnSupervisedClaude`:
 *
 * - `withSandboxSpawn` cancels the prepared launch if the callback throws.
 * - `superviseSpawn` leads an independent process group; every kill path
 *   (SDK `kill`, the forwarded abort signal) is `child.terminate()` — the
 *   WHOLE tree.
 * - The keychain probe is `unwrapKeychainSpawn("claude_code")`.
 * - SP-6: a system prompt must never ride argv. The installed SDK sends it
 *   over the stdin control channel, but the argv is still rewritten here
 *   (`--system-prompt <text>` → `--system-prompt-file <0600 file>`, same for
 *   `--append-system-prompt`) so an SDK that moves it to argv cannot leak it.
 *   Staged files are removed on exit, error, abort and setup rejection.
 *
 * The SDK's spawn hook is synchronous, so an asynchronous sandbox setup
 * rejection cannot throw from it. It is recorded on the {@link
 * TClaudeSdkSpawnGuard} so callers can rethrow the `SandboxLaunchError` (the
 * SDK itself only reports a generic spawn failure) and serve.ts answers with
 * the sandbox-unavailable response instead of an ordinary decline.
 */

import { EventEmitter } from "node:events";
import { Readable, Writable } from "node:stream";
import type { ReadableStream as TNodeWebStream } from "node:stream/web";
import type {
  SpawnedProcess,
  SpawnOptions,
} from "@anthropic-ai/claude-agent-sdk";
import type { TSupervisedChild } from "../child-supervisor";
import { superviseSpawn } from "../child-supervisor";
import { ensureVendorKeychainReady } from "../delegation/util";
import { SandboxLaunchError, withSandboxSpawn } from "../sandbox/exec";
import { unwrapKeychainSpawn } from "../sandbox/policy";
import type { TStagedSystemPrompt } from "./claude-spawn";
import {
  ClaudeKeychainNotReadyError,
  stageSystemPromptFile,
  sweepStaleSystemPromptFiles,
} from "./claude-spawn";

/**
 * The readiness gate every SDK `query()` must pass BEFORE it is built — the
 * same gate and refusal shape as `claude-spawn.ts`'s `spawnSupervisedClaude`.
 * `unwrapKeychainSpawn` in the spawn hook below only exempts the confinement;
 * it neither checks readiness nor validates FSS-11 permissions. The hook is
 * synchronous and cannot await, so the gate runs here, ahead of `query()`:
 * a refusal means no child, no staged system-prompt file. Abort-aware via
 * `signal`. A no-op off macOS / under the daemon's own home.
 */
export const assertClaudeSdkSpawnReady = async (
  env: Record<string, string>,
  signal?: AbortSignal,
): Promise<void> => {
  const store = await ensureVendorKeychainReady(env, signal);
  if (store.kind !== "present") {
    throw new ClaudeKeychainNotReadyError(
      store.kind === "indeterminate" ? store.cause : store.kind,
    );
  }
};

/** Per-`query()` record of a sandbox refusal the SDK cannot carry. */
export type TClaudeSdkSpawnGuard = {
  /** Set when the spawn hook threw, or the sandbox setup was rejected after
   *  the synchronous hand-off, with a `SandboxLaunchError`. */
  launchFailure: SandboxLaunchError | null;
  /** Settles when the child's sandbox setup has finished (resolved) or been
   *  rejected (rejects). `null` until the spawn hook has started a child. */
  setup: Promise<void> | null;
};

export const createClaudeSdkSpawnGuard = (): TClaudeSdkSpawnGuard => ({
  launchFailure: null,
  setup: null,
});

const SYSTEM_PROMPT_FLAG = "--system-prompt";
const APPEND_SYSTEM_PROMPT_FLAG = "--append-system-prompt";
const FILE_FLAG_FOR: Readonly<Record<string, string>> = {
  [SYSTEM_PROMPT_FLAG]: "--system-prompt-file",
  [APPEND_SYSTEM_PROMPT_FLAG]: "--append-system-prompt-file",
};

export type TSdkArgvRewrite = {
  readonly args: string[];
  readonly staged: TStagedSystemPrompt[];
};

/** Replace every inline system-prompt flag (`--flag text` and `--flag=text`)
 *  with its file-flag twin pointing at a staged 0600 file. Any staging failure
 *  removes the files already staged, then rethrows. */
export const rewriteSdkSystemPromptArgv = (
  args: ReadonlyArray<string>,
): TSdkArgvRewrite => {
  const out: string[] = [];
  const staged: TStagedSystemPrompt[] = [];
  const stage = (flag: string, text: string): void => {
    const file = stageSystemPromptFile(text);
    staged.push(file);
    out.push(FILE_FLAG_FOR[flag] ?? flag, file.path);
  };
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === undefined) continue;
      if (arg === SYSTEM_PROMPT_FLAG || arg === APPEND_SYSTEM_PROMPT_FLAG) {
        const text = args[i + 1];
        if (text === undefined) {
          out.push(arg);
          continue;
        }
        stage(arg, text);
        i++;
        continue;
      }
      const eq = arg.indexOf("=");
      const flag = eq === -1 ? "" : arg.slice(0, eq);
      if (flag === SYSTEM_PROMPT_FLAG || flag === APPEND_SYSTEM_PROMPT_FLAG) {
        stage(flag, arg.slice(eq + 1));
        continue;
      }
      out.push(arg);
    }
  } catch (error) {
    for (const file of staged) file.remove();
    throw error;
  }
  return { args: out, staged };
};

/** Bun stdin sink the SDK writes NDJSON control frames into. */
type TStdinSink = {
  write: (chunk: string | Uint8Array) => number | Promise<number>;
  flush?: () => number | Promise<number>;
  end?: () => number | Promise<number>;
};

const stdinWritable = (sink: TStdinSink): Writable =>
  new Writable({
    write: (chunk: Buffer, _encoding, callback): void => {
      void (async (): Promise<void> => {
        await sink.write(chunk);
        await sink.flush?.();
      })().then(
        () => callback(),
        (error: unknown) =>
          callback(error instanceof Error ? error : new Error(String(error))),
      );
    },
    final: (callback): void => {
      void Promise.resolve(sink.end?.()).then(
        () => callback(),
        () => callback(),
      );
    },
  });

/**
 * Adapt a supervised child to the SDK's `SpawnedProcess`. Every kill is the
 * supervisor's whole-process-group `terminate()`.
 */
const adaptSupervisedChild = (
  child: TSupervisedChild,
  onTerminal: () => void,
): { process: SpawnedProcess; fail: (error: Error) => void } => {
  const proc = child.subprocess;
  const events = new EventEmitter();
  let killed = false;
  const stdin = stdinWritable(proc.stdin as unknown as TStdinSink);
  // A write after the child died is reported through `exit`/`error` events;
  // an unhandled stream 'error' must not take the daemon down.
  stdin.on("error", () => undefined);
  const stdout = Readable.fromWeb(
    proc.stdout as unknown as TNodeWebStream<Uint8Array>,
  );
  stdout.on("error", () => undefined);
  void proc.exited.then(
    (code) => {
      onTerminal();
      events.emit("exit", code, (proc.signalCode as NodeJS.Signals) ?? null);
    },
    () => onTerminal(),
  );
  const process: SpawnedProcess = {
    stdin,
    stdout,
    get killed(): boolean {
      return killed;
    },
    get exitCode(): number | null {
      return proc.exitCode;
    },
    kill: (signal: NodeJS.Signals): boolean => {
      killed = true;
      void child
        .terminate(signal === "SIGKILL" ? { graceMs: 0 } : undefined)
        .catch(() => undefined);
      return true;
    },
    on: (event: "exit" | "error", listener: never): void => {
      events.on(event, listener);
    },
    once: (event: "exit" | "error", listener: never): void => {
      events.once(event, listener);
    },
    off: (event: "exit" | "error", listener: never): void => {
      events.off(event, listener);
    },
  };
  return {
    process,
    fail: (error: Error): void => {
      if (events.listenerCount("error") > 0) events.emit("error", error);
    },
  };
};

/**
 * The `spawnClaudeCodeProcess` implementation for one `query()`. `guard` is
 * written to (never read) here.
 */
export const createClaudeSdkSpawn =
  (guard: TClaudeSdkSpawnGuard) =>
  (options: SpawnOptions): SpawnedProcess => {
    sweepStaleSystemPromptFiles();
    const rewritten = rewriteSdkSystemPromptArgv(options.args);
    const removeStaged = (): void => {
      for (const file of rewritten.staged) file.remove();
    };
    const env: Record<string, string | undefined> = options.env;
    let child: TSupervisedChild;
    try {
      child = withSandboxSpawn(
        [options.command, ...rewritten.args],
        (wrapped) =>
          superviseSpawn(wrapped, {
            kind: "native-runtime",
            stdin: "pipe",
            stdout: "pipe",
            stderr: "ignore",
            ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
            env,
          }),
        { probe: unwrapKeychainSpawn("claude_code") },
      );
    } catch (error) {
      removeStaged();
      if (error instanceof SandboxLaunchError) guard.launchFailure = error;
      throw error;
    }
    const adapted = adaptSupervisedChild(child, removeStaged);
    const setup = (child.sandbox?.ready ?? Promise.resolve()).catch(
      (error: unknown): never => {
        if (error instanceof SandboxLaunchError) guard.launchFailure = error;
        removeStaged();
        void child.terminate().catch(() => undefined);
        adapted.fail(error instanceof Error ? error : new Error(String(error)));
        throw error;
      },
    );
    setup.catch(() => undefined);
    guard.setup = setup;
    const abort = (): void => {
      void child.terminate().catch(() => undefined);
    };
    if (options.signal.aborted) abort();
    else {
      options.signal.addEventListener("abort", abort, { once: true });
      void child.subprocess.exited.then(
        () => options.signal.removeEventListener("abort", abort),
        () => options.signal.removeEventListener("abort", abort),
      );
    }
    return adapted.process;
  };
