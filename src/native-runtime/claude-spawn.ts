/**
 * Shared `claude -p` argv + spawn owner for `claude-native.ts` and
 * `claude-capture.ts` — capture is a wrapper around the same invocation, never
 * a parallel one. Callers decide env policy (capture layers
 * `ANTHROPIC_BASE_URL` onto the cleaned env first); this module just spawns
 * with whatever final env it's given.
 */

import { randomUUID } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { TSupervisedChild } from "../child-supervisor";
import { superviseSpawn } from "../child-supervisor";
import { spawnCwd } from "../delegation/util";
import { withSandboxSpawn } from "../sandbox/exec";
import { unwrapKeychainSpawn } from "../sandbox/policy";
import { daemonTempDir } from "../sandbox/working-set";

/** Staged system-prompt files ride this exact name shape inside the
 *  daemon-private temp dir. The sweep below matches on it — nothing else in
 *  the dir is touched. */
const SYSTEM_PROMPT_FILE_PREFIX = "system-prompt-";
const SYSTEM_PROMPT_FILE_SUFFIX = ".md";

/** A staged file older than this can only be residue of a DEAD daemon: a
 *  live run removes its file when the child exits, and the staging-to-parse
 *  window is seconds. The bound also keeps the sweep from racing a
 *  co-started daemon still inside its own spawn window. */
const STALE_SYSTEM_PROMPT_AGE_MS = 60_000;

/** Files this process staged and has not removed yet. The sweep never
 *  deletes a live in-flight prompt. */
const liveSystemPromptFiles = new Set<string>();

/** Delete staged prompt files left on disk by a daemon that died mid-turn
 *  (SIGKILL, crash, power loss — the exited-path cleanup never ran).
 *  Bounded: one readdir of the daemon-private temp dir plus an lstat per
 *  matching name — no recursion, no link follows. Ownership-safe: only our
 *  own prefix/suffix shape, only regular files, only entries older than the
 *  stale bound and not live in this process. Best-effort: a failure leaves
 *  the residue for the next call's sweep and never blocks the run. */
export const sweepStaleSystemPromptFiles = (): void => {
  const dir = daemonTempDir();
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  const staleBefore = Date.now() - STALE_SYSTEM_PROMPT_AGE_MS;
  for (const name of names) {
    if (
      !name.startsWith(SYSTEM_PROMPT_FILE_PREFIX) ||
      !name.endsWith(SYSTEM_PROMPT_FILE_SUFFIX)
    ) {
      continue;
    }
    const path = join(dir, name);
    if (liveSystemPromptFiles.has(path)) continue;
    try {
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.mtimeMs >= staleBefore) continue;
      rmSync(path, { force: true });
    } catch {
      // best-effort — residue stays for the next sweep
    }
  }
};

export type TStagedSystemPrompt = {
  readonly path: string;
  /** Idempotent, best-effort removal — 0600 inside a daemon-private 0700 dir
   *  leaks nothing if it fails; the stale sweep collects a missed file. */
  readonly remove: () => void;
};

/**
 * SP-6: the caller's system prompt must NEVER ride argv — `--system-prompt
 * <text>` exposes it to any local user via `ps`/`/proc/<pid>/cmdline`. Stage
 * it in a 0600 file inside the daemon-private 0700 temp dir (which the
 * confined child CAN read — `daemonTempDir` is in the sandbox working set) and
 * pass `--system-prompt-file` instead. Throws on a staging failure AFTER
 * removing any partially-written file, so repeated failures never accumulate
 * prompt copies.
 */
export const stageSystemPromptFile = (text: string): TStagedSystemPrompt => {
  const path = join(
    daemonTempDir(),
    `${SYSTEM_PROMPT_FILE_PREFIX}${randomUUID()}${SYSTEM_PROMPT_FILE_SUFFIX}`,
  );
  let removed = false;
  const remove = (): void => {
    if (removed) return;
    removed = true;
    liveSystemPromptFiles.delete(path);
    try {
      rmSync(path, { force: true });
    } catch {
      // best-effort — see TStagedSystemPrompt.remove
    }
  };
  try {
    writeFileSync(path, text, { encoding: "utf8", mode: 0o600 });
    chmodSync(path, 0o600);
    liveSystemPromptFiles.add(path);
  } catch (error) {
    remove();
    throw error;
  }
  return { path, remove };
};

export type TClaudeCliArgvParams = {
  readonly bin: string;
  readonly providerModelId: string;
  /** Applied ONLY on a fresh session (a resumed session already carries it). */
  readonly systemText: string | null;
  /** Resume this session id (feed only the delta turn), or null → fresh session. */
  readonly resumeSessionId: string | null;
  /** SP-6: path of the staged system-prompt file. The spawn owners pass ONLY
   *  this (never `systemText`), so the prompt text never reaches argv. */
  readonly systemPromptFile?: string;
};

/** The one `claude -p …` argv both callers build. See `claude-native.ts`'s
 *  file doc for per-flag rationale (no `--bare`, `--max-turns 1`, …).
 *  `systemText` is retained for the pure builder contract ONLY: every spawn
 *  path stages the prompt and passes `systemPromptFile` instead. */
export const buildClaudeCliArgv = (params: TClaudeCliArgvParams): string[] => [
  params.bin,
  "-p",
  "--output-format",
  "stream-json",
  "--include-partial-messages",
  "--verbose",
  "--setting-sources",
  "",
  // Belt-and-suspenders with `--setting-sources ""`: never load an MCP server.
  "--strict-mcp-config",
  "--tools",
  "",
  "--max-turns",
  "1",
  "--model",
  params.providerModelId,
  // Resume feeds only the delta turn (session already has history + system
  // prompt); a fresh start applies the system prompt and seeds via stdin.
  ...(params.resumeSessionId !== null
    ? ["--resume", params.resumeSessionId]
    : params.systemPromptFile !== undefined
      ? ["--system-prompt-file", params.systemPromptFile]
      : params.systemText !== null
        ? ["--system-prompt", params.systemText]
        : []),
];

export type TSpawnClaudeCliParams = TClaudeCliArgvParams & {
  /** Fed over stdin: the delta turn on resume, or the seed prompt fresh. */
  readonly userText: string;
  /** Final env to spawn with — already cleaned (and, for capture, loopback-
   *  decorated) by the caller; `cwd` is derived from it via `spawnCwd`. */
  readonly finalEnv: Record<string, string>;
};

/** A supervised `claude` child: `child` owns process-GROUP termination, `proc`
 *  is its subprocess for stdio / `exited`. */
export type TClaudeSpawned = {
  readonly child: TSupervisedChild;
  readonly proc: ReturnType<typeof Bun.spawn>;
};

/**
 * Spawn one supervised `claude` child through the sandbox, owning the SP-6
 * prompt file for its whole life. Common to the capture + facade callers
 * (`claude-native.ts` keeps its own inline `withSandboxSpawn` so the spawn
 * ownership test sees the guarded call in that file).
 *
 * - `withSandboxSpawn` cancels the prepared launch if the callback throws.
 * - `superviseSpawn` leads an independent process group, so `terminate()`
 *   TERM→KILLs the WHOLE tree.
 * - The keychain probe is `unwrapKeychainSpawn` (macOS runs unconfined: securityd
 *   denies a Seatbelt-confined caller; confined on Linux).
 * - The prompt file is removed when the child exits, or at once if no child
 *   ever ran (spawn or sandbox-setup failure); the original error is rethrown
 *   (callers rethrow `SandboxLaunchError` so setup rejection stays terminal).
 */
const spawnSupervisedClaude = async (
  argv: string[],
  stdin: "pipe" | Uint8Array,
  finalEnv: Record<string, string>,
  stagedPrompt: TStagedSystemPrompt | null,
): Promise<TClaudeSpawned> => {
  let child: TSupervisedChild;
  try {
    child = withSandboxSpawn(
      argv,
      (wrapped) =>
        superviseSpawn(wrapped, {
          kind: "native-runtime",
          stdin,
          stdout: "pipe",
          stderr: "pipe",
          cwd: spawnCwd(finalEnv),
          env: finalEnv,
        }),
      { probe: unwrapKeychainSpawn("claude_code") },
    );
  } catch (error) {
    stagedPrompt?.remove();
    throw error;
  }
  const proc = child.subprocess;
  // The prompt file is needed only while the child parses it at startup; tie
  // removal to exit so every terminal path cleans it up exactly once.
  if (stagedPrompt !== null) {
    void proc.exited.then(stagedPrompt.remove).catch(() => undefined);
  }
  try {
    await child.sandbox?.ready;
  } catch (error) {
    stagedPrompt?.remove();
    await child.terminate().catch(() => undefined);
    throw error;
  }
  return { child, proc };
};

/** Stage the prompt (fresh session only), build the argv and spawn the
 *  isolated `claude` CLI child. Rejects with whatever staging / the sandbox
 *  throws; callers translate that into their own decline. */
export const spawnClaudeCli = async (
  params: TSpawnClaudeCliParams,
): Promise<TClaudeSpawned> => {
  sweepStaleSystemPromptFiles();
  const staged =
    params.resumeSessionId === null && params.systemText !== null
      ? stageSystemPromptFile(params.systemText)
      : null;
  const argv = buildClaudeCliArgv({
    bin: params.bin,
    providerModelId: params.providerModelId,
    systemText: null,
    resumeSessionId: params.resumeSessionId,
    ...(staged !== null ? { systemPromptFile: staged.path } : {}),
  });
  return spawnSupervisedClaude(
    argv,
    new TextEncoder().encode(params.userText),
    params.finalEnv,
    staged,
  );
};

/**
 * A loopback MCP server exposing this turn's caller tools (schema only —
 * `claude-facade-mcp-server.ts`'s handler is inert), or `null` for a
 * tool-free turn. `--strict-mcp-config` (always passed below) means this is
 * the ONLY MCP source the facade child ever sees.
 */
export type TClaudeFacadeMcpServerRef = {
  readonly url: string;
  readonly headers: ReadonlyArray<{
    readonly name: string;
    readonly value: string;
  }>;
};

export type TClaudeFacadeCliArgvParams = {
  readonly bin: string;
  readonly providerModelId: string;
  /** Full system text for this turn — the facade replays whole history every
   *  turn (no vendor session to carry it), so this is never conditional on
   *  resume like {@link TClaudeCliArgvParams.systemText}. */
  readonly systemText: string | null;
  readonly mcpServer: TClaudeFacadeMcpServerRef | null;
  /** SP-6: staged system-prompt file; spawn passes ONLY this, never `systemText`. */
  readonly systemPromptFile?: string;
};

const facadeMcpConfigJson = (server: TClaudeFacadeMcpServerRef): string =>
  JSON.stringify({
    mcpServers: {
      openllm: {
        type: "http",
        url: server.url,
        headers: Object.fromEntries(
          server.headers.map((h) => [h.name, h.value] as const),
        ),
      },
    },
  });

/**
 * The `claude -p --input-format stream-json --output-format stream-json …`
 * argv for the `sdk-facade` completion variant (H2/H3,
 * `docs/plan/bridge-variants-and-capture-adapters/12-hermes-adoption-plan.md`
 * §3.A/§5) — a SEPARATE invocation policy from {@link buildClaudeCliArgv}'s
 * single-shot text CLI, never a copy of it: the facade feeds FRAMED
 * bidirectional stream-json (full history replay every turn, no
 * `--resume`/session persistence — see `claude-sdk-facade.ts`) and may
 * declare caller tools via a loopback MCP server, both of which the plain
 * text variant structurally cannot do. `--tools ""` still disables every
 * BUILT-IN tool regardless of `mcpServer` — caller tools stay caller-owned
 * (00-requirements.md req. 6); `--disable-slash-commands` +
 * `--setting-sources ""` + `--strict-mcp-config` keep the turn hermetic;
 * `--no-session-persistence` matches the plan's "no parked native session"
 * principle (12-hermes-adoption-plan.md §3.E, §5/H2).
 */
export const buildClaudeFacadeArgv = (
  params: TClaudeFacadeCliArgvParams,
): string[] => [
  params.bin,
  "-p",
  "--input-format",
  "stream-json",
  "--output-format",
  "stream-json",
  "--include-partial-messages",
  "--verbose",
  "--setting-sources",
  "",
  "--strict-mcp-config",
  "--disable-slash-commands",
  "--tools",
  "",
  "--max-turns",
  "1",
  "--permission-mode",
  "dontAsk",
  "--no-session-persistence",
  "--model",
  params.providerModelId,
  ...(params.systemPromptFile !== undefined
    ? ["--system-prompt-file", params.systemPromptFile]
    : params.systemText !== null
      ? ["--system-prompt", params.systemText]
      : []),
  ...(params.mcpServer !== null
    ? ["--mcp-config", facadeMcpConfigJson(params.mcpServer)]
    : []),
];

export type TSpawnClaudeFacadeCliParams = TClaudeFacadeCliArgvParams & {
  /** Final env — already cleaned (and, for `sdk-facade-capture`, loopback-
   *  decorated) by the caller, exactly like {@link TSpawnClaudeCliParams}. */
  readonly finalEnv: Record<string, string>;
};

/**
 * Spawn the facade's `claude` child with a WRITABLE stdin pipe — unlike
 * {@link spawnClaudeCli}'s one-shot buffered stdin, the facade writes framed
 * history turns incrementally and reads acknowledgments between writes (see
 * `claude-sdk-facade.ts`'s replay loop), so stdin must stay open as a stream
 * across multiple writes rather than being closed at spawn time.
 */
export const spawnClaudeFacadeCli = async (
  params: TSpawnClaudeFacadeCliParams,
): Promise<TClaudeSpawned> => {
  sweepStaleSystemPromptFiles();
  const staged =
    params.systemText !== null
      ? stageSystemPromptFile(params.systemText)
      : null;
  const argv = buildClaudeFacadeArgv({
    bin: params.bin,
    providerModelId: params.providerModelId,
    systemText: null,
    mcpServer: params.mcpServer,
    ...(staged !== null ? { systemPromptFile: staged.path } : {}),
  });
  return spawnSupervisedClaude(argv, "pipe", params.finalEnv, staged);
};
