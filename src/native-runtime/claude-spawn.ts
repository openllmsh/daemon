/**
 * Shared `claude -p` argv + spawn owner for `claude-native.ts` and
 * `claude-capture.ts` — capture is a wrapper around the same invocation, never
 * a parallel one. Callers decide env policy (capture layers
 * `ANTHROPIC_BASE_URL` onto the cleaned env first); this module just spawns
 * with whatever final env it's given.
 */

import { spawnCwd } from "../delegation/util";
import { sandboxSpawnArgs } from "../sandbox/exec";
import { unwrapKeychainSpawn } from "../sandbox/policy";

export type TClaudeCliArgvParams = {
  readonly bin: string;
  readonly providerModelId: string;
  /** Applied ONLY on a fresh session (a resumed session already carries it). */
  readonly systemText: string | null;
  /** Resume this session id (feed only the delta turn), or null → fresh session. */
  readonly resumeSessionId: string | null;
};

/** The one `claude -p …` argv both callers build. See `claude-native.ts`'s
 *  file doc for per-flag rationale (no `--bare`, `--max-turns 1`, …). */
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

/** Build the argv and spawn the isolated `claude` CLI child. Throws whatever
 *  `Bun.spawn` throws; callers translate that into their own decline. */
export const spawnClaudeCli = (
  params: TSpawnClaudeCliParams,
): ReturnType<typeof Bun.spawn> => {
  const argv = buildClaudeCliArgv(params);
  return Bun.spawn(
    sandboxSpawnArgs(argv, { probe: unwrapKeychainSpawn("claude_code") }),
    {
      stdin: new TextEncoder().encode(params.userText),
      stdout: "pipe",
      stderr: "pipe",
      cwd: spawnCwd(params.finalEnv),
      env: params.finalEnv,
    },
  );
};
