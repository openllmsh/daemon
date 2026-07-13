/**
 * Native-runtime bridge contract (trial) — the daemon-local seam that lets a
 * subscription hop execute through the OFFICIAL vendor runtime instead of the
 * walker's manual upstream HTTP serialization:
 *
 *   - claude_code → the isolated Claude Code CLI in headless stream-json mode
 *     (`claude -p --output-format stream-json --include-partial-messages`),
 *   - chatgpt     → the isolated Codex CLI's `codex app-server` JSON-RPC.
 *
 * The bridge changes WHERE the vendor request is produced (the vendor's own
 * runtime, under the daemon's isolated CLI env), never WHO routes: the cloud
 * still resolves + signs the plan, the walker still validates it, and every
 * pre-commit failure falls back to the existing manual transport on the SAME
 * hop. See docs/audit/2026-07-13-t3code-provider-routing-comparison.md §5.
 *
 * Scope (see `nativeRequestOf`): a hop is native-eligible when the request is a
 * plain multi-turn TEXT conversation (served via session resume — only the
 * delta turn is fed), plus tool-bearing `claude_code` requests (the held-open
 * SDK query). Images, structured output, and (for now) chatgpt tools decline
 * up front and the MANUAL transport serves them on the same hop, so the bridge
 * can never regress behavior it does not support.
 */

import type {
  TChatCompletionChunk,
  TChatCompletionRequest,
} from "@quantidexyz/openllmp";
import { stateDir } from "../env";

/**
 * The subscription providers served by the native runtime FIRST — `claude_code`
 * (Claude Code CLI, `claude -p` stream-json) and `chatgpt` (Codex `app-server`
 * JSON-RPC). Both verified live against the daemon's ISOLATED credential: the
 * official runtime owns auth/refresh/identity and the upstream request. The
 * walker falls back to the MANUAL transport when the native path declines
 * (tools/images/structured-output/native gaps), so no workflow is blocked;
 * auth/refresh flow through the CLI on both paths. (kimi_code + grok are
 * manual-only.)
 *
 * Two non-obvious requirements make `claude -p` work with the isolated home
 * (see `claude-native.ts` + `cleanNativeSpawnEnv`): NO `--bare` flag (it drops
 * the setting sources that carry the subscription credential → "Not logged
 * in"), and the FULL session env minus auth-poison (macOS keychain access
 * needs the real env, not an `env -i` minimal one).
 */
export type TNativeRuntimeProvider = "claude_code" | "chatgpt";

const NATIVE_PROVIDERS: ReadonlySet<string> = new Set([
  "claude_code",
  "chatgpt",
]);

/** Whether a plan hop's provider is served exclusively by a native runtime. */
export const isNativeRuntimeProvider = (
  provider: string,
): provider is TNativeRuntimeProvider => NATIVE_PROVIDERS.has(provider);

/** Env-var name prefixes/keys that override a vendor runtime's OWN
 *  subscription credential resolution — dropping them forces the runtime onto
 *  its official login (keychain / auth.json) instead of an ambient API key or
 *  a redirected base URL that would 401 as "Not logged in". */
const POISON_PREFIX = /^(ANTHROPIC_|OPENAI_)/;
const POISON_KEYS: ReadonlySet<string> = new Set([
  "CLAUDE_CODE_API_KEY",
  "CLAUDE_CODE_OAUTH_TOKEN",
  "CODEX_API_KEY",
]);

/**
 * The spawn env for a native vendor runtime: INHERIT the full `process.env`
 * (macOS keychain access needs the real session env — an `env -i`-style
 * minimal env breaks `claude -p`'s credential read), then DROP the auth
 * poison (`ANTHROPIC_*` / `OPENAI_*` / token keys that Bun's auto-loaded
 * `.env*` or the ambient shell can inject and which would override the
 * runtime's subscription login), and finally overlay the isolated CLI env
 * (`cliEnv(...)`: HOME, config-dir, TMPDIR) so the runtime uses the daemon's
 * OWN account state, not the user's interactive one.
 */
export const cleanNativeSpawnEnv = (
  cliEnv: Record<string, string>,
): Record<string, string> => {
  const base: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (POISON_PREFIX.test(key) || POISON_KEYS.has(key)) continue;
    base[key] = value;
  }
  return {
    ...base,
    // Pin the daemon's REAL state dir so any openllm daemon code the child
    // (or a child's child) runs resolves `~/.openllm` to the real location —
    // NOT `<isolated HOME>/.openllm`. Without this, a child computing
    // `stateDir()` under the isolated HOME recursively creates
    // `<iso home>/.openllm/cli/<provider>/home`. (openllmc uses `homedir()`
    // directly and ignores this — the `--strict-mcp-config`/`--setting-sources
    // ""` flags keep the openllm MCP from loading on the inference path.)
    OPENLLM_DAEMON_STATE_DIR: stateDir(),
    ...cliEnv,
  };
};

/**
 * The daemon's per-hop token row (what the recorder + cloud consume).
 * `tokens_in` is the canonical prompt-token total and INCLUDES the two cache
 * fields; the cloud prices the split at cache rates. Shared by BOTH the native
 * path (serve + tool bridges) and the walker's manual transport so the two
 * can't drift.
 */
export type TNativeTokens = {
  readonly tokens_in: number;
  readonly tokens_out: number;
  readonly cached_tokens: number;
  readonly cache_creation_tokens: number;
};

/** The all-zero token row (pre-output failures, un-metered fallbacks). */
export const ZERO_TOKENS: TNativeTokens = {
  tokens_in: 0,
  tokens_out: 0,
  cached_tokens: 0,
  cache_creation_tokens: 0,
};

/** Extract the token row from a canonical response's usage — the SINGLE mapper
 *  both the native and manual paths use (identical field folding). */
export const tokensFromResponse = (resp: {
  readonly usage?: {
    readonly prompt_tokens: number;
    readonly completion_tokens: number;
    readonly prompt_tokens_details?: {
      readonly cached_tokens?: number;
      readonly cache_creation_tokens?: number;
    };
  } | null;
}): TNativeTokens => ({
  tokens_in: resp.usage?.prompt_tokens ?? 0,
  tokens_out: resp.usage?.completion_tokens ?? 0,
  cached_tokens: resp.usage?.prompt_tokens_details?.cached_tokens ?? 0,
  cache_creation_tokens:
    resp.usage?.prompt_tokens_details?.cache_creation_tokens ?? 0,
});

/** One text turn of a canonical conversation (Phase 1 = text only). */
export type TNativeTurn = {
  readonly role: "user" | "assistant";
  readonly text: string;
};

/**
 * A native-eligible request decomposed for session-resume execution: the
 * system prompt plus the ordered user/assistant TEXT turns. The session store
 * derives the conversation identity + the delta turn to feed from `turns`.
 */
export type TNativeRequest = {
  readonly systemText: string | null;
  readonly turns: ReadonlyArray<TNativeTurn>;
};

/**
 * Phase-1 capability gate: decompose a canonical request into `{ systemText,
 * turns }` when it's a plain multi-turn TEXT conversation the native runtimes
 * can serve via session resume, or null when it isn't yet supported (tools /
 * tool_choice / response_format / non-text content / `tool`-role messages —
 * those are Phase 2). It accepts prior assistant turns: the session store
 * feeds only the NEW turn to a resumed session.
 */
export const nativeRequestOf = (
  canonical: TChatCompletionRequest,
): TNativeRequest | null => {
  if ((canonical.tools?.length ?? 0) > 0) return null;
  if (canonical.tool_choice !== undefined && canonical.tool_choice !== null) {
    return null;
  }
  if (
    canonical.response_format !== undefined &&
    canonical.response_format !== null
  ) {
    return null;
  }
  const systemParts: string[] = [];
  const turns: TNativeTurn[] = [];
  for (const message of canonical.messages) {
    if (message.role === "system") {
      const text = plainTextOf(message.content);
      if (text === null) return null;
      if (text.length > 0) systemParts.push(text);
      continue;
    }
    if (message.role === "user" || message.role === "assistant") {
      const text = plainTextOf(message.content);
      if (text === null) return null; // non-text content (image/file) → Phase 2
      turns.push({ role: message.role, text });
      continue;
    }
    return null; // `tool` role → Phase 2 (tool-passthrough)
  }
  // The final turn must be a user turn (the thing to answer), and there must
  // be at least one.
  const last = turns.at(-1);
  if (last === undefined || last.role !== "user" || last.text.length === 0) {
    return null;
  }
  return {
    systemText: systemParts.length > 0 ? systemParts.join("\n\n") : null,
    turns,
  };
};

/** Plain text of a canonical message content, or null when non-text parts
 *  (images/files) are present — those are out of trial scope. */
const plainTextOf = (
  content: TChatCompletionRequest["messages"][number]["content"],
): string | null => {
  if (typeof content === "string") return content;
  if (content === null || content === undefined) return "";
  if (!Array.isArray(content)) return null;
  const parts: string[] = [];
  for (const part of content) {
    if (
      typeof part !== "object" ||
      part === null ||
      (part as { type?: unknown }).type !== "text" ||
      typeof (part as { text?: unknown }).text !== "string"
    ) {
      return null;
    }
    parts.push((part as { text: string }).text);
  }
  return parts.join("");
};

/**
 * A bridge run either COMMITS (first model output observed — the canonical
 * chunk stream is live and the walker must serve it; mirrors the walker's
 * commit-on-first-byte rule) or DECLINES pre-commit (spawn failure, protocol
 * error, vendor refusal before output) — the walker falls back to the manual
 * transport on the same hop.
 */
export type TNativeRunResult =
  | {
      readonly kind: "committed";
      readonly chunks: ReadableStream<TChatCompletionChunk>;
      /** The provider session id to resume next turn — Claude's stream-json
       *  `session_id`, or Codex's app-server thread id. A GETTER because
       *  Claude's authoritative id may only settle on the terminal `result`
       *  line; the serve adapter reads it AFTER the stream drains. Null when
       *  the runtime produced none (→ the session isn't recorded). */
      readonly sessionId: () => string | null;
    }
  | { readonly kind: "declined"; readonly reason: string };
