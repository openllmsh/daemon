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
 * Scope is deliberately narrow for the trial (see `nativePromptOf`): a hop is
 * native-eligible only when the request is a plain single-shot generation —
 * no client tools, no prior assistant/tool turns, text-only content. Anything
 * else declines up front and the manual path serves it, so the bridge can
 * never regress behavior it does not support.
 */

import type {
  TChatCompletionChunk,
  TChatCompletionRequest,
} from "@quantidexyz/openllmp";

/** The two providers with a native runtime bridge in the trial. */
export type TNativeRuntimeProvider = "claude_code" | "chatgpt";

const NATIVE_PROVIDERS: ReadonlySet<string> = new Set([
  "claude_code",
  "chatgpt",
]);

/**
 * Opt-in gate — the trial ships OFF. `OPENLLM_NATIVE_RUNTIME` values:
 *   - unset / "0" / "off" / "false"    → disabled (default)
 *   - "1" / "all" / "true"             → both bridges
 *   - "claude_code,chatgpt" (csv)      → per-provider selection
 */
export const nativeRuntimeEnabledFor = (
  provider: string,
  raw: string | undefined = process.env.OPENLLM_NATIVE_RUNTIME,
): provider is TNativeRuntimeProvider => {
  if (!NATIVE_PROVIDERS.has(provider)) return false;
  const value = (raw ?? "").trim().toLowerCase();
  if (value === "" || value === "0" || value === "off" || value === "false") {
    return false;
  }
  if (value === "1" || value === "all" || value === "true") return true;
  return value
    .split(",")
    .map((s) => s.trim())
    .includes(provider);
};

/** The single-shot prompt a native runtime executes for an eligible request. */
export type TNativePrompt = {
  /** Concatenated system-message text, or null when the client sent none. */
  readonly systemText: string | null;
  /** The one user turn's text. */
  readonly userText: string;
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
 * The trial capability gate: return the native prompt when the canonical
 * request is a plain single-shot generation the vendor runtimes can execute
 * faithfully, or null → the walker keeps the manual transport.
 *
 * Eligible = no tools / tool_choice / response_format, and the messages are
 * exactly (any number of) system turns plus ONE user turn, all text-only.
 * Multi-turn histories are out: the vendor runtimes own their session state,
 * and replaying a foreign assistant/tool transcript through them is not a
 * supported operation (see audit §5.4 — unsupported must be explicit, never
 * approximated).
 */
export const nativePromptOf = (
  canonical: TChatCompletionRequest,
): TNativePrompt | null => {
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
  let userText: string | null = null;
  for (const message of canonical.messages) {
    if (message.role === "system") {
      const text = plainTextOf(message.content);
      if (text === null) return null;
      if (text.length > 0) systemParts.push(text);
      continue;
    }
    if (message.role === "user") {
      if (userText !== null) return null; // second user turn → multi-turn
      const text = plainTextOf(message.content);
      if (text === null || text.length === 0) return null;
      userText = text;
      continue;
    }
    return null; // assistant / tool history → out of trial scope
  }
  if (userText === null) return null;
  return {
    systemText: systemParts.length > 0 ? systemParts.join("\n\n") : null,
    userText,
  };
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
    }
  | { readonly kind: "declined"; readonly reason: string };
