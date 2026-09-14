/**
 * Serve-layer glue for TOOL-bearing `claude_code` requests: decompose the
 * canonical request, route it to the held-query orchestrator
 * (`claude-tool-session.ts`), and re-encode the result onto the client's wire.
 *
 * A full agentic task maps to ONE held query: the first request (ending in a
 * user turn) STARTS it; each tool round-trip (its tail carrying `tool`
 * results, plus any context the client injected alongside them — e.g. loaded
 * Skill instructions) CONTINUES it until the model answers with final text.
 * (Cross-user-turn resume — a brand-new question after a completed tool
 * answer — currently starts fresh; that's the documented follow-up.)
 */

import type { TChatCompletionRequest } from "@openllmsh/protocol";
import { TOOL_SESSION_HEADER } from "@openllmsh/protocol";
import { responseToChunkStream } from "@openllmsh/wire/lib/streaming/response-stream";
import { clientWireOf } from "@openllmsh/wire/providers/upstream-request";
import { deliverJsonResponse, sseResponseForClient } from "../client-encode";
import type { TToolContinuationIdentity } from "./claude-tool-continuation";
import type { TSdkUserContent } from "./claude-tool-media";
import { hasNonTextContent, sdkUserContentFor } from "./claude-tool-media";
import type { TClientTool, TIteratorFactory } from "./claude-tool-session";
import {
  continueToolTurn,
  disposeHeldToolSession,
  startToolTurn,
  toolTurnToResponse,
} from "./claude-tool-session";
import {
  continueCodexToolTurn,
  disposeHeldCodexToolSession,
  startCodexToolTurn,
} from "./codex-tool-session";
import type { TNativeTokens } from "./types";
import { ZERO_TOKENS } from "./types";

export type TToolServeOutcome = Response | { readonly declined: string };

const withContinuationHeader = (
  response: Response,
  continuationToken: string | null,
): Response => {
  if (continuationToken === null) return response;
  const headers = new Headers(response.headers);
  headers.set(TOOL_SESSION_HEADER, continuationToken);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

/** Does the request carry client function tools (→ the tool path)? */
export const hasClientTools = (canonical: TChatCompletionRequest): boolean =>
  (canonical.tools?.length ?? 0) > 0;

const plainText = (
  content: TChatCompletionRequest["messages"][number]["content"],
): string => {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .filter(
      (p): p is { type: "text"; text: string } =>
        typeof p === "object" &&
        p !== null &&
        (p as { type?: unknown }).type === "text",
    )
    .map((p) => p.text)
    .join("");
};

const clientToolsOf = (
  canonical: TChatCompletionRequest,
): ReadonlyArray<TClientTool> =>
  (canonical.tools ?? []).map((t) => ({
    name: t.function.name,
    description: t.function.description,
    parameters: t.function.parameters as Record<string, unknown> | undefined,
  }));

const systemTextOf = (canonical: TChatCompletionRequest): string | null => {
  const parts = canonical.messages
    .filter((m) => m.role === "system")
    .map((m) => plainText(m.content))
    .filter((t) => t.length > 0);
  return parts.length > 0 ? parts.join("\n\n") : null;
};

export type TClaudeToolServeParams = {
  readonly provider: "claude_code" | "chatgpt";
  readonly providerModelId: string;
  readonly surface: "chat_completions" | "messages" | "responses";
  readonly canonical: TChatCompletionRequest;
  /** The client asked for SSE — the completion (with tool_calls) is streamed,
   *  not returned as a single JSON body. */
  readonly wantsStream: boolean;
  readonly stripSubagentIsolation: boolean;
  readonly bin: string;
  readonly env: Record<string, string>;
  readonly record: (tokens: TNativeTokens, status: "success" | "error") => void;
  /** Optional, backward-compatible continuation capability sent by the client. */
  readonly continuationToken?: string | null;
  readonly continuationIdentity?: TToolContinuationIdentity;
  /** Test seam: inject a fake SDK query iterator (default = the real SDK). */
  readonly makeIterator?: TIteratorFactory;
};

/** Everything the client appended since the model's pending tool call: the
 *  tool RESULTS that answer it, plus any context messages injected alongside
 *  them. Claude Code delivers loaded-skill instructions as a user message
 *  right next to the Skill tool_result (and mid-conversation system turns can
 *  land here too) — a continuation that forwards only the results silently
 *  severs that context, so the model answers the bare "Launching skill: …"
 *  acknowledgement and ends the turn (the Skill-halt incident).
 *
 *  `hasMedia` rides the SAME scan (tool results included — the protocol lets a
 *  tool result carry image/file parts, which `plainText` would erase exactly
 *  like an injected user attachment). A separate scan could drift from this
 *  one; a single pass cannot. */
export const splitContinuationTail = (
  messages: TChatCompletionRequest["messages"],
): {
  readonly toolResults: ReadonlyArray<{ id: string; content: string }>;
  readonly injectedContext: string | null;
  readonly hasMedia: boolean;
} => {
  const toolResults: Array<{ id: string; content: string }> = [];
  const injectedParts: string[] = [];
  let hasMedia = false;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m === undefined || m.role === "assistant") break;
    if (hasNonTextContent(m.content)) hasMedia = true;
    if (m.role === "tool") {
      const id = (m as { tool_call_id?: string }).tool_call_id;
      if (typeof id === "string") {
        toolResults.unshift({ id, content: plainText(m.content) });
      }
      continue;
    }
    const text = plainText(m.content);
    if (text.length > 0) injectedParts.unshift(text);
  }
  return {
    toolResults,
    hasMedia,
    injectedContext:
      toolResults.length > 0 && injectedParts.length > 0
        ? `[context added by the client after this tool call — treat it as conversation context, not tool output]\n${injectedParts.join("\n\n")}`
        : null,
  };
};

/** Serve a tool-bearing native request (claude_code held-query orchestrator,
 *  or the gated codex dynamic-tool session). */
export const tryServeNativeToolTurn = async (
  params: TClaudeToolServeParams,
): Promise<TToolServeOutcome> => {
  const {
    toolResults: trailingToolResults,
    injectedContext,
    hasMedia: tailHasMedia,
  } = splitContinuationTail(params.canonical.messages);

  const isClaude = params.provider === "claude_code";
  // MEDIA ADMISSION, evaluated before any query is started (and after the
  // provider-specific dispatch in `serve.ts`, so cursor's own richer surface is
  // untouched).
  //
  // - CONTINUATION (either provider): the held turn is paused inside a tool
  //   handler; neither the SDK query nor the app-server session can take a
  //   fresh user message there, so genuinely new media mid-round is an explicit
  //   unsupported failure, never a silent flatten.
  // - claude_code START: structured content is carried through (below).
  // - chatgpt (codex) START: the app-server tool protocol takes text only, so
  //   decline BEFORE starting a query and let the walker's manual transport —
  //   which does convert media — serve the hop. When policy leaves no such
  //   transport the hop fails explicitly with this reason rather than answering
  //   blind about an attachment the model never saw.
  //
  // A rejected continuation ends this turn for good: the walker serves the hop
  // through the manual transport, so nobody will ever answer the paused tool
  // call. DISPOSE the held query (ownership-matched to the very ids this
  // request carries) instead of leaving a live `claude` subprocess parked until
  // the 10-minute idle TTL.
  if (trailingToolResults.length > 0) {
    if (tailHasMedia) {
      const ids = trailingToolResults.map((r) => r.id);
      if (isClaude) {
        disposeHeldToolSession(
          ids,
          params.continuationIdentity,
          params.continuationToken ?? null,
        );
      } else {
        disposeHeldCodexToolSession(ids);
      }
      return {
        declined:
          "new attachments cannot be delivered while a client tool round is held open",
      };
    }
  } else if (historyHasMedia(params.canonical)) {
    // A FRESH turn replays prior history as the lossy text transcript, which
    // erases an attachment an earlier turn carried. The browser already strips
    // historical attachments before sending, so this only fires for a client
    // that genuinely re-sends them — and for that client a silent drop is the
    // same defect we are fixing. Decline to the manual transport, which does
    // convert the whole conversation's media.
    return {
      declined:
        "historical attachments cannot be replayed into a native tool turn; they fall to the manual transport",
    };
  } else if (
    !isClaude &&
    hasNonTextContent(lastUserContent(params.canonical))
  ) {
    return {
      declined:
        "native tool runtime serves text conversations; attachments fall to the manual transport",
    };
  }
  const active =
    isClaude && trailingToolResults.length === 0
      ? activeUserContentOf(params.canonical)
      : ({ kind: "text" } as const);
  if (active.kind === "unsupported") {
    return { declined: active.reason };
  }
  // The transcript is built ONCE: structured turns embed it as their leading
  // text block (`activeUserContentOf`), so the string seed would be dead work.
  const userText =
    active.kind === "ok" ? "" : seedFromHistory(params.canonical);

  const result =
    trailingToolResults.length > 0
      ? // CONTINUE: feed the client's tool results — and any context the
        // client injected alongside them — into the paused held turn.
        isClaude
        ? await continueToolTurn(
            trailingToolResults,
            injectedContext,
            params.continuationToken ?? null,
            params.continuationIdentity,
          )
        : await continueCodexToolTurn(trailingToolResults, injectedContext)
      : // START: the last user turn opens a new held turn.
        isClaude
        ? await startToolTurn(
            {
              bin: params.bin,
              env: params.env,
              providerModelId: params.providerModelId,
              tools: clientToolsOf(params.canonical),
              systemText: systemTextOf(params.canonical),
              resumeSessionId: null,
              userText,
              userContent: active.kind === "ok" ? active.content : null,
            },
            params.makeIterator,
            params.continuationIdentity,
          )
        : await startCodexToolTurn({
            bin: params.bin,
            env: params.env,
            providerModelId: params.providerModelId,
            tools: clientToolsOf(params.canonical),
            systemText: systemTextOf(params.canonical),
            reasoningEffort: params.canonical.reasoning_effort ?? null,
            userText,
          });

  if (result.kind === "declined") {
    return { declined: result.reason };
  }

  // Record THIS fresh turn's token row. The Claude SDK path surfaces per-turn
  // usage (`result.usage`, folded to the same shape as the plain-text native
  // path); idempotent continuation replays must not record that usage again.
  if (result.replayed !== true) {
    params.record(result.usage ?? ZERO_TOKENS, "success");
  }

  const canonicalResp = toolTurnToResponse(result, params.providerModelId);
  const continuationToken =
    result.kind === "tool_calls" && "continuationToken" in result
      ? (result.continuationToken ?? null)
      : null;
  const clientWire = clientWireOf(params.surface);

  // Streaming client: encode the completion (tool_calls or final text) as SSE
  // so a `stream: true` client gets the wire it expects — a JSON body here
  // breaks/hangs streaming SDK clients (real Claude Code streams). Each request
  // is independent (the client sends its tool results in the NEXT request), so
  // streaming a single completion is correct.
  if (params.wantsStream) {
    // Tokens were already recorded above — encode-only, no meter tee.
    return withContinuationHeader(
      sseResponseForClient(
        responseToChunkStream(canonicalResp),
        params.surface,
        clientWire,
        undefined,
        params.stripSubagentIsolation,
      ),
      continuationToken,
    );
  }

  return withContinuationHeader(
    deliverJsonResponse(
      canonicalResp,
      params.surface,
      clientWire,
      undefined,
      params.stripSubagentIsolation,
    ),
    continuationToken,
  );
};

/** Render one prior message into the lossy multi-turn seed transcript. */
const renderToolMessage = (
  m: TChatCompletionRequest["messages"][number],
): string => {
  if (m.role === "user") return `User: ${plainText(m.content)}`;
  if (m.role === "tool") return `Tool result: ${plainText(m.content)}`;
  if (m.role === "assistant") {
    const calls = (
      m as {
        tool_calls?: ReadonlyArray<{
          function: { name: string; arguments: string };
        }>;
      }
    ).tool_calls;
    const called =
      calls !== undefined && calls.length > 0
        ? ` [called: ${calls
            .map((c) => `${c.function.name}(${c.function.arguments})`)
            .join(", ")}]`
        : "";
    return `Assistant: ${plainText(m.content)}${called}`;
  }
  return "";
};

/**
 * Seed text for a NEW tool turn (the trailing message is a user turn, not a
 * tool result). A genuine first turn — no prior non-system messages — just
 * feeds the user text. A FOLLOW-UP question after a completed tool answer has
 * no live held query to resume, so replay the prior transcript into the seed
 * (the tool-path analogue of the text path's `renderSeed`) — the model stays
 * grounded instead of losing every prior turn the client dutifully resent.
 * Lossy (no session/cache reuse), but no amnesia.
 */
const lastUserIndex = (msgs: TChatCompletionRequest["messages"]): number => {
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i]?.role === "user") return i;
  }
  return -1;
};

/** Everything that precedes the delta user turn's own content: "" on a genuine
 *  first turn, otherwise the lossy prior transcript ending in `User: `. */
const seedPrefixOf = (
  canonical: TChatCompletionRequest,
  lastUser: number,
): string => {
  // Everything before the delta user turn, minus system (rides `systemText`).
  const prior = canonical.messages
    .slice(0, Math.max(lastUser, 0))
    .filter((m) => m.role !== "system");
  if (prior.length === 0) return "";
  const transcript = prior
    .map(renderToolMessage)
    .filter((s) => s.length > 0)
    .join("\n\n");
  return transcript.length === 0
    ? ""
    : `Continue this conversation. Prior transcript:\n\n${transcript}\n\nUser: `;
};

export const seedFromHistory = (canonical: TChatCompletionRequest): string => {
  const msgs = canonical.messages;
  const lastUser = lastUserIndex(msgs);
  const delta = lastUser >= 0 ? plainText(msgs[lastUser]?.content) : "";
  return `${seedPrefixOf(canonical, lastUser)}${delta}`;
};

/**
 * Structured content for the ACTIVE user turn when (and only when) it carries
 * media. The turn's own blocks stay in their original order behind the lossy
 * transcript prefix, so "look at this: <image> …and this one: <image>" reaches
 * the model with both attachments in place.
 *
 * Only the attaching turn is projected: prior turns keep rendering as the
 * text-only transcript, so a browser that re-sends history during a tool round
 * can never attach a second copy of media the model already consumed.
 */
export const activeUserContentOf = (
  canonical: TChatCompletionRequest,
):
  | { readonly kind: "text" }
  | { readonly kind: "ok"; readonly content: TSdkUserContent }
  | { readonly kind: "unsupported"; readonly reason: string } => {
  const msgs = canonical.messages;
  const lastUser = lastUserIndex(msgs);
  if (lastUser < 0) return { kind: "text" };
  const content = msgs[lastUser]?.content;
  if (!hasNonTextContent(content)) return { kind: "text" };
  return sdkUserContentFor(content, seedPrefixOf(canonical, lastUser));
};

/** Content of the trailing user turn (the delta this request asks about). */
export const lastUserContent = (
  canonical: TChatCompletionRequest,
): TChatCompletionRequest["messages"][number]["content"] => {
  const index = lastUserIndex(canonical.messages);
  return index < 0 ? "" : canonical.messages[index]?.content;
};

/** Does any turn BEFORE the active user turn carry media? Those turns only
 *  survive as the lossy text transcript, so their attachments would vanish. */
export const historyHasMedia = (canonical: TChatCompletionRequest): boolean => {
  const lastUser = lastUserIndex(canonical.messages);
  return canonical.messages
    .slice(0, Math.max(lastUser, 0))
    .some((m) => hasNonTextContent(m.content));
};
