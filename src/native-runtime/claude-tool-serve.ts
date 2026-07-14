/**
 * Serve-layer glue for TOOL-bearing `claude_code` requests: decompose the
 * canonical request, route it to the held-query orchestrator
 * (`claude-tool-session.ts`), and re-encode the result onto the client's wire.
 *
 * A full agentic task maps to ONE held query: the first request (ending in a
 * user turn) STARTS it; each tool round-trip (ending in `tool` results)
 * CONTINUES it until the model answers with final text. (Cross-user-turn
 * resume — a brand-new question after a completed tool answer — currently
 * starts fresh; that's the documented follow-up.)
 */

import type { TChatCompletionRequest } from "@quantidexyz/openllmp";
import { responseToChunkStream } from "@quantidexyz/openllmw/lib/streaming/response-stream";
import { withFrameAlignedHeartbeat } from "@quantidexyz/openllmw/lib/streaming/sse";
import { clientWireOf } from "@quantidexyz/openllmw/providers/upstream-request";
import {
  heartbeatOptionsFor,
  jsonBodyForClient,
  sseBytesForClient,
} from "../client-encode";
import type { TClientTool, TIteratorFactory } from "./claude-tool-session";
import {
  continueToolTurn,
  startToolTurn,
  toolTurnToResponse,
} from "./claude-tool-session";
import {
  continueCodexToolTurn,
  startCodexToolTurn,
} from "./codex-tool-session";
import type { TNativeTokens } from "./types";
import { ZERO_TOKENS } from "./types";

export type TToolServeOutcome = Response | { readonly declined: string };

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
  readonly bin: string;
  readonly env: Record<string, string>;
  readonly record: (tokens: TNativeTokens, status: "success" | "error") => void;
  /** Test seam: inject a fake SDK query iterator (default = the real SDK). */
  readonly makeIterator?: TIteratorFactory;
};

/** Serve a tool-bearing native request (claude_code held-query orchestrator,
 *  or the gated codex dynamic-tool session). */
export const tryServeNativeToolTurn = async (
  params: TClaudeToolServeParams,
): Promise<TToolServeOutcome> => {
  const messages = params.canonical.messages;
  const trailingToolResults: Array<{ id: string; content: string }> = [];
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m?.role !== "tool") break;
    const id = (m as { tool_call_id?: string }).tool_call_id;
    if (typeof id === "string") {
      trailingToolResults.unshift({ id, content: plainText(m.content) });
    }
  }

  const isClaude = params.provider === "claude_code";
  const result =
    trailingToolResults.length > 0
      ? // CONTINUE: feed the client's tool results into the paused held turn.
        isClaude
        ? await continueToolTurn(trailingToolResults)
        : await continueCodexToolTurn(trailingToolResults)
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
              userText: seedFromHistory(params.canonical),
            },
            params.makeIterator,
          )
        : await startCodexToolTurn({
            bin: params.bin,
            env: params.env,
            providerModelId: params.providerModelId,
            tools: clientToolsOf(params.canonical),
            systemText: systemTextOf(params.canonical),
            reasoningEffort: params.canonical.reasoning_effort ?? null,
            userText: seedFromHistory(params.canonical),
          });

  if (result.kind === "declined") {
    return { declined: result.reason };
  }

  // Record THIS turn's token row. The Claude SDK path surfaces per-turn usage
  // (`result.usage`, folded to the same shape as the plain-text native path);
  // the gated Codex tool path doesn't yet, so it falls back to zero.
  params.record(result.usage ?? ZERO_TOKENS, "success");

  const canonicalResp = toolTurnToResponse(result, params.providerModelId);
  const clientWire = clientWireOf(params.surface);

  // Streaming client: encode the completion (tool_calls or final text) as SSE
  // so a `stream: true` client gets the wire it expects — a JSON body here
  // breaks/hangs streaming SDK clients (real Claude Code streams). Each request
  // is independent (the client sends its tool results in the NEXT request), so
  // streaming a single completion is correct.
  if (params.wantsStream) {
    const bytes = sseBytesForClient(
      responseToChunkStream(canonicalResp),
      params.surface,
      clientWire,
    );
    return new Response(
      withFrameAlignedHeartbeat(bytes, heartbeatOptionsFor(params.surface)),
      {
        status: 200,
        headers: {
          "content-type": "text/event-stream; charset=utf-8",
          "cache-control": "no-cache",
          connection: "keep-alive",
        },
      },
    );
  }

  const body = jsonBodyForClient(canonicalResp, params.surface, clientWire);
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
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
export const seedFromHistory = (canonical: TChatCompletionRequest): string => {
  const msgs = canonical.messages;
  let lastUser = -1;
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i]?.role === "user") {
      lastUser = i;
      break;
    }
  }
  const delta = lastUser >= 0 ? plainText(msgs[lastUser]?.content) : "";
  // Everything before the delta user turn, minus system (rides `systemText`).
  const prior = msgs
    .slice(0, Math.max(lastUser, 0))
    .filter((m) => m.role !== "system");
  if (prior.length === 0) return delta;
  const transcript = prior
    .map(renderToolMessage)
    .filter((s) => s.length > 0)
    .join("\n\n");
  return transcript.length === 0
    ? delta
    : `Continue this conversation. Prior transcript:\n\n${transcript}\n\nUser: ${delta}`;
};
