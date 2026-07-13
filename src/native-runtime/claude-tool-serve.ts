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
import { toAnthropicMessagesResponse } from "@quantidexyz/openllmw/adapters/messages/response";
import { toResponsesResponse } from "@quantidexyz/openllmw/adapters/responses";
import { clientWireOf } from "@quantidexyz/openllmw/providers/upstream-request";
import {
  continueToolTurn,
  startToolTurn,
  type TClientTool,
  toolTurnToResponse,
} from "./claude-tool-session";
import type { TNativeTokens } from "./serve";

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
  readonly providerModelId: string;
  readonly surface: "chat_completions" | "messages" | "responses";
  readonly canonical: TChatCompletionRequest;
  readonly bin: string;
  readonly env: Record<string, string>;
  readonly record: (tokens: TNativeTokens) => void;
};

const ZERO_TOKENS: TNativeTokens = {
  tokens_in: 0,
  tokens_out: 0,
  cached_tokens: 0,
  cache_creation_tokens: 0,
};

/** Serve a tool-bearing claude_code request through the held-query orchestrator. */
export const tryServeClaudeTools = async (
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

  const result =
    trailingToolResults.length > 0
      ? // CONTINUE: feed the client's tool results into the paused held query.
        await continueToolTurn(trailingToolResults)
      : // START: the last user turn opens a new held query.
        await startToolTurn({
          bin: params.bin,
          env: params.env,
          providerModelId: params.providerModelId,
          tools: clientToolsOf(params.canonical),
          systemText: systemTextOf(params.canonical),
          resumeSessionId: null,
          userText: lastUserText(params.canonical),
        });

  if (result.kind === "declined") {
    return { declined: result.reason };
  }

  // Metadata-only token row (the SDK path doesn't surface token counts yet).
  params.record(ZERO_TOKENS);

  const canonicalResp = toolTurnToResponse(result, params.providerModelId);
  const clientWire = clientWireOf(params.surface);
  const body =
    params.surface === "responses"
      ? toResponsesResponse(canonicalResp)
      : clientWire === "anthropic"
        ? toAnthropicMessagesResponse(canonicalResp)
        : canonicalResp;
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

const lastUserText = (canonical: TChatCompletionRequest): string => {
  for (let i = canonical.messages.length - 1; i >= 0; i--) {
    const m = canonical.messages[i];
    if (m?.role === "user") return plainText(m.content);
  }
  return "";
};
