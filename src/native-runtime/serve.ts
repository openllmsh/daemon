/**
 * Native-runtime serve adapter — the walker-facing entry. Decides whether a
 * subscription hop is native-eligible, runs the provider's bridge, and
 * re-encodes the canonical chunk stream onto the client's wire with exactly
 * the walker's own streaming/JSON/metering behavior, so a native-served
 * response is indistinguishable from a manual-served one downstream
 * (dashboard rows included — token counts ride the same recorder).
 *
 * Returns "fallback" for ANY pre-commit condition (disabled, ineligible,
 * bridge declined) — the walker then serves the SAME hop over the manual
 * transport. Post-commit the response is final (commit-on-first-byte).
 */

import type {
  TChatCompletionChunk,
  TChatCompletionRequest,
} from "@quantidexyz/openllmp";
import { toAnthropicMessagesResponse } from "@quantidexyz/openllmw/adapters/messages/response";
import { chunksToMessagesSseBytes } from "@quantidexyz/openllmw/adapters/messages/streaming";
import {
  chunksToResponsesSseBytes,
  toResponsesResponse,
} from "@quantidexyz/openllmw/adapters/responses";
import { accumulateChunksToResponse } from "@quantidexyz/openllmw/lib/streaming/accumulate";
import { chunksToSseBytes } from "@quantidexyz/openllmw/lib/streaming/provider-decode";
import { withFrameAlignedHeartbeat } from "@quantidexyz/openllmw/lib/streaming/sse";
import { clientWireOf } from "@quantidexyz/openllmw/providers/upstream-request";
import { cliBin, cliEnv } from "../cli-paths";
import { errorJson } from "../cors";
import { runClaudeNative } from "./claude-native";
import { runCodexNative } from "./codex-app-server";
import type { TNativeRunResult } from "./types";
import { nativePromptOf, nativeRuntimeEnabledFor } from "./types";

/** The walker-owned token row the recorder consumes (mirrors its shape). */
export type TNativeTokens = {
  readonly tokens_in: number;
  readonly tokens_out: number;
  readonly cached_tokens: number;
  readonly cache_creation_tokens: number;
};

export type TNativeServeParams = {
  readonly provider: string;
  readonly providerModelId: string;
  readonly surface: "chat_completions" | "messages" | "responses";
  readonly canonical: TChatCompletionRequest;
  readonly wantsStream: boolean;
  readonly signal: AbortSignal;
  /** Report the hop's token counts to the cloud (walker's `report`). */
  readonly record: (tokens: TNativeTokens) => void;
};

const ZERO: TNativeTokens = {
  tokens_in: 0,
  tokens_out: 0,
  cached_tokens: 0,
  cache_creation_tokens: 0,
};

const tokensOf = (resp: {
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

/**
 * Try to serve one subscription hop through its native runtime. `bin`/`env`
 * are injectable for tests (fixture runtimes); production callers omit them
 * and get the daemon's isolated CLI paths.
 */
export const tryServeNativeRuntime = async (
  params: TNativeServeParams,
  overrides?: {
    readonly bin?: string;
    readonly env?: Record<string, string>;
  },
): Promise<Response | "fallback"> => {
  if (!nativeRuntimeEnabledFor(params.provider)) return "fallback";
  const prompt = nativePromptOf(params.canonical);
  if (prompt === null) return "fallback";

  const bin = overrides?.bin ?? cliBin(params.provider);
  const env = overrides?.env ?? cliEnv(params.provider);
  const run: TNativeRunResult =
    params.provider === "claude_code"
      ? await runClaudeNative({
          bin,
          env,
          providerModelId: params.providerModelId,
          prompt,
          signal: params.signal,
        })
      : await runCodexNative({
          bin,
          env,
          providerModelId: params.providerModelId,
          prompt,
          reasoningEffort: params.canonical.reasoning_effort ?? null,
          signal: params.signal,
        });
  if (run.kind === "declined") return "fallback";

  const clientWire = clientWireOf(params.surface);

  // ── Streaming client: tee → meter + encode (walker parity) ──────────
  if (params.wantsStream) {
    const [toClient, toMeter] = run.chunks.tee();
    void accumulateChunksToResponse(toMeter, params.providerModelId)
      .then((resp) => params.record(tokensOf(resp)))
      .catch(() => params.record(ZERO));
    const clientBytes =
      params.surface === "responses"
        ? chunksToResponsesSseBytes(toClient)
        : clientWire === "anthropic"
          ? chunksToMessagesSseBytes(toClient)
          : chunksToSseBytes(toClient);
    return new Response(
      withFrameAlignedHeartbeat(clientBytes, {
        intervalMs: 15_000,
        kind: params.surface === "messages" ? "anthropic_ping" : "comment",
      }),
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

  // ── JSON client: accumulate → record → re-encode per surface ────────
  let canonical: Awaited<ReturnType<typeof accumulateChunksToResponse>>;
  try {
    canonical = await accumulateChunksToResponse(
      run.chunks,
      params.providerModelId,
    );
  } catch {
    params.record(ZERO);
    return errorJson(502, "native runtime stream ended before output");
  }
  params.record(tokensOf(canonical));
  const body =
    params.surface === "responses"
      ? toResponsesResponse(canonical)
      : clientWire === "anthropic"
        ? toAnthropicMessagesResponse(canonical)
        : canonical;
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

export type { TChatCompletionChunk };
/** Re-exported for the walker + tests. */
export { nativePromptOf, nativeRuntimeEnabledFor };
