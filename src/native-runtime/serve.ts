/**
 * Native-runtime serve adapter — the walker-facing entry. Decides whether a
 * subscription hop is native-eligible, runs the provider's bridge, and
 * re-encodes the canonical chunk stream onto the client's wire with exactly
 * the walker's own streaming/JSON/metering behavior, so a native-served
 * response is indistinguishable from a manual-served one downstream
 * (dashboard rows included — token counts ride the same recorder).
 *
 * `claude_code` / `chatgpt` have NO manual transport — this is their sole
 * path. Returns a `Response` on commit, or `{ declined }` for any pre-commit
 * condition (ineligible request / bridge decline). The walker treats a decline
 * as a pre-stream hop failure and advances the plan. Post-commit the response
 * is final (commit-on-first-byte).
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
import { functionNameUsesWebSearch } from "@quantidexyz/openllmw/tools/web-search/helpers";
import { cliBin, cliEnv } from "../cli-paths";
import { errorJson } from "../cors";
import { runClaudeNative } from "./claude-native";
import { hasClientTools, tryServeClaudeTools } from "./claude-tool-serve";
import { runCodexNative } from "./codex-app-server";
import {
  deriveConversation,
  NativeSessionStore,
  nextPrefixHash,
  renderSeed,
} from "./session-store";
import type { TNativeRunResult, TNativeRuntimeProvider } from "./types";
import { isNativeRuntimeProvider, nativeRequestOf } from "./types";

/** One conversation→session map per native provider (daemon-resident; the
 *  live resume files/threads are daemon-local, so the map is too). */
const stores: Record<TNativeRuntimeProvider, NativeSessionStore> = {
  claude_code: new NativeSessionStore(),
  chatgpt: new NativeSessionStore(),
};

/** Flip to true once codex-cli's app-server emits `item/tool/call` for
 *  `dynamicTools` — the completion tool-passthrough is already built in
 *  `codex-tool-session.ts`; only the CLI runtime support is missing. */
const CODEX_TOOLS_READY = false;

/**
 * A native serve either COMMITS (a `Response` — the vendor runtime produced
 * output) or DECLINES with a reason. A decline means the request is outside the
 * native path's scope (tools/images/structured-output, or a pre-commit
 * failure); the walker then falls back to the MANUAL transport on the SAME hop
 * (`UPSTREAM_WIRE`) so no workflow is blocked.
 */
export type TNativeServeOutcome = Response | { readonly declined: string };

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

/** Does the request declare the openllm-managed web_search function tool?
 *  (Mirrors the walker's own gate — the gateway runs this tool, not the
 *  client, so it must NOT enter the native tool-passthrough path.) */
const requestDeclaresWebSearch = (req: TChatCompletionRequest): boolean =>
  req.tools?.some((t) => functionNameUsesWebSearch(t.function.name)) === true;

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
const textOf = (
  resp: Awaited<ReturnType<typeof accumulateChunksToResponse>>,
): string => {
  const content = resp.choices[0]?.message.content;
  return typeof content === "string" ? content : "";
};

export const tryServeNativeRuntime = async (
  params: TNativeServeParams,
  overrides?: {
    readonly bin?: string;
    readonly env?: Record<string, string>;
  },
): Promise<TNativeServeOutcome> => {
  if (!isNativeRuntimeProvider(params.provider)) {
    return { declined: `${params.provider} has no native runtime` };
  }
  // openllm-managed web_search is executed by the GATEWAY — the walker's
  // agentic `serveWithWebSearch` loop (cross-wire) or Anthropic's own native
  // search (messages passthrough) — never by the client. The native tool path
  // would instead register web_search as a client tool and hand the caller a
  // `web_search` tool_call it has no implementation for, stalling the turn. So
  // decline here and let the manual transport (which routes web_search
  // correctly via `shouldInterceptWebSearch`) serve the hop.
  if (requestDeclaresWebSearch(params.canonical)) {
    return {
      declined: "web_search runs on the gateway's managed loop (manual transport)",
    };
  }
  // Tool-bearing requests use completion tool-passthrough. claude_code: the
  // held-open SDK query (works). chatgpt: the Codex app-server's native
  // dynamic-tool protocol (`dynamicTools` + `item/tool/call`) is IMPLEMENTED
  // (`codex-tool-session.ts`) but codex-cli 0.144.0's runtime doesn't route
  // dynamic tool calls to the client yet (the schema ships under
  // `--experimental`; `item/tool/call` never fires) — so chatgpt tools decline
  // until the CLI activates it. Flip `CODEX_TOOLS_READY` when it does.
  if (hasClientTools(params.canonical)) {
    if (params.provider === "chatgpt" && !CODEX_TOOLS_READY) {
      return {
        declined:
          "codex dynamic-tool routing not available in this codex-cli (item/tool/call not emitted)",
      };
    }
    return tryServeClaudeTools({
      provider: params.provider,
      providerModelId: params.providerModelId,
      surface: params.surface,
      canonical: params.canonical,
      bin: overrides?.bin ?? cliBin(params.provider),
      env: overrides?.env ?? cliEnv(params.provider),
      record: params.record,
    });
  }
  const req = nativeRequestOf(params.canonical);
  if (req === null) {
    return {
      declined:
        "native runtime supports text conversations only (tools, images, and structured output are Phase 2)",
    };
  }

  // Correlate to a persisted session and compute the delta turn to feed.
  const store = stores[params.provider];
  const { prefixHash, deltaText, hasPrior } = deriveConversation(
    req.systemText,
    req.turns,
  );
  if (deltaText.length === 0) return { declined: "no user turn to answer" };
  const lease = await store.lease(prefixHash);
  const resumeId = lease.sessionId; // null → fresh session
  // Resume feeds ONLY the delta. A fresh session with unmatched prior history
  // renders the transcript as a seed (lossy fallback); a true first turn feeds
  // the delta (which is all the user text) directly.
  const userText =
    resumeId !== null
      ? deltaText
      : hasPrior
        ? renderSeed(req.turns, deltaText)
        : deltaText;
  // A resumed session already carries the system prompt; only a fresh start
  // applies it.
  const systemText = resumeId !== null ? null : req.systemText;

  const bin = overrides?.bin ?? cliBin(params.provider);
  const env = overrides?.env ?? cliEnv(params.provider);
  let run: TNativeRunResult;
  try {
    run =
      params.provider === "claude_code"
        ? await runClaudeNative({
            bin,
            env,
            providerModelId: params.providerModelId,
            systemText,
            userText,
            resumeSessionId: resumeId,
            signal: params.signal,
          })
        : await runCodexNative({
            bin,
            env,
            providerModelId: params.providerModelId,
            systemText,
            userText,
            resumeThreadId: resumeId,
            reasoningEffort: params.canonical.reasoning_effort ?? null,
            signal: params.signal,
          });
  } catch (error) {
    lease.abandon();
    return {
      declined: error instanceof Error ? error.message : String(error),
    };
  }
  if (run.kind === "declined") {
    lease.abandon();
    return { declined: run.reason };
  }

  const committed = run;
  // After the response is accumulated, record tokens AND advance the session:
  // re-key it under `hash(inbound turns + assistant response)` so the NEXT
  // request resumes it. On accumulation failure, abandon (next turn re-seeds).
  const settle = (
    resp: Awaited<ReturnType<typeof accumulateChunksToResponse>>,
  ): void => {
    params.record(tokensOf(resp));
    lease.commit(
      nextPrefixHash(req.systemText, req.turns, textOf(resp)),
      committed.sessionId(),
    );
  };
  const fail = (): void => {
    params.record(ZERO);
    lease.abandon();
  };

  const clientWire = clientWireOf(params.surface);

  // ── Streaming client: tee → meter + encode (walker parity) ──────────
  if (params.wantsStream) {
    const [toClient, toMeter] = committed.chunks.tee();
    void accumulateChunksToResponse(toMeter, params.providerModelId)
      .then(settle)
      .catch(fail);
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

  // ── JSON client: accumulate → record + advance session → re-encode ──
  let canonical: Awaited<ReturnType<typeof accumulateChunksToResponse>>;
  try {
    canonical = await accumulateChunksToResponse(
      committed.chunks,
      params.providerModelId,
    );
  } catch {
    fail();
    return errorJson(502, "native runtime stream ended before output");
  }
  settle(canonical);
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
export { isNativeRuntimeProvider, nativeRequestOf };
