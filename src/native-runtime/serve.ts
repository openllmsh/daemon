/**
 * Native-runtime serve adapter — the walker-facing entry. Decides whether a
 * subscription hop is native-eligible, runs the provider's bridge, and
 * re-encodes the canonical chunk stream onto the client's wire with exactly
 * the walker's own streaming/JSON/metering behavior, so a native-served
 * response is indistinguishable from a manual-served one downstream
 * (dashboard rows included — token counts ride the same recorder).
 *
 * The native path is PRIMARY for `claude_code` / `chatgpt`; the walker's
 * MANUAL transport is the FALLBACK. Returns a `Response` on commit, or
 * `{ declined }` for any pre-commit condition (ineligible request — tools the
 * native path can't serve, images, structured output — or a bridge decline).
 * A decline falls through to the manual transport on the SAME hop; the walker
 * only advances the plan if the manual transport ALSO fails pre-stream.
 * Post-commit the response is final (commit-on-first-byte).
 */

import type {
  TChatCompletionChunk,
  TChatCompletionRequest,
} from "@quantidexyz/openllmp";
import { accumulateChunksToResponse } from "@quantidexyz/openllmw/lib/streaming/accumulate";
import { withFrameAlignedHeartbeat } from "@quantidexyz/openllmw/lib/streaming/sse";
import { clientWireOf } from "@quantidexyz/openllmw/providers/upstream-request";
import { cliBin, cliEnv } from "../cli-paths";
import {
  heartbeatOptionsFor,
  jsonBodyForClient,
  sseBytesForClient,
} from "../client-encode";
import { errorJson } from "../cors";
import { runClaudeNative } from "./claude-native";
import { hasClientTools, tryServeNativeToolTurn } from "./claude-tool-serve";
import { runCodexNative } from "./codex-app-server";
import {
  deriveConversation,
  NativeSessionStore,
  nextPrefixHash,
  renderSeed,
} from "./session-store";
import type {
  TNativeRunResult,
  TNativeRuntimeProvider,
  TNativeTokens,
} from "./types";
import {
  isNativeRuntimeProvider,
  nativeRequestOf,
  tokensFromResponse,
  unsupportedNativeControl,
  ZERO_TOKENS,
} from "./types";

/** One conversation→session map per native provider (daemon-resident; the
 *  live resume files/threads are daemon-local, so the map is too). */
const stores: Record<TNativeRuntimeProvider, NativeSessionStore> = {
  claude_code: new NativeSessionStore(),
  chatgpt: new NativeSessionStore(),
};

/**
 * A native serve either COMMITS (a `Response` — the vendor runtime produced
 * output) or DECLINES with a reason. A decline means the request is outside the
 * native path's scope (tools/images/structured-output, or a pre-commit
 * failure); the walker then falls back to the MANUAL transport on the SAME hop
 * (`UPSTREAM_WIRE`) so no workflow is blocked.
 */
export type TNativeServeOutcome = Response | { readonly declined: string };

export type TNativeServeParams = {
  readonly provider: string;
  readonly providerModelId: string;
  readonly surface: "chat_completions" | "messages" | "responses";
  readonly rawBody: unknown;
  readonly canonical: TChatCompletionRequest;
  readonly wantsStream: boolean;
  readonly signal: AbortSignal;
  /** Report the hop's token counts + outcome to the cloud (walker's `report`):
   *  "success" with the accumulated tokens, or "error" with ZERO_TOKENS when
   *  the committed stream failed before accumulating. */
  readonly record: (tokens: TNativeTokens, status: "success" | "error") => void;
};

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

const hasAnthropicNativeServerTool = (params: TNativeServeParams): boolean => {
  if (params.surface !== "messages") return false;
  const tools =
    params.rawBody !== null && typeof params.rawBody === "object"
      ? (params.rawBody as { readonly tools?: unknown }).tools
      : undefined;
  return (
    Array.isArray(tools) &&
    tools.some(
      (tool) =>
        tool !== null &&
        typeof tool === "object" &&
        typeof (tool as { readonly type?: unknown }).type === "string" &&
        (tool as { readonly type: string }).type.startsWith("web_search_"),
    )
  );
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
  if (hasAnthropicNativeServerTool(params)) {
    return {
      declined:
        "Anthropic native server tools use the byte-verbatim manual transport",
    };
  }
  // Requests with client-defined tools use the native runtime's ordinary
  // tool passthrough when supported. Search-shaped function tools are not
  // special-cased or executed by the daemon.
  // Generation controls the native runtimes can't honor (non-default
  // temperature/top_p/penalties, stop, seed, n, logprobs, logit_bias,
  // response_format, forced tool_choice) → decline so the manual transport
  // applies them, instead of silently serving at the runtime's defaults. Guards
  // BOTH the tool and text paths. (max_tokens is a documented carve-out — see
  // `unsupportedNativeControl`.)
  const unsupported = unsupportedNativeControl(params.canonical);
  if (unsupported !== null) {
    return {
      declined: `native runtime can't honor ${unsupported} — served by the manual transport`,
    };
  }
  // Tool-bearing requests use completion tool-passthrough. claude_code: the
  // held-open SDK query. chatgpt: the Codex app-server's native dynamic-tool
  // protocol (`dynamicTools` + `item/tool/call` with code-mode disabled —
  // `codex-tool-session.ts`). A native decline still falls through to the
  // manual transport on the same hop, so an unexpected protocol mismatch just
  // routes slower, never breaks.
  if (hasClientTools(params.canonical)) {
    return tryServeNativeToolTurn({
      provider: params.provider,
      providerModelId: params.providerModelId,
      surface: params.surface,
      canonical: params.canonical,
      wantsStream: params.wantsStream,
      bin: overrides?.bin ?? cliBin(params.provider),
      env: overrides?.env ?? cliEnv(params.provider),
      record: params.record,
    });
  }
  const req = nativeRequestOf(params.canonical);
  if (req === null) {
    // Tool-bearing requests were handled above; this is a non-tool request the
    // native text path still can't represent (image parts, structured output,
    // a tool-role message) — the manual transport serves it.
    return {
      declined:
        "native runtime serves text + tool conversations; images and structured output fall to the manual transport",
    };
  }

  // Correlate to a persisted session and compute the delta turn to feed.
  const store = stores[params.provider];
  const { prefixHash, deltaText, hasPrior } = deriveConversation(
    params.providerModelId,
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
    params.record(tokensFromResponse(resp), "success");
    lease.commit(
      nextPrefixHash(
        params.providerModelId,
        req.systemText,
        req.turns,
        textOf(resp),
      ),
      committed.sessionId(),
    );
  };
  const fail = (): void => {
    params.record(ZERO_TOKENS, "error");
    lease.abandon();
  };

  const clientWire = clientWireOf(params.surface);

  // ── Streaming client: tee → meter + encode (walker parity) ──────────
  if (params.wantsStream) {
    const [toClient, toMeter] = committed.chunks.tee();
    void accumulateChunksToResponse(toMeter, params.providerModelId)
      .then(settle)
      .catch(fail);
    const clientBytes = sseBytesForClient(toClient, params.surface, clientWire);
    return new Response(
      withFrameAlignedHeartbeat(
        clientBytes,
        heartbeatOptionsFor(params.surface),
      ),
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
  const body = jsonBodyForClient(canonical, params.surface, clientWire);
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

export type { TChatCompletionChunk };
/** Re-exported for the walker + tests. */
export { isNativeRuntimeProvider, nativeRequestOf };
