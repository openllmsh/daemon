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
import { functionNameUsesWebSearch } from "@quantidexyz/openllmw/tools/web-search/helpers";
import { cliBin, cliEnv } from "../cli-paths";
import { jsonBodyForClient, sseBytesForClient } from "../client-encode";
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
import type {
  TNativeRunResult,
  TNativeRuntimeProvider,
  TNativeTokens,
} from "./types";
import {
  isNativeRuntimeProvider,
  nativeRequestOf,
  tokensFromResponse,
  ZERO_TOKENS,
} from "./types";

/** One conversation→session map per native provider (daemon-resident; the
 *  live resume files/threads are daemon-local, so the map is too). */
const stores: Record<TNativeRuntimeProvider, NativeSessionStore> = {
  claude_code: new NativeSessionStore(),
  chatgpt: new NativeSessionStore(),
};

/** Flip to true ONLY once codex-cli's app-server actually emits `item/tool/call`
 *  for `dynamicTools` (as of 0.144.0 it doesn't — the schema ships under
 *  `--experimental` but the call never fires). The codex tool-passthrough in
 *  `codex-tool-session.ts` is written and protocol-correct but UNVALIDATED: no
 *  fixture/live coverage, and it still lacks the Claude-side fixes from Batch B
 *  (per-turn usage is a no-op; the tool drive() timeout doesn't interrupt the
 *  turn). Pre-flip checklist lives in that file's header — do NOT flip without it. */
const CODEX_TOOLS_READY = false;

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
  readonly canonical: TChatCompletionRequest;
  readonly wantsStream: boolean;
  readonly signal: AbortSignal;
  /** Report the hop's token counts to the cloud (walker's `report`). */
  readonly record: (tokens: TNativeTokens) => void;
};

/** Does the request declare the openllm-managed web_search function tool?
 *  (Mirrors the walker's own gate — the gateway runs this tool, not the
 *  client, so it must NOT enter the native tool-passthrough path.) */
const requestDeclaresWebSearch = (req: TChatCompletionRequest): boolean =>
  req.tools?.some((t) => functionNameUsesWebSearch(t.function.name)) === true;

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
      declined:
        "web_search runs on the gateway's managed loop (manual transport)",
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
    params.record(tokensFromResponse(resp));
    lease.commit(
      nextPrefixHash(req.systemText, req.turns, textOf(resp)),
      committed.sessionId(),
    );
  };
  const fail = (): void => {
    params.record(ZERO_TOKENS);
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
  const body = jsonBodyForClient(canonical, params.surface, clientWire);
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

export type { TChatCompletionChunk };
/** Re-exported for the walker + tests. */
export { isNativeRuntimeProvider, nativeRequestOf };
