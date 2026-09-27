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

import { randomUUID } from "node:crypto";
import type {
  TChatCompletionChunk,
  TChatCompletionRequest,
  TCooldownReason,
} from "@openllmsh/protocol";
import { declaresAnthropicServerSearchTool } from "@openllmsh/wire/adapters/messages/request";
import { accumulateChunksToResponse } from "@openllmsh/wire/lib/streaming/accumulate";
import { partialUsageFrom } from "@openllmsh/wire/lib/streaming/upstream-error";
import { clientWireOf } from "@openllmsh/wire/providers/upstream-request";
import { cliBin, cliEnv } from "../cli-paths";
import {
  deliverChunkStream,
  deliverJsonResponse,
  isClientHangUp,
} from "../client-encode";
import { planSigningKey } from "../config";
import { errorJson } from "../cors";
import { daemonApiKeyId } from "../env";
import { logDebug, logWarn, safeDiagnosticMessage } from "../logger";
import {
  bridgeRequestCaptureReadiness,
  shouldActivateBridgeRequestCapture,
} from "./bridge-request-capture-readiness";
import { runClaudeNative } from "./claude-native";
import type {
  TClaudeToolCaptureBuilder,
  TClaudeToolCaptureHistoryFeed,
} from "./claude-tool-capture";
import type { TToolContinuationIdentity } from "./claude-tool-continuation";
import {
  clientToolsOf,
  hasClientTools,
  tryServeNativeToolTurn,
} from "./claude-tool-serve";
import { runCodexNative } from "./codex-app-server";
import { runCursorNative, runCursorNativeCapture } from "./cursor-acp";
import type { TCursorTransactionSender } from "./cursor-capture";
import { cursorRequestOf, jsonInstruction } from "./cursor-request";
import { runMuseNativeCapture } from "./muse-capture";
import { museRequestOf } from "./muse-request";
import { runMuseNative } from "./muse-runtime";
import type { TCapturedDispatchSender } from "./request-capture";
import { historyTurnsFromCanonicalMessages } from "./request-capture-history";
import {
  captureAwareTextBuilderPlan,
  deriveConversation,
  NativeSessionStore,
  nextPrefixHash,
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

/** Production capture sender — forward the vendor envelope unchanged once. */
const defaultCaptureSender: TCapturedDispatchSender = async (
  request,
  _envelope,
  signal,
): Promise<Response> => fetch(request, { signal });

export type TNativeServeCaptureToolOverrides = {
  /** Hermetic Claude tool-capture builder (fixture). Production omits → SDK. */
  readonly claudeBuilder?: TClaudeToolCaptureBuilder;
  /** Production default is `sdk_session_resume` (synthetic JSONL + resume). */
  readonly claudeHistoryFeed?: TClaudeToolCaptureHistoryFeed;
  readonly captureSender?: TCapturedDispatchSender;
  readonly codexFetchImpl?: (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => Promise<Response>;
  /** Production omits → live inject_items stays unproven. */
  readonly codexStructuredInjectProven?: boolean;
};

export type TNativeServeOverrides = {
  readonly bin?: string;
  readonly env?: Record<string, string>;
  readonly captureTool?: TNativeServeCaptureToolOverrides;
  /** Hermetic Cursor capture sender (production omits → real fetch once). */
  readonly cursorCaptureSender?: TCursorTransactionSender;
  /** Hermetic Cursor ACP runner injected into {@link runCursorNativeCapture}. */
  readonly cursorCaptureRunAcp?: Parameters<
    typeof runCursorNativeCapture
  >[0]["runAcp"];
};

/** One conversation→session map per native provider (daemon-resident; the
 *  live resume files/threads are daemon-local, so the map is too). */
const stores: Record<TNativeRuntimeProvider, NativeSessionStore> = {
  claude_code: new NativeSessionStore(),
  chatgpt: new NativeSessionStore(),
  // cursor runs COLD sessions in v1 (`runCursorNative` never yields a
  // resumable id, so this store stays empty); every prior-history turn takes
  // the renderSeed path. TODO(cursor-resume): ACP `session/load` follow-up.
  cursor: new NativeSessionStore(),
  // muse also runs COLD sessions in v1 (`runMuseNative`); store stays empty.
  muse: new NativeSessionStore(),
};

const toolContinuationEpoch = randomUUID();
const localContinuationSecret = randomUUID();

const toolContinuationIdentity = (): TToolContinuationIdentity => {
  const ownerDaemonKey = daemonApiKeyId() ?? "unpaired";
  return {
    // The bootstrap signing secret is scoped per user. The key id distinguishes
    // devices/keys within that account without putting a user id on the wire.
    subject: ownerDaemonKey,
    ownerDaemonKey,
    ownerDaemonEpoch: toolContinuationEpoch,
    secret: planSigningKey() ?? localContinuationSecret,
  };
};

/**
 * Resume-correlation counters, per provider. INSTRUMENTATION ONLY — nothing
 * branches on these.
 *
 * The session key is derived from a hash of the conversation prefix
 * (`deriveConversation`), not from a vendor session id, so any client-side
 * history edit, compaction, or model switch MISSES and falls back to
 * `renderSeed` — which flattens the whole transcript into a fresh cold
 * session. That fallback is the expensive path (full history re-sent, no
 * vendor-side session memory), and we currently have no visibility into how
 * often it fires. These counters answer that before we invest in a
 * persistent-session redesign.
 *
 * Bridge-capture forces cold + seed (`captureAwareTextBuilderPlan`) because
 * the builder never saw the true assistant reply — warm resume would be wrong.
 *
 *   - `firstTurn`  — no prior assistant turn; a fresh session is CORRECT.
 *   - `resumeHit`  — prior history AND the prefix matched → delta-only feed.
 *   - `resumeMiss` — prior history but NO match → `renderSeed` cold start.
 *
 * The ratio that matters is `resumeMiss / (resumeHit + resumeMiss)`;
 * `firstTurn` is excluded because it isn't a correlation failure.
 */
type TResumeStats = {
  firstTurn: number;
  resumeHit: number;
  resumeMiss: number;
};

const resumeStats: Record<TNativeRuntimeProvider, TResumeStats> = {
  claude_code: { firstTurn: 0, resumeHit: 0, resumeMiss: 0 },
  chatgpt: { firstTurn: 0, resumeHit: 0, resumeMiss: 0 },
  cursor: { firstTurn: 0, resumeHit: 0, resumeMiss: 0 },
  muse: { firstTurn: 0, resumeHit: 0, resumeMiss: 0 },
};

/** Snapshot the resume-correlation counters (introspection / tests). */
export const nativeResumeStats = (): Record<
  TNativeRuntimeProvider,
  TResumeStats
> => ({
  claude_code: { ...resumeStats.claude_code },
  chatgpt: { ...resumeStats.chatgpt },
  cursor: { ...resumeStats.cursor },
  muse: { ...resumeStats.muse },
});

/** Reset the counters (tests). */
export const resetNativeResumeStats = (): void => {
  resumeStats.claude_code = { firstTurn: 0, resumeHit: 0, resumeMiss: 0 };
  resumeStats.chatgpt = { firstTurn: 0, resumeHit: 0, resumeMiss: 0 };
  resumeStats.cursor = { firstTurn: 0, resumeHit: 0, resumeMiss: 0 };
  resumeStats.muse = { firstTurn: 0, resumeHit: 0, resumeMiss: 0 };
};

/**
 * Record one correlation outcome and log it. A MISS logs at `warn` with the
 * transcript size being re-sent (the cost of the fallback); the other two log
 * at `debug` so steady-state traffic stays quiet.
 */
const recordResumeOutcome = (
  provider: TNativeRuntimeProvider,
  outcome: "firstTurn" | "resumeHit" | "resumeMiss",
  turnCount: number,
  seedChars: number,
): void => {
  const s = resumeStats[provider];
  s[outcome]++;
  const meta = {
    provider,
    outcome,
    turnCount,
    firstTurn: s.firstTurn,
    resumeHit: s.resumeHit,
    resumeMiss: s.resumeMiss,
  };
  if (outcome === "resumeMiss") {
    logWarn(
      "native-runtime",
      safeDiagnosticMessage`resume MISS — prior history did not correlate; re-seeding a fresh session with the rendered transcript`,
      { ...meta, seedChars },
    );
    return;
  }
  logDebug("native-runtime", `resume ${outcome}`, meta);
};

/**
 * A native serve either COMMITS (a `Response` — the vendor runtime produced
 * output) or DECLINES with a reason. A decline means the request is outside the
 * native path's scope (tools/images/structured-output, or a pre-commit
 * failure); the walker then falls back to the MANUAL transport on the SAME hop
 * (`UPSTREAM_WIRE`) so no workflow is blocked.
 */
export type TNativeServeOutcome =
  | Response
  | {
      readonly declined: string;
      readonly cooldownReason?: TCooldownReason;
      readonly captureOwnership?: "none" | "accepted" | "uncertain";
    };

const declinedOutcome = (
  declined: string,
  cooldownReason?: TCooldownReason,
  captureOwnership?: "none" | "accepted" | "uncertain",
): {
  readonly declined: string;
  readonly cooldownReason?: TCooldownReason;
  readonly captureOwnership?: "none" | "accepted" | "uncertain";
} => ({
  declined,
  ...(cooldownReason !== undefined ? { cooldownReason } : {}),
  ...(captureOwnership !== undefined && captureOwnership !== "none"
    ? { captureOwnership }
    : {}),
});

export type TNativeServeParams = {
  readonly provider: string;
  readonly providerModelId: string;
  readonly surface: "chat_completions" | "messages" | "responses";
  readonly rawBody: unknown;
  readonly canonical: TChatCompletionRequest;
  readonly wantsStream: boolean;
  /** Opaque continuation capability echoed by a client after a tool pause. */
  readonly continuationToken?: string | null;
  /**
   * True when this hop's selected sub-method is `bridge-capture` (from
   * `ACTIVE_SUB_METHOD` via capability selection). Serve activates capture
   * only when readiness also admits the provider — there is no separate
   * capture env flag.
   */
  readonly bridgeCapture?: boolean;
  /** Catalog-gated client-output repair, resolved by the walker. */
  readonly stripSubagentIsolation: boolean;
  readonly signal: AbortSignal;
  /** Report the hop's token counts + outcome to the cloud (walker's `report`):
   *  "success" with accumulated tokens, or "error" with the last usage observed
   *  before a committed stream failed (zero only when no usage was emitted). */
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

const hasAnthropicNativeServerTool = (params: TNativeServeParams): boolean =>
  params.surface === "messages" &&
  declaresAnthropicServerSearchTool(params.rawBody);

export const tryServeNativeRuntime = async (
  params: TNativeServeParams,
  overrides?: TNativeServeOverrides,
): Promise<TNativeServeOutcome> => {
  if (!isNativeRuntimeProvider(params.provider)) {
    return { declined: `${params.provider} has no native runtime` };
  }
  // claude_code ONLY: an Anthropic-native server tool must reach Anthropic
  // byte-verbatim (the manual transport IS the Anthropic wire there), so the
  // provider runs it and the client gets authentic server_tool_use blocks.
  // On a chatgpt hop the manual transport is CROSS-WIRE — declining would
  // leak an unexecutable `web_search` tool_use to the client; instead the
  // codex path serves it with HOSTED search (the canonicalised `web_search`
  // function is suppressed from dynamicTools — one search owner per turn).
  if (
    params.provider === "claude_code" &&
    hasAnthropicNativeServerTool(params)
  ) {
    return {
      declined:
        "Anthropic native server tools need the byte-verbatim transport",
    };
  }
  // Requests with client-defined tools use the native runtime's ordinary
  // tool passthrough when supported. Search-shaped function tools are not
  // special-cased or executed by the daemon.
  // cursor is BRIDGE-ONLY (no manual transport to decline to), so its serve
  // path accepts the widest request surface the ACP runtime can represent:
  // tools (loopback MCP), images (ACP image blocks), and structured output
  // (prompt-embedded instruction + local JSON extraction). It skips the
  // generic control gate below — declining response_format/tool_choice there
  // would fail the hop outright instead of routing slower.
  if (params.provider === "cursor") {
    // cursor accepts the wide surface (tools/images/response_format/tool_choice/
    // sampling), but `n>1` (multiple choices) and `logprobs` are STRUCTURALLY
    // unrepresentable over ACP — the agent yields one message with no
    // token-logprob channel. Decline explicitly rather than silently serving a
    // single un-scored choice against a request that asked for more.
    const cursorUnrepresentable =
      (typeof params.canonical.n === "number" && params.canonical.n > 1) ||
      params.canonical.logprobs === true;
    if (cursorUnrepresentable) {
      return {
        declined:
          "cursor ACP can't honor n>1 or logprobs (single un-scored message per turn)",
      };
    }
    return serveCursorHop(params, overrides);
  }
  if (params.provider === "muse") {
    // muse is BRIDGE-ONLY. Decline controls the native runtime cannot honor
    // rather than silently serving defaults; unsupported request shapes are
    // rejected by `museRequestOf` before any spawn.
    const museUnrepresentable =
      (typeof params.canonical.n === "number" && params.canonical.n > 1) ||
      params.canonical.logprobs === true;
    if (museUnrepresentable) {
      return {
        declined:
          "muse runtime can't honor n>1 or logprobs (single un-scored message per turn)",
      };
    }
    const unsupported = unsupportedNativeControl(params.canonical);
    if (unsupported !== null) {
      return { declined: `muse runtime can't honor ${unsupported}` };
    }
    return serveMuseHop(params, overrides);
  }
  // Generation controls the native runtimes can't honor (non-default
  // temperature/top_p/penalties, stop, seed, n, logprobs, logit_bias,
  // response_format, forced tool_choice) → decline rather than silently serving
  // at the runtime's defaults. The walker decides whether a handrolled transport
  // is available for this hop. Guards BOTH the tool and text paths. (max_tokens
  // is a documented carve-out — see `unsupportedNativeControl`.)
  // TODO(docs/audit/2026-08-30-claude-code-bridge-failures.md §4 B2): route
  // bridge-only temperature requests through an approved temperature-honoring
  // transport rather than rejecting this native capability gap.
  const unsupported = unsupportedNativeControl(params.canonical);
  if (unsupported !== null) {
    return { declined: `native runtime can't honor ${unsupported}` };
  }
  // Tool-bearing requests: when `bridge-capture` is selected AND readiness
  // admits the provider, use capture (inert schemas / refused item/tool/call)
  // — NEVER the ordinary held SDK / app-server execution path. Otherwise keep
  // today's completion tool-passthrough. A pre-send capture decline may still
  // fall through to handrolled on the same hop when `localMethodsForHop` lists
  // it; accepted/uncertain terminates the walk (walker-enforced).
  if (hasClientTools(params.canonical)) {
    const toolProvider: "claude_code" | "chatgpt" | null =
      params.provider === "chatgpt"
        ? "chatgpt"
        : params.provider === "claude_code"
          ? "claude_code"
          : null;
    if (
      toolProvider !== null &&
      shouldActivateBridgeRequestCapture(
        toolProvider,
        params.bridgeCapture === true,
      )
    ) {
      return serveCapturedToolTurn(params, overrides, toolProvider);
    }
    return tryServeNativeToolTurn({
      provider: params.provider,
      providerModelId: params.providerModelId,
      surface: params.surface,
      canonical: params.canonical,
      wantsStream: params.wantsStream,
      stripSubagentIsolation: params.stripSubagentIsolation,
      bin: overrides?.bin ?? cliBin(params.provider),
      env: overrides?.env ?? cliEnv(params.provider),
      record: params.record,
      continuationToken: params.continuationToken ?? null,
      continuationIdentity: toolContinuationIdentity(),
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

  // Text path is Claude/Codex only (cursor/muse returned above).
  const textProvider: "claude_code" | "chatgpt" =
    params.provider === "chatgpt" ? "chatgpt" : "claude_code";
  // Correlate to a persisted session and compute the delta turn to feed.
  const store = stores[textProvider];
  const captureActive = shouldActivateBridgeRequestCapture(
    textProvider,
    params.bridgeCapture === true,
  );
  const { prefixHash, deltaText, hasPrior } = deriveConversation(
    params.providerModelId,
    req.systemText,
    req.turns,
  );
  if (deltaText.length === 0) {
    return { declined: "no user turn to answer" };
  }
  const lease = await store.lease(prefixHash);
  const resumeId = lease.sessionId; // null → fresh session
  // Capture builders never saw true assistant output — force cold + seed.
  // Today's non-capture path still resumes: delta-only feed on hit, seed on miss.
  const feed = captureAwareTextBuilderPlan({
    captureActive,
    resumeId,
    hasPrior,
    deltaText,
    systemText: req.systemText,
    turns: req.turns,
  });
  const userText = feed.userText;
  const systemText = feed.systemText;
  const builderResumeId = feed.builderResumeId;
  // Instrumentation: which of the three correlation outcomes this turn took.
  // `hasPrior && builderResumeId === null` is the expensive `renderSeed` fallback
  // (includes capture-forced cold starts).
  recordResumeOutcome(
    textProvider,
    builderResumeId !== null
      ? "resumeHit"
      : hasPrior
        ? "resumeMiss"
        : "firstTurn",
    req.turns.length,
    builderResumeId === null && hasPrior ? userText.length : 0,
  );

  const bin = overrides?.bin ?? cliBin(textProvider);
  const env = overrides?.env ?? cliEnv(textProvider);
  // Capture activates only when the hop selected `bridge-capture` AND readiness
  // admits the provider. Serve does not inject a capture sender here
  // (production uses real fetch to the captured external URL). Hermetic suites
  // inject `requestCapture.sender` on the runner.
  if (captureActive) {
    logDebug("native-runtime", "bridge request capture active", {
      provider: textProvider,
      readiness: bridgeRequestCaptureReadiness(textProvider).mode,
      coldBuilder: true,
    });
  }
  let run: TNativeRunResult;
  try {
    run =
      textProvider === "claude_code"
        ? await runClaudeNative({
            bin,
            env,
            providerModelId: params.providerModelId,
            systemText,
            userText,
            resumeSessionId: builderResumeId,
            signal: params.signal,
            ...(captureActive ? { requestCapture: {} } : {}),
          })
        : await runCodexNative({
            bin,
            env,
            providerModelId: params.providerModelId,
            systemText,
            userText,
            resumeThreadId: builderResumeId,
            reasoningEffort: params.canonical.reasoning_effort ?? null,
            signal: params.signal,
            bridgeCapture: captureActive,
          });
  } catch (error) {
    lease.abandon();
    return {
      declined: error instanceof Error ? error.message : String(error),
    };
  }
  if (run.kind === "declined") {
    lease.abandon();
    return declinedOutcome(
      run.reason,
      run.cooldownReason,
      run.captureOwnership,
    );
  }

  const committed = run;
  // After the response is accumulated, record tokens AND advance the session:
  // re-key under `hash(inbound turns + assistant response)` so the NEXT
  // request resumes it. Capture must not publish a resume handle — the builder
  // never incorporated the true assistant reply into vendor session state.
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
      feed.publishResumeSession ? committed.sessionId() : null,
    );
  };
  const fail = (err: unknown): void => {
    if (params.signal.aborted || isClientHangUp(err)) {
      lease.abandon();
      return;
    }
    const usage = partialUsageFrom(err);
    params.record(
      usage === null ? ZERO_TOKENS : tokensFromResponse({ usage }),
      "error",
    );
    lease.abandon();
  };

  const clientWire = clientWireOf(params.surface);

  // ── Streaming client: the shared delivery tail (walker parity) ──────
  if (params.wantsStream) {
    return deliverChunkStream(committed.chunks, {
      surface: params.surface,
      clientWire,
      providerModelId: params.providerModelId,
      onResponse: settle,
      onError: fail,
      stripSubagentIsolation: params.stripSubagentIsolation,
    });
  }

  // ── JSON client: accumulate → record + advance session → re-encode ──
  let canonical: Awaited<ReturnType<typeof accumulateChunksToResponse>>;
  try {
    canonical = await accumulateChunksToResponse(
      committed.chunks,
      params.providerModelId,
    );
  } catch (err) {
    fail(err);
    const reason =
      partialUsageFrom(err) === null
        ? "native runtime stream ended before output"
        : "native runtime stream failed after output began";
    // Capture already dispatched upstream — surface as a capture-owned decline
    // so the walker cannot handroll/fleet/advance to another provider.
    if (captureActive) {
      return declinedOutcome(reason, undefined, "accepted");
    }
    return errorJson(502, reason);
  }
  settle(canonical);
  return deliverJsonResponse(
    canonical,
    params.surface,
    clientWire,
    undefined,
    params.stripSubagentIsolation,
  );
};

/**
 * Tool-bearing bridge-capture route for Claude/Codex. Caller tools are
 * registered so schemas appear in the vendor envelope; MCP / item/tool/call
 * execution is NOT the capture boundary. True response stays daemon-owned.
 * Capture never falls back to {@link tryServeNativeToolTurn} inside this hop.
 */
const serveCapturedToolTurn = async (
  params: TNativeServeParams,
  overrides: TNativeServeOverrides | undefined,
  provider: "claude_code" | "chatgpt",
): Promise<TNativeServeOutcome> => {
  const decomposed = historyTurnsFromCanonicalMessages(
    params.canonical.messages,
  );
  if (decomposed === null) {
    return {
      declined:
        "bridge-capture tool turn: conversation shape unsupported (non-text parts or missing user delta)",
    };
  }
  if (
    decomposed.deltaText.length === 0 &&
    decomposed.deltaKind !== "tool_results"
  ) {
    return { declined: "no user turn to answer" };
  }

  const tools = clientToolsOf(params.canonical);
  const bin = overrides?.bin ?? cliBin(provider);
  const env = overrides?.env ?? cliEnv(provider);
  const captureTool = overrides?.captureTool;
  const captureSender = captureTool?.captureSender ?? defaultCaptureSender;

  logDebug("native-runtime", "bridge request capture tool turn active", {
    provider,
    readiness: bridgeRequestCaptureReadiness(provider).mode,
    toolCount: tools.length,
    hasPrior: decomposed.hasPrior,
  });

  let run: TNativeRunResult;
  try {
    if (provider === "claude_code") {
      const { runClaudeToolCapture } = await import("./claude-tool-capture");
      const result = await runClaudeToolCapture({
        bin,
        env,
        providerModelId: params.providerModelId,
        systemText: decomposed.systemText,
        tools,
        historyTurns: decomposed.historyTurns,
        deltaText: decomposed.deltaText,
        hasPrior: decomposed.hasPrior,
        signal: params.signal,
        captureSender,
        // Production: synthetic on-disk session JSONL + SDK `resume` (proven by
        // local loopback probe). Hermetic suites may still inject fixture_messages.
        historyFeed: captureTool?.claudeHistoryFeed ?? "sdk_session_resume",
        ...(captureTool?.claudeBuilder !== undefined
          ? { builder: captureTool.claudeBuilder }
          : {}),
        canonical: params.canonical,
      });
      run = result.run;
    } else {
      const { runCodexCapturedToolTurn } = await import(
        "./codex-capture-tools"
      );
      run = await runCodexCapturedToolTurn({
        bin,
        env,
        providerModelId: params.providerModelId,
        systemText: decomposed.systemText,
        userText: decomposed.deltaText,
        // Capture never warm-resumes — history is reconstructed or refused.
        resumeThreadId: null,
        tools,
        historyTurns: decomposed.historyTurns,
        reasoningEffort: params.canonical.reasoning_effort ?? null,
        signal: params.signal,
        ...(captureTool?.codexFetchImpl !== undefined
          ? { fetchImpl: captureTool.codexFetchImpl }
          : {}),
        ...(captureTool?.codexStructuredInjectProven !== undefined
          ? {
              structuredInjectProven: captureTool.codexStructuredInjectProven,
            }
          : {}),
      });
    }
  } catch (error) {
    return {
      declined: error instanceof Error ? error.message : String(error),
    };
  }

  if (run.kind === "declined") {
    return declinedOutcome(
      run.reason,
      run.cooldownReason,
      run.captureOwnership,
    );
  }

  // Capture tool turns never publish a resume handle — builder never saw the
  // true assistant/tool exchange.
  const settle = (
    resp: Awaited<ReturnType<typeof accumulateChunksToResponse>>,
  ): void => {
    params.record(tokensFromResponse(resp), "success");
  };
  const fail = (err: unknown): void => {
    if (params.signal.aborted || isClientHangUp(err)) return;
    const usage = partialUsageFrom(err);
    params.record(
      usage === null ? ZERO_TOKENS : tokensFromResponse({ usage }),
      "error",
    );
  };
  const clientWire = clientWireOf(params.surface);
  if (params.wantsStream) {
    return deliverChunkStream(run.chunks, {
      surface: params.surface,
      clientWire,
      providerModelId: params.providerModelId,
      onResponse: settle,
      onError: fail,
      stripSubagentIsolation: params.stripSubagentIsolation,
    });
  }
  let canonical: Awaited<ReturnType<typeof accumulateChunksToResponse>>;
  try {
    canonical = await accumulateChunksToResponse(
      run.chunks,
      params.providerModelId,
    );
  } catch (err) {
    fail(err);
    const reason =
      partialUsageFrom(err) === null
        ? "native runtime stream ended before output"
        : "native runtime stream failed after output began";
    return declinedOutcome(reason, undefined, "accepted");
  }
  settle(canonical);
  return deliverJsonResponse(
    canonical,
    params.surface,
    clientWire,
    undefined,
    params.stripSubagentIsolation,
  );
};

/**
 * The cursor serve path — bridge-only, so it accepts tools/images/structured
 * output instead of declining them (there is no manual transport behind it).
 * One COLD ACP session per request: `cursorRequestOf` flattens the full
 * conversation (including assistant tool_calls + tool results) into one
 * prompt. When `bridge-capture` is selected and readiness admits cursor, the
 * official {@link runCursorNativeCapture} builder collects RunSSE+BidiAppend
 * and daemon-dispatches exact RPCs once (HTTP/2 duplex fail-closed post-accept).
 */
const serveCursorHop = async (
  params: TNativeServeParams,
  overrides?: TNativeServeOverrides,
): Promise<TNativeServeOutcome> => {
  const captureActive = shouldActivateBridgeRequestCapture(
    "cursor",
    params.bridgeCapture === true,
  );
  if (params.bridgeCapture === true && !captureActive) {
    const readiness = bridgeRequestCaptureReadiness("cursor");
    logDebug("native-runtime", "cursor bridge request capture not activated", {
      ready: readiness.ready,
      reason: readiness.reason,
    });
  }
  if (captureActive) {
    logDebug("native-runtime", "bridge request capture active", {
      provider: "cursor",
      readiness: bridgeRequestCaptureReadiness("cursor").mode,
      coldBuilder: true,
    });
  }
  const req = cursorRequestOf(params.canonical);
  if (req.promptText.length === 0 && req.images.length === 0) {
    return { declined: "no user turn to answer" };
  }
  const run = captureActive
    ? await runCursorNativeCapture({
        bin: overrides?.bin ?? cliBin("cursor"),
        env: overrides?.env ?? cliEnv("cursor"),
        providerModelId: params.providerModelId,
        systemText: req.systemText,
        userText: req.promptText,
        images: req.images,
        tools: req.tools,
        jsonInstructionText:
          req.jsonMode !== null
            ? jsonInstruction(req.jsonMode, req.jsonSchema)
            : null,
        signal: params.signal,
        ...(overrides?.cursorCaptureSender !== undefined
          ? { sender: overrides.cursorCaptureSender }
          : {}),
        ...(overrides?.cursorCaptureRunAcp !== undefined
          ? { runAcp: overrides.cursorCaptureRunAcp }
          : {}),
      })
    : await runCursorNative({
        bin: overrides?.bin ?? cliBin("cursor"),
        env: overrides?.env ?? cliEnv("cursor"),
        providerModelId: params.providerModelId,
        systemText: req.systemText,
        userText: req.promptText,
        images: req.images,
        tools: req.tools,
        jsonInstructionText:
          req.jsonMode !== null
            ? jsonInstruction(req.jsonMode, req.jsonSchema)
            : null,
        signal: params.signal,
      });
  if (run.kind === "declined") {
    return declinedOutcome(
      run.reason,
      run.cooldownReason,
      run.captureOwnership,
    );
  }

  const settle = (
    resp: Awaited<ReturnType<typeof accumulateChunksToResponse>>,
  ): void => {
    params.record(tokensFromResponse(resp), "success");
  };
  const fail = (err: unknown): void => {
    if (params.signal.aborted || isClientHangUp(err)) return;
    const usage = partialUsageFrom(err);
    params.record(
      usage === null ? ZERO_TOKENS : tokensFromResponse({ usage }),
      "error",
    );
  };
  const clientWire = clientWireOf(params.surface);
  if (params.wantsStream) {
    return deliverChunkStream(run.chunks, {
      surface: params.surface,
      clientWire,
      providerModelId: params.providerModelId,
      onResponse: settle,
      onError: fail,
      stripSubagentIsolation: params.stripSubagentIsolation,
    });
  }
  let canonical: Awaited<ReturnType<typeof accumulateChunksToResponse>>;
  try {
    canonical = await accumulateChunksToResponse(
      run.chunks,
      params.providerModelId,
    );
  } catch (err) {
    fail(err);
    return errorJson(
      502,
      partialUsageFrom(err) === null
        ? "native runtime stream ended before output"
        : "native runtime stream failed after output began",
    );
  }
  settle(canonical);
  return deliverJsonResponse(
    canonical,
    params.surface,
    clientWire,
    undefined,
    params.stripSubagentIsolation,
  );
};

/**
 * Muse serve path — cold SDK/MSP session per request, or bridge-capture via
 * settings.endpoint_transport (loopback capture → one daemon-owned upstream
 * dispatch → Responses SSE decode). Unsupported shapes fail closed via
 * `museRequestOf`.
 */
const serveMuseHop = async (
  params: TNativeServeParams,
  overrides?: TNativeServeOverrides,
): Promise<TNativeServeOutcome> => {
  const captureActive = shouldActivateBridgeRequestCapture(
    "muse",
    params.bridgeCapture === true,
  );
  if (params.bridgeCapture === true && !captureActive) {
    const readiness = bridgeRequestCaptureReadiness("muse");
    logDebug("native-runtime", "muse bridge request capture not activated", {
      ready: readiness.ready,
      reason: readiness.reason,
    });
  }
  if (captureActive) {
    logDebug("native-runtime", "bridge request capture active", {
      provider: "muse",
      readiness: bridgeRequestCaptureReadiness("muse").mode,
      coldBuilder: true,
    });
  }

  const req = museRequestOf(params.canonical);
  if (!req.ok) {
    return { declined: req.reason };
  }
  let run: TNativeRunResult;
  try {
    run = captureActive
      ? await runMuseNativeCapture({
          bin: overrides?.bin ?? cliBin("muse"),
          env: overrides?.env ?? cliEnv("muse"),
          providerModelId: params.providerModelId,
          parts: req.parts,
          promptText: req.promptText,
          tools: req.tools,
          signal: params.signal,
        })
      : await runMuseNative({
          bin: overrides?.bin ?? cliBin("muse"),
          env: overrides?.env ?? cliEnv("muse"),
          providerModelId: params.providerModelId,
          parts: req.parts,
          promptText: req.promptText,
          tools: req.tools,
          signal: params.signal,
        });
  } catch (error) {
    return { declined: error instanceof Error ? error.message : String(error) };
  }
  if (run.kind === "declined") {
    return declinedOutcome(
      run.reason,
      run.cooldownReason,
      run.captureOwnership,
    );
  }

  const settle = (
    resp: Awaited<ReturnType<typeof accumulateChunksToResponse>>,
  ): void => {
    params.record(tokensFromResponse(resp), "success");
  };
  const fail = (err: unknown): void => {
    if (params.signal.aborted || isClientHangUp(err)) return;
    const usage = partialUsageFrom(err);
    params.record(
      usage === null ? ZERO_TOKENS : tokensFromResponse({ usage }),
      "error",
    );
  };
  const clientWire = clientWireOf(params.surface);
  if (params.wantsStream) {
    return deliverChunkStream(run.chunks, {
      surface: params.surface,
      clientWire,
      providerModelId: params.providerModelId,
      onResponse: settle,
      onError: fail,
      stripSubagentIsolation: params.stripSubagentIsolation,
    });
  }
  let canonical: Awaited<ReturnType<typeof accumulateChunksToResponse>>;
  try {
    canonical = await accumulateChunksToResponse(
      run.chunks,
      params.providerModelId,
    );
  } catch (err) {
    fail(err);
    const reason =
      partialUsageFrom(err) === null
        ? "native runtime stream ended before output"
        : "native runtime stream failed after output began";
    // Capture already dispatched upstream (see runMuseNativeCapture /
    // requireCaptureTerminalFinishReason) — surface as a capture-owned
    // decline so the walker cannot handroll/fleet/advance to another
    // provider for this hop. Matches the Claude/Codex capture routes above.
    if (captureActive) {
      return declinedOutcome(reason, undefined, "accepted");
    }
    return errorJson(502, reason);
  }
  settle(canonical);
  return deliverJsonResponse(
    canonical,
    params.surface,
    clientWire,
    undefined,
    params.stripSubagentIsolation,
  );
};

export {
  bridgeRequestCaptureReadiness,
  bridgeRequestCaptureReadinessTable,
  shouldActivateBridgeRequestCapture,
} from "./bridge-request-capture-readiness";
export type { TChatCompletionChunk };
/** Re-exported for the walker + tests. */
export { isNativeRuntimeProvider, nativeRequestOf };
