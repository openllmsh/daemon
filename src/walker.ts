/**
 * The coreless §3.3 walker — a thin executor of the cloud-resolved plan.
 *
 * The cloud is the only brain: it resolves the alias + cooldowns and hands
 * the daemon the concrete ordered chain across the 307 as `?__plan=`. This
 * walker walks that list in order — making ZERO routing decisions:
 *
 *   for hop in __plan (in order):
 *     - subscription hop  → inject the local CLI credential, call the
 *                           vendor upstream
 *     - API-key hop       → forward inbound to the cloud, pinned to the hop
 *                           (the cloud decrypts the BYOK credential + runs)
 *     - PRE-STREAM candidate failure → next hop (unless client aborted)
 *     - committed (response received, ok) → stream straight to the client
 *
 * Coreless: imports `@quantidexyz/openllmw` + `@quantidexyz/openllmp` + local modules
 * only — NEVER `@openllm/core`. The pure provider wire transforms
 * (request/response/streaming for anthropic + chatgpt, the canonical
 * message adapters, and the SSE decode/encode primitives) all live in
 * `@quantidexyz/openllmw`; the walker wires them into a tiny per-hop mini-runner.
 *
 * Serves all three subscription providers + cross-wire:
 *   - claude_code (Anthropic upstream): passthrough for an Anthropic-wire
 *     client; toAnthropicRequest + response re-encode for an OpenAI client.
 *   - chatgpt (Codex/Responses upstream): always transform via
 *     toChatGptRequest, decode Responses events → canonical → client wire.
 *   - kimi_code (OpenAI-compatible upstream): passthrough for an OpenAI
 *     client; canonical re-encode for an Anthropic client.
 * API-key hops are forwarded to the cloud. See
 * docs/proposals/coreless-daemon-passthrough.md §3.3 + §9(a).
 *
 * This is the daemon's ONLY data path (no `@openllm/core`, no flag, no
 * fallback). It reports TOKEN COUNTS only — accurate for both streaming
 * (accumulated off a tee'd canonical-chunk stream) and non-streaming — and
 * the cloud computes cost from them (single pricing source of truth, so no
 * pricing table is shipped to the box).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import {
  AnthropicResponse,
  AnthropicStreamEvent,
  ChatCompletionChunk,
  daemonPlanSigningPayload,
  type TAnthropicResponse,
  type TChatCompletionChunk,
  type TChatCompletionRequest,
  type TChatCompletionResponse,
  type TDaemonRecordRequest,
  type TErrorEnvelope,
  type TRequestStatus,
  type TToolCall,
} from "@quantidexyz/openllmp";
import { toAnthropicMessagesResponse } from "@quantidexyz/openllmw/adapters/messages/response";
import { toResponsesResponse } from "@quantidexyz/openllmw/adapters/responses";
import {
  isEncryptedContentError,
  responsesBodyHasEncryptedContent,
  stripResponsesEncryptedContent,
} from "@quantidexyz/openllmw/lib/encrypted-content";
import { classifyHopError } from "@quantidexyz/openllmw/lib/error-class";
import { originatorHeadersFrom } from "@quantidexyz/openllmw/lib/forwarded-headers";
import { accumulateChunksToResponse } from "@quantidexyz/openllmw/lib/streaming/accumulate";
import { decodeProviderEventStream } from "@quantidexyz/openllmw/lib/streaming/provider-decode";
import { responseToChunkStream } from "@quantidexyz/openllmw/lib/streaming/response-stream";
import { withFrameAlignedHeartbeat } from "@quantidexyz/openllmw/lib/streaming/sse";
import {
  UpstreamStreamError,
  upstreamErrorFrom,
} from "@quantidexyz/openllmw/lib/streaming/upstream-error";
import { stripSchemaKeywords } from "@quantidexyz/openllmw/lib/tool-schema";
import { fromAnthropicResponse } from "@quantidexyz/openllmw/providers/anthropic/response";
import {
  fromAnthropicStreamEvent,
  newAnthropicStreamState,
} from "@quantidexyz/openllmw/providers/anthropic/streaming";
import {
  chatGptEventToChunk,
  newChatGptStreamState,
  type TChatGptStreamEvent,
} from "@quantidexyz/openllmw/providers/chatgpt/streaming";
// The SINGLE (clientWire × upstreamWire) request recipe — shared with the
// cloud runner so the two can't drift (this fork caused two regressions). See
// `docs/proposals/unified-upstream-request-builder.md`.
import {
  buildUpstreamHeaders,
  buildUpstreamRequest,
  canonicalFromInbound,
  canonicalToUpstreamBody,
  clientWireOf,
} from "@quantidexyz/openllmw/providers/upstream-request";
import {
  buildAssistantToolCallMessage,
  buildToolResultMessages,
  extractQueryFromToolCall,
  functionNameUsesWebSearch,
  MAX_WEB_SEARCH_ROUNDS,
  toolCallUsesWebSearch,
} from "@quantidexyz/openllmw/tools/web-search/helpers";
import { Schema } from "effect";
import {
  heartbeatOptionsFor,
  jsonBodyForClient,
  sseBytesForClient,
} from "./client-encode";
import { recordRequest, searchViaCloud } from "./cloud-client";
import { lookupCatalogEntry, planSigningKey } from "./config";
import { errorJson } from "./cors";
import { getDelegate, isSubscriptionSlug } from "./delegation";
import type { TProviderDelegate } from "./delegation/types";
import { forwardToCloud } from "./forward";
import { logWarn } from "./logger";
import {
  isNativeRuntimeProvider,
  tryServeNativeRuntime,
} from "./native-runtime/serve";
import type { TNativeTokens } from "./native-runtime/types";
import { tokensFromResponse, ZERO_TOKENS } from "./native-runtime/types";
import { sampleUsageAfterRequest } from "./usage-cache";

// Upstream WIRE per subscription provider — structural (which adapter to run),
// the one constant that stays in the walker. The upstream URL is no longer
// hardcoded here: it's resolved per hop from the delegate's auth config
// (`credentialForUpstream().url`), captured from the real CLI request. See
// `packages/daemon/src/delegation/auth-config.ts`.
// The MANUAL upstream-HTTP transport. `claude_code` + `chatgpt` are served by
// the native-runtime path FIRST (`isNativeRuntimeProvider`); the manual entries
// here are the FALLBACK the walker uses when native declines (tools/images/
// structured-output/native gaps), so no workflow is blocked. Auth + refresh
// still flow through the CLIs — the manual path reads the credential via the
// delegate's `credentialForUpstream` (isolated CLI store + CLI-driven refresh),
// exactly like kimi_code + grok.
export type TUpstreamWire = "anthropic" | "chatgpt" | "openai";
const UPSTREAM_WIRE: Readonly<Record<string, TUpstreamWire>> = {
  // Claude Pro/Max via the isolated Claude Code OAuth bearer + the
  // `anthropic-beta: oauth-2025-04-20` header on the Anthropic Messages wire.
  claude_code: "anthropic",
  // ChatGPT/Codex subscription via the Codex Responses wire
  // (`/backend-api/codex/responses`) with the Codex identity preamble.
  chatgpt: "chatgpt",
  // Kimi's managed "Kimi For Coding" subscription speaks the OpenAI wire
  // (`/coding/v1/chat/completions`) — exactly what the official `kimi-code-cli`
  // sends. So we delegate over the openai wire with the CLI's genuine identity
  // (URL + headers from the delegate's `credentialForUpstream`, captured from
  // the real `kimi -p ping` request). See `kimi-code.ts`.
  kimi_code: "openai",
  // xAI Grok ("Grok Build") serves its models via the OpenAI Responses API
  // (both report `api_backend: "responses"`) at the CLI chat proxy
  // (`cli-chat-proxy.grok.com/v1/responses`, captured per-hop from the
  // delegate's auth config) — same wire as codex, so we delegate over the
  // chatgpt (Responses) adapter with the CLI's genuine bearer. It does NOT get
  // the Codex preamble (see `wantsCodexPreamble`).
  grok: "chatgpt",
};

// The Codex system preamble ("You are Codex…") is a Codex IDENTITY the ChatGPT
// backend requires — but WRONG for other providers that merely share the
// Responses wire (xAI Grok). Injected only for the real `chatgpt` provider on
// the manual FALLBACK path.
const wantsCodexPreamble = (provider: string): boolean =>
  provider === "chatgpt";

// The chatgpt Responses API emits freeform JSON events (no strict schema);
// discrimination happens inside `chatGptEventToChunk`. Mirrors the core
// spec's `Schema.Record(string, unknown)` validator.
const ChatGptStreamEventSchema: Schema.Schema<TChatGptStreamEvent> =
  Schema.Record({ key: Schema.String, value: Schema.Unknown });

export type TWalkArgs = {
  readonly req: Request;
  readonly surface: "chat_completions" | "messages" | "responses";
  readonly endpoint: string;
  /** The parsed inbound JSON body (Anthropic- or OpenAI-shaped per surface). */
  readonly rawBody: unknown;
  /** The raw inbound bytes — forwarded verbatim to the cloud for API-key hops. */
  readonly rawBytes: ArrayBuffer;
  /** The `?__plan=` value off the 307 redirect, or null. */
  readonly planParam: string | null;
  /** The `?__pmids=` value — concrete upstream `provider_model_id`s parallel
   *  to `__plan`, so the daemon serves catalog-free. Null on older redirects. */
  readonly pmidsParam: string | null;
  /** The `?__origin=` value — the deployment that issued the 307; the daemon
   *  forwards API-key hops + records usage back here. Null → pinned origin. */
  readonly originParam: string | null;
  /** The `?__sig=` HMAC of the signed payload (plan+pmids+origin), or null. */
  readonly sigParam: string | null;
  readonly startedAt: number;
};

type THop = {
  readonly modelId: string;
  readonly provider: string;
  readonly providerModelId: string;
};

/** Parse `?__plan=provider/model,provider/model` into ordered model ids.
 *  Also used for the parallel `?__pmids=` list (same comma encoding). */
export const parsePlan = (planParam: string | null): ReadonlyArray<string> =>
  planParam === null
    ? []
    : planParam
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

/**
 * Resolve a plan model id to its `{ provider, providerModelId }`. Precedence:
 * (1) the concrete `providerModelId` the cloud pushed in `__pmids` — the
 * catalog-free path; (2) the cloud-pulled catalog; (3) splitting the
 * `provider/model` pair (dev / older redirects). Only the provider prefix is
 * ever derived locally; the upstream id is authoritative from the cloud.
 */
export const resolveHop = (modelId: string, providerModelId?: string): THop => {
  const slash = modelId.indexOf("/");
  const provider = slash > 0 ? modelId.slice(0, slash) : modelId;
  if (providerModelId !== undefined && providerModelId.length > 0) {
    return { modelId, provider, providerModelId };
  }
  const entry = lookupCatalogEntry(modelId);
  if (entry !== null) {
    return {
      modelId,
      provider: entry.provider,
      providerModelId: entry.provider_model_id,
    };
  }
  return slash > 0
    ? { modelId, provider, providerModelId: modelId.slice(slash + 1) }
    : { modelId, provider: modelId, providerModelId: modelId };
};

/**
 * Verify a cloud-signed `?__plan=` against the per-user key handed over at
 * bootstrap (coreless proposal §9). Timing-safe. A missing/short/mismatched
 * signature fails closed.
 */
export const verifyPlanSignature = (
  plan: string,
  sig: string | null,
  key: string,
): boolean => {
  if (sig === null || sig.length === 0) return false;
  const expected = createHmac("sha256", key).update(plan).digest("hex");
  if (expected.length !== sig.length) return false;
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  } catch {
    return false;
  }
};

/**
 * Can the walker serve this whole plan coreless? Every subscription hop
 * must be one of the three the walker knows an upstream for; API-key hops
 * are always walkable (forwarded to the cloud). DECLINE the whole plan up
 * front for an unknown subscription provider — so we never half-attempt a
 * chain and then bail. (All wire combinations of the three known providers
 * are supported now — passthrough where client-wire == upstream-wire,
 * transform-and-re-encode otherwise.)
 */
export const canWalkPlan = (hops: ReadonlyArray<THop>): boolean => {
  for (const hop of hops) {
    if (!isSubscriptionSlug(hop.provider)) continue; // API-key → forwardable
    if (isNativeRuntimeProvider(hop.provider)) continue; // native runtime path
    if (UPSTREAM_WIRE[hop.provider] === undefined) return false;
  }
  return true;
};

/**
 * Final-hop in-place retry policy. Chain routing does NOT use this status
 * allow-list: every non-abort pre-commit candidate failure walks via the shared
 * `classifyHopError` policy below. The final hop has nowhere to walk, so it gets
 * one bounded retry only for transport/rate/server failures before its original
 * response is surfaced verbatim.
 */
export const shouldRetryFinalHopInPlace = (status: number): boolean =>
  status === 429 || status === 408 || (status >= 500 && status <= 599);

// Final-hop in-place retry bounds: ONE retry, delay from a bounded
// `Retry-After` (else 1s). Mid-chain hops never retry in place — the walk IS
// the retry — but with no next hop a transient 429/5xx would otherwise
// surface immediately, where partner clients absorb the same blip with SDK
// backoff (audit 2026-07-14 §F6).
const FINAL_HOP_RETRY_DELAY_MS = 1_000;
const FINAL_HOP_RETRY_AFTER_CAP_MS = 10_000;

/** Bounded delay from a 429/5xx response's `Retry-After` (seconds or
 *  HTTP-date), falling back to {@link FINAL_HOP_RETRY_DELAY_MS}. */
const retryAfterDelayMs = (resp: Response): number => {
  const raw = resp.headers.get("retry-after");
  if (raw !== null) {
    const secs = Number(raw);
    if (!Number.isNaN(secs)) {
      return Math.max(0, Math.min(secs * 1000, FINAL_HOP_RETRY_AFTER_CAP_MS));
    }
    const at = Date.parse(raw);
    if (!Number.isNaN(at)) {
      return Math.max(
        0,
        Math.min(at - Date.now(), FINAL_HOP_RETRY_AFTER_CAP_MS),
      );
    }
  }
  return FINAL_HOP_RETRY_DELAY_MS;
};

/** Resolve after `ms` — or immediately once the client disconnects, so a
 *  final-hop backoff never outlives the request it serves. */
const abortableDelay = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const done = (): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });

/**
 * POST the built request upstream — plus, on the plan's FINAL hop, ONE
 * bounded in-place retry when the failure is pre-stream retryable (a network
 * error or a 429/408/5xx). Returns `null` when every attempt failed at the
 * network layer (no `Response` to surface).
 */
export const postUpstream = async (
  url: string,
  init: RequestInit,
  finalHop: boolean,
  signal: AbortSignal,
): Promise<Response | null> => {
  let first: Response | null = null;
  try {
    first = await fetch(url, init);
  } catch {
    first = null;
  }
  const failedRetryable =
    first === null || (!first.ok && shouldRetryFinalHopInPlace(first.status));
  if (!failedRetryable || !finalHop || signal.aborted) return first;
  await abortableDelay(
    first === null ? FINAL_HOP_RETRY_DELAY_MS : retryAfterDelayMs(first),
    signal,
  );
  if (signal.aborted) return first;
  try {
    return await fetch(url, init);
  } catch {
    return first;
  }
};

/**
 * POST a Responses-wire (chatgpt + grok) body, plus ONE same-hop retry that
 * STRIPS replayed `reasoning.encrypted_content` when the upstream rejects it
 * as undecryptable. A fallback that switched account/model replays the prior
 * hop's encrypted reasoning into a hop that can't decrypt it → a 400; stripping
 * the ciphertext lets the model re-reason instead of the client seeing a hard
 * error (audit 2026-07-14-codex-upstream-wire §F2). Non-Responses wires and
 * bodies without encrypted state fall straight through to {@link postUpstream}.
 */
const postWithDecryptRetry = async (
  url: string,
  headers: Record<string, string>,
  body: unknown,
  wire: TUpstreamWire,
  finalHop: boolean,
  signal: AbortSignal,
): Promise<Response | null> => {
  const send = (b: unknown): Promise<Response | null> =>
    postUpstream(
      url,
      { method: "POST", headers, body: JSON.stringify(b), signal },
      finalHop,
      signal,
    );
  const first = await send(body);
  // `chatgpt` is the only encrypted-content-bearing upstream wire (grok maps to
  // it in UPSTREAM_WIRE). Anything else, an OK response, a non-400, or a body
  // with no encrypted state → nothing to strip.
  if (
    first === null ||
    first.ok ||
    first.status !== 400 ||
    wire !== "chatgpt" ||
    !responsesBodyHasEncryptedContent(body)
  ) {
    return first;
  }
  // Peek the error body via `clone()` so the caller can still read `first` on
  // the terminal path if this turns out NOT to be a decrypt failure.
  const raw = await first
    .clone()
    .text()
    .catch(() => "");
  if (!isEncryptedContentError(raw)) return first;
  const retried = await send(stripResponsesEncryptedContent(body));
  return retried ?? first;
};

/** Map the daemon's upstream wire to the classifier's provider format
 *  (chatgpt + kimi both speak the OpenAI error-envelope shape). */
const hopFormat = (wire: TUpstreamWire): "openai" | "anthropic" =>
  wire === "anthropic" ? "anthropic" : "openai";

/** Best-effort error-envelope extraction for reason tagging. Parsing is never
 * a routing gate: an unknown provider body still represents an uncommitted
 * candidate failure and therefore walks. */
const errorEnvelopeFrom = (raw: string): TErrorEnvelope | undefined => {
  try {
    const json = JSON.parse(raw) as { error?: unknown };
    return json.error !== null && typeof json.error === "object"
      ? { error: json.error as TErrorEnvelope["error"] }
      : undefined;
  } catch {
    return undefined;
  }
};

/** Classify a raw upstream error response: best-effort envelope parse, then
 *  the shared cloud/daemon policy. The single call point for every
 *  daemon-served hop — subscription (wire-derived format) and cloud-forward
 *  ("openai": forwarded responses are normalized to the shared envelope). */
const classifyRawResponse = (
  status: number,
  raw: string,
  providerFormat: "openai" | "anthropic",
  aborted: boolean,
): ReturnType<typeof classifyHopError> =>
  classifyHopError({
    status,
    envelope: errorEnvelopeFrom(raw),
    providerFormat,
    aborted,
  });

/** Shared pre-commit candidate decision used for every daemon-served hop. */
export const classifyPrecommitResponse = (
  status: number,
  raw: string,
  wire: TUpstreamWire,
  aborted: boolean,
): ReturnType<typeof classifyHopError> =>
  classifyRawResponse(status, raw, hopFormat(wire), aborted);

const statusFor = (httpStatus: number): TRequestStatus =>
  httpStatus < 400
    ? "success"
    : httpStatus === 429
      ? "rate_limited"
      : httpStatus === 408
        ? "timeout"
        : "error";

/** Strip hop-by-hop headers so the body re-streams cleanly to the client. */
const passthroughHeaders = (resp: Response): Headers => {
  const headers = new Headers(resp.headers);
  for (const h of [
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
  ]) {
    headers.delete(h);
  }
  return headers;
};

const report = (row: TDaemonRecordRequest, origin: string | null): void => {
  void recordRequest(row, origin);
  if (
    row.status !== "success" ||
    !isSubscriptionSlug(row.provider) ||
    row.tokens_in + row.tokens_out <= 0
  ) {
    return;
  }
  const delegate = getDelegate(row.provider);
  if (delegate !== null) {
    sampleUsageAfterRequest(row.provider, () => delegate.usage());
  }
};

const decodeAnthropicResponse = Schema.decodeUnknownSync(AnthropicResponse);

// The (clientWire × upstreamWire) request recipe — body + headers — lives in
// `@quantidexyz/openllmw/providers/upstream-request` (buildUpstreamRequest /
// buildUpstreamHeaders / buildUpstreamBody / canonicalToUpstreamBody /
// canonicalFromInbound / clientWireOf). The walker is a thin caller; it never
// re-derives the recipe (that fork caused two regressions).

/** Decode an upstream SSE stream into canonical chunks, per upstream wire. */
export const decodeUpstreamStream = (
  wire: TUpstreamWire,
  body: ReadableStream<Uint8Array>,
  providerModelId: string,
): ReadableStream<TChatCompletionChunk> => {
  const options = { providerModelId };
  if (wire === "anthropic") {
    return decodeProviderEventStream(
      body,
      {
        eventSchema: AnthropicStreamEvent,
        initialState: newAnthropicStreamState,
        eventToChunk: fromAnthropicStreamEvent,
      },
      options,
    );
  }
  if (wire === "chatgpt") {
    return decodeProviderEventStream(
      body,
      {
        eventSchema: ChatGptStreamEventSchema,
        initialState: newChatGptStreamState,
        eventToChunk: chatGptEventToChunk,
      },
      options,
    );
  }
  // openai/kimi: the upstream chunk IS the canonical chunk.
  return decodeProviderEventStream(
    body,
    {
      eventSchema: ChatCompletionChunk,
      initialState: () => ({}),
      eventToChunk: (event: TChatCompletionChunk) => event,
    },
    options,
  );
};

/** Decode an upstream non-streaming JSON body into a canonical response. */
const decodeUpstreamJson = (
  wire: TUpstreamWire,
  json: unknown,
  providerModelId: string,
): TChatCompletionResponse => {
  if (wire === "anthropic") {
    const anthropic: TAnthropicResponse = decodeAnthropicResponse(json);
    return fromAnthropicResponse(anthropic, { providerModelId });
  }
  // chatgpt Responses + openai/kimi: already ChatCompletion-shaped (mirror
  // the core chatgpt spec's inline `fromBody`, which only pins the model).
  return { ...(json as TChatCompletionResponse), model: providerModelId };
};

// The daemon's per-hop token row (`TNativeTokens`) + its mapper + zero value
// are shared with the native path (`./native-runtime/types`) so the manual and
// native transports report identically. `tokens_in` is the canonical
// prompt-token total and INCLUDES the two cache fields; the cloud prices the
// split at the cache rates rather than the input rate.

// ─── web_search (§5) ──────────────────────────────────────────────────
// The agentic round cap (`MAX_WEB_SEARCH_ROUNDS`) is shared with the cloud
// orchestrator via `@quantidexyz/openllmw/tools/web-search/helpers` so both paths
// agent the same depth.

/** Does the request ask the gateway to run web_search (an openllm function
 *  tool, NOT a vendor-native server tool)? */
const requestDeclaresWebSearch = (req: TChatCompletionRequest): boolean =>
  req.tools?.some((t) => functionNameUsesWebSearch(t.function.name)) === true;

/**
 * The gateway runs openllm-managed web_search on every wire path EXCEPT the
 * Anthropic→Anthropic passthrough — there the request's native
 * `web_search_*` server tool is forwarded verbatim and Anthropic runs the
 * search itself (no DEK / vault credential needed). Mirrors the cloud's
 * `webSearchTool.appliesTo` (all combos but `messages.anthropic.passthrough`).
 */
export const shouldInterceptWebSearch = (
  wire: TUpstreamWire,
  surface: TWalkArgs["surface"],
  canonical: TChatCompletionRequest,
): boolean =>
  requestDeclaresWebSearch(canonical) &&
  !(wire === "anthropic" && clientWireOf(surface) === "anthropic");

/** Splice native `server_tool_use` + `web_search_tool_result` blocks to the
 *  front of an Anthropic response's content so Claude Code's WebSearch
 *  parser recognises the search ran (non-streaming messages surface). */
const spliceAnthropicWebSearchBlocks = (
  resp: Record<string, unknown>,
  blocks: ReadonlyArray<{ server_tool_use: unknown; tool_result: unknown }>,
): Record<string, unknown> => {
  if (blocks.length === 0) return resp;
  const native = blocks.flatMap((b) => [b.server_tool_use, b.tool_result]);
  const existing = Array.isArray(resp.content) ? resp.content : [];
  return { ...resp, content: [...native, ...existing] };
};

/**
 * Build the BASE upstream headers for a hop: the ORIGINATOR's own headers
 * (denylist passthrough — `originatorHeadersFrom`), then the credential-intrinsic
 * headers + the subscription bearer layered on top. The wire-derived headers
 * (anthropic-version / anthropic-beta / content-type) are layered last by
 * `buildUpstreamRequest`/`buildUpstreamHeaders`. So a genuine vendor-CLI request
 * reaches the vendor with ITS real identity; the daemon swaps in the bearer
 * (+ the user's own account id where required) and never overrides an identity
 * the originator already presents. The delegate receives the inbound headers so
 * it can BACKFILL a vendor-CLI identity the originator lacks — chatgpt does this
 * for models the Codex backend gates on `originator: codex_cli_rs` (see its
 * `credentialForUpstream`). Returns "retry" when no usable local credential is
 * available, so the walker falls through.
 */
const acquireUpstream = async (
  provider: string,
  args: TWalkArgs,
): Promise<
  | { headers: Record<string, string>; url: string; accountHash: string | null }
  | "retry"
> => {
  const delegate = getDelegate(provider);
  if (delegate === null) return "retry";
  try {
    const cred = await delegate.credentialForUpstream(args.req.headers);
    return {
      headers: {
        ...originatorHeadersFrom(args.req.headers),
        ...cred.headers,
        authorization: `Bearer ${cred.access_token}`,
      },
      url: cred.url,
      // Rides onto the recorded row so the cloud attributes this hop's
      // cost to the right vendor-account meter series.
      accountHash: cred.account_hash ?? null,
    };
  } catch {
    return "retry";
  }
};

/** The client's inbound `anthropic-beta` (messages surface only) — merged into
 *  the upstream beta by `buildUpstreamHeaders`. */
const inboundBetaOf = (args: TWalkArgs): string | null =>
  args.surface === "messages" ? args.req.headers.get("anthropic-beta") : null;

/**
 * Delegate-owned per-model request compat, applied to the BUILT upstream body
 * (grok today; a no-op for delegates that declare neither knob — audit
 * 2026-07-14 §F2/§F7):
 *   - `reasoning` dropped when the vendor's live model row says configurable
 *     effort is unsupported (`supportsReasoningEffort` → `false`; `null` =
 *     unknown leaves the request untouched) — the shared wire builder can't
 *     know this, only the delegate sees the vendor's `/v1/models`;
 *   - tool-schema keywords the endpoint rejects stripped recursively from
 *     every tool's `parameters`.
 * The delegate rides in as a parameter (callers pass `getDelegate(...)`) so
 * the offline suite can exercise the policy with a stub.
 */
export const applyDelegateModelCompat = async (
  delegate: TProviderDelegate | null,
  providerModelId: string,
  body: unknown,
): Promise<unknown> => {
  if (delegate === null || body === null || typeof body !== "object") {
    return body;
  }
  let out = body as Record<string, unknown>;
  if (
    out.reasoning !== undefined &&
    delegate.supportsReasoningEffort !== undefined
  ) {
    const supported = await delegate
      .supportsReasoningEffort(providerModelId)
      .catch((): null => null);
    if (supported === false) {
      const { reasoning: _dropped, ...rest } = out;
      out = rest;
    }
  }
  const keywords = delegate.unsupportedToolSchemaKeywords;
  if (
    keywords !== undefined &&
    keywords.length > 0 &&
    Array.isArray(out.tools)
  ) {
    out = {
      ...out,
      tools: out.tools.map((tool) =>
        tool !== null && typeof tool === "object" && "parameters" in tool
          ? {
              ...(tool as Record<string, unknown>),
              parameters: stripSchemaKeywords(
                (tool as Record<string, unknown>).parameters,
                keywords,
              ),
            }
          : tool,
      ),
    };
  }
  return out;
};

// ── web_search decode-failure diagnostics (issue #274) ────────────────
// The accumulate/decode step inside the agentic loop used to funnel EVERY
// throw — including the vendor's own terminal error events
// (`response.failed` / `response.incomplete` / `error`, thrown as
// `UpstreamStreamError` by the chatgpt decoder) — into one generic
// "could not decode upstream response" 502 that discarded the cause.
// This classifier keeps a sanitized, actionable single line: the failure
// STAGE plus the error's name and FIRST line, hard-truncated — never the
// upstream body, prompt, or search results.

/** Where in the round's decode pipeline the failure happened. */
type TWebSearchDecodeStage =
  | "upstream_error" // the vendor reported an error mid-stream (not a decode bug)
  | "json_parse" // non-streaming body was not JSON
  | "schema_decode" // JSON parsed but failed the wire schema
  | "stream_decode"; // SSE drain / event conversion / accumulation failed

export type TWebSearchDecodeContext = {
  readonly provider: string;
  readonly modelId: string;
  readonly providerModelId: string;
  readonly wire: TUpstreamWire;
  readonly round: number;
  readonly upstreamStatus: number;
  readonly upstreamContentType: string | null;
};

export type TWebSearchDecodeFailure = {
  readonly stage: TWebSearchDecodeStage;
  /** Sanitized error name + first line, hard-truncated. */
  readonly detail: string;
  /** The full single-line 502 body (also what the recorded row carries). */
  readonly clientMessage: string;
};

const sanitizeErrorLine = (err: unknown, max: number): string => {
  const raw =
    err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  const line = raw.split("\n", 1)[0] ?? "";
  return line.length > max ? `${line.slice(0, max)}…` : line;
};

/**
 * Classify a `serveWithWebSearch` round decode failure into a sanitized
 * diagnostic. `upstream_error` keeps the vendor's own error type + message
 * verbatim (that IS the diagnostic the user needs — a usage cap, a
 * max_output_tokens truncation, a rate limit); everything else keeps only
 * the error's first line so no response content can leak.
 */
export const describeWebSearchDecodeFailure = (
  err: unknown,
  ctx: TWebSearchDecodeContext,
): TWebSearchDecodeFailure => {
  let stage: TWebSearchDecodeStage;
  let detail: string;
  if (err instanceof UpstreamStreamError) {
    stage = "upstream_error";
    const { type, message } = upstreamErrorFrom(err);
    detail = sanitizeErrorLine(
      message.startsWith(type) ? message : `${type}: ${message}`,
      300,
    );
  } else if (err instanceof SyntaxError) {
    stage = "json_parse";
    detail = sanitizeErrorLine(err, 160);
  } else if (
    err instanceof Error &&
    (err.name === "ParseError" ||
      (err as { _tag?: unknown })._tag === "ParseError")
  ) {
    // effect Schema decode failure — its message tree embeds actual
    // values, so keep only the first line.
    stage = "schema_decode";
    detail = sanitizeErrorLine(err, 160);
  } else {
    stage = ctx.wire === "chatgpt" ? "stream_decode" : "schema_decode";
    detail = sanitizeErrorLine(err, 160);
  }
  const headline =
    stage === "upstream_error"
      ? "upstream reported an error during a managed web_search round"
      : "could not decode upstream response";
  const clientMessage =
    `web_search: ${headline} ` +
    `(provider=${ctx.provider} model=${ctx.modelId} wire=${ctx.wire} ` +
    `round=${ctx.round} stage=${stage} upstream_status=${ctx.upstreamStatus}` +
    `${ctx.upstreamContentType !== null ? ` content_type=${ctx.upstreamContentType}` : ""}): ` +
    detail;
  return { stage, detail, clientMessage };
};

/**
 * Serve a subscription hop that runs openllm-managed web_search (§5): the
 * agentic loop. Each round calls the vendor (ACCUMULATED — we must read the
 * whole response to spot tool calls), and for every `web_search` tool call
 * POSTs only the QUERY to the cloud (`searchViaCloud`), appends the results
 * as a follow-up turn, and re-calls — until the model answers without
 * searching (or the round cap). The conversation never leaves the box; only
 * the query crosses (to a third-party engine the user already authorized).
 */
const serveWithWebSearch = async (
  hop: THop,
  wire: TUpstreamWire,
  args: TWalkArgs,
  initialCanonical: TChatCompletionRequest,
  finalHop: boolean,
): Promise<Response | "retry"> => {
  const acquired = await acquireUpstream(hop.provider, args);
  if (acquired === "retry") return "retry";
  const { headers: baseHeaders, url, accountHash } = acquired;
  // Headers are computed once; the body is rebuilt per round from the
  // accumulated canonical (web_search appends tool results between rounds).
  const headers = buildUpstreamHeaders({
    surface: args.surface,
    upstreamWire: wire,
    rawBody: args.rawBody,
    providerModelId: hop.providerModelId,
    stream: false,
    baseHeaders,
    inboundBeta: inboundBetaOf(args),
    isOAuth: wire === "anthropic",
  });

  let canonical = initialCanonical;
  const collectedBlocks: Array<{
    server_tool_use: unknown;
    tool_result: unknown;
  }> = [];
  let final: TChatCompletionResponse | null = null;

  for (let round = 0; round < MAX_WEB_SEARCH_ROUNDS; round++) {
    // Accumulated cross-wire body (chatgpt still streams + is drained),
    // then the delegate's per-model compat (reasoning gate + schema strip).
    const body = await applyDelegateModelCompat(
      getDelegate(hop.provider),
      hop.providerModelId,
      canonicalToUpstreamBody(
        wire,
        canonical,
        hop.providerModelId,
        false,
        wantsCodexPreamble(hop.provider),
      ),
    );
    // Rounds > 0 are committed to this hop — no in-place retry there either.
    const resp = await postUpstream(
      url,
      {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: args.req.signal,
      },
      finalHop && round === 0,
      args.req.signal,
    );
    if (resp === null) {
      if (round === 0 && !finalHop) return "retry";
      return errorJson(502, "web_search: upstream request failed");
    }
    if (!resp.ok) {
      const detail = await resp.text().catch(() => "");
      // Round zero has not committed this turn to the candidate, so every
      // non-abort upstream rejection can walk. Later rounds are logically
      // committed to this hop by the preceding tool exchange.
      if (
        round === 0 &&
        !finalHop &&
        classifyPrecommitResponse(
          resp.status,
          detail,
          wire,
          args.req.signal.aborted,
        ).kind === "transient"
      ) {
        return "retry";
      }
      return new Response(detail.length > 0 ? detail : null, {
        status: resp.status,
        headers: { "content-type": "application/json" },
      });
    }
    if (resp.body === null) {
      if (round === 0) return "retry";
      return errorJson(502, "web_search: empty upstream response");
    }
    let roundResp: TChatCompletionResponse;
    try {
      roundResp =
        wire === "chatgpt"
          ? await accumulateChunksToResponse(
              decodeUpstreamStream(wire, resp.body, hop.providerModelId),
              hop.providerModelId,
            )
          : decodeUpstreamJson(
              wire,
              JSON.parse(await resp.text()),
              hop.providerModelId,
            );
    } catch (err) {
      // Issue #274: this used to be a bare catch → one generic 502 that
      // erased the vendor's own error (usage caps, max_output_tokens, rate
      // limits all read as "could not decode"). Keep a sanitized
      // classification, log it, and record the failed hop so the turn can
      // be correlated with gateway telemetry.
      const failure = describeWebSearchDecodeFailure(err, {
        provider: hop.provider,
        modelId: hop.modelId,
        providerModelId: hop.providerModelId,
        wire,
        round,
        upstreamStatus: resp.status,
        upstreamContentType: resp.headers.get("content-type"),
      });
      logWarn("walker", "web_search round decode failed", {
        provider: hop.provider,
        model: hop.modelId,
        provider_model_id: hop.providerModelId,
        wire,
        round,
        surface: args.surface,
        endpoint: args.endpoint,
        upstream_status: resp.status,
        upstream_content_type: resp.headers.get("content-type"),
        stage: failure.stage,
        detail: failure.detail,
      });
      report(
        {
          model: hop.modelId,
          provider: hop.provider,
          status: statusFor(502),
          latency_ms: Date.now() - args.startedAt,
          endpoint: args.endpoint,
          error: failure.clientMessage,
          ...(accountHash !== null ? { account_hash: accountHash } : {}),
          ...ZERO_TOKENS,
        },
        args.originParam,
      );
      return errorJson(502, failure.clientMessage);
    }

    const webCalls: TToolCall[] = (
      roundResp.choices[0]?.message.tool_calls ?? []
    ).filter(toolCallUsesWebSearch);
    const assistantMsg =
      webCalls.length > 0
        ? buildAssistantToolCallMessage({
            response: roundResp,
            toolCalls: webCalls,
          })
        : null;
    if (assistantMsg === null) {
      final = roundResp; // model answered without searching → done
      break;
    }

    const contentsById = new Map<string, string>();
    for (const call of webCalls) {
      const query = extractQueryFromToolCall(call);
      const result =
        query.length === 0
          ? null
          : await searchViaCloud(query, args.originParam, args.req.signal);
      contentsById.set(
        call.id,
        result?.content ??
          "Search error: web_search is unavailable (no result from the gateway)",
      );
      if (result !== null && result.server_tool_use !== null) {
        collectedBlocks.push({
          server_tool_use: result.server_tool_use,
          tool_result: result.tool_result,
        });
      }
    }
    canonical = {
      ...canonical,
      messages: [
        ...canonical.messages,
        assistantMsg,
        ...buildToolResultMessages({ calls: webCalls, contentsById }),
      ],
    };
  }

  if (final === null) {
    return errorJson(
      502,
      `web_search: exceeded ${MAX_WEB_SEARCH_ROUNDS} rounds without a final answer`,
    );
  }

  report(
    {
      model: hop.modelId,
      provider: hop.provider,
      status: statusFor(200),
      latency_ms: Date.now() - args.startedAt,
      endpoint: args.endpoint,
      ...(accountHash !== null ? { account_hash: accountHash } : {}),
      ...tokensFromResponse(final),
    },
    args.originParam,
  );

  const clientWire = clientWireOf(args.surface);
  const wantsStream =
    (args.rawBody as { stream?: unknown } | null)?.stream === true;
  if (wantsStream) {
    const bytes = sseBytesForClient(
      responseToChunkStream(final),
      args.surface,
      clientWire,
    );
    return new Response(bytes, {
      status: 200,
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache",
        connection: "keep-alive",
      },
    });
  }
  const clientBody =
    args.surface === "responses"
      ? toResponsesResponse(final)
      : clientWire === "anthropic"
        ? spliceAnthropicWebSearchBlocks(
            toAnthropicMessagesResponse(final) as unknown as Record<
              string,
              unknown
            >,
            collectedBlocks,
          )
        : final;
  return new Response(JSON.stringify(clientBody), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

/**
 * Serve one subscription hop locally: inject the official CLI's bearer +
 * real identity headers, adapt the request to the provider's wire, call
 * the vendor, and re-encode the response back to the client's wire. The
 * conversation goes only to the vendor; the token never leaves the box.
 * Returns "retry" on any non-abort pre-commit candidate failure so the
 * walker advances.
 */
const serveSubscription = async (
  hop: THop,
  wire: TUpstreamWire,
  args: TWalkArgs,
  finalHop: boolean,
): Promise<Response | "retry"> => {
  const acquired = await acquireUpstream(hop.provider, args);
  if (acquired === "retry") return "retry";
  const { headers: baseHeaders, url, accountHash } = acquired;

  const clientWantsStream =
    (args.rawBody as { stream?: unknown } | null)?.stream === true;
  // ONE shared recipe — body + headers — for the (clientWire × upstreamWire)
  // pairing (the cloud runner calls the same builder).
  const built = buildUpstreamRequest({
    surface: args.surface,
    upstreamWire: wire,
    rawBody: args.rawBody,
    providerModelId: hop.providerModelId,
    stream: clientWantsStream,
    baseHeaders,
    inboundBeta: inboundBetaOf(args),
    isOAuth: wire === "anthropic",
    codexInstructions: wantsCodexPreamble(hop.provider),
  });
  const headers = built.headers;
  const body = await applyDelegateModelCompat(
    getDelegate(hop.provider),
    hop.providerModelId,
    built.body,
  );
  const resp = await postWithDecryptRetry(
    url,
    headers,
    body,
    wire,
    finalHop,
    args.req.signal,
  );
  if (resp === null) return "retry"; // network error — pre-stream, fall through
  if (!resp.ok) {
    const raw = await resp.text().catch(() => "");
    // No output has been committed yet. A different configured candidate may
    // accept the same canonical request regardless of this provider's status
    // code or envelope shape, so use the shared cloud/daemon policy.
    if (
      !finalHop &&
      classifyPrecommitResponse(resp.status, raw, wire, args.req.signal.aborted)
        .kind === "transient"
    ) {
      return "retry";
    }
    // The final hop has nowhere to walk (or the caller aborted): surface the
    // upstream response verbatim, including status and Retry-After.
    return new Response(raw.length > 0 ? raw : null, {
      status: resp.status,
      headers: passthroughHeaders(resp),
    });
  }

  if (!resp.body) return "retry";

  // Committed. Re-encode the response to the client's wire + record a
  // metadata row. Cost is NOT computed here — the cloud recomputes it from
  // these token counts (single pricing source of truth, no local table).
  const clientWire = clientWireOf(args.surface);
  // `responses` clients always need a Responses re-encode (never raw upstream
  // bytes), so they never take the verbatim passthrough.
  const passthrough = wire === clientWire && args.surface !== "responses";
  // What the UPSTREAM produced, decided deterministically (not sniffed):
  // chatgpt's Codex/Responses endpoint ALWAYS streams (`toChatGptRequest`
  // forces `stream: true`); anthropic + kimi propagate the request's stream
  // flag, which buildUpstreamBody set from the client's. So upstream is SSE
  // iff chatgpt, or the client asked to stream.
  const upstreamStreams = wire === "chatgpt" || clientWantsStream;
  const baseRow = {
    model: hop.modelId,
    provider: hop.provider,
    status: statusFor(resp.status),
    latency_ms: Date.now() - args.startedAt,
    endpoint: args.endpoint,
    ...(accountHash !== null ? { account_hash: accountHash } : {}),
  } satisfies Partial<TDaemonRecordRequest>;
  const recordTokens = (u: TNativeTokens): void =>
    report({ ...baseRow, ...u }, args.originParam);

  // ── Client wants a live stream ──────────────────────────────────────
  // First-class path: stream chunk-by-chunk, re-encoding to the client's
  // wire as bytes arrive. (upstreamStreams is always true here — chatgpt
  // always streams; anthropic/kimi stream because the client asked.)
  if (clientWantsStream) {
    const sseHeaders = {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache",
      connection: "keep-alive",
    } as const;
    // Keep the (localhost) client connection warm while the upstream is
    // quiet during a long reasoning / tool run — the same "chat stopped
    // while it was actually doing something" symptom the cloud guards. The
    // daemon does NOT add `withStreamDeadline`: that exists only to beat
    // Vercel's `maxDuration` guillotine (a cloud-only concept), and a daemon
    // crash can't emit a terminator regardless. Frame-aligned so a beat is
    // never spliced inside a half-sent SSE event.
    const heartbeat = (
      bytes: ReadableStream<Uint8Array>,
    ): ReadableStream<Uint8Array> =>
      withFrameAlignedHeartbeat(bytes, heartbeatOptionsFor(args.surface));
    // Meter token usage off a tee'd canonical branch (never blocks the
    // client; accurate counts come from the final chunk's usage).
    const meter = (chunks: ReadableStream<TChatCompletionChunk>): void => {
      void accumulateChunksToResponse(chunks, hop.providerModelId)
        .then((r) => recordTokens(tokensFromResponse(r)))
        .catch(() => recordTokens(ZERO_TOKENS));
    };
    if (passthrough) {
      // Same wire in and out — the client gets the upstream bytes verbatim
      // (no transform round-trip that could alter them); a tee'd copy is
      // decoded purely to meter.
      const [toClient, toMeter] = resp.body.tee();
      meter(decodeUpstreamStream(wire, toMeter, hop.providerModelId));
      return new Response(heartbeat(toClient), {
        status: resp.status,
        headers: passthroughHeaders(resp),
      });
    }
    // Cross-wire (or chatgpt): decode → tee → re-encode + meter.
    const [toClient, toMeter] = decodeUpstreamStream(
      wire,
      resp.body,
      hop.providerModelId,
    ).tee();
    meter(toMeter);
    const clientBytes = sseBytesForClient(toClient, args.surface, clientWire);
    return new Response(heartbeat(clientBytes), {
      status: resp.status,
      headers: sseHeaders,
    });
  }

  // ── Client wants a single JSON response ─────────────────────────────
  const jsonHeaders = { "content-type": "application/json" } as const;
  const reencodeJson = (canonical: TChatCompletionResponse): string =>
    JSON.stringify(jsonBodyForClient(canonical, args.surface, clientWire));

  if (upstreamStreams) {
    // The upstream streamed but the client wants JSON (chatgpt, whose Codex
    // endpoint always streams): DRAIN the SSE → accumulate → one response.
    let canonical: TChatCompletionResponse;
    try {
      canonical = await accumulateChunksToResponse(
        decodeUpstreamStream(wire, resp.body, hop.providerModelId),
        hop.providerModelId,
      );
    } catch (err) {
      recordTokens(ZERO_TOKENS);
      // Same erasure class as the web_search decode 502 (issue #274): keep
      // the vendor's terminal error / the drain failure's first line instead
      // of a bare generic message.
      return errorJson(
        502,
        `upstream stream ended before producing output: ${sanitizeErrorLine(err, 300)}`,
      );
    }
    recordTokens(tokensFromResponse(canonical));
    return new Response(reencodeJson(canonical), {
      status: resp.status,
      headers: jsonHeaders,
    });
  }

  // Upstream returned JSON + client wants JSON (anthropic/kimi non-stream).
  // Decode for tokens + client re-encode; on parse/decode failure surface
  // the upstream payload verbatim rather than mangling it.
  const text = await resp.text();
  let upstreamJson: unknown;
  try {
    upstreamJson = JSON.parse(text);
  } catch {
    recordTokens(ZERO_TOKENS);
    return new Response(text, {
      status: resp.status,
      headers: passthroughHeaders(resp),
    });
  }
  let canonical: TChatCompletionResponse;
  try {
    canonical = decodeUpstreamJson(wire, upstreamJson, hop.providerModelId);
  } catch {
    recordTokens(ZERO_TOKENS);
    return new Response(text, {
      status: resp.status,
      headers: passthroughHeaders(resp),
    });
  }
  recordTokens(tokensFromResponse(canonical));
  // Passthrough returns the upstream bytes verbatim; cross-wire re-encodes.
  return new Response(passthrough ? text : reencodeJson(canonical), {
    status: resp.status,
    headers: jsonHeaders,
  });
};

/**
 * Walk the plan and return the committed `Response`. The walker is the
 * daemon's ONLY data path — there is no core-backed fallback — so it
 * always answers with a Response (never throws; a bare throw would 500 the
 * user instead of surfacing a clean error). A request with no `?__plan=`
 * is a misuse of the daemon surface (clients reach it only via the
 * gateway's 307, which always carries a plan) → 400.
 */
export const runWalker = async (args: TWalkArgs): Promise<Response> => {
  const planModelIds = parsePlan(args.planParam);
  if (planModelIds.length === 0) {
    return errorJson(
      400,
      "the daemon /v1 surface expects a cloud-issued ?__plan= — point your client at the gateway, which 307s subscription chains here with the resolved plan",
    );
  }

  // Reject a forged plan: when the cloud configured a signing secret (so it
  // handed us a per-user key at bootstrap), the 307 MUST carry a valid `__sig`
  // over the full canonical payload (plan + pmids + origin). No key → unsigned
  // mode (dev), accept. (§9 + daemon-presence-without-heartbeat)
  const sigKey = planSigningKey();
  if (
    sigKey !== null &&
    !verifyPlanSignature(
      daemonPlanSigningPayload(
        args.planParam ?? "",
        args.pmidsParam ?? "",
        args.originParam ?? "",
      ),
      args.sigParam,
      sigKey,
    )
  ) {
    return errorJson(403, "invalid or missing __plan signature");
  }

  // The concrete upstream ids ride parallel to the plan — split WITHOUT
  // trimming empties so positions stay aligned (an empty entry = uncatalogued
  // hop, falls back inside resolveHop).
  const pmids = args.pmidsParam === null ? [] : args.pmidsParam.split(",");
  const hops = planModelIds.map((m, i) => resolveHop(m, pmids[i]));
  if (!canWalkPlan(hops)) {
    return errorJson(
      400,
      "the plan contains a subscription provider the daemon has no upstream for",
    );
  }

  // Canonical view of the inbound — used to detect openllm-managed
  // web_search on the transform paths (§5).
  const canonical = canonicalFromInbound(args.surface, args.rawBody);

  let lastError: string | null = null;
  for (const [hopIndex, hop] of hops.entries()) {
    const finalHop = hopIndex === hops.length - 1;
    // Native-runtime providers (claude_code, chatgpt) — try the OFFICIAL vendor
    // runtime FIRST (Claude Code stream-json / Codex app-server). On a native
    // DECLINE (unsupported request — tools/images/structured-output — or a
    // pre-commit failure) fall through to the MANUAL transport on the SAME hop
    // (below) so no workflow is blocked; auth/refresh still run through the CLI
    // via the delegate either way.
    if (isNativeRuntimeProvider(hop.provider)) {
      const native = await tryServeNativeRuntime({
        provider: hop.provider,
        providerModelId: hop.providerModelId,
        surface: args.surface,
        canonical,
        wantsStream:
          (args.rawBody as { stream?: unknown } | null)?.stream === true,
        signal: args.req.signal,
        record: (tokens, status) =>
          report(
            {
              model: hop.modelId,
              provider: hop.provider,
              status,
              latency_ms: Date.now() - args.startedAt,
              endpoint: args.endpoint,
              ...tokens,
            },
            args.originParam,
          ),
      });
      if (native instanceof Response) return native; // committed natively
      lastError = `native hop ${hop.modelId} declined: ${native.declined}`;
      // ↓ fall through to the manual transport for this hop (no `continue`).
    }
    const wire = UPSTREAM_WIRE[hop.provider];
    if (wire !== undefined) {
      // Manual subscription transport — the fallback for native declines
      // (claude_code + chatgpt) and the sole path for kimi_code + grok.
      const served = shouldInterceptWebSearch(wire, args.surface, canonical)
        ? await serveWithWebSearch(hop, wire, args, canonical, finalHop)
        : await serveSubscription(hop, wire, args, finalHop);
      if (served !== "retry") return served; // committed
      lastError = `subscription hop ${hop.modelId} failed pre-stream`;
      continue;
    }
    // API-key hop: forward to the cloud pinned to this concrete model.
    let resp: Response;
    try {
      resp = await forwardToCloud(
        args.req,
        args.rawBytes,
        hop.modelId,
        args.originParam,
      );
    } catch {
      lastError = `forward of ${hop.modelId} to cloud failed`;
      if (args.req.signal.aborted) break;
      continue;
    }
    if (!resp.ok && !finalHop) {
      const raw = await resp
        .clone()
        .text()
        .catch(() => "");
      // Forwarded cloud responses are normalized to the shared envelope;
      // provider format only affects reason tagging, never walk eligibility.
      const cls = classifyRawResponse(
        resp.status,
        raw,
        "openai",
        args.req.signal.aborted,
      );
      if (cls.kind === "transient") {
        lastError = `cloud hop ${hop.modelId} returned ${resp.status}`;
        continue;
      }
    }
    return new Response(resp.body, {
      status: resp.status,
      headers: passthroughHeaders(resp),
    });
  }
  // Every hop in the plan failed pre-stream.
  return errorJson(
    502,
    `all hops in the plan failed${lastError !== null ? ` (last: ${lastError})` : ""}`,
  );
};
