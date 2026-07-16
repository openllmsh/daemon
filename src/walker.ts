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
  type TChatCompletionResponse,
  type TDaemonRecordRequest,
  type TErrorEnvelope,
  type TRequestStatus,
  type TServerSearchCall,
} from "@quantidexyz/openllmp";
import { declaresAnthropicServerSearchTool } from "@quantidexyz/openllmw/adapters/messages/request";
import { fitRequestToHopBudget } from "@quantidexyz/openllmw/features/compaction/tool-output-compact";
import { estimateBodyTokens } from "@quantidexyz/openllmw/lib/canonical/token-estimate";
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
import { withGrokNativeSearch } from "@quantidexyz/openllmw/providers/grok/web-search";
import {
  KIMI_SEARCH_MAX_ROUNDS,
  kimiBuiltinSearchCalls,
  kimiSearchEchoMessages,
  withKimiBuiltinSearch,
} from "@quantidexyz/openllmw/providers/kimi/web-search";
// The SINGLE (clientWire × upstreamWire) request recipe — shared with the
// cloud runner so the two can't drift (this fork caused two regressions). See
// `docs/proposals/unified-upstream-request-builder.md`.
import {
  buildUpstreamRequest,
  canonicalFromInbound,
  clientWireOf,
} from "@quantidexyz/openllmw/providers/upstream-request";
import { Schema } from "effect";
import {
  heartbeatOptionsFor,
  jsonBodyForClient,
  sseBytesForClient,
} from "./client-encode";
import { recordRequest } from "./cloud-client";
import { lookupCatalogEntry, planSigningKey } from "./config";
import { errorJson } from "./cors";
import { getDelegate, isSubscriptionSlug } from "./delegation";
import type { TProviderDelegate } from "./delegation/types";
import { forwardToCloud } from "./forward";
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

/** Outcome of peeking a decoded upstream stream's first event before
 *  committing the client response: the (replayable) chunk stream, or the
 *  rejection that arrived before any output. */
export type TPeekedChunks<T> =
  | { readonly kind: "chunks"; readonly chunks: ReadableStream<T> }
  | { readonly kind: "error"; readonly error: unknown };

/** How long a streaming subscription hop holds the client response
 *  uncommitted waiting for the upstream's first decoded event. In-stream
 *  rejections (context overflow) arrive as the very first event right after
 *  the 200 headers; a healthy turn that stays quiet longer (cold start, long
 *  prompt processing) commits at the deadline and streams exactly as before. */
export const FIRST_EVENT_PEEK_MS = 2_000;

/**
 * Wait (bounded) for the FIRST event of a decoded upstream stream, so an
 * in-stream rejection that precedes any output — the overflow incident
 * shape: HTTP 200, then a first event `error: Your input exceeds the
 * context window` — surfaces while the hop is still an UNCOMMITTED
 * candidate and the caller can walk the plan, instead of failing inside an
 * already-committed 200 stream. Every other outcome (first chunk arrived,
 * stream ended, deadline passed while quiet) returns a stream that replays
 * the in-flight read: no event is lost or duplicated, and a rejection that
 * arrives after the deadline still propagates mid-stream as today.
 */
export const peekFirstChunk = <T>(
  source: ReadableStream<T>,
  deadlineMs: number,
): Promise<TPeekedChunks<T>> => {
  const reader = source.getReader();
  const firstRead = reader.read();
  let pendingFirst: ReturnType<typeof reader.read> | null = firstRead;
  const replayed = (): ReadableStream<T> =>
    new ReadableStream<T>({
      pull: async (controller) => {
        const read = pendingFirst ?? reader.read();
        pendingFirst = null;
        const r = await read;
        if (r.done) {
          controller.close();
          return;
        }
        controller.enqueue(r.value);
      },
      cancel: (reason) => reader.cancel(reason),
    });
  return new Promise((resolve) => {
    let settled = false;
    const settle = (v: TPeekedChunks<T>): void => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    const timer = setTimeout(
      () => settle({ kind: "chunks", chunks: replayed() }),
      deadlineMs,
    );
    firstRead.then(
      () => {
        clearTimeout(timer);
        settle({ kind: "chunks", chunks: replayed() });
      },
      (error: unknown) => {
        clearTimeout(timer);
        settle({ kind: "error", error });
      },
    );
  });
};

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

const sanitizeErrorLine = (err: unknown, max: number): string => {
  const raw =
    err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  const line = raw.split("\n", 1)[0] ?? "";
  return line.length > max ? `${line.slice(0, max)}…` : line;
};

const upstreamErrorLine = (err: UpstreamStreamError): string => {
  const { type, message } = upstreamErrorFrom(err);
  return message.startsWith(type) ? message : `${type}: ${message}`;
};

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
  let body = await applyDelegateModelCompat(
    getDelegate(hop.provider),
    hop.providerModelId,
    built.body,
  );
  // Provider-native search: the client DECLARED the Anthropic
  // `web_search_*` server tool — an explicit platform-executes-search
  // contract (Claude Code's WebSearch). A bare `web_search`-NAMED function
  // tool never triggers either branch.
  //
  //   - grok: xAI's Responses proxy runs web + X search fully server-side
  //     within ONE request. Swap the canonicalised `web_search` function
  //     tool for the native `web_search`/`x_search` tools (one search owner
  //     per turn); the chatgpt stream decoder re-emits the executed
  //     searches as canonical `server_search_calls` → blocks + usage.
  //   - kimi_code: Moonshot's builtin `$web_search` also executes
  //     server-side, but its protocol pauses for a verbatim ARGUMENT ECHO
  //     per search — served by `serveKimiBuiltinSearch` below (a protocol
  //     echo, not gateway agency: nothing is extracted, executed, or
  //     synthesized on this box).
  const declaredSearch =
    args.surface === "messages" &&
    declaresAnthropicServerSearchTool(args.rawBody);
  if (declaredSearch && hop.provider === "grok") {
    body = withGrokNativeSearch(body);
  }
  if (declaredSearch && hop.provider === "kimi_code") {
    return serveKimiBuiltinSearch(
      hop,
      args,
      finalHop,
      { url, headers, accountHash },
      withKimiBuiltinSearch(body),
    );
  }
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
    // Shared terminal handling for a FIRST-event in-stream rejection
    // caught by the pre-commit peek (both branches below): a non-final
    // hop WALKS; the final hop surfaces a 502 recorded as an ERROR row.
    const peekedError = (error: unknown): Response | "retry" => {
      if (!finalHop && !args.req.signal.aborted) return "retry";
      const detail =
        error instanceof UpstreamStreamError
          ? sanitizeErrorLine(upstreamErrorLine(error), 300)
          : sanitizeErrorLine(error, 300);
      report({ ...baseRow, status: "error", ...ZERO_TOKENS }, args.originParam);
      return errorJson(
        502,
        `upstream stream ended before producing output: ${detail}`,
      );
    };
    if (passthrough) {
      // Same wire in and out — the client gets the upstream bytes verbatim
      // (no transform round-trip that could alter them); a tee'd copy is
      // decoded purely to meter. The meter branch doubles as the
      // pre-commit peek: an in-stream rejection that precedes any output
      // (Anthropic emits `event: error` on a 200 for overloaded_error
      // etc.) surfaces BEFORE the byte-verbatim response is committed, so
      // a non-final hop can walk instead of dying inside a committed
      // stream. The client branch stays byte-verbatim either way.
      const [toClient, toMeter] = resp.body.tee();
      const peeked = await peekFirstChunk(
        decodeUpstreamStream(wire, toMeter, hop.providerModelId),
        FIRST_EVENT_PEEK_MS,
      );
      if (peeked.kind === "error") {
        void toClient.cancel().catch(() => undefined);
        return peekedError(peeked.error);
      }
      meter(peeked.chunks);
      return new Response(heartbeat(toClient), {
        status: resp.status,
        headers: passthroughHeaders(resp),
      });
    }
    // Cross-wire (or chatgpt): decode → peek → tee → re-encode + meter.
    // The bounded first-event peek keeps the response uncommitted long
    // enough for a pre-output in-stream rejection (context overflow) to
    // WALK a non-final hop instead of dying inside a committed stream; a
    // quiet-but-healthy turn commits at the deadline and streams as before.
    const peeked = await peekFirstChunk(
      decodeUpstreamStream(wire, resp.body, hop.providerModelId),
      FIRST_EVENT_PEEK_MS,
    );
    if (peeked.kind === "error") return peekedError(peeked.error);
    const [toClient, toMeter] = peeked.chunks.tee();
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
      // The drain threw before ANY output reached the client, so the hop is
      // still an uncommitted candidate in JSON mode — a non-final hop WALKS
      // (the gpt-5.6 overflow incident shape: HTTP 200, then a first event
      // `error: Your input exceeds the context window`). Zero tokens were
      // metered on the failed attempt, so the walk cannot double-bill;
      // nothing is recorded for a walked hop (parity with the pre-commit
      // non-ok path).
      if (!finalHop && !args.req.signal.aborted) return "retry";
      // Keep the vendor's terminal error (with its upstreamType code, not the
      // UpstreamStreamError class name) / the drain failure's first line
      // instead of a bare generic message. Recorded as an ERROR row — the
      // client receives a 502, so `statusFor(resp.status)`'s "success" (from
      // the upstream 200) would misreport the outcome.
      const detail =
        err instanceof UpstreamStreamError
          ? sanitizeErrorLine(upstreamErrorLine(err), 300)
          : sanitizeErrorLine(err, 300);
      report({ ...baseRow, status: "error", ...ZERO_TOKENS }, args.originParam);
      return errorJson(
        502,
        `upstream stream ended before producing output: ${detail}`,
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
 * Serve a kimi_code hop whose client declared the Anthropic server search
 * tool, over Moonshot's builtin `$web_search` PROTOCOL ECHO (see
 * `@quantidexyz/openllmw/providers/kimi/web-search`): each round's builtin
 * tool calls are answered by echoing their opaque arguments back verbatim —
 * the search already ran server-side; Moonshot injects the stored results
 * into context on the next round. The walker extracts nothing, executes
 * nothing, and synthesizes nothing. Rounds are read in full (a `stream:
 * true` client gets the final answer as a one-shot SSE re-encode); each
 * echoed search is reported as a canonical `ServerSearchCall` (opaque —
 * Moonshot never exposes the query) so the client's search counter works.
 * ONE usage row is recorded, summed across rounds.
 */
const serveKimiBuiltinSearch = async (
  hop: THop,
  args: TWalkArgs,
  finalHop: boolean,
  acquired: {
    readonly url: string;
    readonly headers: Record<string, string>;
    readonly accountHash: string | null;
  },
  initialBody: unknown,
): Promise<Response | "retry"> => {
  const wire: TUpstreamWire = "openai";
  const clientWantsStream =
    (args.rawBody as { stream?: unknown } | null)?.stream === true;
  const clientWire = clientWireOf(args.surface);
  let body = initialBody as Record<string, unknown>;
  // Rounds must be read in full to see the builtin calls.
  body = { ...body, stream: false };
  const executed: TServerSearchCall[] = [];
  const totals = { ...ZERO_TOKENS };
  const addTokens = (raw: unknown): void => {
    const usage =
      raw !== null && typeof raw === "object"
        ? (raw as { readonly usage?: Record<string, unknown> }).usage
        : undefined;
    if (usage === undefined) return;
    totals.tokens_in += Number(usage.prompt_tokens ?? 0) || 0;
    totals.tokens_out += Number(usage.completion_tokens ?? 0) || 0;
  };
  const recordOnce = (status: TRequestStatus): void =>
    report(
      {
        model: hop.modelId,
        provider: hop.provider,
        status,
        latency_ms: Date.now() - args.startedAt,
        endpoint: args.endpoint,
        ...(acquired.accountHash !== null
          ? { account_hash: acquired.accountHash }
          : {}),
        ...totals,
      },
      args.originParam,
    );

  for (let round = 0; ; round++) {
    const resp = await postWithDecryptRetry(
      acquired.url,
      acquired.headers,
      body,
      wire,
      finalHop,
      args.req.signal,
    );
    // Round 0 keeps `serveSubscription`'s walk semantics (nothing consumed
    // yet). A LATER round already burned echo rounds + tokens on this hop —
    // walking to another provider would silently discard that usage and
    // re-run the whole conversation, so surface the continuation failure
    // instead and record what was consumed.
    if (resp === null) {
      if (round === 0) return "retry";
      recordOnce("error");
      return errorJson(
        502,
        "kimi built-in web search: continuation round failed (network)",
      );
    }
    if (!resp.ok) {
      const raw = await resp.text().catch(() => "");
      if (
        round === 0 &&
        !finalHop &&
        classifyPrecommitResponse(
          resp.status,
          raw,
          wire,
          args.req.signal.aborted,
        ).kind === "transient"
      ) {
        return "retry";
      }
      recordOnce(statusFor(resp.status));
      return new Response(raw.length > 0 ? raw : null, {
        status: resp.status,
        headers: passthroughHeaders(resp),
      });
    }
    const text = await resp.text();
    let rawJson: unknown;
    try {
      rawJson = JSON.parse(text);
    } catch {
      recordOnce("error");
      return new Response(text, {
        status: resp.status,
        headers: passthroughHeaders(resp),
      });
    }
    addTokens(rawJson);

    const builtinCalls = kimiBuiltinSearchCalls(rawJson);
    // Round ceiling: a model STILL searching at the cap cannot be decoded as
    // a final answer (its builtin tool_calls would fail the canonical decode
    // and leak raw kimi JSON to the client) — fail explicitly instead.
    if (builtinCalls !== null && round >= KIMI_SEARCH_MAX_ROUNDS) {
      recordOnce("error");
      return errorJson(
        502,
        `kimi built-in web search exceeded the round limit (${KIMI_SEARCH_MAX_ROUNDS})`,
      );
    }
    if (builtinCalls === null) {
      // FINAL round — decode canonically, attach the executed searches, and
      // re-encode for the client.
      let canonical: TChatCompletionResponse;
      try {
        canonical = decodeUpstreamJson(wire, rawJson, hop.providerModelId);
      } catch {
        recordOnce("error");
        return new Response(text, {
          status: resp.status,
          headers: passthroughHeaders(resp),
        });
      }
      const choice = canonical.choices[0];
      const final: TChatCompletionResponse =
        executed.length > 0 && choice !== undefined
          ? {
              ...canonical,
              usage: {
                ...canonical.usage,
                prompt_tokens: totals.tokens_in,
                completion_tokens: totals.tokens_out,
                total_tokens: totals.tokens_in + totals.tokens_out,
              },
              choices: [
                {
                  ...choice,
                  message: {
                    ...choice.message,
                    server_search_calls: executed,
                  },
                },
                ...canonical.choices.slice(1),
              ],
            }
          : canonical;
      recordOnce(statusFor(resp.status));
      if (clientWantsStream) {
        const bytes = sseBytesForClient(
          responseToChunkStream(final),
          args.surface,
          clientWire,
        );
        return new Response(
          withFrameAlignedHeartbeat(bytes, heartbeatOptionsFor(args.surface)),
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
      return new Response(
        JSON.stringify(jsonBodyForClient(final, args.surface, clientWire)),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    // Echo round: report each server-executed search (query is opaque to
    // this box) and feed the arguments back verbatim.
    for (const call of builtinCalls) {
      executed.push({ id: call.id, query: "" });
    }
    body = {
      ...body,
      messages: [
        ...((body.messages as unknown[] | undefined) ?? []),
        ...kimiSearchEchoMessages(rawJson, builtinCalls),
      ],
    };
  }
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

  // Canonical view of the inbound for native-runtime eligibility and encoding.
  const canonical = canonicalFromInbound(args.surface, args.rawBody);
  const baseEstimate = estimateBodyTokens(args.rawBody);

  let lastError: string | null = null;
  for (const [hopIndex, hop] of hops.entries()) {
    const finalHop = hopIndex === hops.length - 1;
    // ── Context-overflow ladder, per hop (shared with the cloud chain —
    // `fitRequestToHopBudget`) ────────────────────────────────────────
    // Plan A already happened (the catalog served correct budgets; the
    // client should have compacted). When the request still exceeds THIS
    // hop's input budget: Plan B — compact tool outputs until it fits;
    // only when even full compaction can't fit does Plan C apply — walk
    // to the next (larger-context) hop. The final hop serves the
    // best-effort compacted body regardless (never-drop-all), and the
    // pre-output overflow walk below remains the backstop for estimate
    // misses.
    let hopArgs = args;
    let hopCanonical = canonical;
    const fit = fitRequestToHopBudget({
      surface: args.surface,
      body: args.rawBody,
      estimatedTokens: baseEstimate,
      inputTokenLimit:
        lookupCatalogEntry(hop.modelId)?.input_token_limit ?? null,
      finalHop,
    });
    if (fit.kind === "skip") {
      lastError = `hop ${hop.modelId} skipped: ~${baseEstimate}-token request exceeds its input window even after tool-output compaction`;
      continue;
    }
    if (fit.changed) {
      hopArgs = {
        ...args,
        rawBody: fit.body,
        rawBytes: new TextEncoder().encode(JSON.stringify(fit.body))
          .buffer as ArrayBuffer,
      };
      hopCanonical = canonicalFromInbound(args.surface, fit.body);
    }
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
        rawBody: hopArgs.rawBody,
        canonical: hopCanonical,
        wantsStream:
          (hopArgs.rawBody as { stream?: unknown } | null)?.stream === true,
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
      const served = await serveSubscription(hop, wire, hopArgs, finalHop);
      if (served !== "retry") return served; // committed
      lastError = `subscription hop ${hop.modelId} failed pre-stream`;
      continue;
    }
    // API-key hop: forward to the cloud pinned to this concrete model.
    let resp: Response;
    try {
      resp = await forwardToCloud(
        args.req,
        hopArgs.rawBytes,
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
