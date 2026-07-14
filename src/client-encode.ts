/**
 * Client-wire encoders — pick the right re-encode for the caller's surface.
 *
 * A committed canonical response/stream must be handed back on the SAME wire
 * the client spoke: `responses` clients get the Responses shape, Anthropic-wire
 * (`messages`) clients get Anthropic, everyone else the OpenAI ChatCompletion
 * shape. This selection was copy-pasted across the walker's manual transport
 * and the native serve/tool bridges (three copies each of the JSON and the SSE
 * ternary) — centralising it here keeps them from drifting.
 */

import type {
  TChatCompletionChunk,
  TChatCompletionResponse,
  THeartbeatOptions,
} from "@quantidexyz/openllmp";
import { toAnthropicMessagesResponse } from "@quantidexyz/openllmw/adapters/messages/response";
import { chunksToMessagesSseBytes } from "@quantidexyz/openllmw/adapters/messages/streaming";
import {
  chunksToResponsesSseBytes,
  toResponsesResponse,
} from "@quantidexyz/openllmw/adapters/responses";
import { chunksToSseBytes } from "@quantidexyz/openllmw/lib/streaming/provider-decode";

export type TClientSurface = "chat_completions" | "messages" | "responses";

/** Frame-aligned heartbeat options for a client surface — ONE literal shared
 *  by the walker's manual transport and the native serve/tool bridges so the
 *  interval + per-surface beat kind can't drift. */
export const heartbeatOptionsFor = (
  surface: TClientSurface,
): THeartbeatOptions => ({
  intervalMs: 15_000,
  kind: surface === "messages" ? "anthropic_ping" : "comment",
});
/** Matches `clientWireOf`'s return (`TUpstreamWire`). Only `anthropic`/`openai`
 *  occur for a real client wire; the `=== "anthropic"` branch handles both. */
export type TClientWire = "anthropic" | "chatgpt" | "openai";

/** Encode a canonical chunk stream to the client's wire as SSE bytes. */
export const sseBytesForClient = (
  chunks: ReadableStream<TChatCompletionChunk>,
  surface: TClientSurface,
  clientWire: TClientWire,
): ReadableStream<Uint8Array> =>
  surface === "responses"
    ? chunksToResponsesSseBytes(chunks)
    : clientWire === "anthropic"
      ? chunksToMessagesSseBytes(chunks)
      : chunksToSseBytes(chunks);

/** Re-encode a canonical response to the client's wire (the JSON body). */
export const jsonBodyForClient = (
  canonical: TChatCompletionResponse,
  surface: TClientSurface,
  clientWire: TClientWire,
): unknown =>
  surface === "responses"
    ? toResponsesResponse(canonical)
    : clientWire === "anthropic"
      ? toAnthropicMessagesResponse(canonical)
      : canonical;
