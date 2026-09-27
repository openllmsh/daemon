/**
 * Codex / ChatGPT bridge request capture (W4).
 *
 * Keeps existing inbound adapters + `runCodexNative` routing. When the
 * selected sub-method is `bridge-capture` for chatgpt, an ISOLATED
 * `codex app-server` child is spawned with the established redirect keys:
 *
 *   -c chatgpt_base_url=<loopback>/backend-api
 *   -c openai_base_url=<loopback>/backend-api/codex
 *
 * The loopback receiver captures the vendor-built `/responses` exchange
 * (HTTP POST or WebSocket — transport is preserved, never forced), suppresses
 * any original external send (no preamble forward / no egress), hands the
 * immutable envelope to the daemon for a single dispatch, and settles the
 * builder via `turn/interrupt` + authoritative `turn/completed`.
 *
 * Warm `thread/inject_items` continuation is intentionally NOT claimed here:
 * schema existence is established offline, but interrupt→inject→next-turn
 * parity is unproven. Cold / isolated builders only.
 */

import type { TChatCompletionChunk } from "@openllmsh/protocol";
import { decodeProviderEventStream } from "@openllmsh/wire/lib/streaming/provider-decode";
import type { TChatGptStreamEvent } from "@openllmsh/wire/providers/chatgpt/streaming";
import {
  chatGptEventToChunk,
  isChatGptResponsesTerminalEvent,
  newChatGptStreamState,
} from "@openllmsh/wire/providers/chatgpt/streaming";
import { Schema } from "effect";
import type { TCodexNativeParams } from "./codex-app-server";
import {
  codexBaseStartParams,
  createIsolatedCodexAppServerClient,
  effortOf,
} from "./codex-app-server";
import type {
  TBuilderSettlement,
  TCaptureDestinationPolicy,
  TCapturedHeaderPair,
  TCapturedRequestEnvelope,
  TCaptureTransport,
  TRequestCaptureSession,
} from "./request-capture";
import {
  createRequestCaptureSession,
  headersInitFromCaptured,
  preserveCapturedHeaders,
  requestFromCapturedEnvelope,
  runCapturedDispatch,
} from "./request-capture";
import type { TNativeRunResult } from "./types";
import { PRE_COMMIT_TIMEOUT_MS } from "./types";

/** External origin the daemon may dispatch to (production ChatGPT backend). */
export const CODEX_CAPTURE_EXTERNAL_ORIGIN = "https://chatgpt.com";

/** Canonical Responses URL the vendor intends under ChatGPT auth. */
export const CODEX_CAPTURE_EXTERNAL_RESPONSES_URL =
  "https://chatgpt.com/backend-api/codex/responses";

const ChatGptStreamEventSchema: Schema.Schema<TChatGptStreamEvent> =
  Schema.Record({ key: Schema.String, value: Schema.Unknown });

export type TCodexCaptureRedirectArgs = {
  readonly chatgptBaseUrl: string;
  readonly openaiBaseUrl: string;
  /** Argv fragment: `["-c", "chatgpt_base_url=…", "-c", "openai_base_url=…"]`. */
  readonly argv: readonly string[];
};

/**
 * Build the existing redirect recipe for `codex app-server` (same keys the
 * `codex exec` capture path already uses in `delegation/auth-config.ts`).
 */
export const codexCaptureRedirectArgs = (
  loopbackBase: string,
): TCodexCaptureRedirectArgs => {
  const base = loopbackBase.replace(/\/+$/, "");
  const chatgptBaseUrl = `${base}/backend-api`;
  const openaiBaseUrl = `${base}/backend-api/codex`;
  return {
    chatgptBaseUrl,
    openaiBaseUrl,
    argv: [
      "-c",
      `chatgpt_base_url=${chatgptBaseUrl}`,
      "-c",
      `openai_base_url=${openaiBaseUrl}`,
    ],
  };
};

export const codexCaptureDestinationPolicy = (opts?: {
  readonly allowLoopback?: boolean;
}): TCaptureDestinationPolicy => ({
  allowedOrigins: new Set([CODEX_CAPTURE_EXTERNAL_ORIGIN]),
  allowLoopback: opts?.allowLoopback === true,
});

/** Match the inference call only — preamble paths are stubbed locally. */
export const isCodexCaptureInferencePath = (pathname: string): boolean =>
  pathname.endsWith("/responses");

/**
 * Remap a loopback-observed URL back to the external chatgpt.com authority
 * while preserving path + query. Application headers/body are untouched.
 */
export const remapCodexObservedUrlToExternal = (
  observedUrl: string,
): string => {
  const url = new URL(observedUrl);
  return `${CODEX_CAPTURE_EXTERNAL_ORIGIN}${url.pathname}${url.search}`;
};

const localSettlementHttpResponse = (): Response =>
  new Response(null, { status: 204 });

type TWsCaptureData = {
  readonly headers: ReadonlyArray<TCapturedHeaderPair>;
  readonly observedUrl: string;
  bodyChunks: Uint8Array[];
  offered: boolean;
};

export type TCodexCaptureReceiver = {
  readonly baseUrl: string;
  readonly stop: () => void;
  /** Count of `/responses` offers accepted into the session (0 or 1). */
  readonly capturedCount: () => number;
  /**
   * Count of times the receiver would have forwarded off-box. Always 0 by
   * construction — non-inference traffic is stubbed locally.
   */
  readonly originalExternalSendCount: () => number;
  /** Extra `/responses` attempts after the first capture (WS→HTTP fallback). */
  readonly suppressedRetryCount: () => number;
};

export type TStartCodexCaptureReceiverOptions = {
  readonly session: TRequestCaptureSession;
  readonly signal?: AbortSignal;
};

/**
 * Loopback HTTP + WebSocket receiver. Captures the first `/responses`
 * inference offer (either transport), settles the builder locally, and NEVER
 * forwards to chatgpt.com. Subsequent `/responses` attempts (e.g. WS→HTTP
 * fallback after a captured WS offer) receive the same local settlement
 * without a second `captureSend` / daemon dispatch.
 */
export const startCodexCaptureReceiver = (
  opts: TStartCodexCaptureReceiverOptions,
): TCodexCaptureReceiver => {
  let capturedCount = 0;
  let suppressedRetryCount = 0;
  let builderSettlement: TBuilderSettlement | null = null;

  const offerEnvelope = async (
    envelope: TCapturedRequestEnvelope,
  ): Promise<TBuilderSettlement> => {
    if (capturedCount > 0) {
      suppressedRetryCount += 1;
      return (
        builderSettlement ?? {
          kind: "suppressed",
          reason: "codex capture already owns this turn; retry suppressed",
        }
      );
    }
    capturedCount += 1;
    const settlement = await opts.session.captureSend(envelope);
    builderSettlement = settlement;
    return settlement;
  };

  const offerFromHttp = async (req: Request): Promise<Response> => {
    const observedUrl = req.url;
    const headers = preserveCapturedHeaders(req.headers);
    const bodyBuf = await req.arrayBuffer();
    const body = bodyBuf.byteLength === 0 ? null : new Uint8Array(bodyBuf);
    await offerEnvelope({
      transport: "http",
      method: req.method,
      observedUrl,
      externalUrl: remapCodexObservedUrlToExternal(observedUrl),
      headers,
      body,
      framing: null,
    });
    return localSettlementHttpResponse();
  };

  const server = Bun.serve<TWsCaptureData>({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req, srv): Response | undefined | Promise<Response> {
      if (opts.signal?.aborted) {
        return new Response(null, { status: 499 });
      }
      const url = new URL(req.url);
      const inference = isCodexCaptureInferencePath(url.pathname);
      const wantsUpgrade =
        req.headers.get("upgrade")?.toLowerCase() === "websocket";

      if (inference && wantsUpgrade) {
        const upgraded = srv.upgrade(req, {
          data: {
            headers: preserveCapturedHeaders(req.headers),
            observedUrl: req.url,
            bodyChunks: [],
            offered: false,
          },
        });
        return upgraded
          ? undefined
          : new Response("websocket upgrade failed", { status: 400 });
      }

      if (inference) {
        return offerFromHttp(req);
      }

      // Preamble / non-inference: local stub ONLY — never forward off-box.
      return new Response(null, { status: 204 });
    },
    websocket: {
      message(ws, message): void {
        if (ws.data.offered) return;
        const chunk =
          typeof message === "string"
            ? new TextEncoder().encode(message)
            : message instanceof Uint8Array
              ? message
              : new Uint8Array(message);
        ws.data.bodyChunks.push(chunk);
        // Offer on the first data frame — Responses WS carries the request
        // payload as the initial client message. Further frames (if any) are
        // ignored for capture; the daemon owns the exchange after this.
        ws.data.offered = true;
        const total = ws.data.bodyChunks.reduce((n, c) => n + c.byteLength, 0);
        const body = new Uint8Array(total);
        let offset = 0;
        for (const c of ws.data.bodyChunks) {
          body.set(c, offset);
          offset += c.byteLength;
        }
        void offerEnvelope({
          transport: "websocket",
          method: "GET",
          observedUrl: ws.data.observedUrl,
          externalUrl: remapCodexObservedUrlToExternal(ws.data.observedUrl),
          headers: ws.data.headers,
          body,
          framing: {
            entries: {
              protocol: "responses-websocket",
              upgrade: true,
            },
          },
        }).finally(() => {
          // Local settlement: close without feeding a model response.
          try {
            ws.close(1000, "capture-suppressed");
          } catch {
            // already closed
          }
        });
      },
      close(ws): void {
        // Upgrade-without-body (failed WS before payload): leave the session
        // open so an HTTP fallback can still offer once.
        if (!ws.data.offered && ws.data.bodyChunks.length === 0) return;
      },
    },
  });

  const baseUrl = `http://127.0.0.1:${server.port}`;

  const stop = (): void => {
    try {
      server.stop(true);
    } catch {
      // already stopped
    }
  };

  opts.signal?.addEventListener(
    "abort",
    () => {
      stop();
    },
    { once: true },
  );

  return {
    baseUrl,
    stop,
    capturedCount: (): number => capturedCount,
    originalExternalSendCount: (): number => 0,
    suppressedRetryCount: (): number => suppressedRetryCount,
  };
};

const concatBytes = (chunks: readonly Uint8Array[]): Uint8Array => {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
};

/**
 * Dispatch a captured Codex envelope. HTTP uses `fetch` with the preserved
 * Request. WebSocket keeps the WS transport (never coerced to HTTP POST):
 * opens the external URL, sends the captured body frame, marks accept on
 * open, and wraps inbound text frames as an SSE-shaped Response body so the
 * existing Responses decoder can run when the upstream speaks SSE-over-WS
 * or plain JSON event frames.
 */
export const createCodexCapturedDispatchSender = (args: {
  readonly session: TRequestCaptureSession;
  readonly fetchImpl?: typeof fetch;
}): ((
  request: Request,
  envelope: TCapturedRequestEnvelope,
  signal: AbortSignal,
) => Promise<Response>) => {
  const fetchImpl = args.fetchImpl ?? fetch;
  return async (request, envelope, signal): Promise<Response> => {
    if (envelope.transport === "http") {
      return await fetchImpl(request, { signal });
    }

    if (envelope.transport !== "websocket") {
      throw new Error(
        `codex capture: unsupported transport ${envelope.transport}`,
      );
    }

    const wsUrl = (() => {
      const u = new URL(envelope.externalUrl);
      u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
      return u.toString();
    })();

    const headerObj: Record<string, string> = {};
    for (const [name, value] of envelope.headers) {
      if (name.toLowerCase() === "host") continue;
      if (name.toLowerCase() === "upgrade") continue;
      if (name.toLowerCase() === "connection") continue;
      if (name.toLowerCase() === "sec-websocket-key") continue;
      if (name.toLowerCase() === "sec-websocket-version") continue;
      if (name.toLowerCase() === "sec-websocket-extensions") continue;
      headerObj[name] = value;
    }

    // lib.dom only models the protocol overload; Bun accepts custom headers.
    // Same local ctor cast as `audio/claude-ws.ts` / `cli/clients/attach.ts`.
    type TBunWebSocketCtor = new (
      url: string,
      options?: { readonly headers?: Readonly<Record<string, string>> },
    ) => WebSocket;
    const ws = new (WebSocket as unknown as TBunWebSocketCtor)(wsUrl, {
      headers: headerObj,
    });
    ws.binaryType = "arraybuffer";

    const inbound: Uint8Array[] = [];
    let wake: (() => void) | null = null;
    let closed = false;
    let openErr: Error | null = null;

    const wait = (): Promise<void> =>
      new Promise<void>((resolve) => {
        wake = resolve;
      });

    const notify = (): void => {
      wake?.();
      wake = null;
    };

    const opened = new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => {
        args.session.markUpstreamAccepted();
        resolve();
      });
      ws.addEventListener("error", () => {
        openErr = new Error("codex capture websocket failed before open");
        reject(openErr);
      });
    });

    ws.addEventListener("message", (ev) => {
      if (typeof ev.data === "string") {
        inbound.push(new TextEncoder().encode(ev.data));
      } else if (ev.data instanceof ArrayBuffer) {
        inbound.push(new Uint8Array(ev.data));
      } else if (ev.data instanceof Uint8Array) {
        inbound.push(ev.data);
      }
      notify();
    });
    ws.addEventListener("close", () => {
      closed = true;
      notify();
    });
    ws.addEventListener("error", () => {
      closed = true;
      notify();
    });

    const onAbort = (): void => {
      try {
        ws.close();
      } catch {
        // ignore
      }
    };
    signal.addEventListener("abort", onAbort, { once: true });

    try {
      await opened;
      if (envelope.body !== null && envelope.body.byteLength > 0) {
        ws.send(new Uint8Array(envelope.body));
      }

      // Collect until the peer closes (fake upstream finishes the turn).
      while (!closed) {
        await wait();
      }

      const bytes = concatBytes(inbound);
      // Present as text/event-stream when the payload already looks like SSE;
      // otherwise wrap each JSON object line as `data: …` so the shared
      // Responses decoder can run. Exact native WS framing remains a live
      // validation gap — hermetic fakes speak JSON/SSE-compatible frames.
      const text = new TextDecoder().decode(bytes);
      const looksSse = text.includes("data:");
      const sseBody = looksSse
        ? bytes
        : new TextEncoder().encode(
            `${text
              .split(/\r?\n/)
              .map((line) => line.trim())
              .filter((line) => line.length > 0)
              .map((line) => `data: ${line}\n\n`)
              .join("")}data: [DONE]\n\n`,
          );

      return new Response(new Uint8Array(sseBody), {
        status: 200,
        headers: {
          "content-type": "text/event-stream",
        },
      });
    } finally {
      signal.removeEventListener("abort", onAbort);
      try {
        ws.close();
      } catch {
        // ignore
      }
    }
  };
};

const decodeCodexUpstreamResponse = (
  response: Response,
  providerModelId: string,
): ReadableStream<TChatCompletionChunk> => {
  if (response.body === null) {
    return new ReadableStream<TChatCompletionChunk>({
      start(controller) {
        controller.close();
      },
    });
  }
  return decodeProviderEventStream(
    response.body,
    {
      eventSchema: ChatGptStreamEventSchema,
      initialState: newChatGptStreamState,
      eventToChunk: chatGptEventToChunk,
      isTerminalEvent: isChatGptResponsesTerminalEvent,
    },
    { providerModelId },
  );
};

export type TCodexCapturedTurnHandles = {
  readonly receiver: TCodexCaptureReceiver;
  readonly session: TRequestCaptureSession;
  readonly client: ReturnType<typeof createIsolatedCodexAppServerClient>;
  readonly threadId: string;
  readonly turnId: string | null;
  dispose(): void;
};

/**
 * Interrupt the isolated turn and wait for an authoritative terminal
 * (`turn/completed`). Kill is NOT used as settlement proof.
 */
export const settleCodexCaptureTurn = async (args: {
  readonly client: {
    request(method: string, params: unknown): Promise<unknown>;
    addSink(sink: {
      readonly threadId: string;
      onDelta: (text: string) => void;
      onAgentMessage: (text: string) => void;
      onUsage: (usage: unknown) => void;
      onCompleted: (status: string, errorMessage: string | null) => void;
    }): void;
    removeSink(threadId: string): void;
  };
  readonly threadId: string;
  readonly turnId: string | null;
  readonly timeoutMs?: number;
}): Promise<{ readonly status: string; readonly error: string | null }> => {
  let status = "interrupted";
  let error: string | null = null;
  let done!: () => void;
  const finished = new Promise<void>((resolve) => {
    done = resolve;
  });

  args.client.addSink({
    threadId: args.threadId,
    onDelta: () => {},
    onAgentMessage: () => {},
    onUsage: () => {},
    onCompleted: (s, e) => {
      status = s;
      error = e;
      done();
    },
  });

  if (args.turnId !== null) {
    try {
      await args.client.request("turn/interrupt", {
        threadId: args.threadId,
        turnId: args.turnId,
      });
    } catch {
      // interrupt is best-effort; we still wait for terminal / timeout
    }
  }

  const timeoutMs = args.timeoutMs ?? 5_000;
  await Promise.race([
    finished,
    new Promise<void>((resolve) => {
      setTimeout(resolve, timeoutMs);
    }),
  ]);
  args.client.removeSink(args.threadId);
  return { status, error };
};

/**
 * Isolated capture text route: vendor constructs the authenticated envelope
 * against loopback; daemon dispatches once; builder is interrupted locally;
 * true upstream bytes are decoded with the existing Responses helpers.
 *
 * Callers enter this only when the selected sub-method is `bridge-capture`
 * and readiness admits chatgpt ({@link runCodexNative} with `bridgeCapture`).
 */
export const runCodexCapturedTextTurn = async (
  params: TCodexNativeParams,
): Promise<TNativeRunResult> => {
  const session = createRequestCaptureSession({
    destinationPolicy: codexCaptureDestinationPolicy({
      // Hermetic tests remap externalUrl to loopback via a custom sender;
      // production policy rejects non-chatgpt.com. Tests pass allowLoopback
      // destinations by rewriting externalUrl in the fake builder path —
      // the receiver always remaps to chatgpt.com; the dispatch sender in
      // tests overrides fetch to a loopback fake upstream.
      allowLoopback: false,
    }),
    signal: params.signal,
    captureTimeoutMs: params.precommitMs ?? PRE_COMMIT_TIMEOUT_MS,
  });

  const receiver = startCodexCaptureReceiver({
    session,
    signal: params.signal,
  });
  const redirects = codexCaptureRedirectArgs(receiver.baseUrl);
  const client = createIsolatedCodexAppServerClient(params.bin, params.env, {
    spawnArgvExtra: redirects.argv,
  });

  let threadId: string | null = null;
  let turnId: string | null = null;
  let captureOwnership: "none" | "accepted" | "uncertain" = "none";

  const disposeAll = (): void => {
    try {
      session.dispose();
    } catch {
      // ignore
    }
    receiver.stop();
    client.dispose();
  };

  try {
    await client.ensureStarted();
    const startParams = codexBaseStartParams(
      params.providerModelId,
      params.systemText,
    );
    // Capture path always starts a FRESH isolated thread — do not resume the
    // shared warm map's thread ids (history injection unproven).
    const opened = (await client.request("thread/start", startParams)) as {
      thread?: { id?: string };
    };
    if (typeof opened.thread?.id !== "string") {
      disposeAll();
      return {
        kind: "declined",
        reason: "codex capture thread/start returned no thread id",
      };
    }
    threadId = opened.thread.id;

    const effort = effortOf(params.reasoningEffort);
    const turn = (await client.request("turn/start", {
      threadId,
      input: [{ type: "text", text: params.userText, text_elements: [] }],
      ...(effort !== null ? { effort } : {}),
    })) as { turn?: { id?: string } };
    turnId = typeof turn.turn?.id === "string" ? turn.turn.id : null;

    if (params.signal.aborted) {
      if (turnId !== null) {
        await settleCodexCaptureTurn({ client, threadId, turnId });
      }
      disposeAll();
      return { kind: "declined", reason: "client aborted" };
    }

    const sender = createCodexCapturedDispatchSender({ session });
    const dispatched = await runCapturedDispatch({
      session,
      sender,
      signal: params.signal,
      suppressReason:
        "codex original external send suppressed; daemon owns the exchange",
    });
    captureOwnership = "accepted";
    // Builder settlement: interrupt + authoritative terminal. Do NOT treat
    // process kill as proof of graceful reuse.
    const terminal = await settleCodexCaptureTurn({
      client,
      threadId,
      turnId,
    });

    const chunks = decodeCodexUpstreamResponse(
      dispatched.response,
      params.providerModelId,
    );

    // Capture the thread id for sessionId(); the isolated client is disposed
    // after the stream cancels/closes.
    const capturedThreadId = threadId;
    const stream = new ReadableStream<TChatCompletionChunk>({
      async start(controller) {
        const reader = chunks.getReader();
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            controller.enqueue(value);
          }
          controller.close();
        } catch (err) {
          controller.error(err);
        } finally {
          reader.releaseLock();
          disposeAll();
        }
      },
      cancel() {
        disposeAll();
      },
    });

    // Surface interrupt status only as diagnostics — the caller stream is the
    // daemon-owned upstream decode, not the builder's (empty) view.
    void terminal;

    return {
      kind: "committed",
      chunks: stream,
      sessionId: () => capturedThreadId,
    };
  } catch (error) {
    if (threadId !== null) {
      try {
        await settleCodexCaptureTurn({
          client,
          threadId,
          turnId,
          timeoutMs: 1_000,
        });
      } catch {
        // best-effort
      }
    }
    if (captureOwnership === "none" && session.dispatchStarted()) {
      captureOwnership = session.upstreamAccepted() ? "accepted" : "uncertain";
    }
    disposeAll();
    return {
      kind: "declined",
      reason: error instanceof Error ? error.message : String(error),
      ...(captureOwnership !== "none" ? { captureOwnership } : {}),
    };
  }
};

/** Test/helper: build a Request from a captured envelope (HTTP path). */
export const codexHttpRequestFromCaptured = (
  envelope: TCapturedRequestEnvelope,
): Request => requestFromCapturedEnvelope(envelope);

/** Test/helper: rebuild headers without stripping auth. */
export const codexHeadersFromCaptured = (
  pairs: ReadonlyArray<TCapturedHeaderPair>,
): Headers => headersInitFromCaptured(pairs, { dropHost: true });

export type { TCaptureTransport };
