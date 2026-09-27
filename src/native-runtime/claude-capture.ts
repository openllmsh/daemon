/**
 * Claude Code text request-capture adapter (W2).
 *
 * After existing routing / transforms, the same `claude -p` builder constructs
 * the authenticated Anthropic Messages request. This module:
 *
 *   1. applies `ANTHROPIC_BASE_URL` to a private loopback recorder **after**
 *      `cleanNativeSpawnEnv` (never before — poison cleaning must win first),
 *   2. captures the FULL application headers + body (not the identity-filtered
 *      auth-config fixture),
 *   3. never forwards preamble traffic to the real vendor (no auth leak),
 *   4. suppresses the original external inference send,
 *   5. lets the daemon dispatch that envelope once,
 *   6. decodes the TRUE upstream response with `decodeAnthropicEventStream`
 *      (no request/response rebuild),
 *   7. settles the text `-p` builder locally.
 *
 * Text settlement is explicitly **unproven** as warm-builder reuse: returning
 * HTTP 204 (and/or killing the process) is local ownership transfer only — it
 * is NOT evidence of graceful SDK interrupt / reusable session state. Prefer
 * documented SDK `interrupt()` on the tool/Agent-SDK path when that path is
 * later proven; do not treat this text settlement as that proof.
 *
 * Tool capture is **not** proven here. Keep `claude-tool-session.ts` on today's
 * bridge path and surface {@link CLAUDE_TOOL_CAPTURE_STATUS}.
 *
 * Default off via `request-capture-config.ts`. This module does not edit
 * `serve.ts` / `walker.ts` / shared capture files / session-store.
 */

import { existsSync } from "node:fs";
import type {
  TChatCompletionChunk,
  TChatCompletionRequest,
} from "@openllmsh/protocol";
import { isRefusalChunk } from "@openllmsh/wire/lib/refusal";
import { isMeaningfulChunk } from "@openllmsh/wire/lib/streaming/peek";
import { decodeAnthropicEventStream } from "@openllmsh/wire/providers/anthropic/streaming";
import { defaultUpstreamUrl } from "../delegation/auth-config";
import { spawnCwd } from "../delegation/util";
import { logError, safeDiagnosticMessage } from "../logger";
import { sandboxSpawnArgs } from "../sandbox/exec";
import { unwrapKeychainSpawn } from "../sandbox/policy";
import type {
  TBuilderSettlement,
  TCaptureDestinationPolicy,
  TCapturedDispatchSender,
  TCapturedHeaderPair,
  TCapturedRequestEnvelope,
  TRequestCaptureSession,
  TRunCapturedDispatchResult,
} from "./request-capture";
import {
  createRequestCaptureSession,
  preserveCapturedHeaders,
  runCapturedDispatch,
} from "./request-capture";
import type { TNativeRunResult } from "./types";
import {
  cleanNativeSpawnEnv,
  PRE_COMMIT_TIMEOUT_MS,
  unsupportedNativeControl,
} from "./types";

/** Trusted Anthropic Messages origin — dispatch target, never the loopback host. */
export const CLAUDE_CAPTURE_TRUSTED_ORIGIN = new URL(
  defaultUpstreamUrl("claude_code"),
).origin;

/** Default external Messages URL the daemon dispatches to. */
export const CLAUDE_CAPTURE_EXTERNAL_MESSAGES_URL =
  defaultUpstreamUrl("claude_code");

/**
 * Tool capture is unproven on this branch. Callers must keep the existing
 * SDK/tool bridge (`claude-tool-session.ts`) when tools are present.
 */
export const CLAUDE_TOOL_CAPTURE_STATUS = {
  proven: false,
  label:
    "tool capture unproven — preserve existing SDK/tool bridge path; text-only capture only",
} as const;

/**
 * Local settlement of the text `-p` builder. `unproven_text_settlement` means
 * the original external send was suppressed and the process was settled
 * locally (typically HTTP 204). That is NOT proof of graceful warm reuse or
 * of the Agent SDK interrupt handshake.
 */
export type TClaudeTextSettlementKind =
  | "unproven_text_settlement"
  | "cancelled"
  | "failed";

export type TClaudeCaptureDiagnostics = {
  readonly textSettlement: TClaudeTextSettlementKind | null;
  readonly toolCapture: typeof CLAUDE_TOOL_CAPTURE_STATUS;
  readonly daemonDispatchCount: number;
  /** Preamble requests forwarded to the real vendor — must stay 0. */
  readonly preambleExternalForwards: 0;
  readonly capturedEnvelope: TCapturedRequestEnvelope | null;
};

export type TClaudeCaptureAdapterResult = {
  readonly run: TNativeRunResult;
  readonly diagnostics: TClaudeCaptureDiagnostics;
};

export const isClaudeMessagesInferencePath = (pathname: string): boolean =>
  pathname.endsWith("/v1/messages");

export const claudeCaptureDestinationPolicy = (opts?: {
  readonly allowLoopback?: boolean;
}): TCaptureDestinationPolicy => ({
  allowedOrigins: new Set([CLAUDE_CAPTURE_TRUSTED_ORIGIN]),
  allowLoopback: opts?.allowLoopback === true,
});

/**
 * Apply the loopback redirect AFTER env cleaning. Callers must pass the result
 * of `cleanNativeSpawnEnv` (or an equivalent cleaned map) — never raw ambient
 * env — so a pre-clean `ANTHROPIC_BASE_URL` cannot survive.
 */
export const withClaudeCaptureBaseUrl = (
  cleanedEnv: Record<string, string>,
  loopbackBase: string,
): Record<string, string> => ({
  ...cleanedEnv,
  ANTHROPIC_BASE_URL: loopbackBase,
});

const settlementKindOf = (
  settlement: TBuilderSettlement,
): TClaudeTextSettlementKind => {
  if (settlement.kind === "cancelled") return "cancelled";
  if (settlement.kind === "failed") return "failed";
  return "unproven_text_settlement";
};

const httpStatusForSettlement = (settlement: TBuilderSettlement): number => {
  if (settlement.kind === "cancelled") return 499;
  if (settlement.kind === "failed") return 502;
  // 204 = local ownership transfer for the text builder. Unproven as graceful
  // warm-session settlement — see TClaudeTextSettlementKind.
  return 204;
};

export type TClaudeCaptureLoopback = {
  readonly baseUrl: string;
  readonly stop: () => void;
};

/**
 * Private loopback recorder for Claude Messages capture.
 *
 * Inference (`…/v1/messages`): full headers+body → `session.captureSend`, then
 * a local settlement status (never the true upstream body).
 *
 * Preamble / other paths: synthetic local JSON 200. Never forwards to the
 * trusted origin (no authorization leak onto the public network).
 */
export const startClaudeCaptureLoopback = (args: {
  readonly session: TRequestCaptureSession;
  readonly onSettlement?: (kind: TClaudeTextSettlementKind) => void;
}): TClaudeCaptureLoopback => {
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);
      if (!isClaudeMessagesInferencePath(url.pathname)) {
        return new Response("{}", {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      const method = req.method.toUpperCase();
      const rawBody =
        method === "GET" || method === "HEAD"
          ? null
          : new Uint8Array(await req.arrayBuffer());
      const body = rawBody !== null && rawBody.byteLength > 0 ? rawBody : null;
      const headers: ReadonlyArray<TCapturedHeaderPair> =
        preserveCapturedHeaders(req.headers);
      const externalUrl = `${CLAUDE_CAPTURE_TRUSTED_ORIGIN}${url.pathname}${url.search}`;
      const envelope: TCapturedRequestEnvelope = {
        transport: "http",
        method,
        observedUrl: url.toString(),
        externalUrl,
        headers,
        body,
        framing: null,
      };

      try {
        const settlement = await args.session.captureSend(envelope);
        args.onSettlement?.(settlementKindOf(settlement));
        return new Response(null, {
          status: httpStatusForSettlement(settlement),
        });
      } catch (err) {
        args.onSettlement?.("failed");
        const message = err instanceof Error ? err.message : String(err);
        return new Response(JSON.stringify({ error: message }), {
          status: 500,
          headers: { "content-type": "application/json" },
        });
      }
    },
  });

  return {
    baseUrl: `http://127.0.0.1:${server.port}`,
    stop: (): void => {
      server.stop(true);
    },
  };
};

/**
 * Text-capture spawn params. Mirrors `TClaudeNativeParams` without a runtime
 * import cycle against `claude-native.ts`.
 */
export type TClaudeTextCaptureParams = {
  readonly bin: string;
  readonly env: Record<string, string>;
  readonly providerModelId: string;
  readonly systemText: string | null;
  readonly userText: string;
  readonly resumeSessionId: string | null;
  readonly signal: AbortSignal;
  /** Daemon-owned upstream sender (tests inject a mock; never omit in hermetic runs). */
  readonly captureSender: TCapturedDispatchSender;
  /** Hermetic tests set true so dispatch may target loopback fakes. */
  readonly allowLoopbackDestinations?: boolean;
  readonly captureTimeoutMs?: number;
  readonly maxBodyBytes?: number;
};

const emptyDiagnostics = (): TClaudeCaptureDiagnostics => ({
  textSettlement: null,
  toolCapture: CLAUDE_TOOL_CAPTURE_STATUS,
  daemonDispatchCount: 0,
  preambleExternalForwards: 0,
  capturedEnvelope: null,
});

/**
 * Decline unsupported generation controls before any loopback/upstream work.
 * Reuses the shared native gate — does not expand handrolled eligibility.
 */
export const declineClaudeCaptureForUnsupportedControls = (
  canonical: TChatCompletionRequest,
): string | null => unsupportedNativeControl(canonical);

const killProc = (proc: ReturnType<typeof Bun.spawn>): void => {
  try {
    proc.kill("SIGTERM");
  } catch {
    // already exited
  }
};

/**
 * Decode the daemon-owned Anthropic upstream response into canonical chunks
 * via the existing wire helper — never rebuild system/tools/history.
 */
export const chunksFromCapturedAnthropicResponse = (
  response: Response,
  providerModelId: string,
): ReadableStream<TChatCompletionChunk> => {
  const body = response.body;
  if (body === null) {
    return new ReadableStream<TChatCompletionChunk>({
      start(controller) {
        controller.close();
      },
    });
  }
  return decodeAnthropicEventStream(body, { providerModelId });
};

const commitFromChunkStream = async (args: {
  readonly chunks: ReadableStream<TChatCompletionChunk>;
  readonly signal: AbortSignal;
  readonly kill: () => void;
  readonly sessionId: () => string | null;
}): Promise<TNativeRunResult> => {
  const reader = args.chunks.getReader();
  const buffered: TChatCompletionChunk[] = [];

  const pump = async (): Promise<
    | { kind: "meaningful"; chunk: TChatCompletionChunk }
    | { kind: "exit" }
    | { kind: "error"; reason: string }
  > => {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return { kind: "exit" };
      if (isMeaningfulChunk(value)) {
        if (isRefusalChunk(value)) {
          return {
            kind: "error",
            reason:
              "claude capture upstream refused the request (content filter)",
          };
        }
        return { kind: "meaningful", chunk: value };
      }
      buffered.push(value);
    }
  };

  let precommitTimer: ReturnType<typeof setTimeout> | undefined;
  const first = await Promise.race([
    pump(),
    new Promise<"timeout">((resolve) => {
      precommitTimer = setTimeout(
        () => resolve("timeout"),
        PRE_COMMIT_TIMEOUT_MS,
      );
    }),
  ]);
  clearTimeout(precommitTimer);

  if (first === "timeout" || first.kind === "exit") {
    args.kill();
    void reader.cancel().catch(() => undefined);
    return {
      kind: "declined",
      reason:
        first === "timeout"
          ? "claude capture produced no output before the pre-commit deadline"
          : "claude capture upstream ended before producing output",
    };
  }
  if (first.kind === "error") {
    args.kill();
    void reader.cancel().catch(() => undefined);
    return { kind: "declined", reason: first.reason };
  }

  const firstMeaningful = first.chunk;
  const out = new ReadableStream<TChatCompletionChunk>({
    start(controller) {
      for (const c of buffered) controller.enqueue(c);
      controller.enqueue(firstMeaningful);
    },
    async pull(controller) {
      const { value, done } = await reader.read();
      if (done) {
        controller.close();
        args.kill();
        return;
      }
      controller.enqueue(value);
    },
    cancel() {
      args.kill();
      void reader.cancel().catch(() => undefined);
    },
  });

  return {
    kind: "committed",
    chunks: out,
    sessionId: args.sessionId,
  };
};

/**
 * Text-only capture path: spawn the vendor CLI against a private loopback,
 * capture its Messages envelope, daemon-dispatch once, decode with the
 * Anthropic wire helper, settle the builder locally (unproven warm reuse).
 */
export const runClaudeTextCapture = async (
  params: TClaudeTextCaptureParams,
): Promise<TClaudeCaptureAdapterResult> => {
  const diagnostics = emptyDiagnostics();
  if (!existsSync(params.bin)) {
    return {
      run: { kind: "declined", reason: "claude CLI not installed" },
      diagnostics,
    };
  }

  const session = createRequestCaptureSession({
    destinationPolicy: claudeCaptureDestinationPolicy({
      allowLoopback: params.allowLoopbackDestinations === true,
    }),
    signal: params.signal,
    captureTimeoutMs: params.captureTimeoutMs,
    maxBodyBytes: params.maxBodyBytes,
  });

  let textSettlement: TClaudeTextSettlementKind | null = null;
  const loopback = startClaudeCaptureLoopback({
    session,
    onSettlement: (kind) => {
      textSettlement = kind;
    },
  });

  const cleaned = cleanNativeSpawnEnv(params.env);
  const spawnEnv = withClaudeCaptureBaseUrl(cleaned, loopback.baseUrl);

  const argv = [
    params.bin,
    "-p",
    "--output-format",
    "stream-json",
    "--include-partial-messages",
    "--verbose",
    "--setting-sources",
    "",
    "--strict-mcp-config",
    "--tools",
    "",
    "--max-turns",
    "1",
    "--model",
    params.providerModelId,
    ...(params.resumeSessionId !== null
      ? ["--resume", params.resumeSessionId]
      : params.systemText !== null
        ? ["--system-prompt", params.systemText]
        : []),
  ];

  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = Bun.spawn(
      sandboxSpawnArgs(argv, { probe: unwrapKeychainSpawn("claude_code") }),
      {
        stdin: new TextEncoder().encode(params.userText),
        stdout: "pipe",
        stderr: "pipe",
        cwd: spawnCwd(spawnEnv),
        env: spawnEnv,
      },
    );
  } catch (error) {
    loopback.stop();
    session.dispose();
    return {
      run: {
        kind: "declined",
        reason: `spawn failed: ${error instanceof Error ? error.message : String(error)}`,
      },
      diagnostics,
    };
  }

  const kill = (): void => killProc(proc);
  if (params.signal.aborted) {
    kill();
    loopback.stop();
    session.dispose();
    return {
      run: { kind: "declined", reason: "client aborted" },
      diagnostics: {
        ...diagnostics,
        textSettlement: "cancelled",
      },
    };
  }
  params.signal.addEventListener("abort", kill, { once: true });

  // Best-effort session_id from builder stdout (init line). Answer content
  // comes from the daemon-owned upstream decode — never from the builder.
  let capturedSessionId: string | null = params.resumeSessionId;
  const stdoutTask = (async (): Promise<void> => {
    try {
      const text = await new Response(
        proc.stdout as ReadableStream<Uint8Array>,
      ).text();
      for (const line of text.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.length === 0) continue;
        try {
          const parsed = JSON.parse(trimmed) as { session_id?: unknown };
          if (
            typeof parsed.session_id === "string" &&
            parsed.session_id.length > 0
          ) {
            capturedSessionId = parsed.session_id;
          }
        } catch {
          // non-JSON noise
        }
      }
    } catch {
      // closed/killed
    }
  })();

  let dispatchResult: TRunCapturedDispatchResult;
  let daemonDispatchCount = 0;
  try {
    dispatchResult = await runCapturedDispatch({
      session,
      sender: async (request, envelope, signal) => {
        daemonDispatchCount += 1;
        return params.captureSender(request, envelope, signal);
      },
      signal: params.signal,
      suppressReason:
        "claude text capture: original external send suppressed; local settlement is unproven_text_settlement (not warm-reuse proof)",
    });
  } catch (err) {
    kill();
    loopback.stop();
    const ownership =
      daemonDispatchCount > 0
        ? session.upstreamAccepted()
          ? ("accepted" as const)
          : ("uncertain" as const)
        : ("none" as const);
    session.dispose();
    await stdoutTask.catch(() => undefined);
    const reason = err instanceof Error ? err.message : String(err);
    logError(
      "native-runtime",
      safeDiagnosticMessage`claude capture dispatch failed`,
      { reason },
    );
    return {
      run: {
        kind: "declined",
        reason: `claude capture dispatch failed: ${reason}`,
        ...(ownership !== "none" ? { captureOwnership: ownership } : {}),
      },
      diagnostics: {
        textSettlement: textSettlement ?? "failed",
        toolCapture: CLAUDE_TOOL_CAPTURE_STATUS,
        daemonDispatchCount,
        preambleExternalForwards: 0,
        capturedEnvelope: session.captured(),
      },
    };
  }

  const chunks = chunksFromCapturedAnthropicResponse(
    dispatchResult.response,
    params.providerModelId,
  );
  const run = await commitFromChunkStream({
    chunks,
    signal: params.signal,
    kill,
    sessionId: () => capturedSessionId,
  });

  // Once the daemon owns the exchange, ensure the builder is not left hanging.
  // Kill is cleanup — not evidence of graceful reuse (see settlement kind).
  if (run.kind === "declined") {
    kill();
    loopback.stop();
    session.dispose();
    void stdoutTask.catch(() => undefined);
    return {
      run: {
        ...run,
        // Dispatch already completed — walker must not handroll/fleet retry.
        captureOwnership: "accepted" as const,
      },
      diagnostics: {
        textSettlement: textSettlement ?? "failed",
        toolCapture: CLAUDE_TOOL_CAPTURE_STATUS,
        daemonDispatchCount,
        preambleExternalForwards: 0,
        capturedEnvelope: dispatchResult.envelope,
      },
    };
  }

  // Defer session/loopback teardown until the committed SSE body is fully
  // consumed. Disposing here would abort the shared capture signal and truncate
  // a still-live upstream Response body mid-stream.
  const committedChunks = run.chunks;
  let lifetimeReader: ReadableStreamDefaultReader<TChatCompletionChunk> | null =
    null;
  let lifetimeCleaned = false;
  const cleanupLifetime = (): void => {
    if (lifetimeCleaned) return;
    lifetimeCleaned = true;
    loopback.stop();
    session.dispose();
    void stdoutTask.catch(() => undefined);
  };
  const lifetimeChunks = new ReadableStream<TChatCompletionChunk>({
    async pull(controller) {
      if (lifetimeReader === null) {
        lifetimeReader = committedChunks.getReader();
      }
      try {
        const { value, done } = await lifetimeReader.read();
        if (done) {
          controller.close();
          cleanupLifetime();
          return;
        }
        controller.enqueue(value);
      } catch (err) {
        cleanupLifetime();
        controller.error(err);
      }
    },
    cancel(reason) {
      const reader = lifetimeReader;
      lifetimeReader = null;
      if (reader !== null) {
        void reader.cancel(reason).catch(() => undefined);
      } else {
        void committedChunks.cancel(reason).catch(() => undefined);
      }
      kill();
      cleanupLifetime();
    },
  });

  return {
    run: {
      kind: "committed",
      chunks: lifetimeChunks,
      sessionId: run.sessionId,
    },
    diagnostics: {
      textSettlement: textSettlement ?? "unproven_text_settlement",
      toolCapture: CLAUDE_TOOL_CAPTURE_STATUS,
      daemonDispatchCount,
      preambleExternalForwards: 0,
      capturedEnvelope: dispatchResult.envelope,
    },
  };
};

export type TClaudeCaptureAdapterInput = {
  readonly native: Omit<
    TClaudeTextCaptureParams,
    | "captureSender"
    | "allowLoopbackDestinations"
    | "captureTimeoutMs"
    | "maxBodyBytes"
  >;
  /**
   * When provided, unsupported generation controls decline BEFORE any
   * loopback listen, CLI spawn, or upstream attempt.
   */
  readonly canonical?: TChatCompletionRequest;
  readonly capture: {
    readonly sender: TCapturedDispatchSender;
    readonly allowLoopbackDestinations?: boolean;
    readonly captureTimeoutMs?: number;
    readonly maxBodyBytes?: number;
  };
};

/**
 * Integration entry: control gate + text capture. Tool-bearing requests must
 * not call this — {@link CLAUDE_TOOL_CAPTURE_STATUS}.
 */
export const runClaudeCaptureAdapter = async (
  input: TClaudeCaptureAdapterInput,
): Promise<TClaudeCaptureAdapterResult> => {
  if (input.canonical !== undefined) {
    const unsupported = declineClaudeCaptureForUnsupportedControls(
      input.canonical,
    );
    if (unsupported !== null) {
      return {
        run: {
          kind: "declined",
          reason: `native runtime can't honor ${unsupported}`,
        },
        diagnostics: emptyDiagnostics(),
      };
    }
  }
  return runClaudeTextCapture({
    ...input.native,
    captureSender: input.capture.sender,
    allowLoopbackDestinations: input.capture.allowLoopbackDestinations,
    captureTimeoutMs: input.capture.captureTimeoutMs,
    maxBodyBytes: input.capture.maxBodyBytes,
  });
};
