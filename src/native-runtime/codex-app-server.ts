/**
 * Codex native bridge — executes an eligible `chatgpt` hop through the
 * OFFICIAL `codex app-server` JSON-RPC runtime instead of the manual
 * `/backend-api/codex/responses` fetch (auth.json parse + endpoint capture +
 * identity-header backfill) the walker's manual path maintains.
 *
 * Protocol facts pinned against `codex-cli 0.144.0` (`codex app-server
 * generate-ts`): newline-delimited JSON-RPC over stdio WITHOUT the "jsonrpc"
 * field; `initialize` → `initialized` handshake; `thread/start` (ephemeral,
 * approvalPolicy "never", sandbox "read-only") + `turn/start`; text deltas as
 * `item/agentMessage/delta`; usage as `thread/tokenUsage/updated`
 * (`{total,last}` breakdowns); terminal `turn/completed`. The runtime owns
 * auth, refresh, identity headers, request shape, and cache affinity — none
 * of that is reproduced here.
 *
 * ONE app-server child serves the whole daemon (lazy spawn, respawn on
 * exit); each gateway request gets a fresh EPHEMERAL thread, so no state
 * survives on disk and requests can't leak into each other. Server→client
 * requests (approvals — impossible under "never"+read-only, but fail safe)
 * are answered with a JSON-RPC error so the runtime never blocks on us.
 */

import { existsSync } from "node:fs";
import type { TChatCompletionChunk, TUsage } from "@quantidexyz/openllmp";
import { spawnCwd } from "../delegation/util";
import { logError } from "../logger";
import { DAEMON_VERSION } from "../version";
import type { TNativeRunResult } from "./types";
import { cleanNativeSpawnEnv } from "./types";

/** Pre-commit budget: handshake + thread/start + first turn output. */
const PRE_COMMIT_TIMEOUT_MS = 60_000;
/** Handshake / thread-start RPC budget. */
const RPC_TIMEOUT_MS = 30_000;

type TJsonRpcId = number;
type TInbound = {
  readonly id?: TJsonRpcId;
  readonly method?: string;
  readonly params?: unknown;
  readonly result?: unknown;
  readonly error?: { readonly message?: string };
};

/** `thread/tokenUsage/updated` → the canonical usage the daemon reports.
 *  `total` on a fresh ephemeral thread IS this request's usage; cached input
 *  is a SUBSET of inputTokens (never re-added — cache-usage invariant). */
const usageFromBreakdown = (total: {
  readonly totalTokens?: number;
  readonly inputTokens?: number;
  readonly cachedInputTokens?: number;
  readonly outputTokens?: number;
}): TUsage => ({
  prompt_tokens: total.inputTokens ?? 0,
  completion_tokens: total.outputTokens ?? 0,
  total_tokens: total.totalTokens ?? 0,
  prompt_tokens_details: { cached_tokens: total.cachedInputTokens ?? 0 },
});

/** Per-request listener the app-server client routes thread events to. */
type TThreadSink = {
  readonly threadId: string;
  onDelta: (text: string) => void;
  onAgentMessage: (text: string) => void;
  onUsage: (usage: TUsage) => void;
  onCompleted: (status: string, errorMessage: string | null) => void;
  /** A dynamic-tool call the model made (`item/tool/call` server request) —
   *  `requestId` is the JSON-RPC id to respond to with the client's result. */
  onToolCall?: (
    requestId: number,
    callId: string,
    tool: string,
    args: unknown,
  ) => void;
};

class CodexAppServerClient {
  private nextId: TJsonRpcId = 1;
  private readonly pending = new Map<
    TJsonRpcId,
    { resolve: (result: unknown) => void; reject: (err: Error) => void }
  >();
  private readonly sinks = new Map<string, TThreadSink>();
  private initialized: Promise<void> | null = null;
  private stdin: { write: (s: string) => void; flush?: () => void } | null =
    null;

  constructor(
    private readonly bin: string,
    private readonly env: Record<string, string>,
  ) {}

  /** Spawn + handshake exactly once per child; respawn after an exit. */
  ensureStarted(): Promise<void> {
    if (this.initialized !== null) return this.initialized;
    this.initialized = this.start();
    return this.initialized;
  }

  private async start(): Promise<void> {
    const proc = Bun.spawn([this.bin, "app-server"], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "ignore",
      cwd: spawnCwd(this.env),
      env: cleanNativeSpawnEnv(this.env),
    });
    this.stdin = proc.stdin as unknown as {
      write: (s: string) => void;
      flush?: () => void;
    };
    void this.pump(proc.stdout as ReadableStream<Uint8Array>).catch(() => {
      // reader ends on child exit; teardown below handles state
    });
    void proc.exited.then(() => this.teardown("codex app-server exited"));
    await this.request("initialize", {
      clientInfo: {
        name: "openllmd",
        title: "OpenLLM Daemon",
        version: DAEMON_VERSION,
      },
      // experimentalApi enables `thread/start.dynamicTools` (the completion
      // tool-passthrough via `item/tool/call`).
      capabilities: { experimentalApi: true, requestAttestation: false },
    });
    this.notify("initialized");
  }

  private teardown(reason: string): void {
    for (const [, entry] of this.pending) entry.reject(new Error(reason));
    this.pending.clear();
    for (const [, sink] of this.sinks) sink.onCompleted("failed", reason);
    this.sinks.clear();
    this.stdin = null;
    this.initialized = null; // next request respawns
  }

  private send(message: Record<string, unknown>): void {
    if (this.stdin === null) throw new Error("codex app-server not running");
    this.stdin.write(`${JSON.stringify(message)}\n`);
    this.stdin.flush?.();
  }

  private notify(method: string, params?: unknown): void {
    this.send(params === undefined ? { method } : { method, params });
  }

  request(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId++;
    const result = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.delete(id)) {
          reject(new Error(`codex app-server ${method} timed out`));
        }
      }, RPC_TIMEOUT_MS);
    });
    this.send({ id, method, params });
    return result;
  }

  /** Respond to a held server→client request (a dynamic-tool call) with the
   *  client's result, letting the paused turn continue. */
  respondToServer(id: number, result: unknown): void {
    try {
      this.send({ id, result });
    } catch {
      // child gone — the sink's terminal event ends the turn
    }
  }

  addSink(sink: TThreadSink): void {
    this.sinks.set(sink.threadId, sink);
  }

  removeSink(threadId: string): void {
    this.sinks.delete(threadId);
  }

  private async pump(stdout: ReadableStream<Uint8Array>): Promise<void> {
    const decoder = new TextDecoder();
    let buffer = "";
    const reader = stdout.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) break;
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (line.length === 0) continue;
        try {
          this.route(JSON.parse(line) as TInbound);
        } catch {
          // non-JSON stdout noise — skip
        }
      }
    }
  }

  private route(message: TInbound): void {
    // Response to one of our requests.
    if (message.id !== undefined && message.method === undefined) {
      const entry = this.pending.get(message.id);
      if (entry === undefined) return;
      this.pending.delete(message.id);
      if (message.error !== undefined) {
        entry.reject(
          new Error(message.error.message ?? "codex app-server error"),
        );
        return;
      }
      entry.resolve(message.result);
      return;
    }
    // Server→client REQUEST.
    if (message.id !== undefined && message.method !== undefined) {
      // A dynamic-tool call → hand to the thread's sink to relay to the CLIENT
      // (completion tool semantics); we respond later via `respondToServer`.
      if (message.method === "item/tool/call") {
        const p = message.params as
          | {
              threadId?: string;
              callId?: string;
              tool?: string;
              arguments?: unknown;
            }
          | undefined;
        const sink =
          p?.threadId !== undefined ? this.sinks.get(p.threadId) : undefined;
        if (sink?.onToolCall !== undefined && typeof p?.callId === "string") {
          sink.onToolCall(
            message.id,
            p.callId,
            String(p.tool ?? ""),
            p.arguments,
          );
          return;
        }
      }
      // Everything else (approvals etc.) — refuse; never executes under
      // approvalPolicy "never" + read-only sandbox, but must not block.
      this.send({
        id: message.id,
        error: { code: -32601, message: "not supported by openllmd" },
      });
      return;
    }
    // Notification.
    const params = message.params as
      | {
          readonly threadId?: string;
          readonly delta?: unknown;
          readonly item?: { readonly type?: string; readonly text?: unknown };
          readonly tokenUsage?: { readonly total?: unknown };
          readonly turn?: {
            readonly status?: string;
            readonly error?: { readonly message?: string } | null;
          };
          readonly error?: { readonly message?: string };
        }
      | undefined;
    const threadId = params?.threadId;
    if (threadId === undefined) return;
    const sink = this.sinks.get(threadId);
    if (sink === undefined) return;
    switch (message.method) {
      case "item/agentMessage/delta":
        if (typeof params?.delta === "string") sink.onDelta(params.delta);
        return;
      case "item/completed":
        if (
          params?.item?.type === "agentMessage" &&
          typeof params.item.text === "string"
        ) {
          sink.onAgentMessage(params.item.text);
        }
        return;
      case "thread/tokenUsage/updated":
        if (params?.tokenUsage?.total !== undefined) {
          sink.onUsage(
            usageFromBreakdown(
              params.tokenUsage.total as Parameters<
                typeof usageFromBreakdown
              >[0],
            ),
          );
        }
        return;
      case "turn/completed":
        sink.onCompleted(
          params?.turn?.status ?? "completed",
          params?.turn?.error?.message ?? null,
        );
        return;
      case "error":
        sink.onCompleted("failed", params?.error?.message ?? "codex error");
        return;
      default:
        return;
    }
  }
}

// ONE client per daemon process; keyed by binary path so tests can run a
// fixture server side-by-side with a real install.
const clients = new Map<string, CodexAppServerClient>();

export type { TThreadSink };
export { CodexAppServerClient };
export const clientFor = (
  bin: string,
  env: Record<string, string>,
): CodexAppServerClient => {
  const existing = clients.get(bin);
  if (existing !== undefined) return existing;
  const created = new CodexAppServerClient(bin, env);
  clients.set(bin, created);
  return created;
};

export type TCodexNativeParams = {
  /** Absolute path to the isolated codex binary (`cliBin("chatgpt")`). */
  readonly bin: string;
  /** Isolated run env (`cliEnv("chatgpt")`), merged onto process.env. */
  readonly env: Record<string, string>;
  readonly providerModelId: string;
  /** System prompt — applied ONLY on a fresh `thread/start` (a resumed thread
   *  already carries it). Null when the client sent none. */
  readonly systemText: string | null;
  /** The turn text to feed: the delta user turn on resume, or the seed prompt
   *  on a fresh start. */
  readonly userText: string;
  /** Resume this app-server thread id (feed only `userText`), or null → a
   *  fresh persistent thread. */
  readonly resumeThreadId: string | null;
  /** Canonical `reasoning_effort`, forwarded when the runtime supports it. */
  readonly reasoningEffort: string | null;
  readonly signal: AbortSignal;
};

/** Canonical `reasoning_effort` → app-server effort (same narrowing as the
 *  manual chatgpt encoder: minimal/low→low, medium→medium, rest→high). */
const effortOf = (raw: string | null): string | null => {
  if (raw === null || raw === "none") return null;
  if (raw === "minimal" || raw === "low") return "low";
  if (raw === "medium") return "medium";
  return "high";
};

export const runCodexNative = async (
  params: TCodexNativeParams,
): Promise<TNativeRunResult> => {
  if (!existsSync(params.bin)) {
    return { kind: "declined", reason: "codex CLI not installed" };
  }
  const client = clientFor(params.bin, params.env);
  let threadId: string;
  let turnId: string | null = null;
  try {
    await client.ensureStarted();
    // Resume the persisted thread when we have its id (it already holds prior
    // turns + instructions); otherwise start a fresh NON-ephemeral thread so
    // it survives on disk to be resumed next turn. `thread/resume` falls back
    // to `thread/start` when the id is unknown (daemon restart evicted it).
    const startParams = {
      model: params.providerModelId,
      approvalPolicy: "never",
      sandbox: "read-only",
      ...(params.systemText !== null
        ? { developerInstructions: params.systemText }
        : {}),
    };
    const opened = (await (params.resumeThreadId !== null
      ? client
          .request("thread/resume", {
            threadId: params.resumeThreadId,
            ...startParams,
          })
          .catch(() => client.request("thread/start", startParams))
      : client.request("thread/start", startParams))) as {
      thread?: { id?: string };
    };
    if (typeof opened.thread?.id !== "string") {
      return { kind: "declined", reason: "thread/start returned no thread id" };
    }
    threadId = opened.thread.id;
  } catch (error) {
    return {
      kind: "declined",
      reason: error instanceof Error ? error.message : String(error),
    };
  }

  const created = Math.floor(Date.now() / 1000);
  const chunkId = `chatcmpl-${threadId}`;
  const baseChunk = (
    delta: Record<string, unknown>,
    finish: "stop" | "length" | null,
    usage?: TUsage,
  ): TChatCompletionChunk =>
    ({
      id: chunkId,
      object: "chat.completion.chunk",
      created,
      model: params.providerModelId,
      choices: [{ index: 0, delta, finish_reason: finish }],
      ...(usage !== undefined ? { usage } : {}),
    }) as TChatCompletionChunk;

  // Event plumbing: the sink feeds a queue the ReadableStream drains.
  const queue: Array<TChatCompletionChunk | "end"> = [];
  let wake: (() => void) | null = null;
  let sawDelta = false;
  let usage: TUsage | undefined;
  let terminal: { status: string; error: string | null } | null = null;
  const push = (item: TChatCompletionChunk | "end"): void => {
    queue.push(item);
    wake?.();
    wake = null;
  };
  const sink: TThreadSink = {
    threadId,
    onDelta: (text) => {
      if (!sawDelta) {
        sawDelta = true;
        push(baseChunk({ role: "assistant", content: "" }, null));
      }
      push(baseChunk({ content: text }, null));
    },
    onAgentMessage: (text) => {
      // Full-message completion without deltas (small responses).
      if (sawDelta) return;
      sawDelta = true;
      push(baseChunk({ role: "assistant", content: text }, null));
    },
    onUsage: (u) => {
      usage = u;
    },
    onCompleted: (status, errorMessage) => {
      terminal = { status, error: errorMessage };
      push(baseChunk({}, status === "interrupted" ? "length" : "stop", usage));
      push("end");
    },
  };
  client.addSink(sink);

  const abort = (): void => {
    if (turnId !== null) {
      void client.request("turn/interrupt", { threadId, turnId }).catch(() => {
        // interrupt is best-effort; the sink terminal event still ends us
      });
    }
    push("end");
  };
  if (params.signal.aborted) {
    client.removeSink(threadId);
    return { kind: "declined", reason: "client aborted" };
  }
  params.signal.addEventListener("abort", abort, { once: true });

  const effort = effortOf(params.reasoningEffort);
  try {
    const turn = (await client.request("turn/start", {
      threadId,
      input: [{ type: "text", text: params.userText, text_elements: [] }],
      ...(effort !== null ? { effort } : {}),
    })) as { turn?: { id?: string } };
    turnId = typeof turn.turn?.id === "string" ? turn.turn.id : null;
  } catch (error) {
    client.removeSink(threadId);
    return {
      kind: "declined",
      reason: error instanceof Error ? error.message : String(error),
    };
  }

  const nextItem = async (): Promise<TChatCompletionChunk | "end"> => {
    for (;;) {
      const item = queue.shift();
      if (item !== undefined) return item;
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    }
  };

  // ── Pre-commit: first output, terminal, or deadline ─────────────────
  const first = await Promise.race([
    nextItem(),
    new Promise<"timeout">((resolve) =>
      setTimeout(() => resolve("timeout"), PRE_COMMIT_TIMEOUT_MS),
    ),
  ]);
  const failedBeforeOutput =
    first === "timeout" ||
    (first === "end" && !sawDelta) ||
    (terminal !== null &&
      (terminal as { status: string }).status === "failed" &&
      !sawDelta);
  if (failedBeforeOutput) {
    client.removeSink(threadId);
    const reason =
      first === "timeout"
        ? "codex app-server produced no output before the pre-commit deadline"
        : ((terminal as { error: string | null } | null)?.error ??
          "codex turn ended before producing output");
    logError("native-runtime", "codex hop declined pre-commit", { reason });
    return { kind: "declined", reason };
  }

  const chunks = new ReadableStream<TChatCompletionChunk>({
    start(controller) {
      if (typeof first === "object") controller.enqueue(first);
      else controller.close();
    },
    async pull(controller) {
      const next = await nextItem();
      if (next === "end") {
        controller.close();
        client.removeSink(threadId);
        return;
      }
      controller.enqueue(next);
    },
    cancel() {
      client.removeSink(threadId);
      abort();
    },
  });
  return { kind: "committed", chunks, sessionId: () => threadId };
};
