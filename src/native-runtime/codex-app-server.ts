import type { TReapOutcome, TSupervisedChild } from "../child-supervisor";
import { superviseSpawn } from "../child-supervisor";
/**
 * Codex native bridge — executes an eligible `chatgpt` hop through the
 * OFFICIAL `codex app-server` JSON-RPC runtime instead of the manual
 * `/backend-api/codex/responses` fetch (auth.json parse + endpoint capture +
 * identity-header backfill) the walker's manual path maintains.
 *
 * Protocol facts pinned against `codex-cli 0.144.0` (`codex app-server
 * generate-ts`): newline-delimited JSON-RPC over stdio WITHOUT the "jsonrpc"
 * field; `initialize` → `initialized` handshake; `thread/start`
 * (approvalPolicy "never", sandbox "read-only") + `turn/start`; text deltas as
 * `item/agentMessage/delta`; usage as `thread/tokenUsage/updated`, which
 * carries BOTH a `total` (cumulative since thread creation) and a `last`
 * (this-turn-only) breakdown — we report `last` (see `route`). The runtime
 * owns auth, refresh, identity headers, request shape, and cache affinity —
 * none of that is reproduced here.
 *
 * ONE app-server child serves the whole daemon (lazy spawn, respawn on exit).
 * Threads are PERSISTENT and resumed across turns (`thread/resume`) so only
 * the delta turn is fed to the runtime; the conversation→thread map lives in
 * the session store (`serve.ts`), and distinct conversations get distinct
 * threads so requests can't leak into each other. Server→client requests
 * (approvals — impossible under "never"+read-only, but fail safe) are answered
 * with a JSON-RPC error so the runtime never blocks on us.
 */

import { existsSync } from "node:fs";
import type {
  TChatCompletionChunk,
  TServerSearchCall,
  TUsage,
} from "@openllmsh/protocol";
import { spawnCwd } from "../delegation/util";
import { logError, safeDiagnosticMessage } from "../logger";
import { SandboxLaunchError, sandboxSpawnArgs } from "../sandbox/exec";
import { DAEMON_VERSION } from "../version";
import { CODEX_HOSTED_WEB_SEARCH_CONFIG } from "./codex-web-search";
import type { TNativeRunResult } from "./types";
import { cleanNativeSpawnEnv, PRE_COMMIT_TIMEOUT_MS } from "./types";

/** Handshake / thread-start RPC budget. */
const RPC_TIMEOUT_MS = 30_000;

/** Once a turn has committed output, a silent app-server must not pin the
 *  request forever — a chunk drought past this bound interrupts the turn and
 *  ends the stream (post-commit, so it cannot re-route). PL-D6. */
const POST_COMMIT_IDLE_TIMEOUT_MS = 60_000;
/** Watchdog tick for the post-commit idle check. */
const IDLE_WATCHDOG_TICK_MS = 1_000;
/** Bound on waiting for a superseded child's `whenReleased` before a respawn.
 *  A confirmed reap settles it in ms; an unconfirmed reap stays pending while
 *  the supervisor keeps watching — respawn must not pin on a wedged group,
 *  since route() drops the stale pump's stragglers regardless. */
const RESPAWN_RELEASE_WAIT_MS = 5_000;

type TJsonRpcId = number;
type TInbound = {
  readonly id?: TJsonRpcId;
  readonly method?: string;
  readonly params?: unknown;
  readonly result?: unknown;
  readonly error?: { readonly message?: string };
};

/** `thread/tokenUsage/updated` → the canonical usage the daemon reports. Fed
 *  the `last` (THIS-turn) breakdown, NOT the thread's cumulative `total` —
 *  threads resume across turns, so `total` grows every turn and would
 *  over-report on turn 2+. Cached input is a SUBSET of inputTokens (never
 *  re-added — cache-usage invariant), so this mirrors the manual chatgpt
 *  path's non-folding convention exactly. */
const usageFromBreakdown = (breakdown: {
  readonly totalTokens?: number;
  readonly inputTokens?: number;
  readonly cachedInputTokens?: number;
  readonly outputTokens?: number;
}): TUsage => ({
  prompt_tokens: breakdown.inputTokens ?? 0,
  completion_tokens: breakdown.outputTokens ?? 0,
  total_tokens: breakdown.totalTokens ?? 0,
  prompt_tokens_details: { cached_tokens: breakdown.cachedInputTokens ?? 0 },
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
  /** A HOSTED web search completed inside the turn (`item/completed` with
   *  `item.type: "webSearch"`) — the provider ran it; we only report it so
   *  client wires can re-encode the lifecycle (Claude Code counts these). */
  onWebSearch?: (call: TServerSearchCall) => void;
};

class CodexAppServerClient {
  private nextId: TJsonRpcId = 1;
  private readonly pending = new Map<
    TJsonRpcId,
    { resolve: (result: unknown) => void; reject: (err: Error) => void }
  >();
  private readonly sinks = new Map<string, TThreadSink>();
  private initialized: Promise<void> | null = null;
  private child: TSupervisedChild | null = null;
  private stdin: { write: (s: string) => void; flush?: () => void } | null =
    null;
  /** Release promise of the most recently superseded child (exit teardown or
   *  failed-init detach). The next start() waits for it first so the stale
   *  stdout pump has finished draining before a successor is born. */
  private supersededRelease: Promise<TReapOutcome> | null = null;

  constructor(
    private readonly bin: string,
    private readonly env: Record<string, string>,
  ) {}

  /** Spawn + handshake exactly once per child; respawn after an exit. */
  ensureStarted(): Promise<void> {
    if (this.initialized !== null) return this.initialized;
    const started = this.start();
    this.initialized = started;
    // PL-D4: a timed-out/failed handshake must NOT stay cached — the child it
    // spawned could be alive-but-deaf and would poison every future hop.
    // start() already killed the process group; here we reset so the NEXT
    // request respawns instead of replaying the rejection forever.
    void started.catch(() => {
      if (this.initialized === started) this.initialized = null;
    });
    return started;
  }

  private async start(): Promise<void> {
    // Let a superseded child fully release before respawning: its pump drains
    // stdout to EOF, and a detached pipe holder (a launcher grandchild outside
    // the process group) can keep that pipe open and writing INTO this new
    // generation. The wait is bounded — a group that survives the reap ladder
    // leaves `whenReleased` pending, and route() drops stragglers anyway.
    const priorRelease = this.supersededRelease;
    this.supersededRelease = null;
    if (priorRelease !== null) {
      let waitTimer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          priorRelease,
          new Promise<"waited">((resolve) => {
            waitTimer = setTimeout(
              () => resolve("waited"),
              RESPAWN_RELEASE_WAIT_MS,
            );
          }),
        ]);
      } finally {
        if (waitTimer !== undefined) clearTimeout(waitTimer);
      }
    }
    const child = superviseSpawn(sandboxSpawnArgs([this.bin, "app-server"]), {
      kind: "native-runtime",
      stdin: "pipe",
      stdout: "pipe",
      stderr: "ignore",
      cwd: spawnCwd(this.env),
      env: cleanNativeSpawnEnv(this.env),
    });
    this.child = child;
    const proc = child.subprocess;
    await child.sandbox?.ready;
    this.stdin = proc.stdin as unknown as {
      write: (s: string) => void;
      flush?: () => void;
    };
    // The pump is tagged with ITS child: frames read after a supersession are
    // a dead generation's buffered tail and must not be routed (route() also
    // identity-gates; threads persist across respawns, so a stale frame can
    // carry a LIVE thread id).
    void this.pump(proc.stdout as ReadableStream<Uint8Array>, child).catch(
      () => {
        // reader ends on child exit; teardown below handles state
      },
    );
    // Only the CURRENT child's exit may tear the client down — a stale
    // child's late `exited` (e.g. after an init-failure kill) must not wipe
    // a successor's state.
    void proc.exited.then(() => {
      if (this.child === child) this.teardown("codex app-server exited");
    });
    try {
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
    } catch (error) {
      // PL-D4: kill the child we just spawned (TERM→KILL the process group,
      // bounded) — a handshake timeout leaves it alive-but-useless. Detach it
      // first so its exit doesn't trip the identity-guarded teardown above,
      // and hand its release to the next start() so the stale pump can't
      // outlive the respawn.
      this.child = null;
      this.stdin = null;
      this.supersededRelease = child.whenReleased;
      await child.terminate().catch((): TReapOutcome => "reap_unconfirmed");
      throw error;
    }
    this.notify("initialized");
  }

  private teardown(reason: string): void {
    // The exiting child's release goes to the next start(): its pump can out-
    // live the exit while it drains buffered stdout, so respawn first waits
    // for the supervisor to confirm the group is gone.
    const superseded = this.child;
    for (const [, entry] of this.pending) entry.reject(new Error(reason));
    this.pending.clear();
    // Active turns die as "failed" completions — surface WHY server-side; the
    // sink's terminal event only carries the reason to the client stream.
    if (this.sinks.size > 0) {
      logError(
        "native-runtime",
        safeDiagnosticMessage`codex app-server teardown failed live turns`,
        {
          reason,
          turns: this.sinks.size,
        },
      );
    }
    for (const [, sink] of this.sinks) sink.onCompleted("failed", reason);
    this.sinks.clear();
    this.stdin = null;
    this.child = null;
    if (superseded !== null) this.supersededRelease = superseded.whenReleased;
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
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) {
          reject(new Error(`codex app-server ${method} timed out`));
        }
      }, RPC_TIMEOUT_MS);
      // Wrap both settle paths so the timeout can't outlive the response (a
      // settled RPC's timer would otherwise stay armed for the full budget).
      this.pending.set(id, {
        resolve: (result) => {
          clearTimeout(timer);
          resolve(result);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
      // A synchronous send failure (child gone) must reject THIS promise and
      // drop its pending entry now — thrown, it would leave the entry to time
      // out and reject a promise nobody holds (unhandled rejection).
      try {
        this.send({ id, method, params });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
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

  private async pump(
    stdout: ReadableStream<Uint8Array>,
    child: TSupervisedChild,
  ): Promise<void> {
    const decoder = new TextDecoder();
    let buffer = "";
    const reader = stdout.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      // Superseded: this read came from a dead generation. Stop draining
      // rather than route a stale tail — and rather than read forever a pipe
      // a detached descendant can hold open past the group reap.
      if (this.child !== child) {
        await reader.cancel().catch(() => undefined);
        return;
      }
      buffer += decoder.decode(value, { stream: true });
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) break;
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (line.length === 0) continue;
        try {
          this.route(JSON.parse(line) as TInbound, child);
        } catch {
          // non-JSON stdout noise — skip
        }
      }
    }
  }

  private route(message: TInbound, child: TSupervisedChild): void {
    // Only the CURRENT child's frames may touch pending RPCs or sinks — a
    // superseded child's drained tail can carry a live thread id (threads
    // persist and are resumed across respawns) and would corrupt the live
    // turn or write a refusal into the successor's stdin.
    if (child !== this.child) return;
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
          readonly item?: {
            readonly type?: string;
            readonly text?: unknown;
            /** hosted webSearch items (`type: "webSearch"`) */
            readonly id?: unknown;
            readonly query?: unknown;
            readonly action?: {
              readonly type?: unknown;
              readonly query?: unknown;
              readonly queries?: unknown;
            };
          };
          readonly tokenUsage?: {
            readonly total?: unknown;
            readonly last?: unknown;
          };
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
        // HOSTED web search completed (config-enabled; see codex-web-search.ts).
        // Only the COMPLETED item carries the real query (`item/started` has an
        // empty one). Report it so the serve layer re-encodes the lifecycle on
        // the client's wire; a query-less item is noise, not a search.
        if (params?.item?.type === "webSearch") {
          const item = params.item;
          const queries = Array.isArray(item.action?.queries)
            ? item.action.queries.filter(
                (q): q is string => typeof q === "string" && q.length > 0,
              )
            : [];
          // Model families report the query differently: 5.4 puts it on BOTH
          // `item.query` and `action.query`; 5.6 (sol) fills `item.query` but
          // nulls `action.query` and reports the fan-out only in
          // `action.queries`. Fall through all three so no family's search
          // silently drops.
          const query =
            typeof item.query === "string" && item.query.length > 0
              ? item.query
              : typeof item.action?.query === "string" &&
                  item.action.query.length > 0
                ? item.action.query
                : (queries[0] ?? "");
          if (typeof item.id === "string" && query.length > 0) {
            sink.onWebSearch?.({
              id: item.id,
              query,
              ...(queries.length > 0 ? { queries } : {}),
            });
          }
        }
        return;
      case "thread/tokenUsage/updated": {
        // Report THIS turn's usage (`last`), never the thread's cumulative
        // `total` — a resumed thread's `total` sums every prior turn, which
        // would over-report tokens/cache on turn 2+ (the manual, stateless
        // path always reports per-request). Fall back to `total` only when the
        // runtime omits `last` (a fresh thread's first update).
        const breakdown = params?.tokenUsage?.last ?? params?.tokenUsage?.total;
        if (breakdown !== undefined) {
          sink.onUsage(
            usageFromBreakdown(
              breakdown as Parameters<typeof usageFromBreakdown>[0],
            ),
          );
        }
        return;
      }
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
  /** Override the pre-commit deadline (default 60s). Tests use a small value to
   *  exercise the timeout→interrupt path without a real 60s wait. */
  readonly precommitMs?: number;
  /** Override the post-commit idle watchdog (default
   *  {@link POST_COMMIT_IDLE_TIMEOUT_MS}). Tests use a small value to exercise
   *  the mid-turn stall → `turn/interrupt` path without a real wait. */
  readonly postCommitIdleMs?: number;
};

/** Canonical `reasoning_effort` → app-server effort (same narrowing as the
 *  manual chatgpt encoder: minimal/low→low, medium→medium, rest→high). */
export const effortOf = (raw: string | null): string | null => {
  if (raw === null || raw === "none") return null;
  if (raw === "minimal" || raw === "low") return "low";
  if (raw === "medium") return "medium";
  return "high";
};

/**
 * The `thread/start` fields shared by the text bridge ({@link runCodexNative})
 * and the tool bridge (`codex-tool-session.ts`). We serve inference for an
 * external client that asked for a plain model, so: read-only sandbox +
 * `approvalPolicy:"never"` (never touch the filesystem / never block on an
 * approval), and `personality:"none"` to suppress the runtime's built-in "Codex
 * the coding agent" persona (mirrors the Codex CLI when a developer prompt is
 * supplied). The client's system prompt rides in `developerInstructions` on a
 * fresh start (a resumed thread already carries it). Each caller layers its own
 * unique fields (effort/tools/features) on top.
 *
 * Hosted web search rides `config` here so BOTH callers get it: search is
 * provider-owned on Codex native hops (always-on), and Codex resolves the
 * requested `live` mode against its own permission profile.
 */
export const codexBaseStartParams = (
  providerModelId: string,
  systemText: string | null,
): Record<string, unknown> => ({
  model: providerModelId,
  approvalPolicy: "never",
  sandbox: "read-only",
  personality: "none",
  config: CODEX_HOSTED_WEB_SEARCH_CONFIG,
  ...(systemText !== null ? { developerInstructions: systemText } : {}),
});

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
    const startParams = codexBaseStartParams(
      params.providerModelId,
      params.systemText,
    );
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
    if (error instanceof SandboxLaunchError) throw error;
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
  // Any sink event (delta/usage/completion) is upstream activity — resets the
  // post-commit idle watchdog (PL-D6).
  let lastActivityAt = Date.now();
  const push = (item: TChatCompletionChunk | "end"): void => {
    lastActivityAt = Date.now();
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
      lastActivityAt = Date.now();
      usage = u;
    },
    // A hosted web search completed inside the turn — ride it on the canonical
    // chunk stream so the client-wire encoders re-emit the lifecycle
    // (Anthropic: server_tool_use + web_search_tool_result blocks + usage).
    onWebSearch: (call) => {
      push(baseChunk({ server_search_calls: [call] }, null));
    },
    onCompleted: (status, errorMessage) => {
      terminal = { status, error: errorMessage };
      push(baseChunk({}, status === "interrupted" ? "length" : "stop", usage));
      push("end");
    },
  };
  client.addSink(sink);

  let aborted = false;
  const abort = (): void => {
    aborted = true;
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

  // If the client aborted WHILE turn/start was in flight, the abort closure saw
  // a null turnId and couldn't interrupt — do it now that the id has arrived, or
  // the vendor keeps generating an answer nobody reads (silent quota burn).
  if (aborted) {
    if (turnId !== null) {
      void client
        .request("turn/interrupt", { threadId, turnId })
        .catch(() => undefined);
    }
    client.removeSink(threadId);
    return { kind: "declined", reason: "client aborted" };
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
  let precommitTimer: ReturnType<typeof setTimeout> | undefined;
  const first = await Promise.race([
    nextItem(),
    new Promise<"timeout">((resolve) => {
      precommitTimer = setTimeout(
        () => resolve("timeout"),
        params.precommitMs ?? PRE_COMMIT_TIMEOUT_MS,
      );
    }),
  ]);
  clearTimeout(precommitTimer);
  const failedBeforeOutput =
    first === "timeout" ||
    (first === "end" && !sawDelta) ||
    (terminal !== null &&
      (terminal as { status: string }).status === "failed" &&
      !sawDelta);
  if (failedBeforeOutput) {
    // A pre-commit TIMEOUT means the turn is still running server-side (no
    // terminal event arrived) — interrupt it before we fall back to the manual
    // transport, or the vendor keeps generating an answer we've abandoned
    // (duplicate subscription-quota burn, never recorded). The `end`/`failed`
    // sub-cases already saw `turn/completed`, so they need no interrupt.
    if (first === "timeout" && turnId !== null) {
      void client.request("turn/interrupt", { threadId, turnId }).catch(() => {
        // best-effort; we're declining regardless
      });
    }
    client.removeSink(threadId);
    const reason =
      first === "timeout"
        ? "codex app-server produced no output before the pre-commit deadline"
        : ((terminal as { error: string | null } | null)?.error ??
          "codex turn ended before producing output");
    logError(
      "native-runtime",
      safeDiagnosticMessage`codex hop declined pre-commit`,
      { reason },
    );
    return { kind: "declined", reason };
  }

  // PL-D6: the committed stream used to wait on `nextItem()` forever — a
  // silently-stalled app-server (turn committed, then no events AND no
  // turn/completed) pinned the request while the client-side heartbeat hid
  // the stall. Watchdog the turn: any sink activity re-arms it; a drought
  // sends `turn/interrupt` (best-effort — the vendor may already be dead) and
  // ends the stream as `interrupted` (finish_reason "length").
  const idleMs = params.postCommitIdleMs ?? POST_COMMIT_IDLE_TIMEOUT_MS;
  let idleTimer: ReturnType<typeof setInterval> | null = setInterval(() => {
    if (Date.now() - lastActivityAt <= idleMs) return;
    if (idleTimer !== null) {
      clearInterval(idleTimer);
      idleTimer = null;
    }
    if (turnId !== null) {
      void client
        .request("turn/interrupt", { threadId, turnId })
        .catch(() => undefined);
    }
    client.removeSink(threadId);
    sink.onCompleted("interrupted", "codex app-server idle post-commit");
  }, IDLE_WATCHDOG_TICK_MS);
  const stopIdleWatchdog = (): void => {
    if (idleTimer !== null) {
      clearInterval(idleTimer);
      idleTimer = null;
    }
  };

  const chunks = new ReadableStream<TChatCompletionChunk>({
    start(controller) {
      if (typeof first === "object") controller.enqueue(first);
      else controller.close();
    },
    async pull(controller) {
      const next = await nextItem();
      if (next === "end") {
        stopIdleWatchdog();
        controller.close();
        client.removeSink(threadId);
        return;
      }
      controller.enqueue(next);
    },
    cancel() {
      stopIdleWatchdog();
      client.removeSink(threadId);
      abort();
    },
  });
  return { kind: "committed", chunks, sessionId: () => threadId };
};
