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
import { SandboxLaunchError, withSandboxSpawn } from "../sandbox/exec";
import { DAEMON_VERSION } from "../version";
import type { TClientTool } from "./claude-tool-session";
import {
  CODEX_HOSTED_WEB_SEARCH_CONFIG,
  suppressHostedSearchClientTool,
} from "./codex-web-search";
import type { TNativeRunResult } from "./types";
import { cleanNativeSpawnEnv, PRE_COMMIT_TIMEOUT_MS } from "./types";
import { vendorErrorLogFields } from "./vendor-error-log";

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
  /**
   * Non-terminal stream/retry error (`error` notification with
   * `willRetry: true`). `openai/codex` (`rust-v0.156.0`
   * `app-server/.../bespoke_event_handling.rs`) emits these for
   * `EventMsg::StreamError` ("Reconnecting... N/M") WITHOUT ending the turn;
   * only `willRetry: false` / `turn/completed` are terminals. Optional — sinks
   * that only care about terminals can omit this.
   */
  onRetryError?: (
    message: string,
    info: {
      readonly willRetry: true;
      readonly codexErrorInfo: unknown;
      readonly additionalDetails: string | null;
    },
  ) => void;
};

export type TCodexAppServerClientOptions = {
  /**
   * Extra argv inserted after `app-server` (e.g. `-c chatgpt_base_url=…`).
   * Used by the bridge-request-capture path; the shared warm client passes none.
   * Daemon-authored flags ONLY — never caller text (SP-6: no system prompt /
   * user text in argv); production capture uses the ephemeral CODEX_HOME
   * config.toml instead.
   */
  readonly spawnArgvExtra?: readonly string[];
  /**
   * When true, this client is NOT registered in the process-wide warm map and
   * callers are expected to {@link CodexAppServerClient.dispose} it. Capture
   * builders must be isolated from the shared app-server.
   */
  readonly isolated?: boolean;
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
  /**
   * The CURRENT/most-recent child, retained here (not read off `this.child`)
   * so it survives a `dispose()` call — `dispose()`/teardown null
   * `this.child` immediately, but this field is only reassigned by
   * {@link start} on the NEXT spawn. This is what makes
   * {@link disposeAndWaitForExit} idempotent: a synchronous `dispose()`
   * followed by `disposeAndWaitForExit()`, or two concurrent
   * `disposeAndWaitForExit()` calls, all await the SAME supervised child's
   * (memoized) `terminate()`, so none can resolve early.
   */
  private lastChild: TSupervisedChild | null = null;
  private readonly spawnArgvExtra: readonly string[];
  /** True when created via {@link createIsolatedCodexAppServerClient}. */
  readonly isolated: boolean;

  constructor(
    private readonly bin: string,
    private readonly env: Record<string, string>,
    options: TCodexAppServerClientOptions = {},
  ) {
    this.spawnArgvExtra = options.spawnArgvExtra ?? [];
    this.isolated = options.isolated === true;
  }

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

  /**
   * Kill the child and reject in-flight RPCs. Required for isolated capture
   * builders; safe but unusual for the shared warm client. Signals the kill
   * of the process group via the supervisor's TERM→KILL ladder and returns
   * immediately — it does NOT wait for the process to actually exit (that's
   * {@link disposeAndWaitForExit}). Unchanged: kept exactly as the shared
   * warm client's fire-and-forget teardown always worked.
   */
  dispose(): void {
    const child = this.child;
    this.teardown("codex app-server disposed");
    void child?.terminate().catch((): TReapOutcome => "reap_unconfirmed");
  }

  /**
   * Same signal + teardown as {@link dispose} (calls it verbatim, so the
   * shared warm client's immediate/fire-and-forget behavior is untouched),
   * but resolves only once the child has ACTUALLY exited — awaits the
   * supervised child's `terminate()` rather than returning as soon as the
   * kill signal is sent. `kill()` only requests termination; the process
   * can still be running — and, in the capture path, still holding/reading
   * its ephemeral `CODEX_HOME` — for a window after `dispose()` returns.
   * Callers that must delete that directory (isolated capture builders)
   * need this, not `dispose()`, to avoid deleting out from under a
   * still-live child.
   *
   * IDEMPOTENT and safe to call concurrently or after a prior synchronous
   * `dispose()`: reads {@link lastChild} BEFORE calling `dispose()`, so
   * every caller — however many, in whatever order relative to a plain
   * `dispose()` — awaits the SAME child, and `terminate()` is memoized per
   * child so none can resolve early.
   *
   * A `reap_unconfirmed` outcome is NOT treated as a confirmed exit — it
   * rejects (the caller could otherwise delete a directory a still-running
   * child is using). The rejection propagates; callers that chain cleanup
   * after this MUST NOT run that cleanup from a `.catch()` on this call.
   */
  async disposeAndWaitForExit(): Promise<void> {
    const child = this.lastChild;
    this.dispose();
    if (child === null) return;
    const outcome = await child.terminate();
    if (outcome === "reap_unconfirmed") {
      throw new Error("codex app-server process group reap unconfirmed");
    }
  }

  /** Settles once the most recent child's process tree is confirmed gone
   *  (the supervisor's `whenReleased`), however long that takes. */
  whenReleased(): Promise<void> {
    return (
      this.lastChild?.whenReleased.then(() => undefined) ?? Promise.resolve()
    );
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
    const argv = [this.bin, "app-server", ...this.spawnArgvExtra];
    const child = withSandboxSpawn(
      argv,
      (wrapped) =>
        superviseSpawn(wrapped, {
          kind: "native-runtime",
          stdin: "pipe",
          stdout: "pipe",
          stderr: "ignore",
          cwd: spawnCwd(this.env),
          env: cleanNativeSpawnEnv(this.env),
        }),
      undefined,
    );
    this.child = child;
    // Reset for THIS spawn — a respawn (shared warm client only) must not
    // let a stale `disposeAndWaitForExit()` caller from the PREVIOUS child
    // keep awaiting a reap for a process that's gone.
    this.lastChild = child;
    const proc = child.subprocess;
    await child.sandbox?.ready;
    // Disposed while the sandbox handshake was pending: never drive the
    // protocol on a child the caller already tore down.
    if (this.child !== child)
      throw new Error("codex app-server disposed during startup");
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
    // a successor's state. Settle whichever way `exited` settles.
    const onExit = (reason: string) => (): void => {
      if (this.child === child) this.teardown(reason);
    };
    void proc.exited.then(
      onExit("codex app-server exited"),
      onExit("codex app-server exited (unexpectedly)"),
    );
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
          ...vendorErrorLogFields(reason),
          turns: this.sinks.size,
        },
      );
    }
    for (const [, sink] of this.sinks) sink.onCompleted("failed", reason);
    this.sinks.clear();
    this.stdin = null;
    this.child = null;
    if (superseded !== null) this.supersededRelease = superseded.whenReleased;
    this.initialized = null; // next request respawns (shared warm client only)
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
          readonly error?: {
            readonly message?: string;
            readonly codexErrorInfo?: unknown;
            readonly additionalDetails?: string | null;
          };
          readonly willRetry?: boolean;
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
      case "error": {
        // Preserve retry-vs-terminal. StreamError → ErrorNotification with
        // willRetry:true ("Reconnecting... N/M") is NOT a turn terminal
        // (bespoke_event_handling.rs EventMsg::StreamError). Treating it as
        // onCompleted("failed") races capture and swallows the real cause.
        const message = params?.error?.message ?? "codex error";
        if (params?.willRetry === true) {
          sink.onRetryError?.(message, {
            willRetry: true,
            codexErrorInfo: params.error?.codexErrorInfo ?? null,
            additionalDetails:
              typeof params.error?.additionalDetails === "string"
                ? params.error.additionalDetails
                : null,
          });
          return;
        }
        sink.onCompleted("failed", message);
        return;
      }
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

/**
 * Dispose the shared warm client for `bin` IF ONE EXISTS — never creates one.
 * GET-ONLY by design: `clientFor` would spawn a fresh child on a miss, which
 * is exactly wrong for a cleanup call (nothing to clean up must mean nothing
 * happens, never "make one so we can kill it"). Deletes the captured
 * instance from the shared map BEFORE disposing it, so a concurrent
 * `clientFor(bin, env)` racing this call cannot receive (and then have
 * unexpectedly killed out from under it) the exact instance being torn
 * down — it will see the map miss and create its own fresh replacement
 * instead. Awaits the real child exit via
 * {@link CodexAppServerClient.disposeAndWaitForExit} (kill() alone only
 * requests termination); resolves `false` when no shared client for `bin`
 * was registered (nothing to dispose), `true` once the child has actually
 * exited.
 *
 * Intended for a standalone short-lived caller process (e.g. a benchmark
 * harness) that itself invoked `tryServeNativeRuntime` for a chatgpt
 * "bridge" (non-capture) hop and thereby caused this module to create the
 * shared client — never for use inside the daemon's own long-lived runtime,
 * which must keep serving warm requests across calls.
 */
export const disposeSharedCodexAppServerClientAndWaitForExit = async (
  bin: string,
): Promise<boolean> => {
  const existing = clients.get(bin);
  if (existing === undefined) return false;
  clients.delete(bin);
  await existing.disposeAndWaitForExit();
  return true;
};

/**
 * Fresh app-server child that is NOT shared with {@link clientFor}. Capture
 * builders must use this so `turn/interrupt` cannot disturb unrelated warm
 * threads, and so `-c chatgpt_base_url` / `-c openai_base_url` redirects apply
 * only to the experimental child.
 */
export const createIsolatedCodexAppServerClient = (
  bin: string,
  env: Record<string, string>,
  options: Omit<TCodexAppServerClientOptions, "isolated"> = {},
): CodexAppServerClient =>
  new CodexAppServerClient(bin, env, { ...options, isolated: true });

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
  /**
   * When true (serve selected sub-method `bridge-capture` + readiness), run the
   * isolated capture text path instead of the warm shared app-server bridge.
   */
  readonly bridgeCapture?: boolean;
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

/** One dynamic (client function) tool as the app-server's `thread/start.dynamicTools`
 *  entry shape (`inputSchema` is raw JSON — the client's JSON-Schema passes through). */
export type TCodexDynamicToolSpec = {
  readonly type: "function";
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
};

/**
 * Map caller function tools → app-server `dynamicTools`, after dropping the
 * hosted-search collision (Codex owns `web_search` on native hops — see
 * `codex-web-search.ts`). Identical mapping was previously duplicated between
 * the bridge tool path (`codex-tool-session.ts`) and the bridge-capture tool
 * path (`codex-capture-tools.ts`); both now call this one definition.
 */
export const codexDynamicToolsFrom = (
  tools: ReadonlyArray<TClientTool>,
): ReadonlyArray<TCodexDynamicToolSpec> =>
  suppressHostedSearchClientTool(tools).map((t) => ({
    type: "function" as const,
    name: t.name,
    description: t.description ?? t.name,
    inputSchema: t.parameters ?? { type: "object", properties: {} },
  }));

/**
 * The `thread/start` fields shared by BOTH codex tool bridges — the bridge
 * tool path (`codex-tool-session.ts`) and the bridge-capture tool path
 * (`codex-capture-tools.ts`) — layered on top of {@link codexBaseStartParams}.
 * Routes dynamic-tool calls to US via `item/tool/call` instead of the
 * `codex-code-mode-host` sidecar (which the isolated install doesn't ship).
 * Verified live 2026-07-14: with code-mode ON the call never reaches the
 * client (once misread as "0.144.0 doesn't emit item/tool/call"); with it
 * OFF the call fires and the turn completes. `experimentalRawEvents` matches
 * openclaw's `thread/start`.
 */
export const codexToolStartParams = (
  providerModelId: string,
  systemText: string | null,
  dynamicTools: ReadonlyArray<TCodexDynamicToolSpec>,
): Record<string, unknown> => ({
  ...codexBaseStartParams(providerModelId, systemText),
  features: { code_mode: false, code_mode_only: false },
  experimentalRawEvents: true,
  dynamicTools,
});

/**
 * The `turn/start` input shared by EVERY codex call site — bridge text
 * (`runCodexNative`), bridge tool (`codex-tool-session.ts`), bridge-capture
 * text (`codex-capture.ts`), and bridge-capture tool (`codex-capture-tools.ts`):
 * one text element (no `text_elements` payload of our own) plus the optional
 * canonical `effort`.
 */
export const codexTurnStartParams = (
  threadId: string,
  text: string,
  effort: string | null,
): Record<string, unknown> => ({
  threadId,
  input: [{ type: "text", text, text_elements: [] }],
  ...(effort !== null ? { effort } : {}),
});

export const runCodexNative = async (
  params: TCodexNativeParams,
): Promise<TNativeRunResult> => {
  if (!existsSync(params.bin)) {
    return { kind: "declined", reason: "codex CLI not installed" };
  }
  // bridge-capture sub-method (W4). Dynamic import keeps the warm path free of
  // a hard cycle with `codex-capture.ts`.
  if (params.bridgeCapture === true) {
    const { runCodexCapturedTextTurn } = await import("./codex-capture");
    return await runCodexCapturedTextTurn(params);
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
          .catch((error: unknown) => {
            if (error instanceof SandboxLaunchError) throw error;
            return client.request("thread/start", startParams);
          })
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
    const turn = (await client.request(
      "turn/start",
      codexTurnStartParams(threadId, params.userText, effort),
    )) as { turn?: { id?: string } };
    turnId = typeof turn.turn?.id === "string" ? turn.turn.id : null;
  } catch (error) {
    client.removeSink(threadId);
    params.signal.removeEventListener("abort", abort);
    if (error instanceof SandboxLaunchError) throw error;
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
      vendorErrorLogFields(reason),
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
