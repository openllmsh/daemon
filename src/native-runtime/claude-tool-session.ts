/**
 * Claude tool-passthrough — the held-open `query()` orchestrator for
 * TOOL-bearing `claude_code` requests, so a stateless `/v1/*` completion
 * client (which runs its OWN tools) can use the Claude subscription: the
 * model's tool call is returned to the CLIENT to execute, and the client's
 * result is fed back on the next request. Native runtimes execute tools
 * internally, so this drives the SDK in a completion-passthrough shape:
 *
 *   1. The client's function tools are registered as in-process SDK MCP tools
 *      (`alwaysLoad` — no ToolSearch deferral). `canUseTool` grants them
 *      (headless auto-denies un-permitted MCP tools). The tool HANDLER pauses
 *      awaiting the client's result.
 *   2. On the model's tool call, the `query()` is left PAUSED inside the
 *      handler; we return the `tool_use` to the client and hold the live query
 *      (indexed by its pending tool-call ids). Verified live: the model uses an
 *      externally-supplied result correctly.
 *   3. The client executes and sends `tool_result`(s) next request; we resolve
 *      the paused handler(s) and drive the query to its next pause (another
 *      tool call) or final text — which ends the turn.
 *
 * Only `claude_code`. Codex `app-server` has no completion-tool mode (Phase 3).
 */

import {
  createSdkMcpServer,
  query,
  tool,
} from "@anthropic-ai/claude-agent-sdk";
import type { TChatCompletionResponse } from "@quantidexyz/openllmp";
import { z } from "zod";
import { spawnCwd } from "../delegation/util";
import type { TNativeTokens } from "./types";
import { cleanNativeSpawnEnv } from "./types";

/** Idle TTL for a held (paused) query before it's force-closed. */
const HELD_TTL_MS = 10 * 60 * 1000;
/** How long to wait for the model's first output / next pause. */
const DRIVE_TIMEOUT_MS = 120_000;
/** After the FIRST tool handler fires, how long to keep collecting the rest of
 *  a parallel tool_use burst before returning. Parallel handlers fire within
 *  milliseconds; this only bounds a pathological unpaired block so it can't
 *  wait out the whole drive deadline. */
const FIRE_SETTLE_MS = 2_000;
const MCP_PREFIX = "mcp__openllm__";

const sanitize = (name: string): string => name.replace(/[^a-zA-Z0-9_-]/g, "_");
const nowMs = (): number => Date.now();

/** SDK assistant-message usage (Anthropic `BetaUsage`) → the daemon token row,
 *  using the SAME additive fold as every other Anthropic path (prompt_tokens =
 *  input + cache_read + cache_creation; the two cache fields ride the details),
 *  so a tool completion's usage aligns with a plain-text native completion and
 *  the cloud prices both identically. */
export const betaUsageToTokens = (
  usage:
    | {
        readonly input_tokens?: number;
        readonly output_tokens?: number;
        readonly cache_read_input_tokens?: number | null;
        readonly cache_creation_input_tokens?: number | null;
      }
    | null
    | undefined,
): TNativeTokens => {
  const cacheRead = usage?.cache_read_input_tokens ?? 0;
  const cacheCreation = usage?.cache_creation_input_tokens ?? 0;
  return {
    tokens_in: (usage?.input_tokens ?? 0) + cacheRead + cacheCreation,
    tokens_out: usage?.output_tokens ?? 0,
    cached_tokens: cacheRead,
    cache_creation_tokens: cacheCreation,
  };
};

/** The allow/deny decision the SDK's `canUseTool` returns. */
type TPermission =
  | {
      readonly behavior: "allow";
      readonly updatedInput: Record<string, unknown>;
    }
  | { readonly behavior: "deny"; readonly message: string };

/** Permit ONLY the client's registered tools (by full MCP name); deny anything
 *  else. Built-in tools are already stripped via `tools: []` on the query, so
 *  this is defense-in-depth — even if a built-in (Bash/Edit/…) were somehow
 *  surfaced, it can never execute on the user's machine on this passthrough
 *  path, whose whole contract is that the CLIENT runs its own tools. */
export const buildPermit =
  (allowed: ReadonlySet<string>) =>
  async (name: string, input: Record<string, unknown>): Promise<TPermission> =>
    allowed.has(name)
      ? { behavior: "allow", updatedInput: input }
      : {
          behavior: "deny",
          message: `tool ${name} is not permitted on the gateway tool-passthrough path`,
        };

/** A client-supplied function tool (canonical `tools[].function`). */
export type TClientTool = {
  readonly name: string;
  readonly description?: string;
  /** The client's JSON-Schema `parameters` — converted to a Zod shape so the
   *  model sees the real parameter names and produces matching arguments. */
  readonly parameters?: Record<string, unknown>;
};

type TZodShape = Record<string, z.ZodTypeAny>;

/** Shallow JSON-Schema → Zod-raw-shape: enough for the model to see the tool's
 *  top-level parameter names/types. Nested shapes stay loose (`z.unknown()`) —
 *  we forward the raw args to the client, which does the real validation. */
const jsonSchemaToZodShape = (
  parameters: Record<string, unknown> | undefined,
): TZodShape => {
  const props = (parameters?.properties ?? {}) as Record<
    string,
    { type?: string }
  >;
  const required = new Set(
    Array.isArray(parameters?.required)
      ? (parameters?.required as string[])
      : [],
  );
  const shape: TZodShape = {};
  for (const [key, spec] of Object.entries(props)) {
    let base: z.ZodTypeAny;
    switch (spec?.type) {
      case "string":
        base = z.string();
        break;
      case "number":
      case "integer":
        base = z.number();
        break;
      case "boolean":
        base = z.boolean();
        break;
      case "array":
        base = z.array(z.unknown());
        break;
      case "object":
        base = z.record(z.string(), z.unknown());
        break;
      default:
        base = z.unknown();
    }
    shape[key] = required.has(key) ? base : base.optional();
  }
  return shape;
};

/** One tool call the model made, returned to the client to execute. */
export type TToolCallOut = {
  readonly id: string;
  readonly name: string;
  readonly argumentsJson: string;
};

/** The outcome of driving the query to its next boundary. `usage` is THIS
 *  turn's token counts (from the assistant message driven in this call — never
 *  cumulative across rounds); optional because the gated Codex tool path does
 *  not surface usage yet. */
export type TToolTurnResult =
  | {
      readonly kind: "tool_calls";
      readonly text: string;
      readonly toolCalls: ReadonlyArray<TToolCallOut>;
      readonly usage?: TNativeTokens;
    }
  | {
      readonly kind: "final";
      readonly text: string;
      readonly usage?: TNativeTokens;
    }
  | { readonly kind: "declined"; readonly reason: string };

/** Shared channel between the paused tool handlers and the driver: fired
 *  handler resolvers, plus a one-shot wake for the driver. */
type TChannel = {
  readonly fired: Array<(result: string) => void>;
  wake: (() => void) | null;
};

type THeld = {
  readonly it: AsyncIterator<unknown>;
  readonly chan: TChannel;
  /** client tool-call id → the paused handler's resolver. */
  readonly pending: Map<string, (result: string) => void>;
  sessionId: string | null;
  lastUsed: number;
};

/** Held (paused) queries, indexed by EACH pending tool-call id so a
 *  continuation request (which references those ids) finds the live query. */
const held = new Map<string, THeld>();

const dropIndex = (h: THeld): void => {
  for (const [id, entry] of held) if (entry === h) held.delete(id);
};

const closeHeld = (h: THeld): void => {
  for (const r of h.chan.fired.splice(0)) r("(cancelled)");
  for (const [, resolve] of h.pending) resolve("(cancelled)");
  h.pending.clear();
  void h.it.return?.(undefined).catch(() => undefined);
  dropIndex(h);
};

const evictStale = (): void => {
  const cutoff = nowMs() - HELD_TTL_MS;
  const stale = new Set<THeld>();
  for (const [, h] of held) if (h.lastUsed < cutoff) stale.add(h);
  for (const h of stale) closeHeld(h);
};

// Sweep abandoned held queries even when no further tool request arrives — a
// client that never returns its tool_result would otherwise leak the live
// `claude` subprocess until daemon restart (eviction was previously only
// opportunistic, on the next start/continue call). `.unref()` so the timer
// never keeps the daemon process alive on its own.
const sweep = setInterval(evictStale, HELD_TTL_MS);
sweep.unref?.();

const buildIterator = (
  params: TStartToolTurnParams,
  chan: TChannel,
): AsyncIterator<unknown> => {
  const onFire = (resolve: (result: string) => void): void => {
    chan.fired.push(resolve);
    const w = chan.wake;
    chan.wake = null;
    w?.();
  };
  const sdkTools = params.tools.map((t) =>
    tool(
      sanitize(t.name),
      t.description ?? t.name,
      // The client's JSON-Schema params → a Zod shape so the model produces
      // arguments matching the client's tool (we forward them raw).
      jsonSchemaToZodShape(t.parameters),
      // Pause here until the CLIENT's tool_result arrives (next request), then
      // hand it back as the tool's output so the model continues.
      async () => {
        const result = await new Promise<string>((resolve) => onFire(resolve));
        return { content: [{ type: "text", text: result }] };
      },
      { alwaysLoad: true },
    ),
  );
  // The full MCP names the SDK presents to `canUseTool` — the ONLY tools
  // permitted to run. Everything else (every built-in) is denied.
  const allowed = new Set(
    params.tools.map((t) => `${MCP_PREFIX}${sanitize(t.name)}`),
  );
  const q = query({
    prompt: params.userText,
    options: {
      model: params.providerModelId,
      pathToClaudeCodeExecutable: params.bin,
      env: cleanNativeSpawnEnv(params.env),
      cwd: spawnCwd(params.env),
      settingSources: [],
      // Strip ALL built-in tools (Bash/Read/Write/Edit/…): a completion
      // passthrough must NEVER execute a tool on the user's machine — the
      // CLIENT runs its own tools. Only the client's function tools (the MCP
      // server below) reach the model. Mirrors `claude-native.ts`'s
      // `--tools ""`, which the plain-text path relies on for the same reason.
      tools: [],
      mcpServers: {
        openllm: createSdkMcpServer({
          name: "openllm",
          version: "1.0.0",
          tools: sdkTools,
        }),
      },
      // Grant ONLY the registered client tools; deny anything else (built-ins
      // are already gone via `tools: []` — this is the defense-in-depth guard).
      canUseTool: buildPermit(allowed) as never,
      ...(params.systemText !== null
        ? { systemPrompt: params.systemText }
        : {}),
      ...(params.resumeSessionId !== null
        ? { resume: params.resumeSessionId }
        : {}),
    } as never,
  });
  return (q as AsyncIterable<unknown>)[Symbol.asyncIterator]();
};

export type TStartToolTurnParams = {
  readonly bin: string;
  readonly env: Record<string, string>;
  readonly providerModelId: string;
  readonly tools: ReadonlyArray<TClientTool>;
  readonly systemText: string | null;
  readonly resumeSessionId: string | null;
  readonly userText: string;
};

/** Start a NEW tool-bearing turn: run to the first tool call or final text. */
export const startToolTurn = async (
  params: TStartToolTurnParams,
): Promise<TToolTurnResult> => {
  evictStale();
  const chan: TChannel = { fired: [], wake: null };
  let it: AsyncIterator<unknown>;
  try {
    it = buildIterator(params, chan);
  } catch (error) {
    return {
      kind: "declined",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
  const h: THeld = {
    it,
    chan,
    pending: new Map(),
    sessionId: params.resumeSessionId,
    lastUsed: nowMs(),
  };
  return drive(h);
};

/** Continue a HELD turn: resolve the paused handlers with the client's tool
 *  results, then drive to the next tool call or final text. */
export const continueToolTurn = async (
  toolResults: ReadonlyArray<{ readonly id: string; readonly content: string }>,
): Promise<TToolTurnResult> => {
  evictStale();
  const h = toolResults.map((r) => held.get(r.id)).find((x) => x !== undefined);
  if (h === undefined) {
    return { kind: "declined", reason: "no held tool session for these ids" };
  }
  for (const r of toolResults) {
    const resolve = h.pending.get(r.id);
    if (resolve !== undefined) {
      h.pending.delete(r.id);
      held.delete(r.id);
      resolve(r.content);
    }
  }
  h.lastUsed = nowMs();
  return drive(h);
};

/**
 * Drive the held query to its next boundary. Collects assistant text + any
 * tool_use blocks; a handler pause (fired) returns `tool_calls`; a terminal
 * result returns `final`.
 */
const drive = async (h: THeld): Promise<TToolTurnResult> => {
  let text = "";
  let toolUse: Array<{ id: string; name: string; input: unknown }> = [];
  let usage: TNativeTokens | undefined;
  const deadline = nowMs() + DRIVE_TIMEOUT_MS;

  for (;;) {
    if (nowMs() > deadline) {
      closeHeld(h);
      return { kind: "declined", reason: "tool turn drive timed out" };
    }
    const firePromise = new Promise<"fired">((resolve) => {
      h.chan.wake = () => resolve("fired");
    });
    let step: { done?: boolean; value?: unknown } | "fired";
    try {
      step = await Promise.race([
        h.it.next().then((r) => r as { done?: boolean; value?: unknown }),
        firePromise,
      ]);
    } catch (error) {
      closeHeld(h);
      return {
        kind: "declined",
        reason: error instanceof Error ? error.message : String(error),
      };
    }

    // A handler paused → the model called tool(s). Parallel tool_use emits N
    // handlers that the SDK invokes in a burst; wait until every block has a
    // fired resolver before returning, so none is dropped — a dropped block
    // would leave the model awaiting a tool_result the client was never asked
    // to produce, hanging the turn to the drive deadline. Bounded by a short
    // settle window (the 10ms poll re-checks even if a wake is missed).
    if (step === "fired") {
      const settleBy = nowMs() + FIRE_SETTLE_MS;
      while (h.chan.fired.length < toolUse.length && nowMs() < settleBy) {
        await Promise.race([
          new Promise<void>((resolve) => {
            h.chan.wake = () => resolve();
          }),
          new Promise<void>((resolve) => setTimeout(resolve, 10)),
        ]);
      }
      return pauseAndReturn(h, text, toolUse, usage);
    }

    const msg = step.value as
      | {
          type?: string;
          session_id?: string;
          message?: {
            content?: ReadonlyArray<Record<string, unknown>>;
            usage?: {
              input_tokens?: number;
              output_tokens?: number;
              cache_read_input_tokens?: number | null;
              cache_creation_input_tokens?: number | null;
            };
          };
        }
      | undefined;
    if (step.done === true || msg === undefined) {
      dropIndex(h);
      return { kind: "final", text, usage };
    }
    if (typeof msg.session_id === "string") h.sessionId = msg.session_id;
    if (msg.type === "assistant") {
      // Fresh tool_use set per assistant message; capture THIS turn's usage
      // (the SDK carries it on each assistant message — it is not cumulative,
      // so recording per drive() call can't double-count across tool rounds).
      toolUse = [];
      if (msg.message?.usage !== undefined) {
        usage = betaUsageToTokens(msg.message.usage);
      }
      for (const block of msg.message?.content ?? []) {
        if (block.type === "text" && typeof block.text === "string") {
          text += block.text;
        } else if (block.type === "tool_use") {
          toolUse.push({
            id: String(block.id ?? ""),
            name: String(block.name ?? "").replace(MCP_PREFIX, ""),
            input: block.input ?? {},
          });
        }
      }
      continue;
    }
    if (msg.type === "result") {
      dropIndex(h);
      return { kind: "final", text, usage };
    }
    // system / partial / other frames — ignore.
  }
};

const pauseAndReturn = (
  h: THeld,
  text: string,
  toolUse: ReadonlyArray<{ id: string; name: string; input: unknown }>,
  usage: TNativeTokens | undefined,
): TToolTurnResult => {
  const toolCalls: TToolCallOut[] = [];
  for (const b of toolUse) {
    const resolve = h.chan.fired.shift();
    if (resolve === undefined) break; // fewer resolvers than blocks — unexpected
    h.pending.set(b.id, resolve);
    held.set(b.id, h);
    toolCalls.push({
      id: b.id,
      name: b.name,
      argumentsJson: JSON.stringify(b.input ?? {}),
    });
  }
  h.lastUsed = nowMs();
  if (toolCalls.length === 0) {
    closeHeld(h);
    return { kind: "declined", reason: "tool pause produced no tool calls" };
  }
  return { kind: "tool_calls", text, toolCalls, usage };
};

/** Build a canonical response envelope from a completed tool turn. */
export const toolTurnToResponse = (
  result: Extract<TToolTurnResult, { kind: "tool_calls" | "final" }>,
  model: string,
): TChatCompletionResponse => {
  const toolCalls =
    result.kind === "tool_calls"
      ? result.toolCalls.map((c) => ({
          id: c.id,
          type: "function" as const,
          function: { name: c.name, arguments: c.argumentsJson },
        }))
      : undefined;
  const u = result.usage;
  return {
    id: `chatcmpl-${nowMs()}`,
    object: "chat.completion",
    created: Math.floor(nowMs() / 1000),
    model,
    usage: {
      prompt_tokens: u?.tokens_in ?? 0,
      completion_tokens: u?.tokens_out ?? 0,
      total_tokens: (u?.tokens_in ?? 0) + (u?.tokens_out ?? 0),
      prompt_tokens_details: {
        cached_tokens: u?.cached_tokens ?? 0,
        cache_creation_tokens: u?.cache_creation_tokens ?? 0,
      },
    },
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: result.text.length > 0 ? result.text : null,
          ...(toolCalls !== undefined && toolCalls.length > 0
            ? { tool_calls: toolCalls }
            : {}),
        },
        finish_reason: result.kind === "tool_calls" ? "tool_calls" : "stop",
      },
    ],
  } as TChatCompletionResponse;
};

/** Test/introspection: count of held (paused) queries. */
export const heldToolSessionCount = (): number => {
  const seen = new Set<THeld>();
  for (const [, h] of held) seen.add(h);
  return seen.size;
};
