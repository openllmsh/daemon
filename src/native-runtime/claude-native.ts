/**
 * Claude native bridge — executes an eligible `claude_code` hop through the
 * OFFICIAL Claude Code runtime instead of exporting its OAuth bearer for a
 * hand-built Anthropic fetch (the manual path in `walker.ts`).
 *
 *   claude -p --output-format stream-json --include-partial-messages …
 *
 * runs under the daemon's isolated CLI env (`cliEnv("claude_code")` — HOME +
 * CLAUDE_CONFIG_DIR pinned inside `~/.openllm/cli/claude_code/`), so the
 * runtime owns authentication, refresh, identity, and the upstream request
 * itself; the daemon never reads the credential store on this path.
 *
 * `--include-partial-messages` wraps the RAW Anthropic SSE events in
 * `{"type":"stream_event","event":{…}}` NDJSON lines — exactly the event
 * shape the walker already decodes for the manual anthropic wire — so this
 * bridge reuses `fromAnthropicStreamEvent` verbatim and emits the same
 * canonical chunks the rest of the pipeline consumes. Flags:
 *   --tools ""                   no built-in tools — the init frame reports
 *                                an EMPTY tool set, so the model can't run
 *                                bash/edits on the user's machine for a
 *                                gateway text request (`nativePromptOf` also
 *                                gates out tool-bearing requests upstream)
 *   --setting-sources ""         hermetic: ignore user/project/local settings
 *                                (e.g. a stray ANTHROPIC_BASE_URL redirect)
 *   --max-turns 1                single-shot; no agentic loop
 * NB: NO `--bare` — it disables the setting sources that carry the Claude
 * subscription credential, so `claude -p --bare` reports "Not logged in"
 * even when logged in. Verified empirically against the isolated CLI.
 * Any flag the installed CLI rejects surfaces as an early exit with no
 * output → the bridge DECLINES and the manual transport serves the hop.
 */

import { existsSync } from "node:fs";
import {
  AnthropicStreamEvent,
  type TChatCompletionChunk,
} from "@quantidexyz/openllmp";
import {
  fromAnthropicStreamEvent,
  newAnthropicStreamState,
} from "@quantidexyz/openllmw/providers/anthropic/streaming";
import { Schema } from "effect";
import { spawnCwd } from "../delegation/util";
import type { TNativeRunResult } from "./types";
import { cleanNativeSpawnEnv } from "./types";

const decodeStreamEvent = Schema.decodeUnknownOption(AnthropicStreamEvent);

/** How long the runtime may stay silent BEFORE first model output. After
 *  commit there is deliberately no deadline (mirrors the walker). */
const PRE_COMMIT_TIMEOUT_MS = 60_000;

export type TClaudeNativeParams = {
  /** Absolute path to the isolated claude binary (`cliBin("claude_code")`). */
  readonly bin: string;
  /** Isolated run env (`cliEnv("claude_code")`), merged onto process.env. */
  readonly env: Record<string, string>;
  readonly providerModelId: string;
  /** System prompt — applied ONLY when starting a fresh session (a resumed
   *  session already carries it). Null when the client sent none. */
  readonly systemText: string | null;
  /** The turn text to feed: the delta user turn on resume, or the seed prompt
   *  on a fresh start. */
  readonly userText: string;
  /** Resume this session id (feed only `userText`), or null → fresh session. */
  readonly resumeSessionId: string | null;
  readonly signal: AbortSignal;
};

/** One NDJSON line of `claude -p --output-format stream-json` output. */
type TClaudeStreamLine = {
  readonly type?: unknown;
  readonly event?: unknown;
  readonly subtype?: unknown;
  readonly is_error?: unknown;
  readonly result?: unknown;
  readonly session_id?: unknown;
};

export const runClaudeNative = async (
  params: TClaudeNativeParams,
): Promise<TNativeRunResult> => {
  if (!existsSync(params.bin)) {
    return { kind: "declined", reason: "claude CLI not installed" };
  }
  // NB: the bridge deliberately does NOT unlock or re-partition the isolated
  // keychain. `claude` reads its OWN keychain item (resolved from the isolated
  // HOME), and the daemon's status watcher already keeps that keychain
  // unlocked; a `set-key-partition-list` here would RESTRICT claude's access
  // and break auth. The load-bearing prep is the SCRUBBED env below —
  // `cleanNativeSpawnEnv` drops `ANTHROPIC_*`/`CLAUDE_CODE_*` auth vars that
  // would otherwise override the subscription credential.
  const argv = [
    params.bin,
    "-p",
    "--output-format",
    "stream-json",
    "--include-partial-messages",
    "--verbose",
    "--setting-sources",
    "",
    // Belt-and-suspenders with `--setting-sources ""`: never load an MCP
    // server (e.g. the user's global openllm MCP) — a loaded openllm MCP would
    // run `openllmc` under the isolated HOME and recursively create
    // `<iso home>/.openllm/...`.
    "--strict-mcp-config",
    "--tools",
    "",
    "--max-turns",
    "1",
    "--model",
    params.providerModelId,
    // Resume feeds ONLY the delta turn into the persisted session (which
    // already holds prior history + the system prompt). A fresh start applies
    // the system prompt and seeds with `userText`.
    ...(params.resumeSessionId !== null
      ? ["--resume", params.resumeSessionId]
      : params.systemText !== null
        ? ["--system-prompt", params.systemText]
        : []),
  ];
  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = Bun.spawn(argv, {
      stdin: new TextEncoder().encode(params.userText),
      stdout: "pipe",
      stderr: "pipe",
      cwd: spawnCwd(params.env),
      env: cleanNativeSpawnEnv(params.env),
    });
  } catch (error) {
    return {
      kind: "declined",
      reason: `spawn failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const kill = (): void => {
    try {
      proc.kill("SIGTERM");
    } catch {
      // already exited
    }
  };
  if (params.signal.aborted) {
    kill();
    return { kind: "declined", reason: "client aborted" };
  }
  params.signal.addEventListener("abort", kill, { once: true });

  const state = newAnthropicStreamState({
    providerModelId: params.providerModelId,
  });
  const lines = ndjsonLines(proc.stdout as ReadableStream<Uint8Array>);
  const reader = lines.getReader();

  // Captured from every line that carries a `session_id` — the `system`/init
  // line (available at commit) and the terminal `result` line (authoritative
  // for the NEXT resume, in case Claude rotated the id mid-turn). The serve
  // adapter reads this AFTER the stream drains.
  let capturedSessionId: string | null = params.resumeSessionId;

  /** Pull NDJSON lines until the next canonical chunk (or end/failure). */
  const nextChunk = async (): Promise<
    TChatCompletionChunk | "end" | { error: string }
  > => {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return "end";
      let line: TClaudeStreamLine;
      try {
        line = JSON.parse(value) as TClaudeStreamLine;
      } catch {
        continue; // non-JSON noise (debug output) — skip
      }
      if (typeof line.session_id === "string" && line.session_id.length > 0) {
        capturedSessionId = line.session_id;
      }
      if (line.type === "stream_event" && line.event !== undefined) {
        const event = decodeStreamEvent(line.event);
        if (event._tag !== "Some") continue; // unknown event shape — skip
        const chunk = fromAnthropicStreamEvent(event.value, state, {
          providerModelId: params.providerModelId,
        });
        if (chunk !== null) return chunk;
        continue;
      }
      if (line.type === "result") {
        if (line.is_error === true) {
          return {
            error:
              typeof line.result === "string"
                ? line.result
                : "claude runtime reported an error result",
          };
        }
        return "end";
      }
      // "system" (init) / "assistant" (full-message echo) lines — the
      // partial stream_events already carry the content; skip.
    }
  };

  // ── Pre-commit: wait for the FIRST model output ─────────────────────
  const first = await Promise.race([
    nextChunk(),
    new Promise<"timeout">((resolve) =>
      setTimeout(() => resolve("timeout"), PRE_COMMIT_TIMEOUT_MS),
    ),
  ]);
  if (first === "timeout" || first === "end" || typeof first !== "object") {
    kill();
    const stderr = await new Response(proc.stderr as ReadableStream<Uint8Array>)
      .text()
      .catch(() => "");
    return {
      kind: "declined",
      reason:
        first === "timeout"
          ? "claude runtime produced no output before the pre-commit deadline"
          : `claude runtime exited before producing output${stderr.length > 0 ? `: ${stderr.slice(0, 300)}` : ""}`,
    };
  }
  if ("error" in first) {
    kill();
    return { kind: "declined", reason: first.error };
  }

  // ── Committed: stream canonical chunks until the result line ────────
  const chunks = new ReadableStream<TChatCompletionChunk>({
    start(controller) {
      controller.enqueue(first);
    },
    async pull(controller) {
      const next = await nextChunk();
      if (next === "end" || typeof next !== "object" || "error" in next) {
        // Post-commit failure can't re-route (commit-on-first-byte): end the
        // stream; the accumulated usage/finish state is whatever arrived.
        controller.close();
        kill();
        return;
      }
      controller.enqueue(next);
    },
    cancel() {
      kill();
    },
  });
  return { kind: "committed", chunks, sessionId: () => capturedSessionId };
};

/** Split a byte stream into NDJSON lines (no trailing-newline loss). */
const ndjsonLines = (
  raw: ReadableStream<Uint8Array>,
): ReadableStream<string> => {
  const decoder = new TextDecoder();
  let buffer = "";
  const reader = raw.getReader();
  return new ReadableStream<string>({
    async pull(controller) {
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline >= 0) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (line.length > 0) {
            controller.enqueue(line);
            return;
          }
          continue;
        }
        const { value, done } = await reader.read();
        if (done) {
          const rest = buffer.trim();
          buffer = "";
          if (rest.length > 0) controller.enqueue(rest);
          controller.close();
          return;
        }
        buffer += decoder.decode(value, { stream: true });
      }
    },
    cancel() {
      void reader.cancel().catch(() => undefined);
    },
  });
};
