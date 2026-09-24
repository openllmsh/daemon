/**
 * Muse native runtime — one cold official-SDK session per request.
 *
 * The official `@muse-code/sdk@0.1.1` spawn (`spawnMspConnection`) has no
 * custom-process hook: it calls `node:child_process.spawn(command, args)`.
 * Confinement is therefore the SAME argv wrap Cursor uses: `sandboxSpawnArgs`
 * turns `[museBin, "serve", --disable-write, --disable-shell]` into the
 * daemon's `--sandbox-exec` shim so the SDK-owned child is the confined shim,
 * which then execs `muse serve`. An SDK that spawned outside this path would
 * be a blocker; this file does not invent a parallel MSP.
 *
 * Caller tools ride an ephemeral loopback MCP server injected via an isolated
 * XDG overlay (auth.json symlinked from the provider home; no ambient
 * settings/hooks/skills). The first tools/call ends the turn with OpenAI
 * `tool_calls` and cancels the native turn — never a fabricated success.
 *
 * Safety floor (what we can enforce without inventing host rules):
 *   - `--disable-write` + `--disable-shell` (spawn argv)
 *   - `denyUnmatched` approval mode (host policy select-never-create; no
 *     client-authored allowlist exists on MSP)
 *   - `onApproval` allows ONLY exact host-native `web_search` once when the
 *     host asks; it does NOT see known-safe auto-exec under `onRequest`
 *     (official probe: known-safe `pwd` runs without asking)
 *   - auth overlay HOME is a SIBLING of `workspaceRoot`, not inside it, so
 *     workspace-scoped reads cannot reach the auth symlink by relative path
 *
 * Residual host-policy blocker (documented, not claimed fixed): MSP cannot
 * install a "web_search only" rule; known-safe absolute-path reads of HOME
 * under `denyUnmatched` are unverified without a live Muse host. Do not
 * equate callback denial with "all other native tools are denied".
 *
 * Completed provider-executed searches ride `server_search_calls`; they are
 * never re-emitted as caller `tool_calls`. Exact `session/setModel` +
 * `session/read` confirmation is required before a turn starts.
 */

import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MuseClient,
  readSessionDurability,
  spawnMspConnection,
} from "@muse-code/sdk";
import type {
  TChatCompletionChunk,
  TProviderModelEntry,
} from "@openllmsh/protocol";
import { cliBin, cliEnv, MUSE_CREDENTIAL_BACKEND } from "../cli-paths";
import {
  museNativeModelFingerprint,
  museNativeModelGeneration,
  noteMuseAuthenticatedSession,
  rememberMuseNativeModels,
} from "../delegation/muse";
import { spawnCwd } from "../delegation/util";
import { logError, logWarn, safeDiagnosticMessage } from "../logger";
import { sandboxSpawnArgs } from "../sandbox/exec";
import { DAEMON_VERSION } from "../version";
import type {
  TMuseFoldedItem,
  TMuseItemDelta,
  TMuseSessionUsage,
} from "./muse-events";
import { createMuseTurnState } from "./muse-events";
import type { TMuseMcpServer } from "./muse-mcp-server";
import { startMuseMcpServer } from "./muse-mcp-server";
import type { TMuseOverlay } from "./muse-overlay";
import { createMuseExecutionOverlay } from "./muse-overlay";
import type { TMuseCallerTool, TMuseInputPart } from "./muse-request";
import type { TMuseApprovalRequest } from "./muse-web-search";
import { decideMuseNativeApproval } from "./muse-web-search";
import type { TNativeRunResult } from "./types";
import { cleanNativeSpawnEnv, PRE_COMMIT_TIMEOUT_MS } from "./types";

/** Official `muse serve` flags verified in the pinned reference
 *  (`safety-settings.ts` `safetyArgs`). There is no verified disable-all
 *  built-ins switch; write + shell are the documented restrictions. */
export const MUSE_SERVE_SAFETY_ARGS = [
  "--disable-write",
  "--disable-shell",
] as const;

export const MUSE_TURN_TIMEOUT_MS = 180_000;
export const MUSE_IDLE_TIMEOUT_MS = 60_000;
export const MUSE_RPC_TIMEOUT_MS = 30_000;

/**
 * Fail-closed host approval mode (official `ApprovalMode`).
 *
 * `denyUnmatched` is the closed enum's default-deny selection. The callback
 * still approves exact host-native `web_search` once when the host asks.
 * This is NOT equivalent to a custom allowlist — MSP forbids client-authored
 * rules (select-never-create). Prefer this over `onRequest`, which official
 * probes show auto-runs known-safe tools without `onApproval`.
 */
export const MUSE_APPROVAL_MODE = "denyUnmatched" as const;

const AUTH_REJECTION_RE =
  /not logged in|not signed in|unauthorized|unauthenticated|authentication (?:failed|rejected)|auth(?:entication)? rejected|please (?:log|sign)[\s-]?in/i;

const API_KEY_OVERRIDE_RE = /^(META_|MUSE_).*(API_KEY|TOKEN|SECRET|ACCESS)/i;

const OPENLLM_RECURSION_KEYS = new Set([
  "OPENLLM_API_KEY",
  "OPENLLM_CLOUD_ORIGIN",
  "OPENLLM_BASE_URL",
  "OPENLLM_ENDPOINT",
]);

const EXPLICIT_METERED_KEYS = new Set([
  "META_API_KEY",
  "MUSE_API_KEY",
  "META_ACCESS_TOKEN",
  "MUSE_ACCESS_TOKEN",
]);

/** Ambient Muse settings/MCP/data overlays, Codex home, and ACP-only yolo
 *  flags must not leak into gateway execution. Per-turn isolated HOME /
 *  XDG_* / CODEX_HOME are re-applied after this cleaner. */
const SETTINGS_LEAK_KEYS = new Set([
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_STATE_HOME",
  "CODEX_HOME",
  "MUSE_CODE_ACP_ALLOW_YOLO",
]);

type TNodeEnv = "development" | "production" | "test";

/** Absent → production. Present but invalid → throw (never silently coerce). */
const nodeEnvOf = (value: string | undefined): TNodeEnv => {
  if (value === undefined) return "production";
  if (value === "development" || value === "production" || value === "test") {
    return value;
  }
  throw new Error(
    "muse spawn env requires NODE_ENV to be development, production, or test",
  );
};

export type TMuseSpawnTarget = {
  readonly command: string;
  readonly args: ReadonlyArray<string>;
};

/** Wrap official `muse serve` argv with the daemon sandbox shim. Pure. */
export const wrapMuseServeSpawn = (museBin: string): TMuseSpawnTarget => {
  const wrapped = sandboxSpawnArgs([
    museBin,
    "serve",
    ...MUSE_SERVE_SAFETY_ARGS,
  ]);
  const command = wrapped[0];
  if (command === undefined) {
    throw new Error("sandboxSpawnArgs returned an empty argv");
  }
  return { command, args: wrapped.slice(1) };
};

/** Drop documented metered-key overrides, OpenLLM recursion knobs, and user
 *  Muse settings/MCP overlay after the shared native poison filter. Returns a
 *  genuine ProcessEnv so NODE_ENV stays the Next-required literal. */
export const cleanMuseSpawnEnv = (
  cliEnv: Record<string, string>,
): NodeJS.ProcessEnv => {
  const cleaned = cleanNativeSpawnEnv(cliEnv);
  // Prefer the cleaned env, then process.env; default production only when
  // both are absent. A present invalid value still rejects.
  const rawNodeEnv =
    cleaned.NODE_ENV !== undefined
      ? cleaned.NODE_ENV
      : process.env.NODE_ENV !== undefined
        ? process.env.NODE_ENV
        : undefined;
  const nodeEnv = nodeEnvOf(rawNodeEnv);
  const next: NodeJS.ProcessEnv = { NODE_ENV: nodeEnv };
  for (const [key, value] of Object.entries(cleaned)) {
    if (key === "NODE_ENV") continue;
    if (EXPLICIT_METERED_KEYS.has(key)) continue;
    if (OPENLLM_RECURSION_KEYS.has(key)) continue;
    if (SETTINGS_LEAK_KEYS.has(key)) continue;
    if (API_KEY_OVERRIDE_RE.test(key)) continue;
    next[key] = value;
  }
  // Always pin the vendor file credential backend (overrides ambient
  // `keychain` / unset). Same invariant as `cliEnv("muse")` so login,
  // logout, serve, model/list, and inference never open macOS Keychain.
  next.TBH_CREDENTIAL_BACKEND = MUSE_CREDENTIAL_BACKEND;
  return next;
};

export type TMuseHostSpawnOptions = {
  readonly command: string;
  readonly args: ReadonlyArray<string>;
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly onStderr?: (chunk: string) => void;
  /** Abort in-flight spawn/initialize (closes MSP handshake / child). */
  readonly signal?: AbortSignal;
};

export type TMuseSessionRead = {
  readonly sessionId: string;
  readonly modelId: string | null;
  readonly providerId?: string | null;
  /** Effective approval mode from session/read, when the host reported one. */
  readonly approvalMode?: string | null;
};

export type TMuseTurnOutcome = {
  readonly kind:
    | "completed"
    | "failed"
    | "cancelled"
    | "unqueued"
    | "terminalUnknown";
  readonly terminal?: string;
  readonly usage?: TMuseSessionUsage;
};

export type TMuseTurn = {
  readonly turnId: string;
  readonly completed: Promise<TMuseTurnOutcome>;
  items(): AsyncIterable<TMuseFoldedItem>;
  deltas(): AsyncIterable<TMuseItemDelta>;
  cancel(): Promise<void>;
};

export type TMuseSession = {
  readonly sessionId: string;
  setModel(model: {
    readonly modelId: string;
    readonly providerId?: string;
  }): Promise<void>;
  read(): Promise<TMuseSessionRead>;
  /** Best-effort last `session/tokenUsage` folded for this session. */
  lastUsage(): TMuseSessionUsage | undefined;
  /**
   * Demand-driven `model/list` against the live host. Returns mapped provider
   * entries (may be empty). Does not invent catalog facts.
   */
  listModels(): Promise<ReadonlyArray<TProviderModelEntry>>;
  sendUserTurn(input: ReadonlyArray<TMuseInputPart>): Promise<TMuseTurn>;
  onApproval(
    handler: (
      request: TMuseApprovalRequest,
    ) => Promise<{ readonly choiceId: string }> | { readonly choiceId: string },
  ): void;
};

export type TMuseHost = {
  startSession(options: {
    readonly sessionId: string;
    readonly workspaceRoot: string;
    readonly modelId: string;
    readonly providerId?: string;
    readonly approvalMode: typeof MUSE_APPROVAL_MODE;
  }): Promise<TMuseSession>;
  /** Demand-driven `model/list` (sessionId optional on the wire). */
  listModels(sessionId?: string): Promise<ReadonlyArray<TProviderModelEntry>>;
  close(): Promise<void>;
};

export type TMuseHostFactory = (
  options: TMuseHostSpawnOptions,
) => Promise<TMuseHost>;

const asRecord = (value: unknown): Record<string, unknown> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

const asString = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

/** Narrow host-native policy — allow web_search once; deny everything else. */
const decideNativeApproval = (
  request: TMuseApprovalRequest,
): { readonly choiceId: string } => decideMuseNativeApproval(request);

const usageFromFold = (session: {
  readonly fold: {
    readonly sessionState: {
      get: (family: "session/tokenUsage") => unknown;
    };
  };
}): TMuseSessionUsage | undefined => {
  const reported = session.fold.sessionState.get("session/tokenUsage");
  const rec = asRecord(reported);
  if (rec === null) return undefined;
  return rec as TMuseSessionUsage;
};

const mapFoldedItem = (item: unknown): TMuseFoldedItem | null => {
  const rec = asRecord(item);
  if (rec === null) return null;
  const itemId = asString(rec.itemId);
  const kind = asString(rec.kind);
  const revision =
    typeof rec.revision === "number" && Number.isSafeInteger(rec.revision)
      ? rec.revision
      : null;
  if (itemId === null || kind === null || revision === null) return null;
  return {
    itemId,
    kind,
    revision,
    ...(typeof rec.status === "string" ? { status: rec.status } : {}),
    ...(typeof rec.text === "string" ? { text: rec.text } : {}),
    ...(Array.isArray(rec.summary)
      ? {
          summary: rec.summary.filter(
            (part): part is string => typeof part === "string",
          ),
        }
      : {}),
    ...(typeof rec.truncated === "boolean" ? { truncated: rec.truncated } : {}),
    ...(typeof rec.callId === "string" ? { callId: rec.callId } : {}),
    ...(typeof rec.tool === "string" ? { tool: rec.tool } : {}),
    ...(typeof rec.args === "string" ? { args: rec.args } : {}),
    ...(typeof rec.visibleOutput === "string"
      ? { visibleOutput: rec.visibleOutput }
      : {}),
  };
};

const mapApprovalRequest = (request: {
  readonly approvalId: string;
  readonly toolName: string;
  readonly toolCallId: string;
  readonly rawArgs: string;
  readonly protectedWrite: boolean;
  readonly availableChoices: ReadonlyArray<{
    readonly choiceId: string;
    readonly decision: string;
    readonly scope: string;
  }>;
  readonly subject: {
    readonly kind: string;
    readonly toolName?: string;
    readonly path?: string;
    readonly command?: string;
  };
}): TMuseApprovalRequest => ({
  approvalId: request.approvalId,
  toolName: request.toolName,
  toolCallId: request.toolCallId,
  rawArgs: request.rawArgs,
  protectedWrite: request.protectedWrite,
  availableChoices: request.availableChoices.map((choice) => ({
    choiceId: choice.choiceId,
    decision: choice.decision,
    scope: choice.scope,
  })),
  subject: {
    kind: request.subject.kind,
    ...(request.subject.toolName !== undefined
      ? { toolName: request.subject.toolName }
      : {}),
    ...(request.subject.path !== undefined
      ? { path: request.subject.path }
      : {}),
    ...(request.subject.command !== undefined
      ? { command: request.subject.command }
      : {}),
  },
});

const mapItemDelta = (delta: unknown): TMuseItemDelta | null => {
  const rec = asRecord(delta);
  if (rec === null) return null;
  const itemId = asString(rec.itemId);
  const text = typeof rec.delta === "string" ? rec.delta : null;
  if (itemId === null || text === null) return null;
  return {
    itemId,
    delta: text,
    ...(typeof rec.field === "string" ? { field: rec.field } : {}),
  };
};

/** Mutable MSP turn parts — SDK `TurnInputPart[]` is not readonly. */
const toTurnInput = (
  input: ReadonlyArray<TMuseInputPart>,
): Array<
  | { type: "text"; text: string }
  | { type: "image"; base64Data: string; mediaType: string }
> =>
  input.map((part) =>
    part.type === "text"
      ? { type: "text" as const, text: part.text }
      : {
          type: "image" as const,
          base64Data: part.base64Data,
          mediaType: part.mediaType,
        },
  );

/** Map authentic MSP `model/list` rows — no daemon-side name policy. Catalog
 *  ownership and cloud live-merge decide which ids are routable. */
const mapModelList = (raw: unknown): ReadonlyArray<TProviderModelEntry> => {
  const rec = asRecord(raw);
  const models = Array.isArray(rec?.models) ? rec.models : [];
  const out: TProviderModelEntry[] = [];
  for (const row of models) {
    const entry = asRecord(row);
    const modelId = asString(entry?.modelId);
    if (modelId === null) continue;
    const display = asString(entry?.displayLabel);
    const context =
      typeof entry?.contextLimit === "number" &&
      Number.isSafeInteger(entry.contextLimit) &&
      entry.contextLimit > 0
        ? entry.contextLimit
        : undefined;
    const maxOut =
      typeof entry?.outputLimit === "number" &&
      Number.isSafeInteger(entry.outputLimit) &&
      entry.outputLimit > 0
        ? entry.outputLimit
        : undefined;
    out.push({
      provider_model_id: modelId,
      ...(display !== null ? { display_name: display } : {}),
      ...(context !== undefined ? { context_window: context } : {}),
      ...(maxOut !== undefined ? { max_output_tokens: maxOut } : {}),
    });
  }
  return out;
};

const approvalModeOf = (
  sessionRec: Record<string, unknown> | null,
): string | null => {
  if (sessionRec === null) return null;
  const modeBlock = asRecord(sessionRec.approvalMode);
  return asString(modeBlock?.mode) ?? asString(sessionRec.approvalMode);
};

const wrapOfficialHost = async (
  options: TMuseHostSpawnOptions,
): Promise<TMuseHost> => {
  const handshake = spawnMspConnection({
    command: options.command,
    args: [...options.args],
    cwd: options.cwd,
    env: options.env,
    ...(options.onStderr !== undefined ? { onStderr: options.onStderr } : {}),
    shutdownTimeoutMs: 1_000,
  });
  const onAbort = (): void => {
    void handshake.close().catch(() => {});
  };
  options.signal?.addEventListener("abort", onAbort, { once: true });
  if (options.signal?.aborted) {
    options.signal.removeEventListener("abort", onAbort);
    await handshake.close().catch(() => {});
    throw new Error("muse SDK spawn aborted");
  }
  let spawned: Awaited<ReturnType<typeof handshake.initialize>>;
  try {
    spawned = await handshake.initialize({
      clientInfo: { name: "openllm-daemon", version: DAEMON_VERSION },
    });
  } catch (error) {
    // initialize failure / abort must not leave the owned muse serve child.
    await handshake.close().catch(() => {});
    throw error;
  } finally {
    options.signal?.removeEventListener("abort", onAbort);
  }
  const durability = readSessionDurability(spawned.initializeResult);
  const client = new MuseClient(spawned.connection, { durability });
  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    await client.close().catch(() => {});
    await handshake.close().catch(() => {});
  };
  return {
    close,
    listModels: async (sessionId) => {
      const listed = await spawned.connection.request(
        "model/list",
        sessionId !== undefined ? { sessionId } : {},
      );
      return mapModelList(listed);
    },
    startSession: async (start) => {
      const session = await client.startSession({
        sessionId: start.sessionId,
        workspaceRoot: start.workspaceRoot,
        modelId: start.modelId,
        ...(start.providerId !== undefined
          ? { providerId: start.providerId }
          : {}),
        approvalMode: start.approvalMode,
      });
      session.onApproval((request) =>
        decideNativeApproval(mapApprovalRequest(request)),
      );
      return {
        sessionId: session.sessionId,
        setModel: async (model) => {
          await spawned.connection.command("session/setModel", {
            sessionId: session.sessionId,
            model: {
              modelId: model.modelId,
              ...(model.providerId !== undefined
                ? { providerId: model.providerId }
                : {}),
            },
          });
        },
        read: async () => {
          const observed = await spawned.connection.request("session/read", {
            sessionId: session.sessionId,
            excludeItems: true,
          });
          const saved = asRecord(asRecord(observed)?.session);
          const sessionId = asString(saved?.sessionId);
          if (sessionId === null) {
            throw new Error("Muse session/read returned no sessionId");
          }
          return {
            sessionId,
            modelId: asString(saved?.modelId),
            providerId:
              saved !== null && "providerId" in saved
                ? asString(saved.providerId)
                : undefined,
            approvalMode: approvalModeOf(saved),
          };
        },
        lastUsage: () => usageFromFold(session),
        listModels: async () => {
          const listed = await spawned.connection.request("model/list", {
            sessionId: session.sessionId,
          });
          return mapModelList(listed);
        },
        sendUserTurn: async (input) => {
          const turn = await session.sendUserTurn({
            input: toTurnInput(input),
          });
          return {
            turnId: turn.turnId,
            completed: turn.completed.then((outcome) => {
              const usage = usageFromFold(session);
              if (outcome.kind === "completed") {
                const terminal = asString(asRecord(outcome.params)?.terminal);
                return {
                  kind: "completed" as const,
                  ...(terminal !== null ? { terminal } : {}),
                  ...(usage !== undefined ? { usage } : {}),
                };
              }
              if (outcome.kind === "unqueued") {
                return {
                  kind: "unqueued" as const,
                  ...(usage !== undefined ? { usage } : {}),
                };
              }
              return {
                kind: "terminalUnknown" as const,
                ...(usage !== undefined ? { usage } : {}),
              };
            }),
            items: async function* () {
              for await (const item of turn.items()) {
                const mapped = mapFoldedItem(item);
                if (mapped !== null) yield mapped;
              }
            },
            deltas: async function* () {
              for await (const delta of turn.deltas()) {
                const mapped = mapItemDelta(delta);
                if (mapped !== null) yield mapped;
              }
            },
            cancel: async () => {
              await spawned.connection
                .command(
                  "turn/cancel",
                  { sessionId: session.sessionId, turnId: turn.turnId },
                  { maxAttempts: 1 },
                )
                .catch(() => {});
            },
          };
        },
        onApproval: () => {
          // Official path is wired at startSession; extra handlers are ignored.
        },
      };
    },
  };
};

export const defaultMuseHostFactory: TMuseHostFactory = wrapOfficialHost;

export type TMuseNativeParams = {
  readonly bin: string;
  readonly env: Record<string, string>;
  readonly providerModelId: string;
  readonly providerId?: string;
  readonly parts: ReadonlyArray<TMuseInputPart>;
  readonly promptText: string;
  /** Caller function tools exposed via the per-request loopback MCP server. */
  readonly tools?: ReadonlyArray<TMuseCallerTool>;
  readonly signal: AbortSignal;
  readonly precommitMs?: number;
  readonly idleMs?: number;
  readonly turnTimeoutMs?: number;
  readonly rpcTimeoutMs?: number;
  readonly hostFactory?: TMuseHostFactory;
  readonly cwd?: string;
};

const setupDecline = (
  error: unknown,
  signal: AbortSignal,
): TNativeRunResult => {
  if (signal.aborted) {
    return { kind: "declined", reason: "client aborted" };
  }
  const message = error instanceof Error ? error.message : String(error);
  return {
    kind: "declined",
    reason: `muse SDK handshake failed: ${message}`,
    ...(AUTH_REJECTION_RE.test(message)
      ? { cooldownReason: "auth" as const }
      : {}),
  };
};

const withTimeout = async <T>(
  work: Promise<T>,
  ms: number,
  label: string,
): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Open a Muse host under a deadline. On timeout OR outer abort: abort the
 * spawn signal (so official handshake can close the child), promptly reject
 * the waiter, and still close any host that resolves late — including when
 * `open` ignores AbortSignal. Preserves the original timeout/abort error.
 */
export const openMuseHostWithTimeout = async (
  open: (signal: AbortSignal) => Promise<TMuseHost>,
  ms: number,
  label: string,
  outerSignal?: AbortSignal,
): Promise<TMuseHost> => {
  // Fail closed before allocating abortWait — abandoning a never-raced
  // rejected promise would be an unhandled rejection.
  if (outerSignal?.aborted) {
    throw new Error(`${label} aborted`);
  }
  const ac = new AbortController();
  /** True once this waiter has abandoned the open (timeout or outer abort). */
  let abandoned = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let rejectAbort: ((error: Error) => void) | undefined;
  const abortWait = new Promise<never>((_, reject) => {
    rejectAbort = reject;
  });
  // Always observe abortWait: abandon may reject it after the race has
  // already settled (or if open() throws before race).
  void abortWait.catch(() => {});
  const abandon = (error: Error): void => {
    if (abandoned) return;
    abandoned = true;
    ac.abort();
    rejectAbort?.(error);
  };
  const onOuterAbort = (): void => {
    abandon(new Error(`${label} aborted`));
  };
  outerSignal?.addEventListener("abort", onOuterAbort, { once: true });
  try {
    let pending: Promise<TMuseHost>;
    try {
      pending = open(ac.signal);
    } catch (error) {
      abandoned = true;
      throw error;
    }
    void pending.then(
      (host) => {
        if (abandoned) void host.close().catch(() => {});
      },
      () => {},
    );
    // Timeout and outer abort both settle `abortWait` via `abandon` — one
    // rejection channel, no double-reject after the race has finished.
    timer = setTimeout(() => {
      abandon(new Error(`${label} timed out`));
    }, ms);
    return await Promise.race([pending, abortWait]);
  } finally {
    clearTimeout(timer);
    outerSignal?.removeEventListener("abort", onOuterAbort);
  }
};

const confirmExactModelAndPolicy = async (
  session: TMuseSession,
  modelId: string,
  providerId: string | undefined,
): Promise<void> => {
  await session.setModel({
    modelId,
    ...(providerId !== undefined ? { providerId } : {}),
  });
  const observed = await session.read();
  if (observed.sessionId !== session.sessionId) {
    throw new Error(
      "Muse did not confirm the requested session; no turn was started",
    );
  }
  if (observed.modelId !== modelId) {
    throw new Error(
      "Muse did not confirm the requested model/provider; no turn was started",
    );
  }
  if (providerId !== undefined && observed.providerId !== providerId) {
    throw new Error(
      "Muse did not confirm the requested model/provider; no turn was started",
    );
  }
  // Fail closed when the host reports an approval mode that is not our
  // requested denyUnmatched policy. Absent mode (older hosts / fakes) is
  // tolerated only when the startSession call already requested it.
  if (
    observed.approvalMode !== undefined &&
    observed.approvalMode !== null &&
    observed.approvalMode !== MUSE_APPROVAL_MODE
  ) {
    throw new Error(
      `Muse effective approval mode is ${observed.approvalMode}, expected ${MUSE_APPROVAL_MODE}`,
    );
  }
};

/** Feed the auth-owned passive cache from authentic native model ids. */
const rememberObservedMuseModels = (
  models: ReadonlyArray<TProviderModelEntry>,
  generation: number,
  noteAuthenticated = true,
): ReadonlyArray<TProviderModelEntry> => {
  if (models.length === 0) return models;
  // Cache/auth-note require a live store fingerprint; still return the native
  // rows to the demand caller when the store is absent (tests / pre-login).
  const fingerprint = museNativeModelFingerprint();
  if (fingerprint !== null) {
    rememberMuseNativeModels({
      fingerprint,
      accountHint: null,
      generation,
      models,
    });
    // Connect verification may suppress this so the owner can note only
    // AFTER epoch/signal fencing (see listMuseModelsDemand.noteAuthenticated).
    if (noteAuthenticated) {
      noteMuseAuthenticatedSession({ fingerprint });
    }
  }
  return models;
};

/** Feed the auth-owned passive cache from a live MSP model/list snapshot. */
export const rememberMuseModelsFromSession = async (
  session: TMuseSession,
  generation: number,
): Promise<ReadonlyArray<TProviderModelEntry>> => {
  let models: ReadonlyArray<TProviderModelEntry> = [];
  try {
    models = await session.listModels();
  } catch (error) {
    logWarn(
      "native-runtime",
      safeDiagnosticMessage`muse model/list failed; skipping observation`,
      {
        error: error instanceof Error ? error.message : String(error),
      },
    );
    return [];
  }
  return rememberObservedMuseModels(models, generation);
};

export type TListMuseModelsDemandParams = {
  readonly bin?: string;
  readonly env?: Record<string, string>;
  readonly signal?: AbortSignal;
  readonly hostFactory?: TMuseHostFactory;
  readonly cwd?: string;
  /**
   * When true (default), a successful list also calls
   * {@link noteMuseAuthenticatedSession}. Connect / login-exit verification
   * should pass `false` and commit the auth note itself only after its
   * epoch/signal fence — otherwise a late list can race logout/rotate.
   */
  readonly noteAuthenticated?: boolean;
};

/**
 * Demand-driven MSP `model/list` for the Muse delegate. Strips metered-key
 * overrides, uses a fresh HOME overlay with auth-only symlink, never claims
 * entitlement/quota. Returns admitted catalog-exact rows, or `null` when the
 * binary/auth/host path cannot produce a list.
 */
export const listMuseModelsDemand = async (
  params: TListMuseModelsDemandParams = {},
): Promise<ReadonlyArray<TProviderModelEntry> | null> => {
  if (params.signal?.aborted) return null;
  const bin = params.bin ?? cliBin("muse");
  if (!existsSync(bin)) return null;
  const generation = museNativeModelGeneration();
  const baseEnv = params.env ?? cliEnv("muse");
  // Auth overlay must stay OUTSIDE workspaceRoot (known-safe reads).
  // Always allocate a unique turn root — even under params.cwd — so parallel
  // tests sharing a parent directory cannot collide on workspace/runtime.
  const turnRoot = await mkdtemp(
    join(params.cwd ?? (spawnCwd(baseEnv) || tmpdir()), "muse-models-"),
  );
  const workspaceRoot = join(turnRoot, "workspace");
  const runtimeParent = join(turnRoot, "runtime");
  await mkdir(workspaceRoot, { recursive: true, mode: 0o700 });
  await mkdir(runtimeParent, { recursive: true, mode: 0o700 });
  let overlay: TMuseOverlay | null = null;
  let host: TMuseHost | null = null;
  try {
    overlay = await createMuseExecutionOverlay({
      baseEnv,
      mcp: null,
      parentDir: runtimeParent,
    });
    const env: NodeJS.ProcessEnv = {
      ...cleanMuseSpawnEnv(baseEnv),
      ...overlay.env,
    };
    const spawn = wrapMuseServeSpawn(bin);
    const hostFactory = params.hostFactory ?? defaultMuseHostFactory;
    host = await openMuseHostWithTimeout(
      (signal) =>
        hostFactory({
          command: spawn.command,
          args: spawn.args,
          cwd: workspaceRoot,
          env,
          signal,
        }),
      MUSE_RPC_TIMEOUT_MS,
      "muse model/list spawn",
      params.signal,
    );
    if (params.signal?.aborted) return null;
    const models = await withTimeout(
      host.listModels(),
      MUSE_RPC_TIMEOUT_MS,
      "muse model/list",
    );
    // Re-check after the await so a cancel during listModels cannot still
    // cache/note auth evidence for a stale connect verification.
    if (params.signal?.aborted) return null;
    const observed = rememberObservedMuseModels(
      models,
      generation,
      params.noteAuthenticated !== false,
    );
    return observed.length > 0 ? observed : [];
  } catch (error) {
    logWarn(
      "native-runtime",
      safeDiagnosticMessage`muse demand model/list failed`,
      {
        error: error instanceof Error ? error.message : String(error),
      },
    );
    return null;
  } finally {
    if (host !== null) await host.close().catch(() => {});
    if (overlay !== null) await overlay.cleanup().catch(() => {});
    await rm(turnRoot, { recursive: true, force: true }).catch(() => {});
  }
};

/**
 * Run one cold Muse turn through the official SDK surface. Commit-on-first
 * output; every pre-commit failure declines. The child / host is closed on
 * completion, abort, and both timeouts.
 */
export const runMuseNative = async (
  params: TMuseNativeParams,
): Promise<TNativeRunResult> => {
  if (params.signal.aborted) {
    return { kind: "declined", reason: "client aborted" };
  }
  if (!existsSync(params.bin)) {
    return { kind: "declined", reason: "muse CLI not installed" };
  }
  if (params.parts.length === 0) {
    return {
      kind: "declined",
      reason: "prompt contains no text or image content",
    };
  }

  const spawn = wrapMuseServeSpawn(params.bin);
  // Split layout: workspaceRoot (session cwd) NEVER contains the auth
  // overlay HOME. Known-safe workspace reads therefore cannot reach the
  // auth symlink by a workspace-relative path. Absolute-path reads of HOME
  // remain a residual host-policy risk (see file header).
  // Always unique under params.cwd / tmp — avoids parallel cwd collisions.
  const turnRoot = await mkdtemp(
    join(params.cwd ?? (spawnCwd(params.env) || tmpdir()), "muse-turn-"),
  );
  const workspaceRoot = join(turnRoot, "workspace");
  const runtimeParent = join(turnRoot, "runtime");
  await mkdir(workspaceRoot, { recursive: true, mode: 0o700 });
  await mkdir(runtimeParent, { recursive: true, mode: 0o700 });
  const hostFactory = params.hostFactory ?? defaultMuseHostFactory;
  const rpcTimeoutMs = params.rpcTimeoutMs ?? MUSE_RPC_TIMEOUT_MS;
  const observationGeneration = museNativeModelGeneration();
  const turn = createMuseTurnState({
    providerModelId: params.providerModelId,
  });

  type TQueueItem = TChatCompletionChunk | "end" | { readonly error: Error };
  const queue: Array<TQueueItem> = [];
  let wake: (() => void) | null = null;
  const push = (item: TQueueItem): void => {
    queue.push(item);
    wake?.();
    wake = null;
  };
  let ended = false;
  let lastActivityAt = Date.now();
  const endWith = (chunks: ReadonlyArray<TChatCompletionChunk>): void => {
    if (ended) return;
    ended = true;
    for (const chunk of chunks) push(chunk);
    push("end");
  };
  /** Post-commit non-moderation failure: error the stream, do not finish ok. */
  const failStream = (error: Error): void => {
    if (ended) return;
    ended = true;
    push({ error });
  };

  let host: TMuseHost | null = null;
  let session: TMuseSession | null = null;
  let activeTurn: TMuseTurn | null = null;
  let mcp: TMuseMcpServer | null = null;
  let overlay: TMuseOverlay | null = null;
  let idleTimer: ReturnType<typeof setInterval> | undefined;
  let turnTimer: ReturnType<typeof setTimeout> | undefined;

  const stopMcp = (): void => {
    mcp?.stop();
    mcp = null;
  };

  const cleanup = async (): Promise<void> => {
    clearInterval(idleTimer);
    clearTimeout(turnTimer);
    if (activeTurn !== null) {
      await activeTurn.cancel().catch(() => {});
      activeTurn = null;
    }
    if (host !== null) {
      await host.close().catch(() => {});
      host = null;
    }
    stopMcp();
    if (overlay !== null) {
      await overlay.cleanup().catch(() => {});
      overlay = null;
    }
    await rm(turnRoot, { recursive: true, force: true }).catch(() => {});
  };

  const abort = (): void => {
    void cleanup();
    if (ended) return;
    if (turn.sawOutput()) {
      endWith(turn.finish("cancelled"));
      return;
    }
    ended = true;
    push("end");
  };
  params.signal.addEventListener("abort", abort, { once: true });

  try {
    if ((params.tools?.length ?? 0) > 0) {
      mcp = startMuseMcpServer({
        tools: params.tools ?? [],
        onToolCall: (name, args) => {
          if (ended) return;
          lastActivityAt = Date.now();
          // Capture vendor usage around cancellation when the fold already
          // holds a session/tokenUsage notification.
          const usage = session?.lastUsage();
          if (usage !== undefined) turn.observeUsage(usage);
          endWith(turn.emitToolCall(name, args));
          void activeTurn?.cancel().catch(() => {});
        },
      });
    }
    overlay = await createMuseExecutionOverlay({
      baseEnv: params.env,
      mcp,
      modelId: params.providerModelId,
      ...(params.providerId !== undefined
        ? { providerId: params.providerId }
        : {}),
      parentDir: runtimeParent,
    });
    // cleanMuseSpawnEnv strips ambient XDG_*; re-apply the isolated overlay.
    const env: NodeJS.ProcessEnv = {
      ...cleanMuseSpawnEnv(params.env),
      ...overlay.env,
    };
    host = await openMuseHostWithTimeout(
      (signal) =>
        hostFactory({
          command: spawn.command,
          args: spawn.args,
          cwd: workspaceRoot,
          env,
          signal,
          onStderr: (chunk) => {
            const trimmed = chunk.trim();
            if (trimmed.length === 0) return;
            logWarn("native-runtime", safeDiagnosticMessage`muse-sdk stderr`, {
              bytes: trimmed.length,
            });
          },
        }),
      rpcTimeoutMs,
      "muse SDK spawn",
      params.signal,
    );
    session = await withTimeout(
      host.startSession({
        sessionId: crypto.randomUUID(),
        workspaceRoot,
        modelId: params.providerModelId,
        ...(params.providerId !== undefined
          ? { providerId: params.providerId }
          : {}),
        approvalMode: MUSE_APPROVAL_MODE,
      }),
      rpcTimeoutMs,
      "muse session/start",
    );
    session.onApproval(decideNativeApproval);
    await withTimeout(
      confirmExactModelAndPolicy(
        session,
        params.providerModelId,
        params.providerId,
      ),
      rpcTimeoutMs,
      "muse session/setModel",
    );
    {
      const fingerprint = museNativeModelFingerprint();
      if (fingerprint !== null) {
        noteMuseAuthenticatedSession({ fingerprint });
      }
    }
    // Demand-driven observation for passive discoverModels — never blocks the
    // turn on failure; exact native ids only.
    void rememberMuseModelsFromSession(session, observationGeneration).catch(
      () => {},
    );
    if (params.signal.aborted) {
      await cleanup();
      return { kind: "declined", reason: "client aborted" };
    }
    activeTurn = await withTimeout(
      session.sendUserTurn(params.parts),
      rpcTimeoutMs,
      "muse turn/start",
    );
  } catch (error) {
    await cleanup();
    return setupDecline(error, params.signal);
  }

  const emitItem = (item: TMuseFoldedItem): void => {
    lastActivityAt = Date.now();
    const chunk = turn.handleItem(item);
    if (chunk !== null && !ended) push(chunk);
  };
  const emitDelta = (delta: TMuseItemDelta): void => {
    lastActivityAt = Date.now();
    const chunk = turn.handleDelta(delta);
    if (chunk !== null && !ended) push(chunk);
  };

  const pumpItems = (async (): Promise<void> => {
    if (activeTurn === null) return;
    for await (const item of activeTurn.items()) {
      if (ended) return;
      emitItem(item);
    }
  })();
  const pumpDeltas = (async (): Promise<void> => {
    if (activeTurn === null) return;
    for await (const delta of activeTurn.deltas()) {
      if (ended) return;
      emitDelta(delta);
    }
  })();
  void pumpItems.catch((error: unknown) => {
    logError("native-runtime", safeDiagnosticMessage`muse item pump failed`, {
      error: error instanceof Error ? error.message : String(error),
    });
  });
  void pumpDeltas.catch((error: unknown) => {
    logError("native-runtime", safeDiagnosticMessage`muse delta pump failed`, {
      error: error instanceof Error ? error.message : String(error),
    });
  });

  const idleBudget = params.idleMs ?? MUSE_IDLE_TIMEOUT_MS;
  idleTimer = setInterval(() => {
    if (ended) {
      clearInterval(idleTimer);
      return;
    }
    if (Date.now() - lastActivityAt > idleBudget) {
      clearInterval(idleTimer);
      logError(
        "native-runtime",
        safeDiagnosticMessage`muse turn idle timeout — cancelling`,
        { idleMs: idleBudget },
      );
      void cleanup();
      if (turn.sawOutput()) endWith(turn.finish("cancelled"));
      else push("end");
    }
  }, 1_000);

  turnTimer = setTimeout(() => {
    if (ended) return;
    logError(
      "native-runtime",
      safeDiagnosticMessage`muse turn budget exceeded — cancelling`,
      { turnTimeoutMs: params.turnTimeoutMs ?? MUSE_TURN_TIMEOUT_MS },
    );
    void cleanup();
    if (turn.sawOutput()) endWith(turn.finish("cancelled"));
    else push("end");
  }, params.turnTimeoutMs ?? MUSE_TURN_TIMEOUT_MS);

  // Official SDK adapters wait for item/delta pumps AFTER turn.completed
  // (held items can still be in the iterator). Finishing on completed alone
  // drops that tail and can emit an empty terminal as the first chunk.
  void (async () => {
    try {
      const outcome = await activeTurn.completed;
      if (outcome.usage !== undefined) turn.observeUsage(outcome.usage);
      else {
        const folded = session?.lastUsage();
        if (folded !== undefined) turn.observeUsage(folded);
      }
      await Promise.all([
        pumpItems.catch(() => {}),
        pumpDeltas.catch(() => {}),
      ]);
      if (ended) return;
      // SDK TurnOutcome: success is only `kind: "completed"` with terminal
      // completed|cancelled (or omitted). `unqueued` never ran; `terminalUnknown`
      // is host-death/unknown; `terminal: "failed"` is a mid-turn failure on
      // the completed arm. After partial output, none of those may look like
      // a successful finish — error the stream. Before output, decline.
      const terminal = outcome.terminal;
      const acknowledgedSuccess =
        outcome.kind === "completed" &&
        (terminal === undefined ||
          terminal === "completed" ||
          terminal === "cancelled" ||
          terminal === "tool_calls");
      if (!turn.sawOutput() && !acknowledgedSuccess) {
        ended = true;
        push("end");
        void cleanup();
        return;
      }
      if (!acknowledgedSuccess) {
        failStream(
          new Error(
            `muse turn ended without acknowledged success (${outcome.kind}${terminal !== undefined ? `/${terminal}` : ""})`,
          ),
        );
        void cleanup();
        return;
      }
      endWith(turn.finish(terminal ?? "completed"));
      void cleanup();
    } catch (error: unknown) {
      await Promise.all([
        pumpItems.catch(() => {}),
        pumpDeltas.catch(() => {}),
      ]);
      if (ended) return;
      const folded = session?.lastUsage();
      if (folded !== undefined) turn.observeUsage(folded);
      logError(
        "native-runtime",
        safeDiagnosticMessage`muse turn failed after start`,
        { error: error instanceof Error ? error.message : String(error) },
      );
      if (turn.sawOutput()) {
        failStream(error instanceof Error ? error : new Error(String(error)));
      } else {
        ended = true;
        push("end");
      }
      void cleanup();
    }
  })();

  const nextItem = async (): Promise<TQueueItem> => {
    for (;;) {
      const item = queue.shift();
      if (item !== undefined) return item;
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    }
  };

  let first: TQueueItem | "timeout";
  for (;;) {
    let precommitTimer: ReturnType<typeof setTimeout> | undefined;
    first = await Promise.race([
      nextItem(),
      new Promise<"timeout">((resolve) => {
        precommitTimer = setTimeout(
          () => resolve("timeout"),
          params.precommitMs ?? PRE_COMMIT_TIMEOUT_MS,
        );
      }),
    ]);
    clearTimeout(precommitTimer);
    if (first === "timeout" && turn.sawOutput()) continue;
    break;
  }
  if (
    first === "timeout" ||
    first === "end" ||
    (typeof first === "object" && first !== null && "error" in first)
  ) {
    await cleanup();
    const reason =
      first === "timeout"
        ? "muse SDK produced no output before the pre-commit deadline"
        : params.signal.aborted
          ? "client aborted"
          : typeof first === "object" && first !== null && "error" in first
            ? first.error.message
            : "muse turn ended before producing output";
    return {
      kind: "declined",
      reason,
      ...(params.signal.aborted ? {} : {}),
    };
  }

  const chunks = new ReadableStream<TChatCompletionChunk>({
    start(controller) {
      controller.enqueue(first);
    },
    async pull(controller) {
      const next = await nextItem();
      if (next === "end") {
        controller.close();
        await cleanup();
        return;
      }
      if (typeof next === "object" && next !== null && "error" in next) {
        controller.error(next.error);
        await cleanup();
        return;
      }
      controller.enqueue(next);
    },
    cancel() {
      abort();
    },
  });
  return { kind: "committed", chunks, sessionId: () => null };
};
