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
 * This module never imports `@muse-code/sdk` at compile time (the package is
 * not a project dependency yet). Callers inject a host factory that matches
 * the official Connection / session / turn surface. Tests supply a fake.
 * The default factory dynamically loads the official package when present.
 *
 * Safety is conservative: `--disable-write` + `--disable-shell`, approval
 * mode `denyUnmatched`, and every native-tool approval is denied. Exact
 * `session/setModel` + `session/read` confirmation is required before a turn
 * starts. Missing usage is omitted, never estimated as real.
 */

import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TChatCompletionChunk } from "@openllmsh/protocol";
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
import type { TMuseInputPart } from "./muse-request";
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

/** Approval mode that refuses unmatched native tools (official `ApprovalMode`). */
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

/** User Muse settings/MCP overlay and ACP-only yolo flags must not leak into
 *  gateway execution. Official auth stays in the isolated HOME overlay. */
const SETTINGS_LEAK_KEYS = new Set([
  "XDG_CONFIG_HOME",
  "MUSE_CODE_ACP_ALLOW_YOLO",
]);

type TNodeEnv = "development" | "production" | "test";

const nodeEnvOf = (value: string | undefined): TNodeEnv => {
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
  const nodeEnv = nodeEnvOf(cleaned.NODE_ENV ?? process.env.NODE_ENV);
  const next: NodeJS.ProcessEnv = { NODE_ENV: nodeEnv };
  for (const [key, value] of Object.entries(cleaned)) {
    if (key === "NODE_ENV") continue;
    if (EXPLICIT_METERED_KEYS.has(key)) continue;
    if (OPENLLM_RECURSION_KEYS.has(key)) continue;
    if (SETTINGS_LEAK_KEYS.has(key)) continue;
    if (API_KEY_OVERRIDE_RE.test(key)) continue;
    next[key] = value;
  }
  return next;
};

export type TMuseHostSpawnOptions = {
  readonly command: string;
  readonly args: ReadonlyArray<string>;
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly onStderr?: (chunk: string) => void;
};

export type TMuseSessionRead = {
  readonly sessionId: string;
  readonly modelId: string | null;
  readonly providerId?: string | null;
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
  sendUserTurn(input: ReadonlyArray<TMuseInputPart>): Promise<TMuseTurn>;
  onApproval(
    handler: (request: {
      readonly approvalId: string;
      readonly availableChoices: ReadonlyArray<{
        readonly choiceId: string;
        readonly decision: string;
        readonly scope: string;
      }>;
    }) =>
      | Promise<{ readonly choiceId: string }>
      | { readonly choiceId: string },
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

const denyNativeApproval = (request: {
  readonly availableChoices: ReadonlyArray<{
    readonly choiceId: string;
    readonly decision: string;
    readonly scope: string;
  }>;
}): { readonly choiceId: string } => {
  const deny =
    request.availableChoices.find(
      (choice) =>
        (choice.decision === "denied" || choice.decision === "abort") &&
        choice.scope === "once",
    ) ??
    request.availableChoices.find(
      (choice) => choice.decision === "denied" || choice.decision === "abort",
    );
  if (deny === undefined) {
    throw new Error(
      "Muse offered no deny/abort choice; native tool was not approved",
    );
  }
  return { choiceId: deny.choiceId };
};

type TOfficialSdk = {
  readonly spawnMspConnection: (options: {
    readonly command: string;
    readonly args?: readonly string[];
    readonly cwd?: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly onStderr?: (chunk: string) => void;
    readonly shutdownTimeoutMs?: number;
  }) => {
    initialize: (params: {
      readonly clientInfo: { readonly name: string; readonly version: string };
    }) => Promise<{
      readonly connection: {
        command: (
          method: string,
          params: Record<string, unknown>,
          options?: { readonly maxAttempts?: number },
        ) => Promise<Record<string, unknown>>;
        request: (
          method: string,
          params?: Record<string, unknown>,
        ) => Promise<Record<string, unknown>>;
      };
      readonly initializeResult?: unknown;
    }>;
    close: () => Promise<unknown>;
  };
  readonly MuseClient: new (
    connection: unknown,
    options: { readonly durability: string },
  ) => {
    startSession: (options: Record<string, unknown>) => Promise<{
      readonly sessionId: string;
      readonly opening?: {
        readonly result?: { readonly session?: Record<string, unknown> };
      };
      onApproval: (handler: (request: unknown) => Promise<unknown>) => void;
      sendUserTurn: (options: {
        readonly input: ReadonlyArray<TMuseInputPart>;
      }) => Promise<{
        readonly turnId: string;
        readonly completed: Promise<{
          readonly kind: string;
          readonly params?: { readonly terminal?: string };
          readonly usage?: TMuseSessionUsage;
        }>;
        items: () => AsyncIterable<TMuseFoldedItem>;
        deltas: () => AsyncIterable<TMuseItemDelta>;
      }>;
    }>;
    close: () => Promise<void>;
  };
  readonly readSessionDurability: (result: unknown) => string;
};

const loadOfficialSdk = async (): Promise<TOfficialSdk> => {
  const specifier = "@muse-code/sdk";
  try {
    return (await import(specifier)) as TOfficialSdk;
  } catch (error) {
    throw new Error(
      "@muse-code/sdk is not a daemon dependency yet; inject hostFactory for hermetic tests",
      { cause: error },
    );
  }
};

const wrapOfficialHost = async (
  options: TMuseHostSpawnOptions,
): Promise<TMuseHost> => {
  const sdk = await loadOfficialSdk();
  const handshake = sdk.spawnMspConnection({
    command: options.command,
    args: [...options.args],
    cwd: options.cwd,
    env: options.env,
    ...(options.onStderr !== undefined ? { onStderr: options.onStderr } : {}),
    shutdownTimeoutMs: 1_000,
  });
  const spawned = await handshake.initialize({
    clientInfo: { name: "openllm-daemon", version: DAEMON_VERSION },
  });
  const durability = sdk.readSessionDurability(spawned.initializeResult);
  const client = new sdk.MuseClient(spawned.connection, { durability });
  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    await client.close().catch(() => {});
    await handshake.close().catch(() => {});
  };
  return {
    close,
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
      session.onApproval(async (request) => {
        const rec = asRecord(request);
        const choices = Array.isArray(rec?.availableChoices)
          ? rec.availableChoices.flatMap((choice) => {
              const row = asRecord(choice);
              const choiceId = asString(row?.choiceId);
              const decision = asString(row?.decision);
              const scope = asString(row?.scope);
              return choiceId !== null && decision !== null && scope !== null
                ? [{ choiceId, decision, scope }]
                : [];
            })
          : [];
        return denyNativeApproval({ availableChoices: choices });
      });
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
          const saved = asRecord(observed.session);
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
          };
        },
        sendUserTurn: async (input) => {
          const turn = await session.sendUserTurn({ input });
          return {
            turnId: turn.turnId,
            completed: turn.completed.then((outcome) => ({
              kind:
                outcome.kind === "completed" ||
                outcome.kind === "failed" ||
                outcome.kind === "cancelled" ||
                outcome.kind === "unqueued" ||
                outcome.kind === "terminalUnknown"
                  ? outcome.kind
                  : "failed",
              terminal: asString(outcome.params?.terminal) ?? undefined,
              ...(outcome.usage !== undefined ? { usage: outcome.usage } : {}),
            })),
            items: () => turn.items(),
            deltas: () => turn.deltas(),
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

const confirmExactModel = async (
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
  const workspace =
    params.cwd ??
    (await mkdtemp(join(spawnCwd(params.env) || tmpdir(), "muse-turn-")));
  const ownedCwd = params.cwd === undefined;
  const env = {
    ...cleanMuseSpawnEnv(params.env),
    XDG_CONFIG_HOME: workspace,
  };
  const hostFactory = params.hostFactory ?? defaultMuseHostFactory;
  const rpcTimeoutMs = params.rpcTimeoutMs ?? MUSE_RPC_TIMEOUT_MS;
  const turn = createMuseTurnState({
    providerModelId: params.providerModelId,
  });

  const queue: Array<TChatCompletionChunk | "end"> = [];
  let wake: (() => void) | null = null;
  const push = (item: TChatCompletionChunk | "end"): void => {
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

  let host: TMuseHost | null = null;
  let session: TMuseSession | null = null;
  let activeTurn: TMuseTurn | null = null;
  let idleTimer: ReturnType<typeof setInterval> | undefined;
  let turnTimer: ReturnType<typeof setTimeout> | undefined;

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
    if (ownedCwd) {
      await rm(workspace, { recursive: true, force: true }).catch(() => {});
    }
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
    host = await withTimeout(
      hostFactory({
        command: spawn.command,
        args: spawn.args,
        cwd: workspace,
        env,
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
    );
    session = await withTimeout(
      host.startSession({
        sessionId: crypto.randomUUID(),
        workspaceRoot: workspace,
        modelId: params.providerModelId,
        ...(params.providerId !== undefined
          ? { providerId: params.providerId }
          : {}),
        approvalMode: MUSE_APPROVAL_MODE,
      }),
      rpcTimeoutMs,
      "muse session/start",
    );
    session.onApproval(denyNativeApproval);
    await withTimeout(
      confirmExactModel(session, params.providerModelId, params.providerId),
      rpcTimeoutMs,
      "muse session/setModel",
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
      await Promise.all([
        pumpItems.catch(() => {}),
        pumpDeltas.catch(() => {}),
      ]);
      if (ended) return;
      if (!turn.sawOutput() && outcome.kind !== "completed") {
        ended = true;
        push("end");
        void cleanup();
        return;
      }
      endWith(turn.finish(outcome.terminal ?? outcome.kind));
      void cleanup();
    } catch (error: unknown) {
      await Promise.all([
        pumpItems.catch(() => {}),
        pumpDeltas.catch(() => {}),
      ]);
      if (ended) return;
      logError(
        "native-runtime",
        safeDiagnosticMessage`muse turn failed after start`,
        { error: error instanceof Error ? error.message : String(error) },
      );
      if (turn.sawOutput()) endWith(turn.finish("failed"));
      else {
        ended = true;
        push("end");
      }
      void cleanup();
    }
  })();

  const nextItem = async (): Promise<TChatCompletionChunk | "end"> => {
    for (;;) {
      const item = queue.shift();
      if (item !== undefined) return item;
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    }
  };

  let first: TChatCompletionChunk | "end" | "timeout";
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
  if (first === "timeout" || first === "end") {
    await cleanup();
    const reason =
      first === "timeout"
        ? "muse SDK produced no output before the pre-commit deadline"
        : params.signal.aborted
          ? "client aborted"
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
      controller.enqueue(next);
    },
    cancel() {
      abort();
    },
  });
  return { kind: "committed", chunks, sessionId: () => null };
};
