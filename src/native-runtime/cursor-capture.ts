/**
 * Cursor bridge request-capture (W3) — parent-side IPC + spawn decoration.
 *
 * The child preload (`cursor-capture-preload.txt` → materialized `.cjs`) hooks
 * ConnectRPC send paths inside Cursor's bundled Node. This module:
 *   1. materializes that preload (embedded text → temp `.cjs` file),
 *   2. listens on a request-private unix socket,
 *   3. validates AgentService Run* envelopes,
 *   4. offers them to the shared `request-capture` session,
 *   5. settles the child locally (maps onto ACP `session/cancel`).
 *
 * Default off. Do not set the child env unless serve activates a ready
 * `bridge-capture` route for cursor (capability table currently omits it).
 *
 * ## Packaging (integrator-owned compile)
 *
 * The preload source lives as `.txt` and is imported with `{ type: "text" }` so
 * `bun build --compile` inlines it and TypeScript does not type it through
 * `allowJs` as a CommonJS exports object. At runtime
 * `materializeCursorCapturePreload` writes the bytes to a temp `.cjs` path the
 * child can `--require`. No separate compile asset copy is required when the
 * text import stays in the daemon's compile graph (this file is reachable from
 * `cursor-acp.ts` → `serve.ts` → `main.ts`).
 *
 * If a future compile split drops native-runtime from the binary entry, the
 * integrator must either keep this module imported from the entry graph or
 * ship a materialized `cursor-capture-preload.cjs` beside the binary and point
 * `OPENLLM_CURSOR_CAPTURE_PRELOAD_PATH` at it.
 *
 * ## Integration blocker (response decode)
 *
 * Captured envelopes are Connect protocol (`application/connect+proto` /
 * `+json`) for `agent.v1.AgentService/Run|RunSSE|RunPoll`. There is no verified
 * Connect→OpenAI chunk decoder in-tree. Until one exists (or a bounded decode
 * of the observed wire shape is proven), do NOT replace the ACP response path
 * in `serve.ts` / `runCursorNative`. Capture+suppress+settlement is the
 * completed data path; response consumption remains a precise blocker.
 */

import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { providerDeclaresBridgeCapture } from "../sub-method";
import preloadSource from "./cursor-capture-preload.txt" with { type: "text" };
import type {
  TBuilderSettlement,
  TCaptureDestinationPolicy,
  TCapturedHeaderPair,
  TCapturedRequestEnvelope,
  TRequestCaptureSession,
} from "./request-capture";
import {
  createRequestCaptureSession,
  RequestCaptureError,
} from "./request-capture";

export const CURSOR_CAPTURE_SOCK_ENV = "OPENLLM_CURSOR_CAPTURE_SOCK";
export const CURSOR_CAPTURE_TOKEN_ENV = "OPENLLM_CURSOR_CAPTURE_TOKEN";
export const CURSOR_CAPTURE_EXTERNAL_ORIGIN_ENV =
  "OPENLLM_CURSOR_CAPTURE_EXTERNAL_ORIGIN";
export const CURSOR_CAPTURE_PRELOAD_LOADED_ENV =
  "OPENLLM_CURSOR_CAPTURE_PRELOAD_LOADED";

/** Default Cursor agent API origin (CLI `--endpoint` default). */
export const CURSOR_AGENT_DEFAULT_ORIGIN = "https://api2.cursor.sh";

export const CURSOR_AGENT_SERVICE_PATH_RE =
  /\/agent\.v1\.AgentService\/(Run|RunSSE|RunPoll)(?:\?|$)/;

export const CURSOR_CONNECT_CONTENT_TYPE_RE =
  /(?:^|;\s*)application\/connect\+(?:proto|json)(?:\s|;|$)/i;

export type TCursorCaptureIpcCaptureMessage = {
  readonly type: "capture";
  readonly token: string;
  readonly id: string;
  readonly transport: "connect";
  readonly wire: "http" | "http2" | "fetch";
  readonly method: string;
  readonly observedUrl: string;
  readonly externalUrl: string;
  readonly headers: ReadonlyArray<readonly [string, string]>;
  readonly bodyBase64: string | null;
  readonly framing: Readonly<Record<string, string | number | boolean | null>>;
};

export type TCursorCaptureChildEnv = {
  readonly NODE_OPTIONS: string;
  readonly [CURSOR_CAPTURE_SOCK_ENV]: string;
  readonly [CURSOR_CAPTURE_TOKEN_ENV]: string;
  readonly [CURSOR_CAPTURE_EXTERNAL_ORIGIN_ENV]?: string;
};

export type TCursorCaptureBridge = {
  readonly session: TRequestCaptureSession;
  readonly childEnv: TCursorCaptureChildEnv;
  readonly preloadPath: string;
  readonly socketPath: string;
  /** Settle the child after daemon ownership transfer / cancel. */
  settleChild(settlement: TBuilderSettlement): void;
  /** Wait until the preload offers a capture (or the session aborts). */
  waitForOffer(): Promise<TCapturedRequestEnvelope>;
  dispose(): Promise<void>;
};

const appendNodeRequire = (
  existing: string | undefined,
  preloadPath: string,
): string => {
  const flag = `--require ${preloadPath}`;
  if (existing === undefined || existing.trim().length === 0) return flag;
  // Avoid double-injecting the same path.
  if (existing.includes(preloadPath)) return existing;
  return `${existing} ${flag}`;
};

export const isCursorAgentServiceInferencePath = (
  pathWithQuery: string,
): boolean => CURSOR_AGENT_SERVICE_PATH_RE.test(pathWithQuery);

export const isCursorConnectContentType = (
  contentType: string | undefined,
): boolean =>
  typeof contentType === "string" &&
  contentType.length > 0 &&
  CURSOR_CONNECT_CONTENT_TYPE_RE.test(contentType);

/**
 * Classify a candidate outbound request as Cursor AgentService inference
 * (capture) vs everything else (pass-through). Native file_service traffic is
 * not visible to the JS preload; this classifier documents the JS boundary.
 */
export const classifyCursorOutboundRequest = (args: {
  readonly url: string;
  readonly headers?: ReadonlyArray<TCapturedHeaderPair> | Headers;
}):
  | { readonly kind: "agent_service_inference"; readonly path: string }
  | { readonly kind: "non_inference"; readonly reason: string } => {
  let path: string;
  try {
    const u = new URL(args.url);
    path = `${u.pathname}${u.search}`;
  } catch {
    return { kind: "non_inference", reason: "invalid_url" };
  }
  if (!isCursorAgentServiceInferencePath(path)) {
    if (path.includes("file_service") || path.includes("FileService")) {
      return {
        kind: "non_inference",
        reason: "file_service_codebase_sync_not_js_inference",
      };
    }
    return { kind: "non_inference", reason: "not_agent_service_run" };
  }
  return { kind: "agent_service_inference", path };
};

export const cursorCaptureDestinationPolicy = (args?: {
  readonly allowedOrigins?: ReadonlySet<string>;
  readonly allowLoopback?: boolean;
}): TCaptureDestinationPolicy => ({
  allowedOrigins:
    args?.allowedOrigins ?? new Set([CURSOR_AGENT_DEFAULT_ORIGIN]),
  allowLoopback: args?.allowLoopback ?? false,
});

/**
 * Write the embedded preload source to `targetDir/cursor-capture-preload.cjs`.
 * Mode 0o600 — child-readable via the daemon-chosen path in NODE_OPTIONS.
 */
export const materializeCursorCapturePreload = async (
  targetDir: string,
): Promise<string> => {
  await mkdir(targetDir, { recursive: true });
  const path = join(targetDir, "cursor-capture-preload.cjs");
  await writeFile(path, preloadSource, { mode: 0o600 });
  return path;
};

export const buildCursorCaptureChildEnv = (args: {
  readonly baseEnv?: Readonly<Record<string, string | undefined>>;
  readonly preloadPath: string;
  readonly socketPath: string;
  readonly token: string;
  readonly externalOrigin?: string;
}): TCursorCaptureChildEnv => {
  const base = args.baseEnv ?? {};
  const nodeOptions = appendNodeRequire(
    typeof base.NODE_OPTIONS === "string" ? base.NODE_OPTIONS : undefined,
    args.preloadPath,
  );
  const env: TCursorCaptureChildEnv = {
    NODE_OPTIONS: nodeOptions,
    [CURSOR_CAPTURE_SOCK_ENV]: args.socketPath,
    [CURSOR_CAPTURE_TOKEN_ENV]: args.token,
  };
  if (args.externalOrigin !== undefined && args.externalOrigin.length > 0) {
    return {
      ...env,
      [CURSOR_CAPTURE_EXTERNAL_ORIGIN_ENV]: args.externalOrigin,
    };
  }
  return env;
};

/**
 * Whether Cursor declares a serve-activated `bridge-capture` route.
 * Always false until the capability table admits cursor (Connect decoder ready).
 */
export const isCursorBridgeRequestCaptureEnabled = (): boolean =>
  providerDeclaresBridgeCapture("cursor");

const decodeBodyBase64 = (raw: string | null): Uint8Array | null => {
  if (raw === null || raw.length === 0) return null;
  return new Uint8Array(Buffer.from(raw, "base64"));
};

const toCapturedEnvelope = (
  msg: TCursorCaptureIpcCaptureMessage,
): TCapturedRequestEnvelope => ({
  transport: "connect",
  method: msg.method,
  observedUrl: msg.observedUrl,
  externalUrl: msg.externalUrl,
  headers: msg.headers.map(([n, v]) => [n, v] as const),
  body: decodeBodyBase64(msg.bodyBase64),
  framing: {
    entries: {
      ...msg.framing,
      wire: msg.wire,
      provider: "cursor",
    },
  },
});

/**
 * Open a parent-side capture bridge: temp preload + unix IPC + capture session.
 *
 * Call only when capture is enabled for `cursor`. The returned `childEnv` must
 * be merged into the AcpClient spawn env (after `cliEnv`, before/through
 * `cleanNativeSpawnEnv` — NODE_OPTIONS is not poison-stripped).
 */
export const openCursorCaptureBridge = async (args: {
  readonly destinationPolicy?: TCaptureDestinationPolicy;
  readonly signal?: AbortSignal;
  readonly maxBodyBytes?: number;
  readonly captureTimeoutMs?: number;
  readonly externalOrigin?: string;
  /** Override temp root (tests). */
  readonly tempRoot?: string;
}): Promise<TCursorCaptureBridge> => {
  const policy =
    args.destinationPolicy ??
    cursorCaptureDestinationPolicy({ allowLoopback: true });
  const session = createRequestCaptureSession({
    destinationPolicy: policy,
    signal: args.signal,
    maxBodyBytes: args.maxBodyBytes,
    captureTimeoutMs: args.captureTimeoutMs,
  });

  const root =
    args.tempRoot ?? (await mkdtemp(join(tmpdir(), "openllm-cursor-capture-")));
  const preloadPath = await materializeCursorCapturePreload(root);
  const socketPath = join(root, "ipc.sock");
  const token = randomBytes(32).toString("hex");

  let childSettle: ((settlement: TBuilderSettlement) => void) | null = null;
  let lastCaptureId: string | null = null;
  /** @type {import('node:net').Socket | null} */
  let activeSocket: import("node:net").Socket | null = null;

  const server = createServer((socket) => {
    activeSocket = socket;
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      for (;;) {
        const nl = buffer.indexOf("\n");
        if (nl < 0) break;
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (line.length === 0) continue;
        void handleLine(line, socket);
      }
    });
    socket.on("close", () => {
      if (activeSocket === socket) activeSocket = null;
    });
  });

  const handleLine = async (
    line: string,
    socket: import("node:net").Socket,
  ): Promise<void> => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return;
    }
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      (parsed as { type?: unknown }).type !== "capture"
    ) {
      return;
    }
    const msg = parsed as TCursorCaptureIpcCaptureMessage;
    if (msg.token !== token) {
      socket.write(
        `${JSON.stringify({
          type: "settle",
          id: msg.id,
          settlement: { kind: "failed", reason: "unauthorized ipc token" },
        })}\n`,
      );
      return;
    }
    const classified = classifyCursorOutboundRequest({
      url: msg.observedUrl,
      headers: msg.headers.map(([n, v]) => [n, v] as const),
    });
    if (classified.kind !== "agent_service_inference") {
      socket.write(
        `${JSON.stringify({
          type: "settle",
          id: msg.id,
          settlement: {
            kind: "failed",
            reason: `rejected non-inference capture: ${classified.reason}`,
          },
        })}\n`,
      );
      return;
    }

    lastCaptureId = msg.id;
    childSettle = (settlement) => {
      try {
        socket.write(
          `${JSON.stringify({
            type: "settle",
            id: msg.id,
            settlement,
          })}\n`,
        );
      } catch {
        // child gone
      }
    };

    try {
      // Offer to the shared session — this suppresses "daemon send" ownership
      // transfer; the child's await resolves only when settleChild runs (or
      // session terminal settles the builder).
      const settlement = await session.captureSend(toCapturedEnvelope(msg));
      childSettle?.(settlement);
    } catch (err) {
      const reason =
        err instanceof RequestCaptureError
          ? `${err.code}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err);
      childSettle?.({ kind: "failed", reason });
    }
  };

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const childEnv = buildCursorCaptureChildEnv({
    preloadPath,
    socketPath,
    token,
    externalOrigin: args.externalOrigin,
  });

  let disposed = false;
  return {
    session,
    childEnv,
    preloadPath,
    socketPath,
    settleChild(settlement) {
      // Always unblock captureSend's builder waiter — writing the IPC settle
      // alone would leave the parent handleLine await hung.
      session.settleBuilder(settlement);
      if (childSettle !== null) {
        childSettle(settlement);
        return;
      }
      if (lastCaptureId !== null && activeSocket !== null) {
        try {
          activeSocket.write(
            `${JSON.stringify({
              type: "settle",
              id: lastCaptureId,
              settlement,
            })}\n`,
          );
        } catch {
          // ignore
        }
      }
    },
    waitForOffer: () => session.takeCaptured(),
    async dispose() {
      if (disposed) return;
      disposed = true;
      session.dispose();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
      try {
        await rm(root, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    },
  };
};

/**
 * Map a builder settlement onto ACP cancel. Prefer `session/cancel` + await
 * terminal; process kill is cleanup only — not proof of graceful reuse.
 */
export const settleCursorCaptureViaAcpCancel = (args: {
  readonly cancelSession: () => void;
  readonly settlement: TBuilderSettlement;
}): void => {
  // Settlement kind does not invent assistant history — cancel is always the
  // local terminal for a suppressed inference send.
  void args.settlement;
  args.cancelSession();
};
