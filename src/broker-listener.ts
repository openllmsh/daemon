/**
 * Authenticated loopback broker for the local `openllm` CLI. This is not a
 * browser surface: it deliberately has no CORS policy and requires the daemon
 * API key on every HTTP request and WebSocket upgrade.
 */

import { timingSafeEqual } from "node:crypto";
import type {
  TDeviceSessionCli,
  TSessionStreamOpenPayload,
} from "@openllmsh/protocol";
import { DeviceSessionCli, SESSION_ID_PATTERN } from "@openllmsh/protocol";
import { decodeJsonPayload, encodeJsonPayload } from "@openllmsh/tunnel/codec";
import { Schema as S } from "effect";
import { daemonEnv } from "./env";
import { readAllLocalSessions } from "./local-sessions";
import type { TSessionStream } from "./session-host";
import {
  bindSessionStream,
  deviceSessionsForList,
  killSession,
} from "./session-host";

type TBrokerSocketData = {
  stream: BrokerSessionStream | null;
  opened: boolean;
  drainWaiters: Set<() => void>;
};

type TBrokerSocket = Bun.ServerWebSocket<TBrokerSocketData>;

type TBrokerEnvelope = {
  readonly t?: unknown;
  readonly open?: unknown;
  readonly p?: unknown;
};

type TBrokerOpen = {
  readonly session_id?: unknown;
  readonly cli?: unknown;
  readonly cols?: unknown;
  readonly rows?: unknown;
  readonly mode?: unknown;
  readonly title?: unknown;
  readonly dangerous?: unknown;
  readonly vendor_args?: unknown;
  readonly cwd?: unknown;
};

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const keyMatches = (req: Request): boolean => {
  const configured = daemonEnv().apiKey;
  const authorization = req.headers.get("authorization");
  if (configured === null || authorization === null) return false;
  const prefix = "Bearer ";
  if (!authorization.startsWith(prefix)) return false;
  const supplied = authorization.slice(prefix.length);
  const expected = Buffer.from(configured);
  const actual = Buffer.from(supplied);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Protocol-owned membership — tracks future DeviceSessionCli additions. */
const isCli: (value: unknown) => value is TDeviceSessionCli =
  S.is(DeviceSessionCli);

const isDimension = (value: unknown): value is number =>
  typeof value === "number" &&
  Number.isInteger(value) &&
  value >= 1 &&
  value <= 1024;

const parseVendorArgs = (value: unknown): readonly string[] | null => {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 64) return null;
  if (
    !value.every(
      (arg) =>
        typeof arg === "string" &&
        arg.length >= 1 &&
        arg.length <= 512 &&
        !arg.includes("\0"),
    )
  )
    return null;
  return value;
};

const parseOpen = (
  value: unknown,
): {
  readonly open: TSessionStreamOpenPayload;
  readonly vendorArgs: readonly string[];
} | null => {
  if (!isRecord(value)) return null;
  const open: TBrokerOpen = value;
  if (
    typeof open.session_id !== "string" ||
    !SESSION_ID_PATTERN.test(open.session_id) ||
    !isCli(open.cli) ||
    !isDimension(open.cols) ||
    !isDimension(open.rows) ||
    (open.mode !== "spawn" && open.mode !== "attach") ||
    (open.title !== undefined &&
      (typeof open.title !== "string" ||
        open.title.length > 80 ||
        open.title.includes("\0"))) ||
    (open.dangerous !== undefined && typeof open.dangerous !== "boolean") ||
    (open.cwd !== undefined &&
      (typeof open.cwd !== "string" ||
        open.cwd.length < 1 ||
        open.cwd.length > 1024 ||
        open.cwd.includes("\0") ||
        !open.cwd.startsWith("/")))
  )
    return null;
  const vendorArgs = parseVendorArgs(open.vendor_args);
  if (vendorArgs === null) return null;
  return {
    open: {
      kind: "session",
      session_id: open.session_id,
      cli: open.cli,
      cols: open.cols,
      rows: open.rows,
      mode: open.mode,
      ...(open.title === undefined ? {} : { title: open.title }),
      ...(open.dangerous === true ? { dangerous: true } : {}),
      ...(open.cwd === undefined ? {} : { cwd: open.cwd }),
    },
    vendorArgs,
  };
};

class BrokerSessionStream implements TSessionStream {
  private readonly dataHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly ctrlHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly resetHandlers = new Set<(payload: Uint8Array) => unknown>();
  private readonly endHandlers = new Set<() => void>();
  private resetSent = false;

  constructor(private readonly socket: TBrokerSocket) {}

  write = (bytes: Uint8Array): Promise<void> => {
    const status = this.socket.sendBinary(bytes);
    if (status > 0) return Promise.resolve();
    if (status === 0) return Promise.reject(new Error("broker socket closed"));
    return new Promise<void>((resolve) => {
      this.socket.data.drainWaiters.add(resolve);
    });
  };

  sendCtrl = (payload: Uint8Array): void => {
    const decoded = decodeJsonPayload(payload);
    if (decoded !== undefined)
      this.socket.sendText(JSON.stringify({ t: "ctrl", p: decoded }));
  };

  reset = (payload?: Uint8Array): void => {
    if (this.resetSent) return;
    this.resetSent = true;
    const decoded =
      payload === undefined ? undefined : decodeJsonPayload(payload);
    this.socket.sendText(
      JSON.stringify({
        t: "reset",
        p: isRecord(decoded) ? decoded : { code: "protocol_error" },
      }),
    );
    this.socket.close();
  };

  end = (): void => {
    this.socket.close();
  };

  onData = (handler: (payload: Uint8Array) => unknown): (() => void) => {
    this.dataHandlers.add(handler);
    return () => this.dataHandlers.delete(handler);
  };

  onCtrl = (handler: (payload: Uint8Array) => unknown): (() => void) => {
    this.ctrlHandlers.add(handler);
    return () => this.ctrlHandlers.delete(handler);
  };

  onReset = (handler: (payload: Uint8Array) => unknown): (() => void) => {
    this.resetHandlers.add(handler);
    return () => this.resetHandlers.delete(handler);
  };

  onEnd = (handler: () => void): (() => void) => {
    this.endHandlers.add(handler);
    return () => this.endHandlers.delete(handler);
  };

  receiveData = (payload: Uint8Array): void => {
    for (const handler of this.dataHandlers) handler(payload);
  };

  receiveCtrl = (payload: unknown): void => {
    for (const handler of this.ctrlHandlers)
      handler(encodeJsonPayload(payload));
  };

  closed = (): void => {
    if (this.resetSent) {
      for (const handler of this.resetHandlers) handler(new Uint8Array());
      return;
    }
    for (const handler of this.endHandlers) handler();
  };
}

const protocolError = (socket: TBrokerSocket): void => {
  const stream = socket.data.stream ?? new BrokerSessionStream(socket);
  socket.data.stream = stream;
  stream.reset(encodeJsonPayload({ code: "protocol_error" }));
};

/** Routes `/broker/*`; callers pass the Bun server to allow WebSocket upgrade. */
export const handleBrokerRequest = async (
  req: Request,
  server: Bun.Server<TBrokerSocketData>,
): Promise<Response | "upgraded" | null> => {
  const url = new URL(req.url);
  if (!url.pathname.startsWith("/broker/")) return null;
  if (!keyMatches(req)) return json(401, { error: "unauthorized" });
  if (url.pathname === "/broker/session") {
    if (req.method !== "GET") return json(404, { error: "not found" });
    return server.upgrade(req, {
      data: { stream: null, opened: false, drainWaiters: new Set() },
    })
      ? "upgraded"
      : json(400, { error: "websocket upgrade failed" });
  }
  if (url.pathname === "/broker/sessions" && req.method === "GET") {
    const sessions = await readAllLocalSessions({
      limit: 100,
      deps: { deviceSessions: deviceSessionsForList },
    });
    return json(200, { sessions });
  }
  const kill = /^\/broker\/sessions\/([^/]+)\/kill$/.exec(url.pathname);
  if (kill !== null && req.method === "POST") {
    let id: string;
    try {
      id = decodeURIComponent(kill[1] ?? "");
    } catch {
      return json(404, { ok: false });
    }
    const ok = killSession(id);
    return json(ok ? 200 : 404, { ok });
  }
  return json(404, { error: "not found" });
};

export const brokerWebsocket: Bun.WebSocketHandler<TBrokerSocketData> = {
  open: (socket): void => {
    socket.binaryType = "uint8array";
  },
  drain: (socket): void => {
    const waiters = [...socket.data.drainWaiters];
    socket.data.drainWaiters.clear();
    for (const resolve of waiters) resolve();
  },
  message: (socket, message): void => {
    // One catch-all: an exception escaping into Bun's WS runtime would tear
    // the whole listener's error path, not just this socket. Any throw from
    // parse, stream handlers, or bindSessionStream is a protocol reset here.
    try {
      const stream = socket.data.stream;
      if (typeof message !== "string") {
        if (!socket.data.opened || stream === null) {
          protocolError(socket);
          return;
        }
        stream.receiveData(new Uint8Array(message));
        return;
      }
      let envelope: TBrokerEnvelope;
      try {
        const parsed: unknown = JSON.parse(message);
        if (!isRecord(parsed)) throw new Error("not envelope");
        envelope = parsed;
      } catch {
        protocolError(socket);
        return;
      }
      if (!socket.data.opened) {
        if (envelope.t !== "open") {
          protocolError(socket);
          return;
        }
        const parsed = parseOpen(envelope.open);
        if (parsed === null) {
          protocolError(socket);
          return;
        }
        const next = new BrokerSessionStream(socket);
        socket.data.stream = next;
        socket.data.opened = true;
        bindSessionStream(next, parsed.open, {
          vendorArgs: parsed.vendorArgs,
          onExit: (code) => {
            socket.sendText(JSON.stringify({ t: "exit", code }));
          },
        });
        return;
      }
      if (envelope.t === "ctrl" && stream !== null)
        stream.receiveCtrl(envelope.p);
      // Unknown envelopes deliberately disappear for rolling CLI/daemon upgrades.
    } catch {
      protocolError(socket);
    }
  },
  close: (socket): void => {
    // Release writes parked on backpressure first — drain never fires on a
    // closed socket, so a lagging consumer's blocked write would hang the
    // per-consumer tail forever otherwise.
    const waiters = [...socket.data.drainWaiters];
    socket.data.drainWaiters.clear();
    for (const resolve of waiters) resolve();
    socket.data.stream?.closed();
  },
};
