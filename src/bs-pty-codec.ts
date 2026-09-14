/**
 * BridgeSessions session-worker IPC codec.
 *
 * Wire format from `bs-session-worker.h`: `[1 byte type][4 bytes BE length][payload]`.
 * Payload cap is 16 MiB. This module is pure so tests can round-trip frames
 * without a live `bs` binary.
 */

import { Schema } from "effect";

/** Adapter handshake extension; older workers ignore HELLO. */
export const WORKER_PROTOCOL_VERSION = 1;
export const WORKER_HELLO_MAX_BYTES = 4096;

const WorkerHello = Schema.Struct({
  version: Schema.Literal(WORKER_PROTOCOL_VERSION),
  build: Schema.String.pipe(Schema.maxLength(128)),
  features: Schema.Array(Schema.String.pipe(Schema.maxLength(64))).pipe(
    Schema.maxItems(32),
  ),
});

export const parseWorkerHello = (data: Uint8Array) => {
  if (data.byteLength > WORKER_HELLO_MAX_BYTES) {
    throw new Error("bridgesessions HELLO exceeds 4 KiB");
  }
  return Schema.decodeUnknownSync(WorkerHello)(
    JSON.parse(new TextDecoder().decode(data)),
  );
};

export const WMSG = {
  INPUT: 0x01,
  RESIZE: 0x02,
  DETACH: 0x03,
  PING: 0x04,
  SHUTDOWN: 0x05,
  HELLO: 0x06,
  OUTPUT: 0x81,
  SCROLLBACK: 0x82,
  DIED: 0x83,
  READY: 0x84,
  PONG: 0x85,
  ERROR: 0x86,
  HELLO_ACK: 0x87,
} as const;

export type TWorkerMsgType = (typeof WMSG)[keyof typeof WMSG];

export type TWorkerMessage = {
  readonly type: TWorkerMsgType;
  readonly data: Uint8Array;
};

/** Matches the C++ worker's 16 MiB sanity cap. */
export const WORKER_MAX_PAYLOAD = 16 * 1024 * 1024;

const writeU16be = (
  target: Uint8Array,
  offset: number,
  value: number,
): void => {
  target[offset] = (value >> 8) & 0xff;
  target[offset + 1] = value & 0xff;
};

const writeU32be = (
  target: Uint8Array,
  offset: number,
  value: number,
): void => {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
};

export const readU16be = (bytes: Uint8Array, offset = 0): number =>
  ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);

export const readU32be = (bytes: Uint8Array, offset = 0): number =>
  (((bytes[offset] ?? 0) << 24) |
    ((bytes[offset + 1] ?? 0) << 16) |
    ((bytes[offset + 2] ?? 0) << 8) |
    (bytes[offset + 3] ?? 0)) >>>
  0;

export const encodeWorkerFrame = (
  type: TWorkerMsgType,
  payload: Uint8Array | string = new Uint8Array(0),
): Uint8Array => {
  const data =
    typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
  if (data.byteLength > WORKER_MAX_PAYLOAD) {
    throw new Error("bridgesessions worker frame exceeds 16 MiB");
  }
  if (
    (type === WMSG.HELLO || type === WMSG.HELLO_ACK) &&
    data.byteLength > WORKER_HELLO_MAX_BYTES
  ) {
    throw new Error("bridgesessions HELLO exceeds 4 KiB");
  }
  const frame = new Uint8Array(5 + data.byteLength);
  frame[0] = type;
  writeU32be(frame, 1, data.byteLength);
  frame.set(data, 5);
  return frame;
};

export const encodeResizePayload = (cols: number, rows: number): Uint8Array => {
  const payload = new Uint8Array(4);
  writeU16be(payload, 0, cols);
  writeU16be(payload, 2, rows);
  return payload;
};

export type TReadyPayload = {
  readonly name: string;
  readonly childPid: number | null;
};

/** READY = UTF-8 session name + optional trailing u32be child pid. */
export const parseReadyPayload = (
  data: Uint8Array,
  expectedName?: string,
): TReadyPayload => {
  const text = new TextDecoder().decode(data);
  if (expectedName !== undefined) {
    const prefix = new TextEncoder().encode(expectedName);
    if (
      data.byteLength === prefix.byteLength + 4 &&
      text.startsWith(expectedName)
    ) {
      return {
        name: expectedName,
        childPid: readU32be(data, prefix.byteLength),
      };
    }
    if (text === expectedName) return { name: expectedName, childPid: null };
  }
  if (expectedName === undefined && data.byteLength >= 4) {
    return {
      name: new TextDecoder().decode(data.subarray(0, data.byteLength - 4)),
      childPid: readU32be(data, data.byteLength - 4),
    };
  }
  return { name: text, childPid: null };
};

export type TDiedPayload = {
  readonly exitCode: number;
  readonly signal: number;
};

/** DIED = u32be exit_code + u32be signal. */
export const parseDiedPayload = (data: Uint8Array): TDiedPayload => {
  if (data.byteLength < 8) return { exitCode: 1, signal: 0 };
  return {
    exitCode: readU32be(data, 0),
    signal: readU32be(data, 4),
  };
};

/**
 * Pull complete frames from a stream buffer. Returns parsed messages and the
 * unconsumed tail (partial header or payload).
 */
export const decodeWorkerFrames = (
  buffer: Uint8Array,
): {
  readonly messages: readonly TWorkerMessage[];
  readonly rest: Uint8Array;
} => {
  const messages: TWorkerMessage[] = [];
  let offset = 0;
  while (buffer.byteLength - offset >= 5) {
    const type = buffer[offset] as TWorkerMsgType;
    const length = readU32be(buffer, offset + 1);
    if (
      (type === WMSG.HELLO || type === WMSG.HELLO_ACK) &&
      length > WORKER_HELLO_MAX_BYTES
    ) {
      throw new Error("bridgesessions HELLO exceeds 4 KiB");
    }
    if (length > WORKER_MAX_PAYLOAD) {
      throw new Error("bridgesessions worker frame exceeds 16 MiB");
    }
    if (buffer.byteLength - offset < 5 + length) break;
    messages.push({
      type,
      data: buffer.subarray(offset + 5, offset + 5 + length),
    });
    offset += 5 + length;
  }
  return { messages, rest: buffer.subarray(offset) };
};

/** POSIX `sh -c` quoting so a worker command preserves argv exactly. */
export const posixQuote = (value: string): string =>
  `'${value.replace(/'/g, `'\\''`)}'`;

/**
 * Turn a device-session argv into a BridgeSessions `--command` string.
 * `exec` replaces the worker's `sh -c` so the session child is the real CLI.
 */
export const commandFromArgv = (argv: readonly string[]): string => {
  if (argv.length === 0) return "";
  return `exec ${argv.map(posixQuote).join(" ")}`;
};
