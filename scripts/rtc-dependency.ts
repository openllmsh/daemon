import { DtlsServer } from "werift";

/** Fail a standard release build if an old node_modules tree bypasses the
 * pinned dependency patch. Construction uses no network or persistent state. */
export const assertRtcDependency = (): void => {
  const socket = new DtlsServer({ transport: {
    type: "udp", address: { address: "127.0.0.1", family: "IPv4", port: 0 }, closed: false,
    send: async () => {}, close: async () => {}, onData: () => {},
  } });
  try {
    const receiver = (socket as unknown as {
      handshakeReceiver?: { receive?: unknown; close?: unknown; pending?: unknown; abort?: unknown };
    }).handshakeReceiver;
    if (!receiver || typeof receiver.receive !== "function" || typeof receiver.close !== "function" ||
        !(receiver.pending instanceof Map) || !(receiver.abort instanceof AbortController)) {
      throw new Error("Missing pinned werift DTLS repair; run bun install --frozen-lockfile in daemon before building");
    }
  } finally { socket.close(); }
};

if (import.meta.main) assertRtcDependency();
