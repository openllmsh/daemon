import type { TRtcDataChannelLike } from "@openllmsh/tunnel/rtc-duplex";
import type { RTCDataChannel } from "werift";

/**
 * Adapt werift's channel to the thin {@link TRtcDataChannelLike} surface.
 * werift's `send` only accepts `Buffer | string` (not `ArrayBuffer`); the mux
 * always hands a `Uint8Array`, which is a Buffer-view under Bun/Node.
 */
export const asRtcDataChannelLike = (
  dc: RTCDataChannel,
): TRtcDataChannelLike => ({
  get readyState() {
    return dc.readyState;
  },
  get bufferedAmount() {
    return dc.bufferedAmount;
  },
  send: (data) => {
    if (typeof data === "string") {
      dc.send(data);
      return;
    }
    if (Buffer.isBuffer(data)) {
      dc.send(data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      dc.send(Buffer.from(data));
      return;
    }
    // ArrayBufferView (Uint8Array, …) — copy into a Buffer for werift.
    dc.send(
      Buffer.from(
        new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
      ),
    );
  },
  close: () => dc.close(),
  get onmessage() {
    return dc.onmessage as TRtcDataChannelLike["onmessage"];
  },
  set onmessage(value) {
    dc.onmessage = value as RTCDataChannel["onmessage"];
  },
  get onclose() {
    return dc.onclose as TRtcDataChannelLike["onclose"];
  },
  set onclose(value) {
    dc.onclose = value as RTCDataChannel["onclose"];
  },
  get onerror() {
    return dc.onerror as TRtcDataChannelLike["onerror"];
  },
  set onerror(value) {
    dc.onerror = value as RTCDataChannel["onerror"];
  },
});
