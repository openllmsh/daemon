import type { Readable } from "node:stream";

/** The SCM supervisor owns this anonymous pipe. There is no public stop route. */
export const bindServiceControl = (input: Readable, stop: () => void): (() => void) => {
  let pending = "";
  let finished = false;
  const dispose = (): void => {
    input.off("data", data);
    input.off("end", end);
    input.off("error", end);
    input.pause();
  };
  const end = (): void => {
    if (finished) return;
    finished = true;
    dispose();
    stop();
  };
  const data = (chunk: Buffer | string): void => {
    pending += chunk.toString();
    // The only legal frame fits in 64 bytes, including fragmented reads.
    if (pending.length > 64) { dispose(); return; }
    const newline = pending.indexOf("\n");
    if (newline < 0) return;
    if (pending.slice(0, newline).replace(/\r$/, "") === "openllm-service-stop-v1") end();
    else dispose();
  };
  input.on("data", data);
  input.once("end", end);
  input.once("error", end);
  return dispose;
};
