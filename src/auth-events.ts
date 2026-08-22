/**
 * Subscription-auth event sink.
 *
 * `login-flow` (and the connect adaptors) emit `AuthEvent`s; the control
 * channel registers a sink that wraps each one in a `type: "auth"` relay
 * frame and pushes status. A dedicated module so login-flow does not import
 * the WebSocket transport (that would cycle: control-channel → control-relay
 * → delegates → login-flow).
 */
import type { TAuthEvent } from "@openllmsh/protocol";

export type TAuthSink = {
  readonly emit: (event: TAuthEvent) => void;
  readonly pushStatus: () => void;
};

let sink: TAuthSink | null = null;

/** Install (or clear) the transport sink. Called from `startControlChannel`. */
export const setAuthSink = (next: TAuthSink | null): void => {
  sink = next;
};

/** Best-effort: no-op when the control channel is not running (tests, headless). */
export const emitAuth = (event: TAuthEvent): void => {
  sink?.emit(event);
};

/** Best-effort status push so a background login finalize flips the card. */
export const requestStatusPush = (): void => {
  sink?.pushStatus();
};
