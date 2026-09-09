import type { TAuthLoginFailedCode } from "@openllmsh/protocol";
import { observeDoctorEvent } from "./engine";
import { safeDiagnosticMessage } from "./message";

const COOLDOWN_MS = 60_000;
let lastProtocolAt = 0;
let protocolCount = 0;
let lastTransportAt = 0;
let transportCount = 0;
const cliFailStreak = new Map<string, number>();

export const noteControlChannelProtocolFailure = (): void => {
  protocolCount += 1;
  const now = Date.now();
  if (lastProtocolAt !== 0 && now - lastProtocolAt < COOLDOWN_MS) return;
  lastProtocolAt = now;
  observeDoctorEvent({
    severity: "warn",
    message: safeDiagnosticMessage`The control channel received an invalid frame.`,
    timings: { repeat_count: protocolCount },
  });
  protocolCount = 0;
};
const noteChannelTransport = (): void => {
  transportCount += 1;
  const now = Date.now();
  if (lastTransportAt !== 0 && now - lastTransportAt < COOLDOWN_MS) return;
  lastTransportAt = now;
  observeDoctorEvent({
    severity: "warn",
    message: safeDiagnosticMessage`The control connection failed unexpectedly.`,
    timings: { repeat_count: transportCount },
  });
  transportCount = 0;
};
export const noteControlChannelClose = (opts: {
  readonly code: number;
  readonly superseded: boolean;
  readonly clean: boolean;
}): void => {
  if (opts.superseded || opts.clean) return;
  if (opts.code === 4003) noteControlChannelProtocolFailure();
  else noteChannelTransport();
};
export const noteControlChannelSocketError = (_err: unknown): void =>
  noteChannelTransport();
export const noteControlChannelHeartbeatMiss = (): void =>
  noteChannelTransport();
export const noteLoginPromptDelayed = (_opts: {
  readonly provider: string;
}): void => {
  observeDoctorEvent({
    severity: "warn",
    message: safeDiagnosticMessage`Login is still waiting for an authorize prompt.`,
  });
};
export const noteLoginTerminal = (opts: {
  readonly code: TAuthLoginFailedCode;
  readonly provider: string;
}): void => {
  if (opts.code === "user_cancelled") return;
  observeDoctorEvent({
    severity: "warn",
    message:
      opts.code === "poll_expired" || opts.code === "prompt_timeout"
        ? safeDiagnosticMessage`The login time budget expired.`
        : safeDiagnosticMessage`Login ended in an unexpected failure.`,
  });
};
export const resetCliInstallDoctorStreakForTests = (): void => {
  cliFailStreak.clear();
  lastProtocolAt = 0;
  protocolCount = 0;
  lastTransportAt = 0;
  transportCount = 0;
};
export const noteCliInstallProbeResult = (opts: {
  readonly provider: string;
  readonly version: string | null;
  readonly installed: boolean;
}): void => {
  if (!opts.installed || opts.version !== null) {
    cliFailStreak.delete(opts.provider);
    return;
  }
  const n = (cliFailStreak.get(opts.provider) ?? 0) + 1;
  cliFailStreak.set(opts.provider, n);
  if (n !== 3) return;
  observeDoctorEvent({
    severity: "warn",
    message: safeDiagnosticMessage`The installed client version could not be read repeatedly.`,
    timings: { repeat_count: n },
  });
};

/** Local refresh behavior consumes these errnos; they are not report labels. */
export const REFRESH_NETWORK_ERRNOS = [
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "ECONNRESET",
] as const;
const REFRESH_NETWORK_ERRNO_RE = new RegExp(
  `\\b(${REFRESH_NETWORK_ERRNOS.join("|")})\\b`,
  "i",
);
export const matchRefreshNetworkErrno = (text: string): string | null =>
  text.match(REFRESH_NETWORK_ERRNO_RE)?.[1]?.toUpperCase() ?? null;

export const noteWalkerStreamTerminal = (opts: {
  readonly aborted: boolean;
  readonly hang: boolean;
  readonly err: unknown;
}): void => {
  if (opts.aborted) return;
  observeDoctorEvent({
    severity: "warn",
    message: opts.hang
      ? safeDiagnosticMessage`The stream stopped making progress.`
      : safeDiagnosticMessage`The stream ended in an unexpected failure.`,
  });
};
export const runDoctorHookPromise = (work: Promise<unknown>): Promise<void> =>
  work.then(
    () => undefined,
    () => undefined,
  );
