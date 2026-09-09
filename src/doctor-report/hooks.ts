/**
 * Map existing daemon transitions onto closed diagnostic observations.
 * No new probes, no payloads, no argv.
 */
import type {
  TAuthLoginFailedCode,
  TDoctorErrorClass,
  TDoctorProvider,
} from "@openllmsh/protocol";
import { observeDoctorEvent } from "./engine";

export const asDoctorProvider = (slug: string): TDoctorProvider | undefined => {
  if (
    slug === "claude_code" ||
    slug === "chatgpt" ||
    slug === "kimi_code" ||
    slug === "grok" ||
    slug === "cursor"
  ) {
    return slug;
  }
  return undefined;
};

const PROTOCOL_FAILURE_COOLDOWN_MS = 60_000;
let lastProtocolFailureAtMs = 0;
let protocolFailureStreak = 0;

const CHANNEL_TRANSPORT_COOLDOWN_MS = 60_000;
let lastChannelTransportAtMs = 0;
let channelTransportStreak = 0;

const noteProtocolFailure = (): void => {
  const now = Date.now();
  protocolFailureStreak += 1;
  if (
    lastProtocolFailureAtMs !== 0 &&
    now - lastProtocolFailureAtMs < PROTOCOL_FAILURE_COOLDOWN_MS
  ) {
    return;
  }
  lastProtocolFailureAtMs = now;
  const n = protocolFailureStreak;
  protocolFailureStreak = 0;
  observeDoctorEvent({
    code: "control_channel_protocol_failure",
    producer: "control_channel",
    trigger: "reconnect",
    outcome: "protocol_error",
    operation: "reconnect",
    error_class: "protocol_failure",
    ...(n > 1 ? { timings: { repeat_count: n } } : {}),
  });
};

const noteChannelTransport = (errorClass: TDoctorErrorClass): void => {
  try {
    const now = Date.now();
    channelTransportStreak += 1;
    if (
      lastChannelTransportAtMs !== 0 &&
      now - lastChannelTransportAtMs < CHANNEL_TRANSPORT_COOLDOWN_MS
    ) {
      return;
    }
    lastChannelTransportAtMs = now;
    const n = channelTransportStreak;
    channelTransportStreak = 0;
    observeDoctorEvent({
      code: "control_channel_unexpected_disconnect",
      producer: "control_channel",
      trigger: "reconnect",
      outcome: errorClass === "timeout" ? "timeout" : "disconnect",
      operation: "reconnect",
      error_class: errorClass,
      ...(n > 1 ? { timings: { repeat_count: n } } : {}),
    });
  } catch {
    // Diagnostics must not affect the control channel.
  }
};

export const noteControlChannelClose = (opts: {
  readonly code: number;
  readonly superseded: boolean;
  readonly clean: boolean;
}): void => {
  if (opts.superseded || opts.clean) return;
  if (opts.code === 4003) {
    noteProtocolFailure();
    return;
  }
  noteChannelTransport("transport_connect");
};

export const noteControlChannelSocketError = (err: unknown): void => {
  noteChannelTransport(classifyControlTransport(err));
};

export const noteControlChannelHeartbeatMiss = (): void => {
  noteChannelTransport("timeout");
};

export const noteControlChannelProtocolFailure = (): void => {
  noteProtocolFailure();
};

export const noteLoginPromptDelayed = (opts: {
  readonly provider: string;
}): void => {
  try {
    const provider = asDoctorProvider(opts.provider);
    observeDoctorEvent({
      code: "login_prompt_delayed",
      producer: "login_flow",
      trigger: "login",
      outcome: "delayed",
      operation: "login",
      ...(provider !== undefined ? { provider } : {}),
    });
  } catch {
    // Diagnostics must not affect login.
  }
};

export const noteLoginTerminal = (opts: {
  readonly code: TAuthLoginFailedCode;
  readonly provider: string;
}): void => {
  if (opts.code === "user_cancelled") return;
  const provider = asDoctorProvider(opts.provider);
  const watchdog =
    opts.code === "poll_expired" || opts.code === "prompt_timeout";
  observeDoctorEvent({
    code: watchdog ? "login_watchdog_expiry" : "login_terminal_failure",
    producer: "login_flow",
    trigger: "login",
    outcome: watchdog ? "expired" : "failure",
    operation: "login",
    ...(provider !== undefined ? { provider } : {}),
    error_class:
      opts.code === "spawn_denied"
        ? "spawn_denied"
        : opts.code === "cli_crash"
          ? "cli_crash"
          : watchdog
            ? "watchdog"
            : "unclassified",
  });
};

const cliFailStreak = new Map<string, number>();

export const resetCliInstallDoctorStreakForTests = (): void => {
  cliFailStreak.clear();
  lastProtocolFailureAtMs = 0;
  protocolFailureStreak = 0;
  lastChannelTransportAtMs = 0;
  channelTransportStreak = 0;
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
  const provider = asDoctorProvider(opts.provider);
  observeDoctorEvent({
    code: "cli_install_repeated_failure",
    producer: "cli_install",
    trigger: "version_probe",
    outcome: "failure",
    operation: "install",
    ...(provider !== undefined ? { provider } : {}),
    error_class: "unclassified",
    timings: { repeat_count: n },
  });
};

/** POSIX network errnos refresh logging extracts. Doctor scan is a superset. */
export const REFRESH_NETWORK_ERRNOS = [
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "ECONNRESET",
] as const;

const BUN_CONNECT_CODES = ["CONNECTIONREFUSED", "FAILEDTOOPENSOCKET"] as const;
const DOCTOR_TIMEOUT_ERRNOS = ["UND_ERR_CONNECT_TIMEOUT", "ABORT_ERR"] as const;

const tokenBoundaryRe = (tokens: readonly string[]): RegExp =>
  new RegExp(`\\b(${tokens.join("|")})\\b`, "i");

const REFRESH_NETWORK_ERRNO_RE = tokenBoundaryRe(REFRESH_NETWORK_ERRNOS);
const ALLOWLISTED_ERRNO_RE = tokenBoundaryRe([
  ...REFRESH_NETWORK_ERRNOS,
  ...DOCTOR_TIMEOUT_ERRNOS,
  ...BUN_CONNECT_CODES,
]);

export const matchRefreshNetworkErrno = (text: string): string | null => {
  const matched = text.match(REFRESH_NETWORK_ERRNO_RE)?.[1];
  return matched !== undefined ? matched.toUpperCase() : null;
};

const DNS_ERRNOS = new Set(["ENOTFOUND", "EAI_AGAIN"]);
const CONNECT_ERRNOS = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "EHOSTUNREACH",
  "ENETUNREACH",
  ...BUN_CONNECT_CODES,
]);
const TIMEOUT_ERRNOS = new Set(["ETIMEDOUT", ...DOCTOR_TIMEOUT_ERRNOS]);
const TIMEOUT_TOKEN_RE = /\bTIMEOUT\b/;
const TIMED_OUT_RE = /\btimed out\b/i;

const evidenceStrings = (err: unknown): string[] => {
  const out: string[] = [];
  const seen = new Set<unknown>();
  let current: unknown = err;
  while (current !== undefined && current !== null && !seen.has(current)) {
    seen.add(current);
    if (typeof current === "string") {
      out.push(current);
      break;
    }
    if (typeof current !== "object") break;
    const rec = current as {
      code?: unknown;
      errno?: unknown;
      name?: unknown;
      message?: unknown;
      error?: unknown;
      cause?: unknown;
    };
    if (typeof rec.code === "string") out.push(rec.code);
    if (typeof rec.errno === "string") out.push(rec.errno);
    if (typeof rec.name === "string") out.push(rec.name);
    if (typeof rec.message === "string") out.push(rec.message);
    current = rec.cause ?? rec.error;
  }
  return out;
};

const classFromErrno = (token: string): TDoctorErrorClass | undefined => {
  const code = token.toUpperCase();
  if (DNS_ERRNOS.has(code)) return "transport_dns";
  if (CONNECT_ERRNOS.has(code)) return "transport_connect";
  if (TIMEOUT_ERRNOS.has(code)) return "timeout";
  if (
    !/\s/.test(code) &&
    (code.includes("CERT") || code === "ERR_TLS_CERT_ALTNAME_INVALID")
  ) {
    return "transport_tls";
  }
  return undefined;
};

/** Closed errno/token mapping. Never copies free-form messages onto events. */
export const classifyTransportErrno = (
  err: unknown,
): TDoctorErrorClass | undefined => {
  if (typeof err === "string") {
    const fromToken = classFromErrno(err);
    if (fromToken !== undefined) return fromToken;
  }
  for (const part of evidenceStrings(err)) {
    const fromCode = classFromErrno(part);
    if (fromCode !== undefined) return fromCode;
    const matched = part.match(ALLOWLISTED_ERRNO_RE)?.[1];
    if (matched !== undefined) {
      const fromScan = classFromErrno(matched);
      if (fromScan !== undefined) return fromScan;
    }
    if (TIMEOUT_TOKEN_RE.test(part) || TIMED_OUT_RE.test(part)) {
      return "timeout";
    }
  }
  return undefined;
};

export const classifyWalkerTransport = (err: unknown): TDoctorErrorClass =>
  classifyTransportErrno(err) ?? "upstream_http";

export const classifyControlTransport = (err: unknown): TDoctorErrorClass =>
  classifyTransportErrno(err) ?? "transport_connect";

export const classifyRefreshNetwork = (err: unknown): TDoctorErrorClass =>
  classifyTransportErrno(err) ?? "transport_connect";

export const noteWalkerStreamTerminal = (opts: {
  readonly aborted: boolean;
  readonly hang: boolean;
  readonly err: unknown;
}): void => {
  if (opts.aborted) return;
  try {
    observeDoctorEvent({
      code: opts.hang ? "stream_hang_watchdog" : "stream_unexpected_failure",
      producer: "walker",
      trigger: "stream",
      outcome: opts.hang ? "hang" : "failure",
      operation: "stream",
      error_class: opts.hang ? "watchdog" : classifyWalkerTransport(opts.err),
    });
  } catch {
    // reporting failure must not affect the stream
  }
};

export const runDoctorHookPromise = (work: Promise<unknown>): Promise<void> =>
  work.then(
    () => undefined,
    () => undefined,
  );

export const noteNativeAuthTimeout = (input: {
  readonly trigger: "native_login" | "capture" | "refresh" | "status_poll";
  readonly operation: "native_auth" | "capture" | "refresh" | "probe";
  readonly timings: {
    readonly configured_timeout_ms: number;
    readonly spawn_elapsed_ms: number;
    readonly budget_remaining_ms_at_spawn: number;
    readonly timeout_callback_lateness_ms: number;
    readonly cleanup_ms: number;
    readonly stdout_closed: boolean;
    readonly root_exited: boolean;
    readonly root_exit_code?: number;
    readonly stderr_closed?: boolean;
  };
}): void => {
  try {
    observeDoctorEvent({
      code: "native_auth_timeout",
      producer: "spawn",
      trigger: input.trigger,
      outcome: "timeout",
      operation: input.operation,
      error_class: "timeout",
      timings: {
        ...input.timings,
        timeout_callback_lateness_ms: Math.max(
          0,
          input.timings.timeout_callback_lateness_ms,
        ),
        spawn_elapsed_ms: Math.max(0, input.timings.spawn_elapsed_ms),
        cleanup_ms: Math.max(0, input.timings.cleanup_ms),
        budget_remaining_ms_at_spawn: Math.max(
          0,
          input.timings.budget_remaining_ms_at_spawn,
        ),
      },
    });
  } catch {
    // Diagnostics must not affect native authentication.
  }
};

export const noteRefreshFailure = (opts: {
  readonly provider: string;
  readonly errorClass: string;
  readonly spawnElapsedMs: number | null;
  readonly timeoutMs: number;
  readonly exitCode: number | undefined;
  readonly errno?: string | null;
}): void => {
  if (opts.errorClass === "abandoned") return;
  const provider = asDoctorProvider(opts.provider);
  try {
    const errorClass: TDoctorErrorClass =
      opts.errorClass === "timeout"
        ? "timeout"
        : opts.errorClass === "spawn_failed"
          ? "spawn_denied"
          : opts.errorClass === "network"
            ? classifyRefreshNetwork(opts.errno)
            : "unclassified";
    observeDoctorEvent({
      code: "refresh_failure",
      producer: "refresh",
      trigger: "refresh",
      outcome: opts.errorClass === "timeout" ? "timeout" : "failure",
      operation: "refresh",
      error_class: errorClass,
      ...(provider !== undefined ? { provider } : {}),
      timings: {
        ...(opts.spawnElapsedMs !== null
          ? { spawn_elapsed_ms: opts.spawnElapsedMs }
          : {}),
        configured_timeout_ms: opts.timeoutMs,
        ...(typeof opts.exitCode === "number"
          ? { root_exit_code: opts.exitCode }
          : {}),
      },
    });
  } catch {
    // Diagnostics must not affect credential refresh.
  }
};
