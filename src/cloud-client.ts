/**
 * Authenticated HTTP client for the daemon's cloud control-plane calls.
 * Every request carries the user's `sk-llm-...` key as a bearer. The
 * cloud endpoints the daemon talks to:
 *
 *   GET  /api/daemon/bootstrap  — catalog + provider prefixes + routing
 *   POST /api/daemon/requests   — record one subscription-hop usage row
 *
 * No subscription token or user content ever appears in these payloads
 * (the no-off-box-exfiltration invariant — see the proposal §6).
 */
import { hostname } from "node:os";
import type {
  TDaemonBootstrap,
  TDaemonModelReport,
  TDaemonPlanResponse,
  TDaemonRecordRequest,
  TRelayChannelResponse,
} from "@openllmsh/protocol";
import {
  DAEMON_DEVICE_ID_HEADER,
  DAEMON_DEVICE_LABEL_HEADER,
  DaemonPlanResponse,
  RelayChannelResponse,
} from "@openllmsh/protocol";
import { Schema } from "effect";
import { daemonEnv, deviceId } from "./env";

const decodeChannel = Schema.decodeUnknownSync(RelayChannelResponse);
const decodePlan = Schema.decodeUnknownSync(DaemonPlanResponse);

/** Thrown when no API key is configured yet — the daemon is keyless. */
export class NoApiKeyError extends Error {
  constructor() {
    super("no API key configured");
    this.name = "NoApiKeyError";
  }
}

/** Thrown when the cloud rejects the key (401/403) — key invalid/stale. */
export class InvalidApiKeyError extends Error {
  constructor(status: number) {
    super(`cloud rejected the API key (${status})`);
    this.name = "InvalidApiKeyError";
  }
}

/**
 * Thrown when `GET /api/daemon/channel` returns 403 `device_limit_exceeded`.
 * Distinct from {@link InvalidApiKeyError}: the key is fine, the plan's
 * concurrent-device cap is full. Carries the numbers so logs/UI can render
 * "N of M devices" without a second round-trip.
 */
export class DeviceLimitExceededError extends Error {
  readonly deviceCap: number;
  readonly deviceCount: number;
  constructor(deviceCap: number, deviceCount: number) {
    super(`device limit exceeded (${deviceCount}/${deviceCap} active devices)`);
    this.name = "DeviceLimitExceededError";
    this.deviceCap = deviceCap;
    this.deviceCount = deviceCount;
  }
}

/**
 * Parse a 403 channel body for the structured device-limit envelope. Returns
 * the typed error when the body matches; `null` for any other 403 shape
 * (auth rejection, etc.) so the caller can fall through to InvalidApiKeyError.
 */
const parseDeviceLimitError = async (
  resp: Response,
): Promise<DeviceLimitExceededError | null> => {
  try {
    const body = (await resp.json()) as {
      error?: {
        type?: unknown;
        device_cap?: unknown;
        device_count?: unknown;
      };
    };
    const err = body.error;
    if (
      err !== undefined &&
      err.type === "device_limit_exceeded" &&
      typeof err.device_cap === "number" &&
      typeof err.device_count === "number" &&
      Number.isFinite(err.device_cap) &&
      Number.isFinite(err.device_count)
    ) {
      return new DeviceLimitExceededError(err.device_cap, err.device_count);
    }
  } catch {
    // Malformed body → treat as a generic key rejection below.
  }
  return null;
};

// `os.hostname()` is almost always plain ASCII, but a header value must be —
// strip anything outside printable ASCII and cap the length so an exotic
// hostname can't make `fetch` throw on an invalid header.
const deviceLabel = (): string =>
  hostname()
    .replace(/[^\x20-\x7E]/g, "")
    .trim()
    .slice(0, 120);

const authHeaders = (): Record<string, string> => {
  const { apiKey } = daemonEnv();
  if (apiKey === null) throw new NoApiKeyError();
  return {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
    // Device identity (metadata only): the cloud records the latest value per
    // key on `api_key_activity` so the dashboard tells two daemons behind one
    // NAT apart — device code + IP, not IP alone. Rides every control call
    // (incl. the channel handshake) so it stays fresh. See
    // `docs/proposals/daemon-device-aware-this-machine.md`.
    [DAEMON_DEVICE_ID_HEADER]: deviceId(),
    [DAEMON_DEVICE_LABEL_HEADER]: deviceLabel(),
  };
};

// Cloud control-plane calls must never hang forever. Bun's `fetch` has NO
// default timeout, so a half-open TCP connection to the cloud — routine on a
// long-lived remote daemon after a network blip — stalls the request
// indefinitely. For `fetchChannel` this is fatal: partysocket awaits the URL
// provider INSIDE its reconnect lock (`_connectLock`), released only when the
// fetch settles. A hung channel fetch wedges the lock forever, so BOTH
// partysocket's auto-reconnect AND the daemon's liveness-watchdog `reconnect()`
// early-return — the daemon is stuck "connecting" until the process restarts.
// Bounding every call with an AbortSignal lets a stalled connection reject
// promptly so the channel loop's backoff (or the caller) retries cleanly.
const CLOUD_FETCH_TIMEOUT_MS = 15_000;

const cloudFetch = (url: string, init: RequestInit): Promise<Response> =>
  fetch(url, {
    ...init,
    signal:
      init.signal != null
        ? AbortSignal.any([
            init.signal,
            AbortSignal.timeout(CLOUD_FETCH_TIMEOUT_MS),
          ])
        : AbortSignal.timeout(CLOUD_FETCH_TIMEOUT_MS),
  });

// Default to the pinned cloud origin, but let the same-machine-307 path
// override per-request with the deployment that issued the redirect
// (`?__origin=`), so one daemon serves any deployment.
const cloudUrl = (path: string, origin?: string | null): string => {
  const base =
    origin !== undefined && origin !== null && origin.length > 0
      ? origin.replace(/\/+$/, "")
      : daemonEnv().cloudOrigin;
  return `${base}${path}`;
};

/**
 * One snapshot with the catalog + provider prefixes + the user's and
 * global fallback config. Pulled at boot + on a TTL by config.ts.
 * Throws `NoApiKeyError` when keyless and `InvalidApiKeyError` on
 * 401/403 so callers can distinguish "needs a key" from "key is bad".
 */
export const fetchBootstrap = async (): Promise<TDaemonBootstrap> => {
  const resp = await cloudFetch(cloudUrl("/api/daemon/bootstrap"), {
    method: "GET",
    headers: authHeaders(),
  });
  if (resp.status === 401 || resp.status === 403) {
    throw new InvalidApiKeyError(resp.status);
  }
  if (!resp.ok) throw new Error(`bootstrap fetch failed: ${resp.status}`);
  return (await resp.json()) as TDaemonBootstrap;
};

/**
 * Fetch a signed plan for a DIRECT client request (local-first gateway,
 * `docs/proposals/local-first-gateway.md` §4.1): the same tuple a
 * same-machine 307 carries, as JSON — the request body never transits the
 * cloud. The caller MUST verify `sig` (`planSignatureOk`) before caching
 * or executing. Throws on keyless/rejected/unreachable so the listener
 * can fall back to passthrough.
 */
export const fetchPlan = async (
  model: string,
  estTokens: number,
): Promise<TDaemonPlanResponse> => {
  const params = new URLSearchParams({ model });
  if (estTokens > 0) params.set("est_tokens", String(Math.ceil(estTokens)));
  const resp = await cloudFetch(
    cloudUrl(`/api/daemon/plan?${params.toString()}`),
    { method: "GET", headers: authHeaders() },
  );
  if (resp.status === 401 || resp.status === 403) {
    throw new InvalidApiKeyError(resp.status);
  }
  if (!resp.ok) throw new Error(`plan fetch failed: ${resp.status}`);
  return decodePlan(await resp.json());
};

/**
 * Ask the cloud for a relay channel: `GET /api/daemon/channel`. Returns the
 * stable per-env WSS URL + a short-lived connect ticket the daemon presents in
 * its `hello` frame. The daemon then holds ONE WebSocket to the relay — its
 * only control transport. Throws `NoApiKeyError`/`InvalidApiKeyError` so the
 * channel loop can back off, and {@link DeviceLimitExceededError} when the
 * plan's concurrent-device cap is full (403 with a structured body — must NOT
 * be collapsed into InvalidApiKeyError, or a soft cap looks like a bad key).
 * See `docs/proposals/daemon-relay-websocket-push.md`.
 */
export const fetchChannel = async (): Promise<TRelayChannelResponse> => {
  const resp = await cloudFetch(cloudUrl("/api/daemon/channel"), {
    method: "GET",
    headers: authHeaders(),
  });
  if (resp.status === 403) {
    const deviceLimit = await parseDeviceLimitError(resp);
    if (deviceLimit !== null) throw deviceLimit;
    throw new InvalidApiKeyError(resp.status);
  }
  if (resp.status === 401) {
    throw new InvalidApiKeyError(resp.status);
  }
  if (!resp.ok) throw new Error(`channel fetch failed: ${resp.status}`);
  // Validate before we dial: a malformed `wss_url`/`ticket` would otherwise
  // surface as a cryptic WebSocket construction failure. Throwing here routes
  // through the channel loop's backoff like any other channel-fetch error.
  try {
    return decodeChannel(await resp.json());
  } catch (err) {
    throw new Error(
      `invalid channel response: ${err instanceof Error ? err.message : "decode failed"}`,
    );
  }
};

/**
 * Publish this daemon's long-lived X25519 SPKI to the cloud so browser/fleet
 * peers pin against a cloud-attested identity (not solely relay status_push).
 * Best-effort: identity pin lag is non-fatal (RTC falls back to status_push).
 */
export const publishIdentity = async (pubkey: string): Promise<void> => {
  try {
    await cloudFetch(cloudUrl("/api/daemon/identity"), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ pubkey }),
    });
  } catch {
    // swallow — identity pin is best-effort hardening
  }
};

/**
 * Record one `public.requests` row for a subscription hop the daemon ran
 * locally. Best-effort: a recording failure must never fail the user's
 * request (the bytes already streamed back), so callers fire-and-forget.
 */
export const recordRequest = async (
  row: TDaemonRecordRequest,
  origin?: string | null,
): Promise<void> => {
  try {
    await cloudFetch(cloudUrl("/api/daemon/requests", origin), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(row),
    });
  } catch {
    // swallow — usage recording is non-critical telemetry
  }
};

/** The terminal outcome of one cloud model-cache report attempt. */
export type TModelReportResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly error: string };

/**
 * Report the live model lists this daemon's connected delegates observed
 * (`POST /api/daemon/models` — live-provider-model-catalog proposal §4).
 * Metadata only (model ids + optional display/context data, never a
 * credential). The caller chooses whether a failure is background-best-effort
 * or should be surfaced to an explicit user action.
 */
export const reportModels = async (
  report: TDaemonModelReport,
): Promise<TModelReportResult> => {
  try {
    const resp = await cloudFetch(cloudUrl("/api/daemon/models"), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(report),
    });
    if (!resp.ok) {
      return { ok: false, error: `model report failed: HTTP ${resp.status}` };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "model report failed",
    };
  }
};
