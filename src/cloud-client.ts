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
import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  existsSync,
  constants as fsConstants,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import type {
  TDaemonBootstrap,
  TDaemonModelReport,
  TDaemonPlanResponse,
  TDaemonQuotaStatusReached,
  TDaemonRecordRequest,
  TDaemonSessionLost,
  TMediaDefaultRequest,
  TMediaPersistError,
  TPlanSurface,
  TRelayChannelResponse,
  TVideoJobPlanRequest,
} from "@openllmsh/protocol";
import {
  DAEMON_BOOTSTRAP_CAPS_HEADER,
  DAEMON_DEVICE_ID_HEADER,
  DAEMON_DEVICE_LABEL_HEADER,
  DaemonPlanResponse,
  encodeMediaDefaultPlanQuery,
  encodePlanSurfaceQueryValue,
  encodeVideoJobPlanQuery,
  MediaDefaultRequest,
  MODEL_CAPABILITIES_OPEN_CAP,
  PLAN_SURFACE_QUERY_KEY,
  RelayChannelResponse,
  sanitizeUsageError,
  VideoJobPlanRequest,
} from "@openllmsh/protocol";
import { Schema } from "effect";
import { processStartIdentity } from "../../pty-native/session/local-runtime";
import { takeRepeatWindow } from "./doctor-report/repeat";
import { daemonEnv, deviceId, stateDir } from "./env";
import { hasIdentityConflict, setIdentityConflict } from "./identity-state";
import { logWarn, safeDiagnosticMessage } from "./logger";
import { readState } from "./state-file";
import { fetchWithBoundedRedirects } from "./upstream-redirect";

const decodeChannel = Schema.decodeUnknownSync(RelayChannelResponse);
const decodePlan = Schema.decodeUnknownSync(DaemonPlanResponse);
const decodeMediaDefault = Schema.decodeUnknownSync(MediaDefaultRequest);
const decodeVideoJobPlan = Schema.decodeUnknownSync(VideoJobPlanRequest);

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
 * Cloud HTTP 4xx for a media-default plan fetch. Distinct from
 * {@link InvalidApiKeyError} so the listener can echo the actionable
 * envelope (400 `no_media_default`, 402 budget, 401/403 auth) instead of
 * collapsing to a generic 502 or treating it as explicit-model passthrough.
 */
export class MediaDefaultPlanError extends Error {
  readonly status: number;
  readonly type: string;
  readonly code: string | undefined;
  constructor(status: number, message: string, type: string, code?: string) {
    super(message);
    this.name = "MediaDefaultPlanError";
    this.status = status;
    this.type = type;
    this.code = code;
  }
}

const MAX_PLAN_ERROR_TEXT = 512;

const boundedText = (value: unknown, fallback: string): string => {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  if (trimmed.length === 0) return fallback;
  return trimmed.length > MAX_PLAN_ERROR_TEXT
    ? trimmed.slice(0, MAX_PLAN_ERROR_TEXT)
    : trimmed;
};

const fallbackMediaDefaultError = (
  status: number,
): { readonly message: string; readonly type: string } => {
  if (status === 401 || status === 403) {
    return {
      message: `cloud rejected the API key (${status})`,
      type: "auth_error",
    };
  }
  if (status === 402) {
    return {
      message: "OpenLLM: payment required — free tier exhausted",
      type: "free_tier_exhausted",
    };
  }
  if (status === 400) {
    return {
      message: "No media default is available for this request",
      type: "no_media_default",
    };
  }
  return {
    message: "Media default plan request failed",
    type: "request_error",
  };
};

const mediaDefaultPlanErrorFromResponse = async (
  resp: Response,
): Promise<MediaDefaultPlanError> => {
  const fallback = fallbackMediaDefaultError(resp.status);
  let message = fallback.message;
  let type = fallback.type;
  let code: string | undefined;
  try {
    const raw: unknown = await resp.json();
    if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
      const err = (raw as { error?: unknown }).error;
      if (err !== null && typeof err === "object" && !Array.isArray(err)) {
        const rec = err as Record<string, unknown>;
        message = boundedText(rec.message, fallback.message);
        type = boundedText(rec.type, fallback.type);
        if (typeof rec.code === "string" && rec.code.trim().length > 0) {
          const clipped = rec.code.trim().slice(0, MAX_PLAN_ERROR_TEXT);
          code = clipped;
        }
      }
    }
  } catch {
    // Malformed body keeps the status-specific fallback.
  }
  return new MediaDefaultPlanError(resp.status, message, type, code);
};

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
    // This binary decodes DaemonCatalogEntry.capabilities as an open string
    // array (post image_editing/realtime widening) — advertise it so the
    // bootstrap encoder sends the full modern capability list instead of
    // filtering to the bootstrap-safe subset. Never gated on a version bump.
    [DAEMON_BOOTSTRAP_CAPS_HEADER]: MODEL_CAPABILITIES_OPEN_CAP,
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
/** Control-plane header budget. Origin inference reuses this only for
 *  waiting on headers — never as a stream cutoff. */
export const CLOUD_FETCH_TIMEOUT_MS = 15_000;
const MEDIA_UPLOAD_TIMEOUT_MS = 120_000;

// Every control-plane call rides the shared manual-redirect policy
// (`upstream-redirect.ts`): a cloud-issued 30x may only be re-issued to a
// same-origin or canonical-cloud target, bounded — never auto-followed to an
// arbitrary origin with the `sk-llm` bearer attached.
const cloudFetch = (url: string, init: RequestInit): Promise<Response> =>
  fetchWithBoundedRedirects(
    url,
    (target) =>
      fetch(target, {
        ...init,
        redirect: "manual",
        signal:
          init.signal != null
            ? AbortSignal.any([
                init.signal,
                AbortSignal.timeout(CLOUD_FETCH_TIMEOUT_MS),
              ])
            : AbortSignal.timeout(CLOUD_FETCH_TIMEOUT_MS),
      }),
    "cloud-client",
  );

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
  signal?: AbortSignal,
  surface?: TPlanSurface,
): Promise<TDaemonPlanResponse> => {
  const params = new URLSearchParams({ model });
  if (estTokens > 0) params.set("est_tokens", String(Math.ceil(estTokens)));
  // The surface this request is FOR, when the listener knows it (every
  // media endpoint does — it is decided by the path). Without it the
  // cloud can only resolve the name under its chat default, which for an
  // ambiguous family name (`grok` on `/v1/images/generations`) plans the
  // chat model while the cloud's own image handler would select the image
  // one. Omitted on chat, where the default IS the answer, so an older
  // plan cache key and an unbumped daemon keep behaving identically.
  if (surface !== undefined)
    params.set(PLAN_SURFACE_QUERY_KEY, encodePlanSurfaceQueryValue(surface));
  const resp = await cloudFetch(
    cloudUrl(`/api/daemon/plan?${params.toString()}`),
    { method: "GET", headers: authHeaders(), signal },
  );
  if (resp.status === 401 || resp.status === 403) {
    throw new InvalidApiKeyError(resp.status);
  }
  if (!resp.ok) throw new Error(`plan fetch failed: ${resp.status}`);
  return decodePlan(await resp.json());
};

/**
 * Metadata-only media-default plan fetch (no `model` query, never prompt
 * or media bytes). The cloud resolver picks a subscription-first then
 * API-key model; the caller verifies `sig` before using the tuple.
 */
export const fetchMediaDefaultPlan = async (
  request: TMediaDefaultRequest,
  signal?: AbortSignal,
): Promise<TDaemonPlanResponse> => {
  const validated = decodeMediaDefault(request);
  const query = encodeMediaDefaultPlanQuery(validated);
  if (query === null) {
    throw new Error("invalid media default plan request");
  }
  const resp = await cloudFetch(cloudUrl(`/api/daemon/plan?${query}`), {
    method: "GET",
    headers: authHeaders(),
    signal,
  });
  if (resp.status >= 400 && resp.status < 500) {
    throw await mediaDefaultPlanErrorFromResponse(resp);
  }
  if (!resp.ok) throw new Error(`plan fetch failed: ${resp.status}`);
  return decodePlan(await resp.json());
};

/**
 * Metadata-only plan for an existing video job (poll/content/cancel).
 * `video_job={model,provider}` — never aliases, never cooldowns, never prompt.
 */
export const fetchVideoJobPlan = async (
  request: TVideoJobPlanRequest,
  signal?: AbortSignal,
): Promise<TDaemonPlanResponse> => {
  const validated = decodeVideoJobPlan(request);
  const query = encodeVideoJobPlanQuery(validated);
  if (query === null) {
    throw new Error("invalid video job plan request");
  }
  const resp = await cloudFetch(cloudUrl(`/api/daemon/plan?${query}`), {
    method: "GET",
    headers: authHeaders(),
    signal,
  });
  if (resp.status >= 400 && resp.status < 500) {
    throw await mediaDefaultPlanErrorFromResponse(resp);
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
  const raw = await resp.text();
  if (raw.trim() === "") {
    throw new Error(
      `invalid channel response: empty body (status ${resp.status}, content-length ${resp.headers.get("content-length") ?? "unknown"})`,
    );
  }
  try {
    return decodeChannel(JSON.parse(raw));
  } catch (err) {
    throw new Error(
      `invalid channel response: status ${resp.status}: ${err instanceof Error ? err.message : "decode failed"}`,
    );
  }
};

/**
 * Lazy import: control-channel already imports this module. Push only on a
 * conflict *transition* so the dashboard sees the flag without an extra backoff.
 */
const pushIdentityConflictIfChanged = async (): Promise<void> => {
  const { pushStatusIfChanged } = await import("./control-channel");
  await pushStatusIfChanged("bootstrap");
};

/**
 * Publish this daemon's long-lived X25519 SPKI to the cloud so browser/fleet
 * peers pin against a cloud-attested identity (not solely relay status_push).
 * Best-effort: identity pin lag is non-fatal (RTC falls back to status_push).
 */
export const publishIdentity = async (pubkey: string): Promise<void> => {
  try {
    const response = await cloudFetch(cloudUrl("/api/daemon/identity"), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ pubkey }),
    });
    if (response.status === 409) {
      let code: string | null = null;
      try {
        const body: unknown = await response.json();
        if (
          body !== null &&
          typeof body === "object" &&
          "error" in body &&
          body.error !== null &&
          typeof body.error === "object" &&
          "type" in body.error &&
          body.error.type === "identity_conflict"
        ) {
          code = "identity_conflict";
        }
      } catch {
        // A malformed conflict envelope remains non-fatal and unreported.
      }
      if (code === "identity_conflict") {
        const wasConflict = hasIdentityConflict();
        setIdentityConflict(true);
        logWarn(
          "identity",
          safeDiagnosticMessage`cloud pin conflicts with local X25519 key — RTC will fail until the pin is reset`,
          {},
        );
        // Push once per false→true; repeated 409s (bootstrap ~5min) stay silent.
        if (!wasConflict) await pushIdentityConflictIfChanged();
      }
      return;
    }
    if (response.ok) {
      const wasConflict = hasIdentityConflict();
      setIdentityConflict(false);
      // Push the true→false recovery so a reset is visible without an unrelated flip.
      if (wasConflict) await pushIdentityConflictIfChanged();
    }
  } catch {
    // swallow — identity pin is best-effort hardening
  }
};

// ─── Durable usage outbox (EC-2) ────────────────────────────────────────
//
// `POST /api/daemon/requests` rows are the ONLY ledger for daemon-served
// subscription hops and count toward the free-tier monthly cap, so a
// fire-and-forget POST that dies on a cloud 5xx/429, a network blip, or a
// daemon exit right after the stream is silent under-metering (wrong
// billing). The row is therefore appended — fsync'd — to an append-only
// per-process JSONL segment under `<stateDir>/usage-outbox/` BEFORE
// `recordRequest` resolves, then a background drain delivers rows in
// order:
//
//   2xx / 409 / 422          → delivered (409/422 = deduped/never-valid)
//   5xx / 429 / transport    → retry, exponential backoff + jitter
//   any other 4xx            → terminal reject: drop with a log line
//   attempts ≥ cap           → drop with a counted warning
//
// Retries reuse the row's existing `idempotency_key` — the cloud dedupes
// on it, so a retried delivery can never double-count.
//
// Multi-process safety: several daemons can share one state dir (two keys,
// a dev + a service install), so NOTHING ever rewrites a shared file.
// Each process appends only to its OWN segment
// `<start>-<pid>-<startTag>-<rand>.jsonl` — where `startTag` is a hash of
// the owner's `processStartIdentity`, so a REUSED pid cannot impersonate a
// live owner — and a drain pass claims a segment by atomic rename
// (`…​.claim-<pid>-<startTag>-<rand>`) before reading it; losing the
// rename race just skips that segment this pass. A claimed file is deleted
// only once every row in it reached a terminal verdict; rows still needing
// delivery are rewritten into the claim (OURS alone — never a shared file)
// and the claim is released under a FRESH unique segment name — never
// renamed back onto the base path, which a producer could have recreated
// in between (POSIX rename silently replaces an existing destination).
// A crash anywhere in that window loses nothing: the next pass reclaims
// claims whose claimant is proven dead (pid gone or start-identity
// mismatch) and re-delivers under the same idempotency keys. A LIVE
// foreign process's segment or claim is NEVER touched regardless of age —
// claiming requires the owner to be proven dead — so a live process never
// has a row reaped from under an in-flight append. Segments written by the
// round-2 layout (`<start>-<pid>-<rand>` without a start tag) carry no
// verifiable owner identity: they are claimable only while their pid is
// gone, and treated as foreign-live otherwise — unverifiable is never
// confused with dead.
//
// Durability: every append fsyncs the segment (and the directory when the
// segment is first created), so a crash can only lose the not-yet-fsynced
// tail — a trailing PARTIAL line on recovery is skipped, counted and
// warned, and never takes a complete line with it. Any line that can
// never be delivered (torn tail, malformed) is preserved in
// `quarantine.log` rather than silently discarded.
//
// Backpressure: the whole outbox dir is size-capped with oldest-segment-
// first drop + a counted warning, and the drain is coalesced through ONE
// dirty flag — at most one pass in flight and at most one scheduled
// follow-up, always at the CURRENT backoff — so a burst of records during
// a failing pass cannot spin serial retries that hammer a down cloud and
// burn the per-row attempt budget.
//
// A crash mid-delivery loses nothing: the files are the source of truth
// and the next boot's flush (`startControlChannel`) re-delivers. Shutdown
// gets one bounded pass inside `stopControlChannel`.

/** Outbox directory name under the daemon state dir (exported for tests). */
export const USAGE_OUTBOX_DIR = "usage-outbox";
/** Lines that can never be delivered are preserved here (dead letter). */
const USAGE_OUTBOX_QUARANTINE = "quarantine.log";
/** Round-1 layout was ONE shared file; migrated into a segment on load. */
const USAGE_OUTBOX_LEGACY_FILE = "usage-outbox.jsonl";
const USAGE_OUTBOX_MODE = 0o600;
const USAGE_OUTBOX_DIR_MODE = 0o700;
/** ~1–2k rows. Past this, the oldest SEGMENTS drop so a dead cloud cannot
 *  grow the ledger unbounded — every drop is counted and warned. */
const USAGE_OUTBOX_MAX_BYTES = 512 * 1024;
/** After the cap is hit, trim to 3/4 so a steady stream does not drop a
 *  whole segment on every single append. */
const USAGE_OUTBOX_TRIM_TARGET_BYTES = (USAGE_OUTBOX_MAX_BYTES * 3) / 4;
/** Per-row lifetime delivery-attempt cap (persisted across restarts). */
const USAGE_DELIVERY_MAX_ATTEMPTS = 24;
/** Pass-level exponential backoff while a transient failure keeps the head
 *  row undeliverable, capped + jittered so the fleet never locksteps. */
const USAGE_RETRY_BASE_MS = 10_000;
const USAGE_RETRY_MAX_MS = 300_000;
const USAGE_RETRY_JITTER_MS = 5_000;
/** The owner start-identity probe (`ps`/Win32 spawn) is per foreign live
 *  pid — memoize a verdict this long so an append burst cannot fork a
 *  helper per row. Staleness is only ever in the SAFE direction: a dead
 *  verdict is re-proven by kill(0) on every check, and a cached
 *  foreign-live/unknown verdict merely defers claiming a segment whose
 *  owner died within the window. */
const USAGE_OWNER_PROBE_CACHE_MS = 30_000;
/** Start tag written when `processStartIdentity` could not prove the
 *  writer's start. Scanned as `null` — unverifiable is never "dead". */
const USAGE_START_TAG_UNKNOWN = "na";

type TUsageOutboxEntry = {
  readonly row: TDaemonRecordRequest;
  readonly origin: string | null;
  /** Delivery attempts made (persisted each flush pass — a restart cannot
   *  reset the lifetime cap). */
  attempts: number;
};

type TUsageDeliverVerdict =
  | { readonly kind: "delivered" }
  | { readonly kind: "drop"; readonly status: number }
  | { readonly kind: "keep" }
  | { readonly kind: "abort" };

/** Why a drain pass stopped early (drives post-pass scheduling). */
type TUsagePassReport = {
  readonly transient: boolean;
  /** The key vanished mid-pass (or none is configured) — rows wait for a
   *  key, so no retry timer may be armed. */
  readonly aborted: boolean;
};

type TUsageOutboxScanEntry = {
  readonly name: string;
  readonly path: string;
  /** Owning pid for a segment; claimant pid for a `.claim-*` file. */
  readonly pid: number;
  /** Hash of the owner's process start identity; `null` when the name
   *  carries none (round-2 layout, or an unverifiable writer). */
  readonly startTag: string | null;
  readonly size: number;
  readonly claimed: boolean;
};

/** `<startMs>-<pid>-<startTag>-<rand>.jsonl` — the leading timestamp keeps
 *  name order ≈ creation order, so the drain walks segments oldest-first. */
const USAGE_OUTBOX_SEGMENT_RE = /^(\d+)-(\d+)-([0-9a-z]+)-([0-9a-z]+)\.jsonl$/;
/** Round-2 layout without a start tag: `<startMs>-<pid>-<rand>.jsonl`. */
const USAGE_OUTBOX_LEGACY_SEGMENT_RE = /^(\d+)-(\d+)-([0-9a-z]+)\.jsonl$/;
const USAGE_OUTBOX_CLAIM_RE = /\.claim-(\d+)-([0-9a-z]+)-([0-9a-z]+)$/;
const USAGE_OUTBOX_LEGACY_CLAIM_RE = /\.claim-(\d+)-([0-9a-z]+)$/;

let usageOutboxDropped = 0;
/** One producer-side dirty flag: records queued during a pass set it; the
 *  pass end schedules at most ONE follow-up for any number of them. */
let usageOutboxDirty = false;
let usageOutboxFlushInFlight: Promise<void> | null = null;
let usageOutboxRetryTimer: ReturnType<typeof setTimeout> | null = null;
let usageOutboxConsecutiveFailures = 0;
/** One-shot guard for the legacy single-file migration. */
let usageOutboxLegacyChecked = false;

const usageOutboxRandom = (): string =>
  crypto.randomUUID().replace(/-/g, "").slice(0, 10);
/** A producer rolls to a fresh append segment past this size so the dir
 *  cap drops complete OLD segments (~1/4 of the cap) instead of the whole
 *  ledger — keeps oldest-first drop granularity inside a single process. */
const USAGE_OUTBOX_SEGMENT_ROTATE_BYTES = 128 * 1024;

/** Short opaque tag for a `processStartIdentity` value: pid reuse is
 *  detected by comparing the tag recorded in a segment/claim name against
 *  a fresh probe of the pid's identity. `na` marks an unverifiable writer. */
const usageStartTagFromIdentity = (
  identity: string | null | undefined,
): string =>
  typeof identity === "string" && identity.length > 0
    ? createHash("sha256").update(identity).digest("hex").slice(0, 10)
    : USAGE_START_TAG_UNKNOWN;

let usageOwnStartTagCache: string | null = null;
/** This boot's start tag — recorded in every segment we write and every
 *  claim we take, so pid reuse can never make a foreign file look ours. */
const usageOwnStartTag = (): string => {
  if (usageOwnStartTagCache === null) {
    usageOwnStartTagCache = usageStartTagFromIdentity(
      processStartIdentity(process.pid),
    );
  }
  return usageOwnStartTagCache;
};

/** A fresh unique segment name owned by THIS process+start — the target of
 *  every claim release and stale-claim park, so those moves can never
 *  rename over an existing path. */
const freshUsageSegmentName = (): string =>
  `${Date.now()}-${process.pid}-${usageOwnStartTag()}-${usageOutboxRandom()}.jsonl`;

let usageOutboxOwnSegmentName: string | null = null;
const usageOwnSegmentName = (): string => {
  if (usageOutboxOwnSegmentName === null) {
    usageOutboxOwnSegmentName = freshUsageSegmentName();
  }
  return usageOutboxOwnSegmentName;
};

let usageOutboxClaimTokenCache: string | null = null;
/** Token a claim name carries so a later process can tell a LIVE claim of
 *  ours from a crashed boot's (or a foreign daemon's) — pid + start tag +
 *  a per-boot random. */
const usageOutboxClaimToken = (): string => {
  if (usageOutboxClaimTokenCache === null) {
    usageOutboxClaimTokenCache = `${process.pid}-${usageOwnStartTag()}-${usageOutboxRandom()}`;
  }
  return usageOutboxClaimTokenCache;
};

const usageOutboxDirPath = (): string => join(stateDir(), USAGE_OUTBOX_DIR);
const usageOutboxOwnSegmentPath = (): string =>
  join(usageOutboxDirPath(), usageOwnSegmentName());
const usageOutboxQuarantinePath = (): string =>
  join(usageOutboxDirPath(), USAGE_OUTBOX_QUARANTINE);
const usageOutboxLegacyPath = (): string =>
  join(stateDir(), USAGE_OUTBOX_LEGACY_FILE);

const serializeUsageOutboxEntry = (entry: TUsageOutboxEntry): string =>
  JSON.stringify({
    row: entry.row,
    origin: entry.origin,
    attempts: entry.attempts,
  });

const parseUsageOutboxLine = (line: string): TUsageOutboxEntry | null => {
  try {
    const parsed: unknown = JSON.parse(line);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      return null;
    const rec = parsed as {
      row?: unknown;
      origin?: unknown;
      attempts?: unknown;
    };
    if (
      rec.row === null ||
      typeof rec.row !== "object" ||
      Array.isArray(rec.row)
    )
      return null;
    const recovered = rec.row as TDaemonRecordRequest;
    return {
      // Rows written by older builds may carry raw upstream error text;
      // re-sanitize on recovery so nothing unsanitized ever leaves the host.
      row: {
        ...recovered,
        error: sanitizeUsageError(recovered.error, recovered.status),
      },
      origin:
        typeof rec.origin === "string" && rec.origin.length > 0
          ? rec.origin
          : null,
      attempts:
        typeof rec.attempts === "number" &&
        Number.isFinite(rec.attempts) &&
        rec.attempts > 0
          ? Math.floor(rec.attempts)
          : 0,
    };
  } catch {
    return null;
  }
};

let usageOutboxDirFsyncs = 0;
const fsyncDirSync = (dir: string): void => {
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
      usageOutboxDirFsyncs += 1;
    } finally {
      closeSync(fd);
    }
  } catch {
    // Some filesystems can't fsync a directory — best effort only.
  }
};

/**
 * Append one serialized line to THIS process's own segment and fsync it:
 * the row is durable before `recordRequest` resolves, and a crash can only
 * ever tear the not-yet-fsynced trailing line — never a complete one. The
 * segment's first append also fsyncs the directory so the dirent itself
 * survives a power cut.
 */
const appendUsageOutboxLineSync = (line: string): void => {
  const dir = usageOutboxDirPath();
  mkdirSync(dir, { recursive: true, mode: USAGE_OUTBOX_DIR_MODE });
  // Roll the append segment once it passes the rotate bound: the full file
  // becomes a sealed segment (drainable + cap-droppable) and appends move
  // to a fresh name — the size cap then drops whole OLD segments, never
  // the live tail.
  try {
    const current = statSync(usageOutboxOwnSegmentPath());
    if (current.size > USAGE_OUTBOX_SEGMENT_ROTATE_BYTES) {
      usageOutboxOwnSegmentName = freshUsageSegmentName();
    }
  } catch {
    // stat failure → keep appending to the current name.
  }
  const path = usageOutboxOwnSegmentPath();
  const isNew = !existsSync(path);
  const fd = openSync(path, "a", USAGE_OUTBOX_MODE);
  try {
    writeSync(fd, `${line}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (isNew) fsyncDirSync(dir);
};

/** Rewrite a CLAIMED segment in place (tmp + fsync + rename) with the rows
 *  still owed a delivery attempt. Only ever called on a file this pass
 *  owns — the same-path rename is atomic, so a crash can never tear it. */
const writeUsageSegmentFileSync = (
  path: string,
  entries: readonly TUsageOutboxEntry[],
): void => {
  const tmp = `${path}.tmp`;
  const body =
    entries.length === 0
      ? ""
      : `${entries.map(serializeUsageOutboxEntry).join("\n")}\n`;
  const fd = openSync(tmp, "w", USAGE_OUTBOX_MODE);
  try {
    writeSync(fd, body);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
};

/** Dead-letter sink: lines that can never be delivered stay recoverable
 *  for ops instead of being silently discarded. Append-only, 0600. */
const quarantineUsageOutboxLinesSync = (lines: readonly string[]): void => {
  if (lines.length === 0) return;
  try {
    const fd = openSync(usageOutboxQuarantinePath(), "a", USAGE_OUTBOX_MODE);
    try {
      writeSync(fd, `${lines.join("\n")}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    // A failed dead-letter write is logged by the caller's count, not thrown.
  }
};

const processAlive = (pid: number): boolean => {
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // ESRCH = no such process; EPERM = exists but not ours — both alive-safe.
    return (err as { code?: string }).code !== "ESRCH";
  }
};

/** Owner liveness for a segment/claim name. `dead` is proven — the pid is
 *  gone or now runs a different start identity (pid reuse). Anything less
 *  certain is `foreign-live` (pid alive, identity matches or unverifiable)
 *  or `unknown` (the identity probe itself failed) — both NEVER claimable. */
type TUsageOwnerState = "self" | "dead" | "foreign-live" | "unknown";

/** Probe results for live foreign pids, keyed `pid:startTag` — memoized
 *  briefly so an append burst does not spawn `ps` per row per segment. */
const usageOwnerStateCache = new Map<
  string,
  { readonly state: TUsageOwnerState; readonly at: number }
>();

const usageOwnerState = (
  pid: number,
  startTag: string | null,
): TUsageOwnerState => {
  if (pid === process.pid) {
    // Only THIS boot can produce our start tag; a segment under our pid
    // with any other tag belonged to a dead earlier holder of the pid.
    return startTag !== null && startTag === usageOwnStartTag()
      ? "self"
      : "dead";
  }
  // Cheap proof first: a pid that no longer exists is dead regardless of
  // any cached verdict — never trust the memo past kill(0).
  if (!processAlive(pid)) return "dead";
  if (startTag === null) {
    // No recorded identity to disprove: a live pid may well BE the owner —
    // conservative, never touched regardless of age.
    return "foreign-live";
  }
  const cacheKey = `${pid}:${startTag}`;
  const cached = usageOwnerStateCache.get(cacheKey);
  if (
    cached !== undefined &&
    Date.now() - cached.at < USAGE_OWNER_PROBE_CACHE_MS
  ) {
    return cached.state;
  }
  let state: TUsageOwnerState;
  try {
    const identity = processStartIdentity(pid);
    if (identity === null) {
      state = "dead";
    } else if (identity === undefined) {
      // The probe could not answer — proving nothing is NOT the same as
      // proving death, so this pid stays untouchable this round.
      state = "unknown";
    } else {
      state =
        usageStartTagFromIdentity(identity) === startTag
          ? "foreign-live"
          : "dead";
    }
  } catch {
    state = "unknown";
  }
  usageOwnerStateCache.set(cacheKey, { state, at: Date.now() });
  return state;
};

/** Directory listing of segments + claims (sorted oldest-first by the
 *  leading creation timestamp in each name). */
const scanUsageOutboxSync = (): TUsageOutboxScanEntry[] => {
  let names: string[];
  try {
    names = readdirSync(usageOutboxDirPath());
  } catch {
    return [];
  }
  const out: TUsageOutboxScanEntry[] = [];
  for (const name of names) {
    const segment = USAGE_OUTBOX_SEGMENT_RE.exec(name);
    const legacySegment =
      segment === null ? USAGE_OUTBOX_LEGACY_SEGMENT_RE.exec(name) : null;
    const claim = USAGE_OUTBOX_CLAIM_RE.exec(name);
    const legacyClaim =
      claim === null ? USAGE_OUTBOX_LEGACY_CLAIM_RE.exec(name) : null;
    if (
      segment === null &&
      legacySegment === null &&
      claim === null &&
      legacyClaim === null
    ) {
      continue;
    }
    let stat: ReturnType<typeof statSync>;
    try {
      stat = statSync(join(usageOutboxDirPath(), name));
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;
    let pid: number;
    let startTag: string | null;
    let claimed: boolean;
    if (segment !== null) {
      pid = Number(segment[2]);
      startTag =
        segment[3] === USAGE_START_TAG_UNKNOWN ? null : (segment[3] ?? null);
      claimed = false;
    } else if (legacySegment !== null) {
      pid = Number(legacySegment[2]);
      startTag = null;
      claimed = false;
    } else if (claim !== null) {
      pid = Number(claim[1]);
      startTag =
        claim[2] === USAGE_START_TAG_UNKNOWN ? null : (claim[2] ?? null);
      claimed = true;
    } else {
      pid = Number(legacyClaim?.[1]);
      startTag = null;
      claimed = true;
    }
    out.push({
      name,
      path: join(usageOutboxDirPath(), name),
      pid,
      startTag,
      size: stat.size,
      claimed,
    });
  }
  return out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
};

/** A segment is claimable only when its owner is us or PROVEN dead (pid
 *  gone, or a live pid now carrying a different start identity). A live
 *  foreign owner — or one we cannot disprove — is NEVER touched at any
 *  age: racing an in-flight append is how rows get lost. */
const usageSegmentClaimable = (entry: TUsageOutboxScanEntry): boolean => {
  const state = usageOwnerState(entry.pid, entry.startTag);
  return state === "self" || state === "dead";
};

/**
 * Move `src` onto `dst` with a hard no-overwrite guarantee on EVERY
 * filesystem: `link` + `unlink` is rename-without-replace (an existing
 * `dst` fails EEXIST instead of being replaced), and filesystems without
 * hardlink support fall back to an EXCLUSIVE copy (`COPYFILE_EXCL` —
 * create-or-fail) then unlink, never a plain `renameSync`, which POSIX
 * lets silently replace an existing destination. Exported for the
 * no-overwrite regression test.
 */
export const moveFileExclusiveSync = (
  src: string,
  dst: string,
): "moved" | "exists" | "failed" => {
  try {
    linkSync(src, dst);
  } catch (err) {
    if ((err as { code?: string }).code === "EEXIST") return "exists";
    // No hardlink support (EXDEV/EPERM/ENOSYS) or another link failure:
    // the exclusive copy keeps the same create-or-fail guarantee.
    try {
      copyFileSync(src, dst, fsConstants.COPYFILE_EXCL);
    } catch (copyErr) {
      if ((copyErr as { code?: string }).code === "EEXIST") return "exists";
      // A failed copy can leave a partial `dst` — only we could have made
      // this fresh name, so remove it rather than strand a torn segment.
      try {
        unlinkSync(dst);
      } catch {
        // Nothing there or already gone.
      }
      return "failed";
    }
  }
  try {
    unlinkSync(src);
  } catch {
    // `src` stayed: drop the fresh `dst` we just made (a second name for
    // the same rows) so the claim can be re-parked cleanly next pass
    // instead of duplicating its rows under two segments.
    try {
      unlinkSync(dst);
    } catch {
      // Best effort.
    }
    return "failed";
  }
  return "moved";
};

/**
 * Move a claimed file under a FRESH unique segment name without ever
 * overwriting — see {@link moveFileExclusiveSync}. An EEXIST on the fresh
 * target (impossible with the random name, but proven rather than
 * assumed) retries a new name. Used by claim release and stale-claim
 * parking alike — the base segment name is NEVER a destination, because a
 * producer could have recreated it between the existence check and the
 * rename (POSIX rename silently replaces). A successful move fsyncs the
 * directory: a crash between the new dirent and the old one's removal
 * must not be able to lose BOTH.
 */
const parkUsageClaimAsFreshSegmentSync = (claimedPath: string): void => {
  const dir = usageOutboxDirPath();
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const freshPath = join(dir, freshUsageSegmentName());
    const outcome = moveFileExclusiveSync(claimedPath, freshPath);
    if (outcome === "moved") {
      fsyncDirSync(dir);
      return;
    }
    if (outcome !== "exists") return; // leave claimed — the next pass retries
  }
};

/**
 * Return claims to the unclaimed pool when their claimant is proven dead:
 * a claim under OUR pid with a DIFFERENT token (a crashed earlier boot —
 * our own in-flight claim is left strictly alone) or a claim whose
 * claimant pid is gone / now runs a different start identity. A claim of
 * a LIVE foreign process — or one we cannot disprove — is never moved.
 */
const reclaimStaleUsageClaimsSync = (): void => {
  for (const entry of scanUsageOutboxSync()) {
    if (!entry.claimed) continue;
    const isOwnLiveClaim = entry.name.endsWith(
      `.claim-${usageOutboxClaimToken()}`,
    );
    if (isOwnLiveClaim) continue;
    const state = usageOwnerState(entry.pid, entry.startTag);
    if (state === "foreign-live" || state === "unknown") continue;
    parkUsageClaimAsFreshSegmentSync(entry.path);
  }
};

/** Atomic claim: rename wins or returns null — the loser just skips the
 *  segment this pass. The `.claim-<token>` target is unique to this boot,
 *  so the rename cannot land on an existing path. */
const claimUsageSegmentSync = (entry: TUsageOutboxScanEntry): string | null => {
  const claimedPath = `${entry.path}.claim-${usageOutboxClaimToken()}`;
  try {
    renameSync(entry.path, claimedPath);
    return claimedPath;
  } catch {
    return null;
  }
};

/** Release a claim back to the segment pool under a fresh unique name —
 *  never the original base name (a producer can recreate it mid-drain, and
 *  POSIX rename would silently replace those live rows). */
const releaseUsageClaimSync = (claimedPath: string): void => {
  parkUsageClaimAsFreshSegmentSync(claimedPath);
};

/**
 * Is another daemon LIVE on this state dir? Two proofs, either sufficient:
 *
 * - a foreign-live (or not-proven-dead) outbox owner — a co-tenant daemon
 *   running the segment layout; and
 * - the `rtcRun` liveness sentinel in `state.json`: the pid of the last
 *   PROD daemon that booted on this state dir and did not gracefully exit.
 *   A live pid that is not ours is an older binary still running (two prod
 *   daemons cannot coexist once the port is bound, so a foreign live pid
 *   seen here is a co-tenant, e.g. prod seen from a dev boot).
 *
 * A prod daemon running the OLD shared-file layout does not write
 * rtcRun-visible segments but does stamp the sentinel at boot — the case
 * this exists for. Residual gap, documented: a live OLD dev-mode daemon
 * (dev never writes the sentinel) whose pid we cannot otherwise see is
 * undetectable; it can only append after we migrate, never lose a row we
 * already took (its appends land in a recreated file the next pass
 * re-evaluates).
 */
const anotherDaemonLiveForStateDirSync = (): boolean => {
  for (const entry of scanUsageOutboxSync()) {
    const state = usageOwnerState(entry.pid, entry.startTag);
    if (state === "foreign-live" || state === "unknown") return true;
  }
  const sentinel = readState().rtcRun ?? null;
  return (
    sentinel !== null &&
    sentinel.pid !== process.pid &&
    processAlive(sentinel.pid)
  );
};

/**
 * Round-1 left a single shared `usage-outbox.jsonl` file that EVERY daemon
 * on this state dir appended to. Move it into the segment layout so its
 * rows drain like any other segment — but NEVER rename it while an older
 * daemon may still append to that path (a rename would strand its in-flight
 * appends onto a recreated file we already marked migrated). When a live
 * co-tenant is detected the file is left alone and re-evaluated on a later
 * pass / next boot.
 */
const migrateUsageOutboxLegacyFileSync = (): void => {
  if (usageOutboxLegacyChecked) return;
  const legacy = usageOutboxLegacyPath();
  try {
    if (!existsSync(legacy)) {
      usageOutboxLegacyChecked = true;
      return;
    }
    if (anotherDaemonLiveForStateDirSync()) {
      // A possible live appender — leave the shared file untouched; the
      // flag stays clear so the next pass re-evaluates.
      return;
    }
    mkdirSync(usageOutboxDirPath(), {
      recursive: true,
      mode: USAGE_OUTBOX_DIR_MODE,
    });
    renameSync(legacy, join(usageOutboxDirPath(), freshUsageSegmentName()));
    fsyncDirSync(usageOutboxDirPath());
    fsyncDirSync(stateDir());
    // The flag stays CLEAR: a co-tenant still appending recreates the file
    // — the next pass re-gates on liveness and migrates those rows too
    // instead of stranding them until the next boot.
  } catch (err) {
    logWarn("usage-ledger", "legacy usage outbox could not be migrated", {
      err: err instanceof Error ? err.message : String(err),
    });
  }
};

/** Reading a claimed segment either yields its entries or fails — an
 *  UNREADABLE file is not an EMPTY one, and the caller must keep the
 *  claim (never delete/rewrite it) so a later pass can retry. */
type TUsageSegmentRead =
  | { readonly kind: "ok"; readonly entries: TUsageOutboxEntry[] }
  | { readonly kind: "error" };

/**
 * Read a CLAIMED segment into entries. Recovery semantics: only a trailing
 * PARTIAL line — the torn tail a crash leaves mid-append — is ignorable,
 * and even it is quarantined + counted, never silently dropped. Complete
 * lines that parse are always kept; complete lines that don't parse are
 * quarantined (never discarded) and counted. A read failure is reported as
 * `error`, NOT folded into an empty list — folding it in used to make the
 * caller delete a fully-loaded claim as if every row had been delivered.
 */
const readUsageSegmentSync = (path: string): TUsageSegmentRead => {
  let text: string;
  try {
    text = readFileSync(path, "utf-8");
  } catch {
    return { kind: "error" };
  }
  const entries: TUsageOutboxEntry[] = [];
  const undeliverable: string[] = [];
  let partial = 0;
  let malformed = 0;
  const lines = text.split("\n");
  const tornTailIndex =
    text.length > 0 && !text.endsWith("\n") ? lines.length - 1 : -1;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const trimmed = line.trim();
    if (trimmed === "") continue;
    const parsed = parseUsageOutboxLine(trimmed);
    if (parsed !== null) {
      entries.push(parsed);
      continue;
    }
    undeliverable.push(line);
    if (index === tornTailIndex) partial += 1;
    else malformed += 1;
  }
  if (undeliverable.length > 0) {
    quarantineUsageOutboxLinesSync(undeliverable);
    usageOutboxDropped += undeliverable.length;
    logWarn(
      "usage-ledger",
      "usage outbox skipped undeliverable lines (preserved in quarantine.log)",
      {
        partial_lines: partial,
        malformed_lines: malformed,
        dropped_total: usageOutboxDropped,
      },
    );
  }
  return { kind: "ok", entries };
};

/** Segment count of unclaimed rows — used by the size cap and the test
 *  seam. `-1` marks an UNREADABLE file so the cap can keep it rather than
 *  counting it as empty and unlinking rows it could not inspect. */
const countUsageSegmentLinesSync = (path: string): number => {
  try {
    return readFileSync(path, "utf-8")
      .split("\n")
      .filter((line) => line.trim() !== "").length;
  } catch {
    return -1;
  }
};

/**
 * Size cap over the outbox's DROPPABLE set: unclaimed segments owned by
 * this process or a proven-dead owner. Once those exceed the bound, drop
 * the OLDEST until the trim target is met, and warn with the running
 * row-drop total. A live foreign segment is never a candidate — it is the
 * foreign owner's own cap that bounds it, and unlinking it would reap rows
 * from under an in-flight append. Claimed files (in-flight work, ours or
 * foreign) are never candidates either.
 */
const enforceUsageOutboxCapSync = (): void => {
  const entries = scanUsageOutboxSync().filter(
    (entry) => !entry.claimed && usageSegmentClaimable(entry),
  );
  let total = 0;
  for (const entry of entries) total += entry.size;
  if (total <= USAGE_OUTBOX_MAX_BYTES) return;
  let removedRows = 0;
  for (const entry of entries) {
    if (total <= USAGE_OUTBOX_TRIM_TARGET_BYTES) break;
    const rows = countUsageSegmentLinesSync(entry.path);
    if (rows < 0) continue; // unreadable ≠ empty — never delete on doubt
    try {
      unlinkSync(entry.path);
      total -= entry.size;
      removedRows += rows;
    } catch {
      // Raced a claim/rename or a locked file — skip it this round.
    }
  }
  if (removedRows === 0) return;
  usageOutboxDropped += removedRows;
  logWarn("usage-ledger", "usage outbox full; dropped oldest segments", {
    dropped_now: removedRows,
    dropped_total: usageOutboxDropped,
  });
};

/** Any unclaimed segment a pass could still work on? (Claimed files are
 *  their owner's business.) */
const usageOutboxHasClaimableWorkSync = (): boolean =>
  scanUsageOutboxSync().some(
    (entry) => !entry.claimed && usageSegmentClaimable(entry),
  );

/**
 * One delivery attempt for one row. Exactly one attempt per call (attempts
 * are counted + persisted in the segment rewrite so the lifetime cap
 * survives restarts); pacing between attempts is the pass-level backoff.
 * `keep` = transient (5xx/429/network); `abort` = keyless mid-pass — NOT
 * counted against the row, since a key arriving later must still deliver it.
 */
const deliverUsageOutboxEntry = async (
  entry: TUsageOutboxEntry,
): Promise<TUsageDeliverVerdict> => {
  entry.attempts += 1;
  try {
    const response = await cloudFetch(
      cloudUrl("/api/daemon/requests", entry.origin),
      {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(entry.row),
      },
    );
    if (response.ok || response.status === 409 || response.status === 422) {
      return { kind: "delivered" };
    }
    // Terminal rejects drop with a log line; 429 + 5xx stay retryable.
    if (
      response.status >= 400 &&
      response.status < 500 &&
      response.status !== 429
    ) {
      return { kind: "drop", status: response.status };
    }
    return { kind: "keep" };
  } catch (err) {
    if (err instanceof NoApiKeyError) {
      entry.attempts -= 1;
      return { kind: "abort" };
    }
    return { kind: "keep" };
  }
};

const usageOutboxRetryDelayMs = (): number => {
  const exp = Math.min(usageOutboxConsecutiveFailures, 5);
  const base = Math.min(USAGE_RETRY_BASE_MS * 2 ** exp, USAGE_RETRY_MAX_MS);
  return base + Math.floor(Math.random() * USAGE_RETRY_JITTER_MS);
};

/**
 * Drain one claimed segment in row order until it empties, a transient
 * failure stops it (head-of-line: ordering preserved and a down cloud is
 * not hammered once per row), the deadline lands, or the key vanishes.
 * Finalize: delete the claim when every row verdicted, else rewrite it
 * with only the undelivered rows (updated attempts) and release it back to
 * its segment name.
 */
const drainUsageSegment = async (
  entry: TUsageOutboxScanEntry,
  deadline: number,
): Promise<"drained" | "transient" | "deadline" | "abort" | "skip"> => {
  const claimedPath = claimUsageSegmentSync(entry);
  if (claimedPath === null) return "skip";
  const read = readUsageSegmentSync(claimedPath);
  if (read.kind === "error") {
    // Unreadable ≠ empty: keep every row — release the claim untouched so
    // the next pass retries the read, and report transient so the retry is
    // paced by the normal backoff instead of spinning.
    releaseUsageClaimSync(claimedPath);
    return "transient";
  }
  const entries = read.entries;
  const remaining: TUsageOutboxEntry[] = [];
  let stop: "drained" | "transient" | "deadline" | "abort" = "drained";
  for (const row of entries) {
    if (stop !== "drained") {
      remaining.push(row);
      continue;
    }
    if (Date.now() >= deadline) {
      stop = "deadline";
      remaining.push(row);
      continue;
    }
    if (row.attempts >= USAGE_DELIVERY_MAX_ATTEMPTS) {
      usageOutboxDropped += 1;
      logWarn(
        "usage-ledger",
        "usage record dropped after exhausting delivery attempts",
        {
          dropped_total: usageOutboxDropped,
          idempotency_key: row.row.idempotency_key ?? "",
        },
      );
      continue;
    }
    const verdict = await deliverUsageOutboxEntry(row);
    if (verdict.kind === "abort") {
      stop = "abort";
      remaining.push(row);
      continue;
    }
    if (verdict.kind === "keep") {
      stop = "transient";
      remaining.push(row);
      continue;
    }
    if (verdict.kind === "drop") {
      usageOutboxDropped += 1;
      logWarn("usage-ledger", "cloud rejected a usage record; row dropped", {
        status: verdict.status,
        dropped_total: usageOutboxDropped,
        idempotency_key: row.row.idempotency_key ?? "",
      });
    }
    // "delivered" — row simply does not go back into the file.
  }
  if (remaining.length === 0) {
    try {
      unlinkSync(claimedPath);
    } catch {
      releaseUsageClaimSync(claimedPath);
    }
  } else {
    try {
      writeUsageSegmentFileSync(claimedPath, remaining);
    } catch (err) {
      // The rows stay durable under the claim name — releasing still wins,
      // and a failed release leaves the claim for stale-claim recovery.
      logWarn("usage-ledger", "usage outbox segment could not be rewritten", {
        err: err instanceof Error ? err.message : String(err),
      });
    }
    releaseUsageClaimSync(claimedPath);
  }
  return stop;
};

/**
 * One drain pass over every claimable segment, oldest-first. Stops at the
 * first transient failure so a down cloud is not hammered once per row,
 * at the deadline, or when the key vanishes. Reports WHY it stopped so the
 * scheduler honours the current backoff instead of looping hot.
 */
const usageOutboxFlushPass = async (
  budgetMs?: number,
): Promise<TUsagePassReport> => {
  const deadline =
    budgetMs === undefined ? Number.POSITIVE_INFINITY : Date.now() + budgetMs;
  // Keyless: rows stay queued untouched — a key arriving later delivers them.
  if (daemonEnv().apiKey === null) return { transient: false, aborted: true };
  migrateUsageOutboxLegacyFileSync();
  reclaimStaleUsageClaimsSync();
  let hitTransient = false;
  for (const entry of scanUsageOutboxSync()) {
    if (entry.claimed || !usageSegmentClaimable(entry)) continue;
    if (Date.now() >= deadline) break;
    const outcome = await drainUsageSegment(entry, deadline);
    if (outcome === "transient") {
      hitTransient = true;
      break;
    }
    if (outcome === "deadline") break;
    if (outcome === "abort") return { transient: false, aborted: true };
  }
  usageOutboxConsecutiveFailures = hitTransient
    ? usageOutboxConsecutiveFailures + 1
    : 0;
  return { transient: hitTransient, aborted: false };
};

const startUsageOutboxPass = (budgetMs?: number): Promise<void> => {
  // This pass covers every record dirtied up to NOW; anything appended
  // while it runs sets the flag again and earns exactly one follow-up.
  usageOutboxDirty = false;
  const run = usageOutboxFlushPass(budgetMs).catch(
    (err: unknown): TUsagePassReport => {
      logWarn("usage-ledger", "usage outbox flush failed", {
        err: err instanceof Error ? err.message : String(err),
      });
      return { transient: true, aborted: false };
    },
  );
  usageOutboxFlushInFlight = run.then((report) => {
    usageOutboxFlushInFlight = null;
    finishUsageOutboxPass(report);
  });
  return usageOutboxFlushInFlight;
};

/**
 * Post-pass scheduling — the ONLY automatic retry path. Work remains iff
 * records were dirtied during the pass or claimable rows are still on
 * disk; then exactly ONE follow-up timer may exist, armed at the CURRENT
 * backoff (a clean pass has no backoff to honour). A keyless pass arms
 * nothing: rows simply wait for the next producer kick or the boot flush.
 */
const finishUsageOutboxPass = (report: TUsagePassReport): void => {
  if (report.aborted) return;
  let pending = usageOutboxDirty;
  try {
    pending = pending || usageOutboxHasClaimableWorkSync();
  } catch {
    // A scan failure must not wedge the scheduler — assume work remains.
    pending = true;
  }
  if (!pending) {
    usageOutboxConsecutiveFailures = 0;
    return;
  }
  if (usageOutboxRetryTimer !== null || usageOutboxFlushInFlight !== null)
    return;
  const delayMs =
    usageOutboxConsecutiveFailures > 0 ? usageOutboxRetryDelayMs() : 0;
  usageOutboxRetryTimer = setTimeout(() => {
    usageOutboxRetryTimer = null;
    if (usageOutboxFlushInFlight === null) void startUsageOutboxPass();
  }, delayMs);
  usageOutboxRetryTimer.unref?.();
};

/** Producer path: mark the outbox dirty and make sure SOME pass will run —
 *  never more than one in flight, never more than one timer pending. */
const kickUsageOutboxDrain = (): void => {
  usageOutboxDirty = true;
  if (usageOutboxFlushInFlight !== null || usageOutboxRetryTimer !== null)
    return;
  void startUsageOutboxPass();
};

/**
 * An explicit drain — boot (`startControlChannel`), the bounded shutdown
 * pass (`stopControlChannel`), and tests. Each caller gets a pass that
 * started after its call: while a pass is in flight the caller chains one
 * behind it; a pending scheduled follow-up is cancelled because its only
 * purpose — running a pass — is being served now. Automatic retries NEVER
 * come through here (producers only set the dirty flag), so this cannot
 * be used to spin retries past the backoff.
 */
const runExplicitUsageOutboxPass = (budgetMs?: number): Promise<void> => {
  if (usageOutboxRetryTimer !== null) {
    clearTimeout(usageOutboxRetryTimer);
    usageOutboxRetryTimer = null;
  }
  const inFlight = usageOutboxFlushInFlight;
  if (inFlight !== null) {
    return inFlight.then(() => runExplicitUsageOutboxPass(budgetMs));
  }
  return startUsageOutboxPass(budgetMs);
};

/**
 * Drain the durable usage outbox. With `budgetMs` the returned promise is
 * race-bounded — the pass keeps running detached, so the shutdown caller
 * gets its bounded wait either way. Never rejects — the ledger is
 * best-effort by design.
 */
export const flushUsageOutbox = (budgetMs?: number): Promise<void> => {
  usageOutboxDirty = true;
  const run = runExplicitUsageOutboxPass(budgetMs);
  if (budgetMs === undefined) return run;
  return Promise.race([
    run,
    new Promise<void>((resolve) => setTimeout(resolve, budgetMs)),
  ]);
};

/** Test seam: on-disk outbox state + scheduler flags. */
export const usageOutboxSnapshotForTests = (): {
  readonly pending_segments: number;
  readonly pending_rows: number;
  readonly dropped_total: number;
  readonly dir_fsyncs: number;
  readonly dirty: boolean;
  readonly retry_scheduled: boolean;
  readonly in_flight: boolean;
} => {
  const entries = scanUsageOutboxSync();
  let rows = 0;
  for (const entry of entries) {
    rows += Math.max(0, countUsageSegmentLinesSync(entry.path));
  }
  return {
    pending_segments: entries.filter((entry) => !entry.claimed).length,
    pending_rows: rows,
    dropped_total: usageOutboxDropped,
    dir_fsyncs: usageOutboxDirFsyncs,
    dirty: usageOutboxDirty,
    retry_scheduled: usageOutboxRetryTimer !== null,
    in_flight: usageOutboxFlushInFlight !== null,
  };
};

/** Test seam: drop all outbox module state. Does NOT touch the files. */
export const resetUsageOutboxForTests = (): void => {
  if (usageOutboxRetryTimer !== null) {
    clearTimeout(usageOutboxRetryTimer);
    usageOutboxRetryTimer = null;
  }
  usageOutboxDirty = false;
  usageOutboxDropped = 0;
  usageOutboxDirFsyncs = 0;
  usageOutboxConsecutiveFailures = 0;
  usageOutboxLegacyChecked = false;
  usageOwnerStateCache.clear();
};

// ─── Persisted-error sanitization (EC-2 hardening) ──────────────────────
//
// The ledger `error` field is fsync'd to the local outbox AND POSTed to
// the cloud — it must never carry ANY upstream free text. The single
// shared sanitizer is `sanitizeUsageError` in `@openllmsh/protocol`
// (`usage-error.ts`, imported above): a CLOSED allowlist of error
// type/code atoms — anything not on the list stores as `other`, so an
// identifier-shaped secret (`sk-llm-…`) can never ride the classifier —
// plus `HTTP <status>`, a daemon-authored head, and a fixed category. The
// API re-applies the identical function at insert
// (`packages/api/handlers/usage.ts`), so the daemon-side pass is
// idempotent by construction, not by convention.

/**
 * Record one `public.requests` row for a subscription hop the daemon ran
 * locally. Persists to the durable outbox BEFORE resolving — resolving
 * after the fsync'd append means even a process exit immediately after
 * this call keeps the row — then marks the outbox dirty for the coalesced
 * drain. A recording failure must never fail the user's request (the bytes
 * already streamed back), so callers fire-and-forget; outbox persistence
 * failures degrade to a counted, rate-limited warn rather than an
 * unhandled rejection.
 */
export const recordRequest = async (
  row: TDaemonRecordRequest,
  origin?: string | null,
): Promise<void> => {
  const entry: TUsageOutboxEntry = {
    row: { ...row, error: sanitizeUsageError(row.error, row.status) },
    origin: origin ?? null,
    attempts: 0,
  };
  try {
    appendUsageOutboxLineSync(serializeUsageOutboxEntry(entry));
    enforceUsageOutboxCapSync();
  } catch (err) {
    usageOutboxDropped += 1;
    const repeat = takeRepeatWindow("usage-ledger:persist");
    if (repeat !== null) {
      logWarn(
        "usage-ledger",
        "usage record could not be persisted to the local outbox",
        {
          err: err instanceof Error ? err.message : String(err),
          dropped_total: usageOutboxDropped,
          repeat_count: repeat,
        },
      );
    }
    return;
  }
  kickUsageOutboxDrain();
};

/**
 * A transient cloud failure worth one retry within the two-attempt budget:
 * an overloaded server (500) or a rate limit (429). The cloud handler dedups
 * by (user, kind, scope, key), so a retry after a partially-processed request
 * cannot double-send. Every other status is a definitive reject — no retry.
 */
const isRetryableStatus = (status: number): boolean =>
  status === 500 || status === 429;

type TNotifyCloudEventLog = {
  readonly scope: string;
  readonly rejectedMessage: string;
  readonly failedMessage: string;
  readonly slug: string;
  readonly reason?: string;
  readonly diagnostic_code?: string;
};

/**
 * Two-attempt best-effort POST of a daemon cloud event. Retry only 500/429
 * (and thrown transport errors) on attempt 0; terminal otherwise. The cloud
 * handler dedups, so a retry after a partial process cannot double-send.
 */
const notifyCloudEvent = async (
  path: string,
  body: unknown,
  log: TNotifyCloudEventLog,
): Promise<void> => {
  const fields = {
    slug: log.slug,
    ...(log.reason === undefined ? {} : { reason: log.reason }),
    ...(log.diagnostic_code === undefined
      ? {}
      : { diagnostic_code: log.diagnostic_code }),
  };
  const request = (): Promise<Response> =>
    cloudFetch(cloudUrl(path), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(body),
    });

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await request();
      if (response.ok) return;
      if (!isRetryableStatus(response.status) || attempt === 1) {
        logWarn(log.scope, log.rejectedMessage, {
          status: response.status,
          ...fields,
        });
        return;
      }
    } catch (error) {
      if (attempt === 1) {
        logWarn(log.scope, log.failedMessage, {
          error_class: error instanceof Error ? error.name : typeof error,
          ...fields,
        });
        return;
      }
    }
  }
};

/**
 * Report a confirmed local subscription-session loss to the cloud. This is
 * best-effort operational telemetry: the status path must never wait for it.
 */
export const notifySessionLost = async (
  loss: TDaemonSessionLost,
): Promise<void> => {
  await notifyCloudEvent("/api/daemon/session-lost", loss, {
    scope: "auth-loss-notify",
    rejectedMessage: "cloud rejected session-loss notification",
    failedMessage: "session-loss notification failed",
    slug: loss.slug,
    ...(loss.diagnostic_code === undefined
      ? {}
      : { diagnostic_code: loss.diagnostic_code }),
  });
};

/**
 * Report a fresh subscription quota warning or rejection to the cloud. This is
 * best-effort operational telemetry: repeated status computation must not wait
 * for it, and one transport retry is the complete delivery budget.
 */
export const notifyQuotaStatus = async (
  body: TDaemonQuotaStatusReached,
): Promise<void> => {
  await notifyCloudEvent("/api/daemon/quota-status", body, {
    scope: "quota-status-notify",
    rejectedMessage: "cloud rejected quota notification",
    failedMessage: "quota notification failed",
    slug: body.slug,
  });
};

export type TUploadMediaOptions = {
  readonly contentType: string;
  readonly kind: string;
  readonly sourceRef?: string;
  readonly filename?: string;
  /** Pre-minted media row id — sent as `x-media-id` so the cloud row's PK is
   *  known to the daemon up front (keeps `/api/media/<id>` stable). */
  readonly id?: string;
};

export type TUploadMediaResponse = {
  readonly id: string;
  readonly url: string;
};

/**
 * Observe WHY an ingest failed, without changing `uploadMedia`'s resolved
 * shape. A `null` result is the single "not persisted" answer every caller
 * already branches on; this optional sink adds the coarse reason for the one
 * caller that must tell its consumer something more useful than "no URL".
 *
 * Optional + additive on purpose: every existing call site (and every test
 * double that implements `uploadMedia` with three parameters) keeps working
 * unchanged, and a caller that passes no sink pays nothing.
 */
export type TUploadMediaDiagnostic = {
  readonly reason: TMediaPersistError;
  /** Ingest HTTP status, when one was actually received. Never a URL, body,
   *  credential or byte count — this is logged locally AND (as `reason`
   *  alone) crosses the relay. */
  readonly status?: number;
};

const uploadFailureReason = (err: unknown): TMediaPersistError => {
  if (err instanceof DOMException && err.name === "TimeoutError") {
    return "ingest_timeout";
  }
  if (err instanceof Error && err.name === "TimeoutError") {
    return "ingest_timeout";
  }
  return "ingest_unreachable";
};

/**
 * Best-effort ingest of locally generated media into the cloud library. Media
 * bytes can be large, so this deliberately uses a longer timeout than the
 * daemon control plane. Failures are swallowed so callers can choose a local
 * fallback without failing the generation itself.
 */
export const uploadMedia = async (
  bytes: ArrayBuffer | Uint8Array,
  opts: TUploadMediaOptions,
  origin?: string | null,
  onFailure?: (diagnostic: TUploadMediaDiagnostic) => void,
): Promise<TUploadMediaResponse | null> => {
  const fail = (diagnostic: TUploadMediaDiagnostic): null => {
    onFailure?.(diagnostic);
    return null;
  };
  try {
    const headers = {
      ...authHeaders(),
      "content-type": opts.contentType,
      "x-media-kind": opts.kind,
      ...(opts.sourceRef === undefined
        ? {}
        : { "x-media-source-ref": opts.sourceRef }),
      ...(opts.filename === undefined
        ? {}
        : { "x-media-filename": opts.filename }),
      ...(opts.id === undefined ? {} : { "x-media-id": opts.id }),
    };
    // A Blob body is replayable, so an allowed 307/308 may be re-issued under
    // the shared redirect policy; anything else is surfaced verbatim.
    const blob = new Blob([
      bytes instanceof Uint8Array ? new Uint8Array(bytes) : bytes,
    ]);
    const resp = await fetchWithBoundedRedirects(
      cloudUrl("/api/daemon/media", origin),
      (target) =>
        fetch(target, {
          method: "POST",
          headers,
          body: blob,
          redirect: "manual",
          signal: AbortSignal.timeout(MEDIA_UPLOAD_TIMEOUT_MS),
        }),
      "cloud-client",
    );
    if (!resp.ok) {
      return fail({ reason: "ingest_rejected", status: resp.status });
    }
    let body: unknown;
    try {
      body = await resp.json();
    } catch {
      return fail({ reason: "ingest_invalid_response", status: resp.status });
    }
    if (
      typeof body !== "object" ||
      body === null ||
      !("id" in body) ||
      !("url" in body) ||
      typeof body.id !== "string" ||
      typeof body.url !== "string"
    ) {
      return fail({ reason: "ingest_invalid_response", status: resp.status });
    }
    return { id: body.id, url: body.url };
  } catch (err) {
    return fail({ reason: uploadFailureReason(err) });
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
