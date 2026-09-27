/**
 * Daemon-side device-grant verification.
 *
 * The browser signs grants with a vault-derived Ed25519 key (noble); this
 * module verifies them with node:crypto only — the daemon package must
 * NEVER import `@openllm/vault`. Pin comes from bootstrap
 * (`device_access_pubkey`); when null, browser admission fails closed.
 */
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import {
  buildDeviceGrantMessage,
  DEVICE_GRANT_NONCE_CAP,
  DEVICE_GRANT_TS_WINDOW_MS,
  decodeDeviceGrant,
} from "@openllmsh/tunnel";
import { daemonServerNowMs } from "./doctor-report/engine";
import { logWarn, safeDiagnosticMessage } from "./logger";
import { mutateState, readState } from "./state-file";

/**
 * Hard upper bound on nonces retained for the ts window. Sized generously for
 * a busy multi-surface open rate (real grant rates are far below 1/s, so even
 * the widened 600 s window stays well under the cap); expiry pruning is the
 * primary retention control. When the map is full of still-valid nonces, new
 * grants are rejected (`nonce_overload`) rather than silently dropping replay
 * protection.
 */
let nonceLruCap = DEVICE_GRANT_NONCE_CAP;

/** Module-level nonce LRU — expire after the grant ts window; hard-cap above. */
const nonceOrder: string[] = [];
const nonceSeen = new Map<string, number>();

/** TEST SEAM — replace the verifier's local clock reading so nonce-expiry
 *  arithmetic can be exercised across the acceptance window without real
 *  waits. Never set in production. */
let nowImpl: () => number = () => Date.now();

export const setDeviceGrantNowForTests = (fn: (() => number) | null): void => {
  nowImpl = fn ?? (() => Date.now());
};

/** In-memory pin; hydrated from state.json on first read. */
let pinnedPubkey: string | null | undefined;

/** Transport owners invalidate access granted by a changed authority. */
const authorityChangeListeners = new Set<() => void>();
export const onDeviceAccessAuthorityChange = (
  listener: () => void,
): (() => void) => {
  authorityChangeListeners.add(listener);
  return () => {
    authorityChangeListeners.delete(listener);
  };
};

const hydratePin = (): string | null => {
  if (pinnedPubkey !== undefined) return pinnedPubkey;
  const fromDisk = readState().deviceAccessPubkey;
  pinnedPubkey = fromDisk === undefined ? null : fromDisk;
  return pinnedPubkey;
};

/**
 * Currently pinned device-access SPKI (base64), or null when un-provisioned.
 * Reads through state.json so a restart re-enforces without waiting on poll.
 */
export const getDeviceAccessPubkey = (): string | null => hydratePin();

/**
 * Pin (or clear) the device-access public key. Latest wins. Persists to
 * state.json. Logs a warn when the pinned value actually changes.
 */
export const setDeviceAccessPubkey = (pubkey: string | null): void => {
  const prev = hydratePin();
  const changed = prev !== pubkey;
  pinnedPubkey = pubkey;
  // Revoke in memory before persistence, including if the state write fails.
  // An unchanged bootstrap pin must preserve established transports.
  if (changed) {
    for (const listener of authorityChangeListeners) {
      try {
        listener();
      } catch {
        logWarn("device-access", "authority change transport cleanup failed");
      }
    }
  }
  // State writes are best-effort. Retry even an identical in-memory pin so a
  // transient failure cannot leave the old authority persisted indefinitely.
  mutateState((s) => ({ ...s, deviceAccessPubkey: pubkey }));
  logWarn(
    "device-access",
    safeDiagnosticMessage`device_access_pubkey pin changed`,
    {
      previous: prev === null ? "null" : "set",
      next: pubkey === null ? "null" : "set",
    },
  );
};

/** Test-only: set the pin without state-file I/O or log noise. */
export const setDeviceAccessPubkeyForTest = (pubkey: string | null): void => {
  pinnedPubkey = pubkey;
};

/** Test-only: clear the nonce LRU between cases. */
export const clearDeviceGrantNoncesForTest = (): void => {
  nonceOrder.length = 0;
  nonceSeen.clear();
};

/** Test-only: override the nonce map capacity (null restores the default). */
export const setNonceLruCapForTest = (cap: number | null): void => {
  nonceLruCap = cap ?? DEVICE_GRANT_NONCE_CAP;
};

/**
 * Verify an Ed25519 signature over `message` with a base64(SPKI) public key.
 * Never throws — any failure (bad b64, bad key, bad sig) returns false.
 */
export const verifyDeviceGrantNode = (
  pubSpkiB64: string,
  message: Uint8Array,
  sigB64: string,
): boolean => {
  try {
    const key = createPublicKey({
      key: Buffer.from(pubSpkiB64, "base64"),
      format: "der",
      type: "spki",
    });
    if (key.asymmetricKeyType !== "ed25519") {
      return false;
    }
    const sig = Buffer.from(sigB64, "base64");
    return nodeVerify(null, Buffer.from(message), key, sig);
  } catch {
    return false;
  }
};

/**
 * Retention margin past the acceptance window. A nonce is kept until BOTH
 * anchors are this far past `ts`, so a later refresh of the server offset
 * must move the server clock back by more than one full window before a
 * pruned grant could verify again.
 */
const NONCE_RETENTION_MS = 2 * DEVICE_GRANT_TS_WINDOW_MS;

/**
 * Drop nonces whose envelope can no longer be accepted. The map stores the
 * envelope `ts`, not a precomputed expiry: the decision uses the anchors as
 * they are NOW (the server offset can change after acceptance, rework-8).
 * A nonce is dropped only when the local AND the server anchor are both
 * more than NONCE_RETENTION_MS past its `ts`. Scans the full order because
 * `ts` is not insertion-order monotonic.
 */
const pruneExpiredNonces = (now: number, serverNow: number | null): void => {
  if (nonceOrder.length === 0) return;
  const kept: string[] = [];
  for (const n of nonceOrder) {
    const ts = nonceSeen.get(n);
    const liveLocal = ts !== undefined && now <= ts + NONCE_RETENTION_MS;
    const liveServer =
      ts !== undefined &&
      serverNow !== null &&
      serverNow <= ts + NONCE_RETENTION_MS;
    if (liveLocal || liveServer) {
      kept.push(n);
      continue;
    }
    nonceSeen.delete(n);
  }
  nonceOrder.length = 0;
  nonceOrder.push(...kept);
};

/**
 * Remember a verified nonce. The map keeps the envelope `ts`; see
 * `pruneExpiredNonces` for when it is dropped.
 *
 * Callers MUST `pruneExpiredNonces(now, serverNow)` before invoking this so capacity
 * checks see a fresh map. Returns false when the map is already full of
 * still-valid nonces — callers must reject with a distinct overload reason
 * rather than silently drop replay protection by evicting unexpired entries.
 */
const rememberNonce = (n: string, envelopeTs: number): boolean => {
  if (nonceSeen.has(n)) return false;
  if (nonceOrder.length >= nonceLruCap) {
    logWarn(
      "device-access",
      safeDiagnosticMessage`nonce map full; rejecting new grant`,
      {
        cap: nonceLruCap,
      },
    );
    return false;
  }
  nonceSeen.set(n, envelopeTs);
  nonceOrder.push(n);
  return true;
};

export type TCheckDeviceGrantExpect = {
  readonly keyId: string;
  readonly cid: string;
  /**
   * When non-empty, envelope.aud must equal this value. An empty envelope.aud
   * is rejected as `aud_unbound` (provisioned mux/tunnel/RTC must bind the
   * grant to the daemon pubkey).
   */
  readonly aud?: string;
};

export type TCheckDeviceGrantResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

/**
 * Min interval between `stale_ts` diagnostics. A signed-but-stale grant is
 * exceptional (real signer, wrong clock) and the warn carries the measured
 * skew for support — but a burst of skewed retries, or replays of a captured
 * grant past its window, must not stamp one disk line per request. The first
 * stale grant logs; repeats land at most once a minute and carry the
 * suppressed count.
 */
const STALE_TS_WARN_MIN_INTERVAL_MS = 60_000;
let lastStaleTsWarnAt = Number.NEGATIVE_INFINITY;
let staleTsWarnSuppressed = 0;

const warnStaleTs = (skewMs: number, serverSkewMs: number | null): void => {
  const now = Date.now();
  if (now - lastStaleTsWarnAt < STALE_TS_WARN_MIN_INTERVAL_MS) {
    staleTsWarnSuppressed += 1;
    return;
  }
  lastStaleTsWarnAt = now;
  logWarn(
    "device-access",
    safeDiagnosticMessage`device grant rejected: stale_ts (signer/verifier clock skew beyond the grant window)`,
    {
      skew_ms: skewMs,
      ...(serverSkewMs === null ? {} : { server_skew_ms: serverSkewMs }),
      window_ms: DEVICE_GRANT_TS_WINDOW_MS,
      suppressed: staleTsWarnSuppressed,
    },
  );
  staleTsWarnSuppressed = 0;
};

/** Test-only: reset the stale_ts warn throttle between cases. */
export const resetStaleTsDiagnosticsForTest = (): void => {
  lastStaleTsWarnAt = Number.NEGATIVE_INFINITY;
  staleTsWarnSuppressed = 0;
};

/**
 * Full grant check: decode → signature against the pinned pubkey → ts
 * window → key_id/cid/aud → nonce. The signature runs FIRST — before any
 * field check that can write a log line — so an unauthenticated request
 * carrying a crafted old ts dies at `bad_sig` instead of reaching the
 * stale_ts diagnostic (request-driven log/doctor-write amplification).
 */
export const checkDeviceGrant = (
  envelopeB64: string,
  expect: TCheckDeviceGrantExpect,
): TCheckDeviceGrantResult => {
  const pinned = getDeviceAccessPubkey();
  if (pinned === null) {
    return { ok: false, reason: "unprovisioned" };
  }
  const envelope = decodeDeviceGrant(envelopeB64);
  if (envelope === null) {
    return { ok: false, reason: "malformed" };
  }
  const msg = buildDeviceGrantMessage({
    v: envelope.v,
    n: envelope.n,
    ts: envelope.ts,
    key_id: envelope.key_id,
    cid: envelope.cid,
    aud: envelope.aud,
  });
  if (!verifyDeviceGrantNode(pinned, msg, envelope.sig)) {
    return { ok: false, reason: "bad_sig" };
  }
  const now = nowImpl();
  const localSkewMs = now - envelope.ts;
  // Server-anchored check (TCB-5): when a bootstrap receipt has pinned the
  // cloud↔local offset, a grant inside the window of CLOUD time is accepted
  // even when THIS host's clock is skewed — the signer (viewer device) and
  // the cloud are the two clocks a correct viewer is plausibly synced to.
  // Reject only when BOTH anchors say stale; a skewed daemon clock can no
  // longer fail valid grants on its own.
  // The server anchor is read once — the skew branch and the nonce retention
  // both key off the same acceptance-time reading.
  const serverNow = daemonServerNowMs();
  if (Math.abs(localSkewMs) > DEVICE_GRANT_TS_WINDOW_MS) {
    const serverSkewMs = serverNow === null ? null : serverNow - envelope.ts;
    if (
      serverSkewMs === null ||
      Math.abs(serverSkewMs) > DEVICE_GRANT_TS_WINDOW_MS
    ) {
      // Surface the measured skew: `stale_ts` rejections mean the viewer's
      // clock differs from every trusted anchor by more than the grant
      // window (TCB-5). The signed offset lands in the daemon log + doctor
      // observations so support can see WHICH clock is off and by how much —
      // signature-verified only, and rate-limited (see `warnStaleTs`).
      warnStaleTs(localSkewMs, serverSkewMs);
      return { ok: false, reason: "stale_ts" };
    }
  }
  if (envelope.key_id !== expect.keyId) {
    return { ok: false, reason: "key_id_mismatch" };
  }
  if (envelope.cid !== expect.cid) {
    return { ok: false, reason: "cid_mismatch" };
  }
  // When expect.aud is non-empty, envelope.aud must match. Empty expect.aud
  // is the unit-test / low-level opt-out; production callers go through
  // enforceSeedGate which rejects empty expect.aud before reaching here.
  const expectAud = expect.aud ?? "";
  if (expectAud.length > 0) {
    if (envelope.aud.length === 0) {
      return { ok: false, reason: "aud_unbound" };
    }
    if (envelope.aud !== expectAud) {
      return { ok: false, reason: "aud_mismatch" };
    }
  }
  // Nonce check AFTER identity checks so a wrong-key/cid grant cannot
  // burn a legitimate nonce the browser may still retry with.
  pruneExpiredNonces(now, serverNow);
  if (nonceSeen.has(envelope.n)) {
    return { ok: false, reason: "replayed_nonce" };
  }
  // Signature verified — only then admit the nonce. Full map of still-valid
  // nonces rejects rather than evicting (replay protection must not degrade).
  if (!rememberNonce(envelope.n, envelope.ts)) {
    return { ok: false, reason: "nonce_overload" };
  }
  return { ok: true };
};

export type TEnforceSeedGateResult =
  | { readonly mode: "reject"; readonly reason: string }
  | { readonly mode: "ok" };

export type TEnforceSeedGateExpect = {
  readonly keyId: string | null;
  readonly cid: string;
  readonly aud: string;
};

/**
 * Single seed-gate decision tree for browser mux / tunnel / RTC.
 * - pin null → reject "unprovisioned"
 * - missing keyId → reject "no_api_key_id"
 * - missing/empty grant → reject "missing_grant"
 * - checkDeviceGrant fail → reject with checked.reason
 * - else ok
 *
 * Fleet daemon-to-daemon mux hops deliberately bypass this browser gate in
 * mux-host: they do not have a browser vault DEK with which to mint a grant.
 *
 * Callers pass `daemonApiKeyId()` / `daemonPublicKey()` so this module stays
 * free of env/keypair imports (no circular deps).
 */
export const enforceSeedGate = (
  grant: string | undefined,
  expect: TEnforceSeedGateExpect,
): TEnforceSeedGateResult => {
  if (getDeviceAccessPubkey() === null) {
    return { mode: "reject", reason: "unprovisioned" };
  }
  if (expect.keyId === null) {
    return { mode: "reject", reason: "no_api_key_id" };
  }
  // Fail closed: an empty expected aud would skip audience binding inside
  // checkDeviceGrant. Production always binds to the daemon pubkey.
  if (expect.aud.length === 0) {
    return { mode: "reject", reason: "aud_unbound" };
  }
  if (grant === undefined || grant.length === 0) {
    return { mode: "reject", reason: "missing_grant" };
  }
  const checked = checkDeviceGrant(grant, {
    keyId: expect.keyId,
    cid: expect.cid,
    aud: expect.aud,
  });
  if (!checked.ok) {
    return { mode: "reject", reason: checked.reason };
  }
  return { mode: "ok" };
};

/**
 * RTC offer seed-gate: require a provisioned pin, offerVersion 2, and a valid
 * nested grant. Unprovisioned daemons fail closed rather than accepting legacy
 * v1 offers. Single entry for the outer pin + v1 branch that previously lived
 * inline in rtc-host.
 */
export const enforceRtcSeedGate = (
  grant: string | undefined,
  expect: TEnforceSeedGateExpect & { readonly offerVersion: number },
): TEnforceSeedGateResult => {
  if (getDeviceAccessPubkey() === null) {
    return { mode: "reject", reason: "unprovisioned" };
  }
  if (expect.offerVersion !== 2) {
    return { mode: "reject", reason: "v1_offer" };
  }
  return enforceSeedGate(grant, expect);
};
