/**
 * Daemon-side device-grant verification.
 *
 * The browser signs grants with a vault-derived Ed25519 key (noble); this
 * module verifies them with node:crypto only — the daemon package must
 * NEVER import `@openllm/vault`. Pin comes from bootstrap
 * (`device_access_pubkey`); when null, seedgate enforcement is off.
 */
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import {
  buildDeviceGrantMessage,
  DEVICE_GRANT_TS_WINDOW_MS,
  decodeDeviceGrant,
} from "@openllmsh/tunnel";
import { logWarn } from "./logger";
import { mutateState, readState } from "./state-file";

/**
 * Hard upper bound on nonces retained for the ts window. Sized for a busy
 * multi-surface open rate (~30 grants/s × 120s window ≈ 3600) with headroom;
 * expiry pruning is the primary retention control — the cap only logs when
 * reached so a runaway client cannot grow the map without bound.
 */
const NONCE_LRU_CAP = 4096;

/** Module-level nonce LRU — expire after the grant ts window; hard-cap above. */
const nonceOrder: string[] = [];
const nonceSeen = new Map<string, number>();

/** In-memory pin; hydrated from state.json on first read. */
let pinnedPubkey: string | null | undefined;

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
  if (prev === pubkey) return;
  pinnedPubkey = pubkey;
  mutateState((s) => ({ ...s, deviceAccessPubkey: pubkey }));
  logWarn("device-access", "device_access_pubkey pin changed", {
    previous: prev === null ? "null" : "set",
    next: pubkey === null ? "null" : "set",
  });
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
    const sig = Buffer.from(sigB64, "base64");
    return nodeVerify(null, Buffer.from(message), key, sig);
  } catch {
    return false;
  }
};

/**
 * Drop expired nonces. Scans the full order because retention is based on
 * envelope.ts (which may be future-dated within the acceptance window), so
 * expiry is no longer insertion-order monotonic.
 */
const pruneExpiredNonces = (now: number): void => {
  if (nonceOrder.length === 0) return;
  const kept: string[] = [];
  for (const n of nonceOrder) {
    const exp = nonceSeen.get(n);
    if (exp !== undefined && exp > now) {
      kept.push(n);
      continue;
    }
    nonceSeen.delete(n);
  }
  nonceOrder.length = 0;
  nonceOrder.push(...kept);
};

/**
 * Remember a verified nonce until its envelope can no longer be accepted.
 * Retention is `envelopeTs + WINDOW` so a future-dated grant (still inside
 * the acceptance window) cannot be replayed after a premature prune.
 */
const rememberNonce = (n: string, envelopeTs: number, now: number): boolean => {
  pruneExpiredNonces(now);
  if (nonceSeen.has(n)) return false;
  nonceSeen.set(n, envelopeTs + DEVICE_GRANT_TS_WINDOW_MS);
  nonceOrder.push(n);
  // Log once per crossing of the hard cap (not once per eviction in the loop).
  if (nonceOrder.length > NONCE_LRU_CAP) {
    logWarn("device-access", "nonce LRU hard cap reached; evicting oldest", {
      cap: NONCE_LRU_CAP,
    });
    while (nonceOrder.length > NONCE_LRU_CAP) {
      const evicted = nonceOrder.shift();
      if (evicted !== undefined) nonceSeen.delete(evicted);
    }
  }
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
 * Full grant check: decode → rebuild message → ts window → nonce →
 * key_id/cid/aud → signature against the pinned pubkey.
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
  const now = Date.now();
  if (Math.abs(now - envelope.ts) > DEVICE_GRANT_TS_WINDOW_MS) {
    return { ok: false, reason: "stale_ts" };
  }
  if (envelope.key_id !== expect.keyId) {
    return { ok: false, reason: "key_id_mismatch" };
  }
  if (envelope.cid !== expect.cid) {
    return { ok: false, reason: "cid_mismatch" };
  }
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
  // burn a legitimate nonce the browser may still retry with. Only
  // remember the nonce once the signature also verifies.
  pruneExpiredNonces(now);
  if (nonceSeen.has(envelope.n)) {
    return { ok: false, reason: "replayed_nonce" };
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
  rememberNonce(envelope.n, envelope.ts, now);
  return { ok: true };
};

export type TEnforceSeedGateResult =
  | { readonly mode: "off" }
  | { readonly mode: "reject"; readonly reason: string }
  | { readonly mode: "ok" };

export type TEnforceSeedGateExpect = {
  readonly keyId: string | null;
  readonly cid: string;
  readonly aud: string;
};

/**
 * Single seed-gate decision tree for mux / tunnel / RTC.
 * - pin null → mode "off" (legacy, skip enforcement)
 * - missing keyId → reject "no_api_key_id"
 * - missing/empty grant → reject "missing_grant"
 * - checkDeviceGrant fail → reject with checked.reason
 * - else ok
 *
 * Callers pass `daemonApiKeyId()` / `daemonPublicKey()` so this module stays
 * free of env/keypair imports (no circular deps).
 */
export const enforceSeedGate = (
  grant: string | undefined,
  expect: TEnforceSeedGateExpect,
): TEnforceSeedGateResult => {
  if (getDeviceAccessPubkey() === null) {
    return { mode: "off" };
  }
  if (expect.keyId === null) {
    return { mode: "reject", reason: "no_api_key_id" };
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
