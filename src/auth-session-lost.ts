/**
 * Falling-edge `auth.session.lost` detection (audit 2026-08-21 §7 item 5).
 *
 * The subscription login FSM emits `auth.login.succeeded` / `.failed` from the
 * flow itself (`login-flow`). The MIRROR — "you were signed out" — has no flow:
 * it is the falling edge of a previously-connected provider, observed on the
 * status-compute path (hello / the ~2.5s watcher / post-command push). This
 * module watches each computed snapshot and emits `auth.session.lost` exactly
 * once when a provider that WAS connected reads not-connected, with no login in
 * flight.
 *
 * Two guards keep it quiet:
 *   - Cold start (`connected: false` with no prior observation) is NOT a loss —
 *     only a recorded `connected: true` → `false` transition emits.
 *   - A transient probe failure never flips `connected` to `false` (status.ts
 *     `statusFailure` preserves the last-known connection), so this never fires
 *     on a status hiccup.
 *
 * A `logout` / `cancel` command that caused the drop stamps the reason via
 * {@link markSessionLostReason}; otherwise it defaults to `credential_gone`.
 * (`vendor_revoked` has no local signal, so it is never inferred here.)
 */
import type {
  TAuthSessionLostReason,
  TDaemonProviderConnection,
} from "@openllmsh/protocol";
import { emitAuth } from "./auth-events";
import { isSubscriptionSlug } from "./delegation";
import { loginSlot } from "./delegation/login-flow";
import { daemonApiKeyId } from "./env";

type TConnSnapshot = {
  readonly connected: boolean;
  readonly accountHash?: string;
};

/** Last observed connection per subscription slug — the falling-edge baseline. */
const lastConnected = new Map<string, TConnSnapshot>();

/** A command-attributed reason for the NEXT falling edge of a slug (else the
 *  default `credential_gone` is used). Consumed on emit or on reconnect. */
const pendingLostReason = new Map<string, TAuthSessionLostReason>();

/**
 * Attribute the next falling edge of `slug` to `reason` (e.g. a `logout`
 * command). Consumed by {@link noteConnectionsForSessionLost} on the edge, or
 * dropped when the provider is seen still-connected (the command did not take).
 */
export const markSessionLostReason = (
  slug: string,
  reason: TAuthSessionLostReason,
): void => {
  pendingLostReason.set(slug, reason);
};

/**
 * Observe one computed status snapshot's connections and emit
 * `auth.session.lost` for every subscription provider that transitioned
 * connected → not-connected with no in-flight login. Best-effort: `emitAuth`
 * is a no-op when the control channel is not running.
 */
export const noteConnectionsForSessionLost = (
  connections: ReadonlyArray<TDaemonProviderConnection>,
): void => {
  for (const conn of connections) {
    const slug = conn.provider;
    if (!isSubscriptionSlug(slug)) continue;
    // A login in flight momentarily reads not-connected (a re-login). Neither
    // emit a loss NOR disturb the baseline — the falling edge (if the login
    // then fails) is recognized on the first snapshot after the slot clears,
    // against the PRE-login baseline. Overwriting it here would erase the "was
    // connected" fact and swallow the loss.
    if (loginSlot(slug).inFlight()) continue;
    const now = conn.connected === true;
    const prev = lastConnected.get(slug);
    if (prev?.connected === true && !now) {
      const reason = pendingLostReason.get(slug) ?? "credential_gone";
      pendingLostReason.delete(slug);
      emitAuth({
        event: "auth.session.lost",
        key_id: daemonApiKeyId() ?? "local",
        slug,
        reason,
        ...(prev.accountHash !== undefined
          ? { account_hash: prev.accountHash }
          : {}),
      });
    } else if (now) {
      // Still (or freshly) connected — any stamped logout reason is stale.
      pendingLostReason.delete(slug);
    }
    lastConnected.set(slug, {
      connected: now,
      ...(conn.account_hash !== undefined
        ? { accountHash: conn.account_hash }
        : {}),
    });
  }
};

/** Test-only: the trackers are process-global and leak across suites. */
export const resetSessionLostTrackerForTests = (): void => {
  lastConnected.clear();
  pendingLostReason.clear();
};
