/**
 * The daemon's status snapshot, computed in one place so the `/status`
 * one-shot endpoint and the `/events` SSE push share identical logic.
 *
 * Computing it spawns each delegate's `status()` (a CLI `--version` + an
 * auth/store read), so callers should not hammer it — the SSE watcher
 * recomputes on a gentle interval and only while a client is listening.
 */
import { accessSync, constants, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type {
  TDaemonProviderAuthStatus,
  TDaemonProviderConnection,
  TDaemonStatus,
} from "@openllmsh/protocol";
import { autoUpdateEnabled } from "./auto-update-pref";
import { getCloudState } from "./config";
import { DELEGATES, isSubscriptionSlug } from "./delegation";
import { loginSlot } from "./delegation/login-flow";
import { DEFAULT_CAPTURE_TIMEOUT_MS } from "./delegation/spawn";
import { STATUS_CHECK_FAILED_DETAIL } from "./delegation/util";
import { getCliState } from "./device-state";
import { daemonPort, hasApiKey } from "./env";
import { daemonPublicKey } from "./keypair";
import { logWarn } from "./logger";
import { currentDaemonCaps } from "./mux-host";
import { resolveOnPath } from "./path-utils";
import { ptySessionsEnabled } from "./pty-sessions-pref";
import { sandboxState } from "./sandbox/landlock";
import { ptySupported, sessionStatusReport } from "./session-host";
import { cachedUsage, peekUsage } from "./usage-cache";
import { DAEMON_VERSION } from "./version";

/** True when `path` is a regular file the process can execute. */
const isExecutableFile = (path: string): boolean => {
  try {
    if (!statSync(path).isFile()) return false;
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
};

const SESSION_CLI_PROBE_TTL_MS = 30_000;
let opencodeProbe: { readonly at: number; readonly found: boolean } | null =
  null;
let hermesProbe: { readonly at: number; readonly found: boolean } | null = null;

// Status runs at hello/reconnect plus the flow watcher cadence. Each delegate's
// version/auth capture self-terminates its process group at
// `DEFAULT_CAPTURE_TIMEOUT_MS`; this wider snapshot ceiling leaves that cleanup
// time to finish before status degrades and the next snapshot retries it.
const DELEGATE_STATUS_TIMEOUT_MS = 10_000;

if (DELEGATE_STATUS_TIMEOUT_MS < DEFAULT_CAPTURE_TIMEOUT_MS) {
  throw new Error("delegate status timeout must cover the capture timeout");
}

// A failed probe cannot establish that a CLI was removed or a credential was
// revoked. Preserve the last complete observation when this daemon has one;
// otherwise omit the unknown installation state rather than serializing it as
// a definitive `false` to the cloud.
const lastKnownConnections = new Map<string, TDaemonProviderConnection>();

/** User-initiated logout, sticky until the next successful login (or a
 *  failed logout that never actually signed out). Set at command receipt. */
const signedOutByUser = new Set<string>();

/** Mark `slug` signed-out at logout command receipt, before `delegate.logout()`. */
export const markProviderSignedOut = (slug: string): void => {
  signedOutByUser.add(slug);
};

/** Clear sticky signed-out (successful login, or a logout that did not take). */
export const clearProviderSignedOut = (slug: string): void => {
  signedOutByUser.delete(slug);
};

const applyAuthLiteral = (
  slug: string,
  conn: TDaemonProviderConnection,
): TDaemonProviderConnection => {
  const last = lastKnownConnections.get(slug);
  const inFlight =
    isSubscriptionSlug(slug) && loginSlot(slug).inFlight();
  const indeterminate = conn.detail === STATUS_CHECK_FAILED_DETAIL;
  // Determinate = this tick's vendor read, not last-known overlay.
  const determinate = !inFlight && !indeterminate;

  if (determinate && conn.status === "connected") {
    // Logout receipt sets the sticky flag while the vendor may still
    // read connected until `delegate.logout()` finishes. Only a rising
    // edge (fresh connected, last-known was not connected) is a login
    // by any path and clears the flag.
    if (signedOutByUser.has(slug) && last?.status === "connected") {
      return { ...conn, status: "signed_out" };
    }
    signedOutByUser.delete(slug);
    return { ...conn, status: "connected" };
  }
  if (signedOutByUser.has(slug)) {
    return { ...conn, status: "signed_out" };
  }
  if (!determinate) {
    const preserved: TDaemonProviderAuthStatus = last?.status ?? conn.status;
    return {
      ...(last !== undefined ? last : conn),
      detail: conn.detail,
      status: preserved,
      ...(conn.pending_auth !== undefined
        ? { pending_auth: conn.pending_auth }
        : {}),
    };
  }
  return { ...conn, status: "disconnected" };
};

const timedOutSlugs = new Set<string>();
const inFlightSlugProbes = new Map<string, Promise<unknown>>();

/** Test-only: the last-known map is process-global and leaks across suites. */
export const resetLastKnownConnectionsForTests = (): void => {
  lastKnownConnections.clear();
  timedOutSlugs.clear();
  signedOutByUser.clear();
  inFlightSlugProbes.clear();
};

const statusFailure = (slug: string): TDaemonProviderConnection => {
  const lastKnown = lastKnownConnections.get(slug);
  if (lastKnown !== undefined) {
    return {
      ...lastKnown,
      detail: STATUS_CHECK_FAILED_DETAIL,
    };
  }
  return {
    provider: slug,
    // Probe failure is not a logout assertion. Protocol has no `unknown`
    // literal; cold-start keeps `disconnected` + the sentinel detail and
    // does not write last-known (so it cannot emit credential_gone).
    status: "disconnected",
    detail: STATUS_CHECK_FAILED_DETAIL,
  };
};

const boundedDelegateStatus = async (
  slug: string,
  status: (signal?: AbortSignal) => Promise<TDaemonProviderConnection>,
): Promise<TDaemonProviderConnection> => {
  if (inFlightSlugProbes.has(slug)) {
    return statusFailure(slug);
  }
  const ac = new AbortController();
  const work = status(ac.signal);
  const tracked = work.then(
    () => undefined,
    () => undefined,
  );
  inFlightSlugProbes.set(slug, tracked);
  void tracked.finally(() => {
    if (inFlightSlugProbes.get(slug) === tracked) {
      inFlightSlugProbes.delete(slug);
    }
  });
  let timer: ReturnType<typeof setTimeout> | null = null;
  let timedOut = false;
  try {
    const result = await Promise.race([
      work,
      new Promise<TDaemonProviderConnection>((resolve) => {
        timer = setTimeout(() => {
          timedOut = true;
          ac.abort();
          if (!timedOutSlugs.has(slug)) {
            timedOutSlugs.add(slug);
            logWarn("status", "delegate status probe timed out", {
              slug,
              phase: "delegate_status",
              timeout_ms: DELEGATE_STATUS_TIMEOUT_MS,
            });
          }
          resolve(statusFailure(slug));
        }, DELEGATE_STATUS_TIMEOUT_MS);
      }),
    ]);
    if (!timedOut) {
      timedOutSlugs.delete(slug);
      if (result.detail === STATUS_CHECK_FAILED_DETAIL) {
        return statusFailure(slug);
      }
    }
    return result;
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
};

/** OpenCode is a device-session client (not a subscription delegate). Surface
 *  install presence so the device picker can offer it when the binary exists. */
const opencodeInstalled = (): boolean => {
  if (
    opencodeProbe !== null &&
    Date.now() - opencodeProbe.at < SESSION_CLI_PROBE_TTL_MS
  ) {
    return opencodeProbe.found;
  }
  const home = homedir();
  const candidates = [
    join(home, ".opencode", "bin", "opencode"),
    join(home, ".local", "bin", "opencode"),
    ...resolveOnPath("opencode"),
  ];
  const found = candidates.some((path) => isExecutableFile(path));
  opencodeProbe = { at: Date.now(), found };
  return found;
};

/** Hermes is a device-session client (not a subscription delegate). */
const hermesInstalled = (): boolean => {
  if (
    hermesProbe !== null &&
    Date.now() - hermesProbe.at < SESSION_CLI_PROBE_TTL_MS
  ) {
    return hermesProbe.found;
  }
  const home = homedir();
  const candidates = [
    join(home, ".hermes", "bin", "hermes"),
    join(home, ".local", "bin", "hermes"),
    ...resolveOnPath("hermes"),
  ];
  const found = candidates.some((path) => isExecutableFile(path));
  hermesProbe = { at: Date.now(), found };
  return found;
};

const computeStatusFresh = async (): Promise<TDaemonStatus> => {
  const connections = await Promise.all(
    Object.values(DELEGATES).map(async (d) => {
      try {
        const raw = await boundedDelegateStatus(d.slug, (signal) =>
          d.status(signal),
        );
        const conn = applyAuthLiteral(d.slug, raw);
        if (
          conn.detail !== STATUS_CHECK_FAILED_DETAIL &&
          !(isSubscriptionSlug(d.slug) && loginSlot(d.slug).inFlight()) &&
          // Overlaying signed_out on a still-connected vendor read (logout
          // in flight) must not rewrite last-known to signed_out, or the
          // next connected tick would look like a login rising edge.
          !(conn.status === "signed_out" && raw.status === "connected")
        ) {
          lastKnownConnections.set(d.slug, conn);
        }
        // Attach a metadata-only usage snapshot for connected providers so the
        // dashboard can show remaining quota (read locally; never a token).
        if (conn.status !== "connected") return conn;
        // PEEK only — never hit the vendor here. `computeStatus` runs on every
        // status push (hello/reconnect, the ~2.5s flow watcher, post-command),
        // and the vendor usage endpoint rate-limits independently of inference;
        // reading it on that cadence 429'd it ("Claude usage is rate-limited
        // right now") on a daemon nobody was even looking at. Usage is read ONLY
        // on demand — the `refresh` command → `refreshUsage` (the manual button
        // or the providers page mounting). Here we just attach whatever that last
        // on-demand read cached. See `usage-cache.ts`.
        const usage = peekUsage(d.slug, conn.account_hash);
        return usage === null ? conn : { ...conn, usage };
      } catch (err) {
        // One provider's status read must NOT sink the whole snapshot (every
        // card would vanish + the push would fail). Surface a safe placeholder;
        // the next push self-corrects once the provider recovers.
        logWarn("status", `status() failed for ${d.slug}`, {
          err: err instanceof Error ? err.message : String(err),
        });
        return statusFailure(d.slug);
      }
    }),
  );
  // Device-session-only CLI (no subscription connect card). Append so the
  // device picker can list it; /providers filters to subscription slugs.
  if (opencodeInstalled()) {
    connections.push({
      provider: "opencode",
      status: "disconnected",
      cli_installed: true,
    });
  }
  if (hermesInstalled()) {
    connections.push({
      provider: "hermes",
      status: "disconnected",
      cli_installed: true,
    });
  }
  return {
    daemon_version: DAEMON_VERSION,
    key_configured: hasApiKey(),
    auto_update: autoUpdateEnabled(),
    pty_sessions: ptySessionsEnabled(),
    cloud_state: getCloudState(),
    pubkey: daemonPublicKey(),
    port: daemonPort(),
    sandbox: sandboxState(),
    caps: currentDaemonCaps(),
    connections,
    // TTL-cached CLI probe from `getCliState()`. It returns cached state when fresh
    // and schedules a background refresh when stale, so status can stay responsive
    // without blocking and without manifest scans.
    cli: getCliState(),
    // Device chat sessions (feature §2.2): whether this box can host a
    // PTY, and the sessions it currently holds (live/dormant).
    pty_supported: ptySupported(),
    sessions: sessionStatusReport(),
  };
};

let inFlightStatus: Promise<TDaemonStatus> | null = null;

export const computeStatus = async (): Promise<TDaemonStatus> => {
  if (inFlightStatus === null) {
    inFlightStatus = computeStatusFresh().finally(() => {
      inFlightStatus = null;
    });
  }
  return inFlightStatus;
};

/**
 * On-demand usage read — the ONLY path that hits the vendor usage endpoint.
 * Driven by the `refresh` command (the manual "Refresh usage" button or the
 * providers page mounting for this device, via `control-relay.ts`). Fetches
 * figures for every CONNECTED provider (or just `slug` when scoped) into the
 * usage cache; the status push that follows the command then carries them back
 * via `peekUsage`. RESPECTS each provider's TTL — `cachedUsage` serves a
 * still-fresh snapshot from cache (no vendor hit) and only re-fetches a stale or
 * never-fetched one, so a whole-daemon refresh after one login doesn't re-hit
 * every vendor. Best-effort per provider — `cachedUsage` already swallows fetch
 * failures into an `unavailable` snapshot.
 */
export const refreshUsage = async (slug?: string): Promise<void> => {
  // `allSettled`, NOT `all`: ONE provider throwing (e.g. a failing status/refresh
  // read) must not reject the whole refresh — that would error the `refresh`
  // command ack, so the dashboard's "Refresh usage" button would fail and every
  // card stay stale just because a single provider is broken. Each provider's
  // read is independent + best-effort (`cachedUsage` already swallows fetch
  // failures into an `unavailable` snapshot).
  await Promise.allSettled(
    Object.values(DELEGATES)
      .filter((d) => slug === undefined || d.slug === slug)
      .map(async (d) => {
        // Only connected providers have a usage endpoint to read.
        const status = await d.status();
        if (status.status !== "connected") return;
        await cachedUsage(d.slug, () => d.usage(), {
          accountHash: status.account_hash,
        });
      }),
  );
};
