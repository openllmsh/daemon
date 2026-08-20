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
  TDaemonProviderConnection,
  TDaemonStatus,
} from "@openllmsh/protocol";
import { autoUpdateEnabled } from "./auto-update-pref";
import { getCloudState } from "./config";
import { DELEGATES } from "./delegation";
import { DEFAULT_CAPTURE_TIMEOUT_MS } from "./delegation/spawn";
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

const OPENCODE_PROBE_TTL_MS = 30_000;
let opencodeProbe: { readonly at: number; readonly found: boolean } | null =
  null;

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

/** Test-only: the last-known map is process-global and leaks across suites. */
export const resetLastKnownConnectionsForTests = (): void => {
  lastKnownConnections.clear();
};

const statusFailure = (slug: string): TDaemonProviderConnection => {
  const lastKnown = lastKnownConnections.get(slug);
  if (lastKnown !== undefined) {
    return {
      ...lastKnown,
      detail: "status check failed",
    };
  }
  return {
    provider: slug,
    // The protocol requires a connection boolean. This only means the current
    // check did not establish a connection; it is not a logout assertion.
    connected: false,
    detail: "status check failed",
  };
};

const boundedDelegateStatus = async (
  slug: string,
  status: () => Promise<TDaemonProviderConnection>,
): Promise<TDaemonProviderConnection> => {
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    return await Promise.race([
      status(),
      new Promise<TDaemonProviderConnection>((resolve) => {
        timer = setTimeout(
          () => resolve(statusFailure(slug)),
          DELEGATE_STATUS_TIMEOUT_MS,
        );
      }),
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
};

/** OpenCode is a device-session client (not a subscription delegate). Surface
 *  install presence so the device picker can offer it when the binary exists. */
const opencodeInstalled = (): boolean => {
  if (
    opencodeProbe !== null &&
    Date.now() - opencodeProbe.at < OPENCODE_PROBE_TTL_MS
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

const computeStatusFresh = async (): Promise<TDaemonStatus> => {
  const connections = await Promise.all(
    Object.values(DELEGATES).map(async (d) => {
      try {
        const conn = await boundedDelegateStatus(d.slug, d.status);
        if (conn.detail !== "status check failed") {
          lastKnownConnections.set(d.slug, conn);
        }
        // Attach a metadata-only usage snapshot for connected providers so the
        // dashboard can show remaining quota (read locally; never a token).
        if (!conn.connected) return conn;
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
      connected: false,
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
        if (!status.connected) return;
        await cachedUsage(d.slug, () => d.usage(), {
          accountHash: status.account_hash,
        });
      }),
  );
};
