/**
 * The daemon's command executor — the kind→handler mapping for every control
 * command (connect / integration / login-code / auto-update / …).
 *
 * It is transport-agnostic: the WebSocket control channel (`control-channel.ts`)
 * pulls a command off the relay socket, runs it through `runCommandInner`, and
 * acks + pushes a fresh status snapshot back over the same socket. There is no
 * long-poll anymore — the relay socket is the daemon's only control transport.
 */

import type { TDaemonCommand, TDaemonCommandAck } from "@openllmsh/protocol";
import { autoUpdateEnabled, setAutoUpdate } from "./auto-update-pref";
import { maybeUpdateCli } from "./cli-self-update";
import { latestCliVersion, latestVersion, refreshBootstrap } from "./config";
import { getDelegate } from "./delegation";
import { probeIntegration } from "./device-state";
import { runIntegration } from "./integrations";
import { openSealed } from "./keypair";
import { maybeReportModels, resetModelReportThrottle } from "./model-report";
import { clearPendingAuth } from "./pending-auth";
import { clearPlanCache } from "./plan-cache";
import { maybeSelfUpdate } from "./self-update";
import { refreshUsage } from "./status";

// Cap how long the post-install/uninstall `-s` re-probe may delay the command
// ack. The probe only warms the device-state cache for the next status push, so
// missing this window just defers the refreshed state to the next walk — never a
// reason to hold the dashboard's optimistic button.
const PROBE_ACK_TIMEOUT_MS = 15_000;

/**
 * Execute one delivered command via the control handlers. Returns the terminal
 * ack. `cmd` is the CLOSED `DaemonCommand` union — the relay socket's schema
 * decode already rejected unknown kinds and out-of-vocabulary payloads, so
 * each `case` narrows to its exact typed payload (no hand-cast). The delegate
 * null-checks stay as belt-and-braces for any non-wire caller.
 */
export const runCommandInner = async (
  cmd: TDaemonCommand,
): Promise<TDaemonCommandAck> => {
  try {
    switch (cmd.kind) {
      case "connect": {
        const delegate = getDelegate(cmd.payload.slug);
        if (delegate === null) {
          return {
            id: cmd.id,
            status: "error",
            result: { error: "unknown provider" },
          };
        }
        const r = await delegate.connect();
        // A login that just landed is the freshest moment to report this
        // provider's live model list to the cloud's model cache. Clear
        // THIS slug's throttle first — pre-login attempts stamped it
        // with a failure backoff, and a fresh credential must report
        // immediately. Fire-and-forget — never delays the ack.
        if (r.connected) {
          resetModelReportThrottle(cmd.payload.slug);
          void maybeReportModels().catch(() => {});
        }
        return { id: cmd.id, status: "done", result: r };
      }
      case "install_integration":
      case "uninstall_integration": {
        // Run a plugin/setup install or uninstall on THIS machine via the
        // same shared executor the CLI uses. The dashboard enqueues this against
        // the selected daemon key; the executor fetches the gateway script,
        // verifies it (fail-closed), and shells out. See
        // `docs/proposals/daemon-integration-triggers.md` §5. The kind enum +
        // charset-pinned slug/target are guaranteed by the command schema.
        const action =
          cmd.kind === "install_integration" ? "install" : "uninstall";
        const r = await runIntegration(
          cmd.payload.kind,
          action,
          cmd.payload.slug,
          cmd.payload.target,
          cmd.payload.gateway,
        );
        // Re-probe just this item's `-s` state (against the SAME target that was
        // just modified) so the post-command status push reflects the change (no
        // full walk). Best-effort AND bounded: we don't let a slow probe block
        // the command ack — if it doesn't settle within PROBE_ACK_TIMEOUT_MS the
        // ack returns anyway and the cache is corrected on the next boot/refresh
        // walk. A failed probe likewise leaves the cached entry.
        if (r.ok) {
          const probe = probeIntegration(
            cmd.payload.kind,
            cmd.payload.slug,
            cmd.payload.target,
          ).catch(() => {});
          let timer: ReturnType<typeof setTimeout> | undefined;
          await Promise.race([
            probe.finally(() => clearTimeout(timer)),
            new Promise<void>((resolve) => {
              timer = setTimeout(resolve, PROBE_ACK_TIMEOUT_MS);
            }),
          ]);
        }
        return { id: cmd.id, status: r.ok ? "done" : "error", result: r };
      }
      case "connect_device_code": {
        // Start a device-code login (codex remote; kimi falls back to its
        // normal device-code `connect`). Surfaces the URL+code via status.
        const delegate = getDelegate(cmd.payload.slug);
        if (delegate === null) {
          return {
            id: cmd.id,
            status: "error",
            result: { error: "unknown provider" },
          };
        }
        const r =
          delegate.connectDeviceCode !== undefined
            ? await delegate.connectDeviceCode()
            : await delegate.connect();
        return {
          id: cmd.id,
          status: r.connected || r.pending === true ? "done" : "error",
          result: r,
        };
      }
      case "cancel_connect": {
        // Abort an in-flight device-code / browser login: the delegate kills
        // its spawned process / stops its background poll and clears the
        // pending code. Fall back to clearing the daemon's in-memory
        // `pending_auth` directly for a provider whose `connect` is synchronous
        // (no `cancelConnect`) — there's no live flow, so dropping a stale code
        // is the whole job. The post-command status push (with the cleared
        // `pending_auth`) flips the card back to Not signed in.
        const delegate = getDelegate(cmd.payload.slug);
        if (delegate === null) {
          return {
            id: cmd.id,
            status: "error",
            result: { error: "unknown provider" },
          };
        }
        if (delegate.cancelConnect !== undefined) {
          const r = await delegate.cancelConnect();
          return { id: cmd.id, status: r.ok ? "done" : "error", result: r };
        }
        clearPendingAuth(cmd.payload.slug);
        return { id: cmd.id, status: "done", result: { ok: true } };
      }
      case "logout": {
        // Sign out of a subscription provider's CLI-LOGIN credential on this
        // daemon (per-key: the cloud delivered this only to the target key).
        const delegate = getDelegate(cmd.payload.slug);
        if (delegate === null) {
          return {
            id: cmd.id,
            status: "error",
            result: { error: "unknown provider" },
          };
        }
        const r = await delegate.logout();
        return { id: cmd.id, status: r.ok ? "done" : "error", result: r };
      }
      case "submit_login_code": {
        // TARGET (remote) daemon: open the sealed OAuth authorization code the
        // user pasted from the hosted callback page and feed it into the
        // in-flight headless `claude auth login` (paste-back). The code is
        // single-use + PKCE-bound; the cloud relayed only ciphertext.
        const delegate = getDelegate(cmd.payload.slug);
        if (delegate?.submitLoginCode === undefined) {
          return {
            id: cmd.id,
            status: "error",
            result: { error: "submit_login_code: unsupported provider" },
          };
        }
        const code = openSealed(cmd.payload.sealed);
        if (code === null) {
          return {
            id: cmd.id,
            status: "error",
            result: { error: "could not open sealed login code" },
          };
        }
        const r = await delegate.submitLoginCode(code);
        return { id: cmd.id, status: r.ok ? "done" : "error", result: r };
      }
      // The on-demand usage read. The demand is the manual "Refresh usage"
      // button OR the providers page mounting for this device — this is the
      // ONLY path that hits the vendor usage endpoint (the background status
      // push only PEEKS the cache; see `status.ts`). `slug` scopes it to one
      // provider; the dashboard's whole-daemon refresh sends none → all.
      case "refresh":
        // Fetch the connected providers' usage into the cache, RESPECTING each
        // provider's TTL: `refreshUsage` → `cachedUsage` serves a still-fresh
        // snapshot from cache (no vendor hit) and only re-fetches a STALE or
        // never-fetched one. We deliberately do NOT bust the cache first —
        // invalidating would (a) re-hit EVERY provider when only one was just
        // connected (the whole-daemon refresh the dashboard fires on login), (b)
        // ignore a provider's freshness window, and (c) clear the served snapshot
        // so the card blanks mid-refresh. Leaving the cache intact means the last
        // figures keep being served (`peekUsage`) while a re-fetch runs. The
        // post-command status push then carries whatever the cache now holds.
        await refreshUsage(cmd.payload?.slug);
        // NB: a bare `refresh` does NOT re-walk device state — the `-s` walk is
        // heavy (a fetch + bash per registry item) and the dashboard fires
        // `refresh` often, which would flood. Device state refreshes on connect
        // (eager) and after each install/uninstall (single-item probe); a
        // dedicated on-demand re-walk is future work (proposal §9 cadence).
        return { id: cmd.id, status: "done" };
      case "status":
        return { id: cmd.id, status: "done" };
      // Drop every cached signed plan tuple. Enqueued by the dashboard after
      // a chain/config save so the next request re-resolves through the cloud
      // instead of replaying the pre-save chain for up to the cache TTL.
      case "bust_plan_cache":
        clearPlanCache();
        return { id: cmd.id, status: "done" };
      // Force a self-update check now (the daemon also checks on every bootstrap
      // tick WHEN auto-update is opted in). This is an EXPLICIT user request, so
      // it passes `force` to converge regardless of the opt-in preference.
      // Refresh the bootstrap first so a release published since the last tick is
      // seen — otherwise a forced check would read a stale `latestVersion()`.
      // Fire-and-forget: it self-guards and, if it updates, swaps the binary +
      // exits once idle so the supervisor relaunches it.
      case "update":
        void (async () => {
          await refreshBootstrap();
          // CLI first: converging openllmc is a plain file swap, while a daemon
          // update EXITS the process — anything after it would never run (and
          // with auto-update toggled off, the relaunched boot wouldn't force it).
          await maybeUpdateCli(latestCliVersion(), { force: true });
          await maybeSelfUpdate(latestVersion(), { force: true });
        })();
        return { id: cmd.id, status: "done", result: { checking: true } };
      // Toggle the auto-update opt-in from the dashboard. Persisted locally so it
      // survives restarts; the post-command status push carries the new value
      // back so the switch reflects it. Enabling kicks off an immediate
      // convergence check (now that it's allowed) so the daemon catches up
      // without waiting for the next bootstrap tick.
      case "set_auto_update": {
        const enabled = cmd.payload.enabled;
        setAutoUpdate(enabled);
        // Confirm the write actually took before acking success — the persist
        // can fail silently (read-only state dir / full disk; setAutoUpdate logs
        // + swallows it). `autoUpdateEnabled` reads the flag back fresh, so a
        // mismatch means the effective state isn't what was requested → error.
        const persisted = autoUpdateEnabled();
        if (persisted !== enabled) {
          return {
            id: cmd.id,
            status: "error",
            result: {
              error: "failed to persist auto-update preference",
              auto_update: persisted,
            },
          };
        }
        // Only converge now if it actually stuck on.
        if (enabled) {
          void (async () => {
            await refreshBootstrap();
            // CLI first — a daemon update exits the process (see "update" above;
            // here the toggle is on, so the relaunched boot would catch up, but
            // converging both now avoids the extra tick).
            await maybeUpdateCli(latestCliVersion());
            await maybeSelfUpdate(latestVersion());
          })();
        }
        return {
          id: cmd.id,
          status: "done",
          result: { auto_update: persisted },
        };
      }
      default: {
        // Unreachable for a wire-delivered command — the closed union rejects
        // unknown kinds at the schema boundary before this runs. Kept as
        // defence-in-depth for any future non-wire caller.
        const unknown = cmd as { id: string; kind: string };
        return {
          id: unknown.id,
          status: "error",
          result: { error: `unknown command kind "${unknown.kind}"` },
        };
      }
    }
  } catch (err) {
    return {
      id: cmd.id,
      status: "error",
      result: { error: err instanceof Error ? err.message : String(err) },
    };
  }
};
