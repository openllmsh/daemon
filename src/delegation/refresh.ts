/**
 * Native-CLI token refresh.
 *
 * The daemon does NOT refresh subscription OAuth tokens itself any more (no
 * `grant_type=refresh_token` calls, no extracted/hardcoded token endpoint or
 * client id). Instead each delegate's `readToken` checks expiry and, when the
 * access token is near or past expiry, TRIGGERS the official CLI's OWN native
 * refresh by running a bounded CLI invocation; the CLI refreshes + persists its
 * token to its own store, and the daemon just re-reads it. See each delegate's
 * `triggerRefresh` for the per-CLI command (claude/kimi: a minimal `-p` ping;
 * codex: `codex doctor`).
 *
 * Latency: a refresh spawn is seconds, so it must not block the serving hot
 * path. `makeRefresher` fires it in the BACKGROUND while the token is still
 * valid (within the leeway window) and only AWAITS it once the token is already
 * hard-expired — exactly "no latency unless the refresh is close".
 */
import { logDebug, logWarn } from "../logger";
import { spawnLogin, spawnLoginPty } from "./util";

/** Bound on a refresh spawn — generous for a slow first call, short enough that
 *  a wedged child is reaped (the refresh already landed mid-request before the
 *  child's slow exit, so the timeout never costs correctness). */
export const REFRESH_SPAWN_TIMEOUT_MS = 60_000;

/**
 * Post-spawn refresh cooldown shared by every delegate. Larger than the 2.5s
 * status-watch tick (so the watcher can't drive repeat spawns) and smaller than
 * the shortest refresh leeway (60s, claude) so a genuinely near-expiry token
 * still gets a second attempt before it hard-expires. This is the knob that
 * makes "no redundant refresh ever" true across status + request + usage.
 */
export const REFRESH_COOLDOWN_MS = 30_000;

export type TRefreshErrorClass = "timeout" | "spawn_failed" | "rejected";

/**
 * Run a bounded CLI invocation whose SIDE EFFECT is the CLI refreshing +
 * persisting its own OAuth token. Output is ignored; the daemon never writes the
 * store (the CLI owns it). `pty` runs it under a pseudo-terminal for a CLI whose
 * print mode is TTY-gated (kimi's `-p`).
 */
export const spawnRefresh = async (
  argv: ReadonlyArray<string>,
  env: Record<string, string>,
  opts?: {
    readonly pty?: boolean;
    readonly probe?: boolean;
    readonly timeoutMs?: number;
    readonly signal?: AbortSignal;
  },
): Promise<void> => {
  const run = opts?.pty === true ? spawnLoginPty : spawnLogin;
  await run([...argv], env, {
    timeoutMs: opts?.timeoutMs ?? REFRESH_SPAWN_TIMEOUT_MS,
    probe: opts?.probe,
    ...(opts?.signal !== undefined ? { signal: opts.signal } : {}),
  });
};

/** What `makeRefresher` did for this read — tells the caller whether the store
 *  was (synchronously) refreshed and should be re-read. */
export type TRefreshOutcome =
  /** Not near expiry, or no expiry known — nothing triggered. */
  | "fresh"
  /** Within the window but still valid — refresh KICKED in the background; the
   *  current token is returned as-is (the store updates before it's next used). */
  | "kicked"
  /** Hard-expired — the refresh was AWAITED and the trigger settled cleanly;
   *  re-read the store for the new token. */
  | "awaited"
  /** Hard-expired — the trigger rejected; keep the stale credential (the
   *  upstream then 401s → re-login). */
  | { readonly kind: "stale"; readonly reason: TRefreshErrorClass };

export const isStaleRefresh = (
  outcome: TRefreshOutcome,
): outcome is { readonly kind: "stale"; readonly reason: TRefreshErrorClass } =>
  typeof outcome === "object" && outcome.kind === "stale";

const classifyRefreshError = (err: unknown): TRefreshErrorClass => {
  const name = err instanceof Error ? err.name : "";
  const message = err instanceof Error ? err.message : "";
  const text = `${name} ${message}`.toLowerCase();
  if (
    name === "TimeoutError" ||
    name === "AbortError" ||
    text.includes("timeout") ||
    text.includes("timed out")
  ) {
    return "timeout";
  }
  if (
    text.includes("spawn") ||
    text.includes("enoent") ||
    text.includes("eacces") ||
    text.includes("eperm") ||
    text.includes("eagain")
  ) {
    return "spawn_failed";
  }
  return "rejected";
};

/**
 * Build a per-provider refresher around its `trigger` (the CLI-refresh spawn).
 *
 * Two invariants make "correct token, no redundant refresh" hold for EVERY
 * caller (the 2.5s status watcher, the request hot path, usage reads) because
 * all of them funnel through this one function:
 *   - **Single-flight:** concurrent callers that all see a stale token share
 *     ONE spawn (refresh-token rotation means parallel refreshes would
 *     invalidate each other — a second concurrent `claude -p ping` is exactly
 *     the rotation race that logs users out). This is why NO delegate may wrap
 *     this with its own signal-aware bypass.
 *   - **Post-spawn cooldown** (`cooldownMs`, optional): once a trigger has
 *     COMPLETED (success OR failure), no new spawn fires for `cooldownMs`. A
 *     success rotates the token so its new expiry is far out and `"fresh"`
 *     suppresses re-fires on its own; the cooldown additionally bounds the
 *     near-expiry window and, on failure, stops a per-2.5s hammer on a broken
 *     refresh. Net: ≤1 spawn per `cooldownMs` per provider.
 *
 * Returns a function the delegate's `readToken` calls with the token's
 * `expiresAtMs`:
 *   - `>= leewayMs` remaining, or inside the cooldown → `"fresh"` (no trigger).
 *   - within the window but still valid → fire the trigger in the BACKGROUND,
 *     return `"kicked"` (caller returns the current still-valid token — no stall).
 *   - hard-expired → AWAIT the trigger, return `"awaited"` (caller re-reads)
 *     or `{ kind: "stale" }` if the trigger rejected (caller keeps the current
 *     token).
 */
export const makeRefresher = (opts: {
  readonly slug: string;
  readonly label: string;
  readonly leewayMs: number;
  readonly cooldownMs?: number;
  readonly trigger: () => Promise<void>;
}): ((expiresAtMs: number | null) => Promise<TRefreshOutcome>) => {
  let inFlight: Promise<void> | null = null;
  let lastErrorClass: TRefreshErrorClass | null = null;
  let cooldownUntil = 0;
  const cooldownMs = opts.cooldownMs ?? 0;
  const fire = (): Promise<void> => {
    if (inFlight === null) {
      const started = Date.now();
      // A failed trigger is still best-effort: rejecting would (a) leak an
      // unhandled rejection from the background `void fire()` path and (b)
      // throw out of the awaited hard-expired path — both wrong. On failure
      // the store simply isn't refreshed and `readToken` falls back to the
      // stale token (surfacing the vendor's own 401 → re-login). Log a
      // REDACTED class only — never the raw error / token.
      inFlight = opts
        .trigger()
        .then(() => {
          lastErrorClass = null;
        })
        .catch((err: unknown) => {
          lastErrorClass = classifyRefreshError(err);
          logWarn("refresh", "native refresh trigger failed", {
            provider: opts.slug,
            label: opts.label,
            phase: "refresh_trigger",
            error_class: lastErrorClass,
            elapsed_ms: Date.now() - started,
            timeout_ms: REFRESH_SPAWN_TIMEOUT_MS,
          });
        })
        .finally(() => {
          inFlight = null;
          // Open the cooldown from spawn COMPLETION (success or failure), so the
          // window can't be out-run by a wedged child or a fast caller.
          if (cooldownMs > 0) cooldownUntil = Date.now() + cooldownMs;
        });
    }
    return inFlight;
  };
  return async (expiresAtMs) => {
    if (expiresAtMs === null) return "fresh";
    const remaining = expiresAtMs - Date.now();
    if (remaining >= opts.leewayMs) return "fresh";
    // A recent spawn already gathered current info — don't spawn again until the
    // cooldown lapses. Serving the current token for at most `cooldownMs` is the
    // right backoff; it never serves a WORSE token than one spawn ago.
    if (cooldownMs > 0 && Date.now() < cooldownUntil) {
      logDebug("refresh", "native refresh skipped (cooldown)", {
        provider: opts.slug,
        phase: "refresh_skipped",
        reason: "cooldown",
      });
      return "fresh";
    }
    if (remaining > 0) {
      void fire();
      return "kicked";
    }
    await fire();
    if (lastErrorClass !== null) {
      return { kind: "stale", reason: lastErrorClass };
    }
    return "awaited";
  };
};
