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
import type { TLoginResult } from "./util";
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

/** Separate retry schedule for failed refreshes. The first retry remains bounded
 * by the historical 30s cooldown; subsequent failures exponentially back off. */
export const REFRESH_FAILURE_BACKOFF_MS = 30_000;
const MAX_REFRESH_FAILURE_BACKOFF_MS = 5 * 60_000;

export type TRefreshErrorClass =
  | "timeout"
  | "spawn_failed"
  | "abandoned"
  | "invalid_grant"
  | "keychain_unusable"
  | "rejected";

/** A redacted, structured failure from a vendor refresh child. */
export class RefreshTriggerError extends Error {
  readonly errorClass: TRefreshErrorClass;
  readonly abandoned: boolean;
  readonly exitCode: number;

  constructor(
    errorClass: TRefreshErrorClass,
    result: Pick<TLoginResult, "abandoned" | "code">,
  ) {
    super(`native refresh ${errorClass}`);
    this.name = "RefreshTriggerError";
    this.errorClass = errorClass;
    this.abandoned = result.abandoned;
    this.exitCode = result.code;
  }
}

/** Per-provider refresh counters. `cooldown_skips` (post-success 30s window) and
 *  `backoff_skips` (post-failure escalating window) are kept DISTINCT so a healthy
 *  cooldown-dominated ratio can be told apart from a broken provider backing off. */
type TRefreshCounters = {
  attempts: number;
  ok: number;
  fail: number;
  abandoned: number;
  cooldown_skips: number;
  backoff_skips: number;
  fallbacks: number;
  lost: number;
};

const refreshCounters = new Map<string, TRefreshCounters>();

const counterFor = (provider: string): TRefreshCounters => {
  const current = refreshCounters.get(provider);
  if (current !== undefined) return current;
  const next: TRefreshCounters = {
    attempts: 0,
    ok: 0,
    fail: 0,
    abandoned: 0,
    cooldown_skips: 0,
    backoff_skips: 0,
    fallbacks: 0,
    lost: 0,
  };
  refreshCounters.set(provider, next);
  return next;
};

/** Metadata-only refresh telemetry for `openllmd status` consumers. */
export const refreshTelemetrySnapshot = (): Readonly<
  Record<string, Readonly<TRefreshCounters>>
> => Object.fromEntries(refreshCounters.entries());

export const noteRefreshTokenLost = (provider: string): void => {
  counterFor(provider).lost++;
};

/** Shared post-refresh credential decision. A new access token without its
 * refresh companion is intentionally not treated as healthy: it can serve only
 * until expiry and must prompt re-auth before that deadline.
 *
 * The lost-refresh case is currently OBSERVABLE via the `refresh_token_lost`
 * warn + counter emitted here. `reauthRequired` is the shared shape ready for
 * the daemon status/pending-auth surface to render a PRE-expiry re-auth prompt;
 * wiring it through the status protocol is the tracked follow-up (see the plan's
 * "telemetry→protocol / reauthRequired→UI" deferral). Delegates use `token`
 * today and pass the flag through unchanged. */
export type TResolvedToken<T> = {
  readonly token: T;
  readonly reauthRequired: boolean;
};

export const resolveToken = <T>(opts: {
  readonly provider: string;
  readonly prior: T;
  readonly refreshed: T | null;
  readonly hasRefreshToken: (token: T) => boolean;
}): TResolvedToken<T> => {
  const token = opts.refreshed ?? opts.prior;
  if (!opts.hasRefreshToken(token)) {
    noteRefreshTokenLost(opts.provider);
    logWarn("refresh", "refresh token lost", {
      provider: opts.provider,
      phase: "refresh_token_lost",
    });
    return { token, reauthRequired: true };
  }
  return { token, reauthRequired: false };
};

export const credentialUnrefreshable = (provider: string): void => {
  logWarn("refresh", "credential cannot be refreshed", {
    provider,
    phase: "credential_unrefreshable",
  });
};

export const keychainUnusable = (provider: string): never => {
  logWarn("refresh", "keychain is unusable; re-authentication required", {
    provider,
    phase: "keychain_unusable",
  });
  throw new RefreshTriggerError("keychain_unusable", {
    abandoned: false,
    code: -1,
  });
};

const inspectRefreshResult = (result: TLoginResult): void => {
  const output = result.output.toLowerCase();
  // `abandoned` is the deadline/abort SIGTERM — the exact mid-rotation kill that
  // strands a single-use refresh token (the B1 bug). It is the primary failure.
  if (result.abandoned) throw new RefreshTriggerError("abandoned", result);
  // An explicit OAuth error means the credential is genuinely un-refreshable.
  if (output.includes("invalid_grant") || output.includes("invalid_request")) {
    throw new RefreshTriggerError("invalid_grant", result);
  }
  // A BARE non-zero exit is deliberately NOT a failure: the refresh commands are
  // diagnostic-style (`codex doctor`, `grok models`, `cursor status`) that can
  // exit non-zero on a benign warning while still rotating the token as a side
  // effect. Classifying that as failure would escalate the backoff and serve
  // stale tokens on every tick. The persistence-aware grace (Stage 8 / T12 —
  // "store credential is newer than pre-spawn ⇒ success regardless of exit
  // code") is the tracked follow-up; until then a non-zero exit resolves as
  // `"awaited"` and the store re-read decides, exactly as before this change.
};

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
  const result = await run([...argv], env, {
    timeoutMs: opts?.timeoutMs ?? REFRESH_SPAWN_TIMEOUT_MS,
    probe: opts?.probe,
    ...(opts?.signal !== undefined ? { signal: opts.signal } : {}),
  });
  // spawnLogin intentionally resolves after its deadline/non-zero child exit.
  // A refresh must turn those resolved outcomes into a classified rejection so
  // makeRefresher cannot record a killed rotation as a clean success.
  inspectRefreshResult(result);
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

export const classifyRefreshError = (err: unknown): TRefreshErrorClass => {
  if (err instanceof RefreshTriggerError) return err.errorClass;
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
  let failureBackoffUntil = 0;
  let consecutiveFailures = 0;
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
      // NOTE (telemetry semantics, tracked follow-up): `attempts`/`ok` count a
      // trigger INVOCATION that resolved, which includes a benign keychain skip
      // or a non-zero-but-unverified exit where no rotation is proven. Making
      // `ok` mean "rotation confirmed" needs the Stage 8 store-newer-than-
      // pre-spawn predicate; until then `refreshTelemetrySnapshot` (no live
      // consumer yet) slightly over-counts `ok` on those benign paths.
      const counters = counterFor(opts.slug);
      counters.attempts++;
      inFlight = opts
        .trigger()
        .then(() => {
          lastErrorClass = null;
          consecutiveFailures = 0;
          counters.ok++;
          if (cooldownMs > 0) cooldownUntil = Date.now() + cooldownMs;
        })
        .catch((err: unknown) => {
          lastErrorClass = classifyRefreshError(err);
          consecutiveFailures++;
          counters.fail++;
          const triggerError =
            err instanceof RefreshTriggerError ? err : undefined;
          if (triggerError?.abandoned === true) counters.abandoned++;
          const failureBackoffMs = Math.min(
            REFRESH_FAILURE_BACKOFF_MS * 2 ** (consecutiveFailures - 1),
            MAX_REFRESH_FAILURE_BACKOFF_MS,
          );
          failureBackoffUntil = Date.now() + failureBackoffMs;
          logWarn("refresh", "native refresh trigger failed", {
            provider: opts.slug,
            label: opts.label,
            phase: "refresh_trigger",
            error_class: lastErrorClass,
            elapsed_ms: Date.now() - started,
            timeout_ms: REFRESH_SPAWN_TIMEOUT_MS,
            abandoned: triggerError?.abandoned ?? false,
            exit_code: triggerError?.exitCode ?? null,
          });
        })
        .finally(() => {
          inFlight = null;
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
    const now = Date.now();
    if (cooldownMs > 0 && now < cooldownUntil) {
      counterFor(opts.slug).cooldown_skips++;
      logDebug("refresh", "native refresh skipped (cooldown)", {
        provider: opts.slug,
        phase: "refresh_skipped",
        reason: "cooldown",
      });
      return "fresh";
    }
    if (now < failureBackoffUntil) {
      counterFor(opts.slug).backoff_skips++;
      logDebug("refresh", "native refresh skipped (failure backoff)", {
        provider: opts.slug,
        phase: "refresh_skipped",
        reason: "failure_backoff",
      });
      return "fresh";
    }
    if (remaining > 0) {
      void fire();
      return "kicked";
    }
    await fire();
    if (lastErrorClass !== null) {
      // The caller will serve the stale credential — count it centrally so no
      // delegate has to remember to (they all log `refresh_fallback` already).
      counterFor(opts.slug).fallbacks++;
      return { kind: "stale", reason: lastErrorClass };
    }
    return "awaited";
  };
};
