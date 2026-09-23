/**
 * Muse Code subscription delegate through the official `muse` CLI.
 *
 * Login/logout are official CLI only (`muse login` / `muse logout`). Inference
 * is bridge-only via the native Muse runtime — this delegate never exports
 * credential secrets and never serves Meta Model API HTTP with subscription
 * material. META_API_KEY outranks stored credentials in the official runtime,
 * so child env strips ambient API-key overrides.
 *
 * Passive status never spawns the vendor CLI. Auth-file existence/size alone is
 * NEVER connected entitlement. Connected is memory-verified for this process
 * only (`verifiedAuthFingerprint`) and is restored solely on demand:
 * (1) official login exit that changed the store fingerprint,
 * (2) successful authenticated MSP via {@link noteMuseAuthenticatedSession}
 *     (manual `listModels`, inference session, or explicit connect demand
 *     verify of an unchanged existing store).
 * No startup / idle / polling revalidation. Quota/plan are never claimed
 * without an official source.
 */
import { join } from "node:path";
import type {
  TDaemonProviderConnection,
  TProviderModelEntry,
  TProviderUsageSnapshot,
} from "@openllmsh/protocol";
import { noteAuthStoreIdentityChange } from "../auth-user-action";
import { cliInstallState } from "../cli-install";
import { cliBin, cliConfigDir } from "../cli-paths";
import { logError, logInfo, safeDiagnosticMessage } from "../logger";
import {
  clearPendingAuth,
  getPendingAuth,
  pendingAuthDetail,
} from "../pending-auth";
import { unwrapKeychainSpawn } from "../sandbox/policy";
import { resolveUpstreamUrl } from "./auth-config";
import { cliLaunch, loginWiring } from "./delegate-shared";
import { makeStreamConnect } from "./login-direct";
import { makeCancelConnect } from "./login-flow";
import {
  createPassiveObservationCache,
  fileStoreIdentity,
  fingerprintStoreIdentity,
  waitFileStoreHint,
} from "./observation-cache";
import type {
  TModelDiscoveryOptions,
  TModelDiscoveryResult,
  TProviderDelegate,
} from "./types";
import type { TStoreRead } from "./util";
import {
  connectedObservation,
  disconnectedObservation,
  runCapture,
  STATUS_CHECK_FAILED_DETAIL,
  stripAnsi,
  unknownObservation,
} from "./util";

const PROVIDER = "muse" as const;

/** Official auth store under the isolated XDG config home. Existence/size only. */
export const museAuthJsonPath = (): string =>
  join(cliConfigDir(PROVIDER), "auth.json");

/**
 * Ambient metered-key overrides that outrank a stored Muse browser session.
 * Values are set to `undefined` so {@link mergeSpawnEnv} deletes them from the
 * child environment.
 */
const METERED_KEY_OVERRIDES: Readonly<Record<string, undefined>> = {
  META_API_KEY: undefined,
  MUSE_API_KEY: undefined,
  META_ACCESS_TOKEN: undefined,
  MUSE_ACCESS_TOKEN: undefined,
};

const { bin, env: baseEnv } = cliLaunch(PROVIDER);

const env = (): Record<string, string | undefined> => ({
  ...baseEnv(),
  ...METERED_KEY_OVERRIDES,
});

const ALLOWED_AUTH_HOSTS = ["meta.ai", "facebook.com", "meta.com"] as const;

const hostAllowed = (hostname: string): boolean => {
  const host = hostname.toLowerCase();
  return ALLOWED_AUTH_HOSTS.some(
    (root) => host === root || host.endsWith(`.${root}`),
  );
};

/**
 * Parse a Muse authorize URL from official-login stdout.
 *
 * ASSUMPTION (not live-captured here): Muse prints an HTTPS Meta/Facebook
 * auth or device-verification URL. Host allowlist is intentionally narrow —
 * stderr is not trusted as an alternate link source. Trailing punctuation is
 * stripped; userinfo is rejected.
 */
export const parseMuseAuthUrl = (raw: string): string | null => {
  const clean = stripAnsi(raw);
  const match = clean.match(/https:\/\/[^\s<>"'\\]+/i);
  if (match === null || match[0] === undefined) return null;
  const candidate = match[0].replace(/[),.;:!?]+$/u, "");
  try {
    const url = new URL(candidate);
    if (url.protocol !== "https:") return null;
    if (url.username.length > 0 || url.password.length > 0) return null;
    if (!hostAllowed(url.hostname)) return null;
    // Drop fragment — never surface token-like fragments to pending_auth.
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
};

/**
 * Parse optional user code alongside the authorize URL.
 *
 * ASSUMPTION: tertiary guides describe device-code-like "URL + code" output
 * from `muse login`. Official Meta auth docs emphasize browser sign-in /
 * `muse auth set` / `META_API_KEY` and do not document a `--device-auth` flag.
 * When no code is present, pending_auth carries `code: ""` (Cursor parity).
 */
export const parseMuseLoginPrompt = (
  raw: string,
): { readonly url: string; readonly code: string } | null => {
  const url = parseMuseAuthUrl(raw);
  if (url === null) return null;
  const clean = stripAnsi(raw);
  const code =
    clean.match(
      /(?:one[- ]?time code|user code|enter(?:\s+the)?\s+code)[^\n]*\n\s*([A-Z0-9][A-Z0-9-]{3,})/i,
    )?.[1] ??
    clean.match(/\bcode\b[^\n]*?\b([A-Z0-9]{4}(?:-[A-Z0-9]{4})+)\b/i)?.[1] ??
    "";
  return { url, code };
};

type TMuseStoreObservation =
  | { readonly kind: "absent" }
  | { readonly kind: "configured" };

/**
 * Passive store observation: size > 2 means *some* credential material is
 * configured (mirrors muse-code-acp). Secrets are never read. This is NOT
 * connected evidence by itself.
 */
export const observeMuseAuthStore = (): TStoreRead<TMuseStoreObservation> => {
  const identity = fileStoreIdentity(museAuthJsonPath());
  if (!identity.statOk) {
    return { kind: "indeterminate", cause: "stat_failed" };
  }
  if (!identity.present || (identity.size ?? 0) <= 2) {
    return { kind: "present", value: { kind: "absent" } };
  }
  return { kind: "present", value: { kind: "configured" } };
};

const museStatusCache = createPassiveObservationCache<TMuseStoreObservation>();

/** Fingerprint of the store that completed a verified login or MSP auth. */
let verifiedAuthFingerprint: string | null = null;

/**
 * Baseline store fingerprint captured when `muse login` starts. Verify after
 * exit requires the store identity to change from this baseline (new write or
 * replace) — a preexisting stale/`{}x` file alone never counts.
 */
let loginBaselineFingerprint: string | null = null;

const storeFingerprint = (): string | null => {
  const identity = fileStoreIdentity(museAuthJsonPath());
  if (!identity.statOk) return null;
  return fingerprintStoreIdentity(identity);
};

const storeConfigured = (): boolean => {
  const observed = observeMuseAuthStore();
  return observed.kind === "present" && observed.value.kind === "configured";
};

const hasVerifiedAuth = (): boolean => {
  if (verifiedAuthFingerprint === null) return false;
  if (!storeConfigured()) return false;
  const fp = storeFingerprint();
  return fp !== null && fp === verifiedAuthFingerprint;
};

/**
 * Mark Muse as authenticated after a successful MSP operation (model/list or
 * confirmed session). Fingerprint must match the current auth-store identity —
 * never cross-seed an unknown/stale identity.
 */
export const noteMuseAuthenticatedSession = (opts: {
  readonly fingerprint: string;
}): void => {
  if (!storeConfigured()) return;
  const fp = storeFingerprint();
  if (fp === null || fp !== opts.fingerprint) return;
  verifiedAuthFingerprint = fp;
  museStatusCache.invalidate();
};

/** Drop cached Muse status presence after login/logout mutations. */
export const clearMuseStatusObservationCache = (): void => {
  museStatusCache.invalidate();
  clearMuseNativeModels();
  verifiedAuthFingerprint = null;
  loginBaselineFingerprint = null;
  noteAuthStoreIdentityChange(PROVIDER);
};

const readCachedStoreObservation = (): TStoreRead<TMuseStoreObservation> => {
  const identity = fileStoreIdentity(museAuthJsonPath());
  if (!identity.statOk) {
    return { kind: "indeterminate", cause: "stat_failed" };
  }
  const fingerprint = fingerprintStoreIdentity(identity);
  const generation = museStatusCache.generation();
  const cached = museStatusCache.get(fingerprint);
  if (cached !== undefined) {
    return { kind: "present", value: cached };
  }
  const observed = observeMuseAuthStore();
  if (observed.kind !== "present") return observed;
  museStatusCache.set(fingerprint, observed.value, generation);
  return observed;
};

/**
 * Login-verify predicate: verified session OR (active login baseline set and
 * the store fingerprint changed to a configured store). Used only by the
 * connect lifecycle — passive status uses {@link hasVerifiedAuth}.
 */
const loginVerifyConnected = (): boolean => {
  if (hasVerifiedAuth()) return true;
  if (loginBaselineFingerprint === null) return false;
  if (!storeConfigured()) return false;
  const fp = storeFingerprint();
  return fp !== null && fp !== loginBaselineFingerprint;
};

/**
 * Demand-driven MSP `model/list` to re-pin {@link verifiedAuthFingerprint}
 * after a daemon restart (or any process where memory verification was lost)
 * while a configured auth store is still present. Never treats file presence
 * alone as success; refuses when the store disappears or changes mid-flight
 * (logout / rotate). Used only from explicit connect / login-exit verify —
 * not from passive status, startup, or idle paths.
 */
const verifyMuseAuthDemand = async (): Promise<boolean> => {
  if (!storeConfigured()) return false;
  const expectedFp = storeFingerprint();
  if (expectedFp === null) return false;
  try {
    const { listMuseModelsDemand } = await import(
      "../native-runtime/muse-runtime"
    );
    const listed = await listMuseModelsDemand({
      bin: cliBin(PROVIDER),
      env: baseEnv(),
    });
    if (listed === null || listed.length === 0) return false;
    // Concurrent logout / store replace must not stick a stale success.
    if (!storeConfigured()) return false;
    const live = storeFingerprint();
    if (live === null || live !== expectedFp) return false;
    if (!hasVerifiedAuth()) {
      noteMuseAuthenticatedSession({ fingerprint: expectedFp });
    }
    return hasVerifiedAuth();
  } catch {
    return false;
  }
};

/**
 * Connect-lifecycle verify: sync login evidence first, then (only while a
 * login baseline is active) one demand MSP check for an unchanged existing
 * store. Short-circuit at connect start still uses this with a null baseline,
 * so preexisting auth.json alone never short-circuits as signed-in.
 */
const connectLifecycleConnected = async (): Promise<boolean> => {
  if (loginVerifyConnected()) return true;
  if (loginBaselineFingerprint === null) return false;
  if (!storeConfigured()) return false;
  return verifyMuseAuthDemand();
};

// ─── Passive model observation (zero-spawn; filled by runtime later) ─────

type TMuseNativeModelCache = {
  readonly fingerprint: string;
  readonly accountHint: string | null;
  readonly generation: number;
  readonly models: ReadonlyArray<TProviderModelEntry>;
  readonly observedAtMs: number;
};

const MUSE_NATIVE_MODEL_TTL_MS = 30 * 60_000;
let museNativeGeneration = 0;
let museNativeModels: TMuseNativeModelCache | null = null;

export const museNativeModelGeneration = (): number => museNativeGeneration;

export const clearMuseNativeModels = (): void => {
  museNativeModels = null;
  museNativeGeneration += 1;
};

export const museNativeModelFingerprint = (): string | null => {
  const identity = fileStoreIdentity(museAuthJsonPath());
  if (!identity.statOk) return null;
  // Absent store still has a stable "absent" fingerprint — callers must not
  // remember models under an absent/unreadable identity.
  if (!identity.present) return null;
  return fingerprintStoreIdentity(identity);
};

export const rememberMuseNativeModels = (opts: {
  readonly fingerprint: string;
  readonly accountHint: string | null;
  readonly generation: number;
  readonly models: ReadonlyArray<TProviderModelEntry>;
}): void => {
  if (opts.generation !== museNativeGeneration) return;
  if (opts.models.length === 0) return;
  const live = museNativeModelFingerprint();
  // Refuse unknown/absent identity and refuse cross-seeding a different store.
  if (live === null || live !== opts.fingerprint) return;
  museNativeModels = {
    fingerprint: opts.fingerprint,
    accountHint: opts.accountHint,
    generation: opts.generation,
    models: opts.models,
    observedAtMs: Date.now(),
  };
};

export const readMuseNativeModels = (opts: {
  readonly fingerprint: string;
  readonly accountHint: string | null;
}): ReadonlyArray<TProviderModelEntry> | null => {
  const cached = museNativeModels;
  if (cached === null) return null;
  if (cached.generation !== museNativeGeneration) return null;
  if (cached.fingerprint !== opts.fingerprint) return null;
  if (cached.accountHint !== opts.accountHint) return null;
  const live = museNativeModelFingerprint();
  if (live === null || live !== opts.fingerprint) return null;
  if (Date.now() - cached.observedAtMs > MUSE_NATIVE_MODEL_TTL_MS) return null;
  return cached.models;
};

export const resetMuseNativeModelObservationForTests = (): void => {
  museNativeModels = null;
  museNativeGeneration = 0;
  verifiedAuthFingerprint = null;
  loginBaselineFingerprint = null;
  museStatusCache.invalidate();
};

const {
  installHint: INSTALL_HINT,
  connectedDetail: CONNECTED_DETAIL,
  inProgressDetail: IN_PROGRESS_DETAIL,
  isInstalled,
  slot,
} = loginWiring({
  provider: PROVIDER,
  installHint:
    "Muse Code not found — install with `curl -fsSL https://dev.meta.ai/install.sh | sh`, then retry.",
  connectedDetail: "signed in via Muse Code",
  inProgressDetail:
    "Muse sign-in already in progress — finish authorizing in your browser; this updates automatically.",
  // Short-circuit + verify: only a verified auth fingerprint (login exit with
  // store change, or MSP note). Preexisting auth.json alone is NOT connected.
  readToken: async () => (hasVerifiedAuth() ? true : null),
  isConnected: async () => loginVerifyConnected(),
});

const connectDirect = makeStreamConnect({
  provider: PROVIDER,
  slot,
  installed: isInstalled,
  installHint: INSTALL_HINT,
  connected: connectLifecycleConnected,
  connectedDetail: CONNECTED_DETAIL,
  inProgressDetail: IN_PROGRESS_DETAIL,
  argv: () => [bin(), "login"],
  env,
  waitStoreHint: (signal) => waitFileStoreHint(museAuthJsonPath(), signal),
  stream: "stdout",
  parse: (buffer) => parseMuseLoginPrompt(buffer),
  onConnected: (): boolean => {
    const fp = storeFingerprint();
    if (fp === null || !storeConfigured()) return false;
    if (hasVerifiedAuth()) {
      // Demand MSP verify already pinned this fingerprint — unchanged store OK.
      loginBaselineFingerprint = null;
      museStatusCache.invalidate();
      clearMuseNativeModels();
      noteAuthStoreIdentityChange(PROVIDER);
      return true;
    }
    // Official login must change the store; file presence alone never counts.
    if (loginBaselineFingerprint !== null && fp === loginBaselineFingerprint) {
      return false;
    }
    if (!loginVerifyConnected()) return false;
    verifiedAuthFingerprint = fp;
    loginBaselineFingerprint = null;
    museStatusCache.invalidate();
    clearMuseNativeModels();
    noteAuthStoreIdentityChange(PROVIDER);
    return true;
  },
  onStart: () => {
    loginBaselineFingerprint =
      storeFingerprint() ?? `${museAuthJsonPath()}\0absent`;
    logInfo("muse-connect", "spawning `muse login`");
  },
  onParsed: (url) =>
    logInfo("muse-connect", "parsed authorize URL; surfacing to dashboard", {
      urlLen: url.length,
    }),
  onParseFail: (captured) =>
    logError(
      "muse-connect",
      safeDiagnosticMessage`no authorize URL parsed from muse login`,
      {
        // Never log raw stdout — device codes / fragments / tokens can leak.
        capturedLen: captured.length,
      },
    ),
  pendingDetail: (url) =>
    `Authorize Muse in the browser window that opened — or open ${url}. This page updates automatically once you're done.`,
  failDetail:
    "Couldn't start Muse sign-in. Retry, or run `muse login` on the box.",
});

const cancelConnect = makeCancelConnect(PROVIDER, slot, {
  cancelled: "Muse sign-in cancelled",
  none: "no sign-in was in progress",
});

/**
 * Explicit connect: if a configured store is present but memory verification
 * was lost (daemon restart), demand-verify through official MSP `model/list`
 * before spawning `muse login`. Failed demand verify falls through to login.
 * Passive status / startup never call this path.
 */
const connect = async (): Promise<
  Awaited<ReturnType<typeof connectDirect>>
> => {
  if (!hasVerifiedAuth() && storeConfigured()) {
    const ok = await verifyMuseAuthDemand();
    if (ok && hasVerifiedAuth()) {
      return { connected: true, detail: CONNECTED_DETAIL };
    }
  }
  return connectDirect();
};

export const museDelegate: TProviderDelegate = {
  slug: PROVIDER,
  // cliInstallState is a shared probe and does not accept observer aborts.
  statusCancellable: false,
  invalidateStatusObservation: clearMuseStatusObservationCache,
  connect,
  cancelConnect,

  status: async (): Promise<TDaemonProviderConnection> => {
    const { installed, version } = await cliInstallState(PROVIDER);
    const storeRead = installed ? readCachedStoreObservation() : undefined;
    if (storeRead?.kind === "indeterminate") {
      return {
        provider: PROVIDER,
        status: "disconnected",
        ...unknownObservation("store_unreadable"),
        cli_installed: true,
        ...(version !== null ? { cli_version: version } : {}),
        detail: STATUS_CHECK_FAILED_DETAIL,
      };
    }
    const configured =
      storeRead?.kind === "present" && storeRead.value.kind === "configured";
    const verified = hasVerifiedAuth();
    // Only verified auth clears pending_auth — a preexisting store must not
    // suppress reconnect / cancel an in-flight login.
    if (verified) clearPendingAuth(PROVIDER);
    const pending = verified ? null : getPendingAuth(PROVIDER);

    if (verified) {
      return {
        provider: PROVIDER,
        status: "connected",
        ...connectedObservation(),
        cli_installed: true,
        ...(version !== null ? { cli_version: version } : {}),
        last_login_at_ms: null,
        detail:
          "Muse authentication verified this session (official login store change or authenticated MSP). Quota remains unverified; META_API_KEY is stripped from child env.",
      };
    }

    if (configured) {
      return {
        provider: PROVIDER,
        status: "disconnected",
        ...unknownObservation("probe_failed"),
        cli_installed: true,
        ...(version !== null ? { cli_version: version } : {}),
        ...(pending !== null
          ? {
              pending_auth: {
                url: pending.url,
                code: pending.code,
                started_at_ms: pending.startedAt,
                ...(pending.flowId !== undefined
                  ? { flow_id: pending.flowId }
                  : {}),
              },
            }
          : {}),
        detail:
          pending !== null
            ? pendingAuthDetail(pending)
            : "Muse auth store is present but unverified (contents never read). Reconnect via muse login, or wait for an authenticated MSP session. Not treated as signed in.",
      };
    }

    return {
      provider: PROVIDER,
      status: "disconnected",
      ...(pending !== null
        ? {}
        : installed
          ? disconnectedObservation()
          : unknownObservation("cli_unavailable")),
      cli_installed: installed,
      ...(version !== null ? { cli_version: version } : {}),
      ...(pending !== null
        ? {
            pending_auth: {
              url: pending.url,
              code: pending.code,
              started_at_ms: pending.startedAt,
              ...(pending.flowId !== undefined
                ? { flow_id: pending.flowId }
                : {}),
            },
          }
        : {}),
      detail:
        pending !== null
          ? pendingAuthDetail(pending)
          : installed
            ? "muse installed but not signed in"
            : "muse not installed",
    };
  },

  usage: async (): Promise<TProviderUsageSnapshot> => ({
    kind: "unavailable",
    reason:
      "Muse subscription quota is not published through a verified local API for this daemon yet.",
    link: "https://dev.meta.ai/docs/muse-code/auth",
  }),

  discoverModels: async (
    _options: TModelDiscoveryOptions,
  ): Promise<TModelDiscoveryResult> => {
    // Zero-spawn: only reuse observations remembered from a prior native
    // session under the current store fingerprint. Never launch muse / MSP.
    const fingerprint = museNativeModelFingerprint();
    if (fingerprint === null) return { kind: "skipped" };
    const cached = readMuseNativeModels({
      fingerprint,
      accountHint: null,
    });
    if (cached === null || cached.length === 0) return { kind: "skipped" };
    return { kind: "success", models: cached };
  },

  listModels: async (): Promise<ReadonlyArray<TProviderModelEntry> | null> => {
    // Explicit manual refresh: demand-driven MSP model/list via runtime helper
    // (helper remembers + notes authenticated session when fingerprint present).
    try {
      const { listMuseModelsDemand } = await import(
        "../native-runtime/muse-runtime"
      );
      const listed = await listMuseModelsDemand({
        bin: cliBin(PROVIDER),
        env: baseEnv(),
      });
      if (listed === null) return null;
      // Delegate contract: never return an empty list.
      return listed.length > 0 ? listed : null;
    } catch {
      // Helper missing / spawn failed — fall back to cache only.
      const fingerprint = museNativeModelFingerprint();
      if (fingerprint === null) return null;
      return readMuseNativeModels({ fingerprint, accountHint: null });
    }
  },

  credentialForUpstream: async () => {
    if (!hasVerifiedAuth()) {
      throw new Error("muse: not signed in (no verified Muse authentication)");
    }
    const url = await resolveUpstreamUrl(PROVIDER);
    throw new Error(
      `muse is served by the native Muse bridge (muse serve / SDK); there is no manual upstream transport (configured target: ${new URL(url).origin})`,
    );
  },

  logout: async () => {
    clearMuseStatusObservationCache();
    if ((await cliInstallState(PROVIDER)).installed) {
      await runCapture([bin(), "logout"], env(), {
        probe: unwrapKeychainSpawn(PROVIDER),
      });
    }
    const cleared = !storeConfigured();
    clearMuseStatusObservationCache();
    return cleared
      ? {
          ok: true,
          detail:
            "signed out of Muse (an exported META_API_KEY in the host shell is unchanged)",
        }
      : {
          ok: false,
          detail:
            "credential store still present after logout (or still configured via host META_API_KEY outside this daemon)",
        };
  },
};
