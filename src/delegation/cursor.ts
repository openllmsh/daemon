/**
 * Cursor subscription delegate through the official `cursor-agent` CLI.
 *
 * Login URL stream and token store are live-verified; inference remains ACP-only
 * (`cursor-agent acp`). This delegate deliberately exposes login/status/usage only
 * until the daemon ACP bridge is implemented.
 */
import { platform } from "node:os";
import { join } from "node:path";
import type {
  TProviderModelEntry,
  TProviderUsageSnapshot,
  TProviderUsageWindow,
} from "@openllmsh/protocol";
import { MODEL_LIST_FETCH_TIMEOUT_MS } from "@openllmsh/protocol";
import { cliInstallState } from "../cli-install";
import { cliBin, cliConfigDir, cliEnv, cliHome } from "../cli-paths";
import { logError, logInfo } from "../logger";
import { listCursorModelsViaAcp } from "../native-runtime/cursor-acp";
import {
  clearPendingAuth,
  getPendingAuth,
  pendingAuthDetail,
} from "../pending-auth";
import { unwrapKeychainSpawn } from "../sandbox/policy";
import { accountHashField } from "./account-id";
import { resolveProviderUrl, resolveUpstreamUrl } from "./auth-config";
import { jwtExpiryMs, jwtSubject } from "./jwt";
import { makeStreamConnect } from "./login-direct";
import { loginSlot, makeCancelConnect } from "./login-flow";
import { makeRefresher, spawnRefresh } from "./refresh";
import type { TProviderDelegate } from "./types";
import {
  ensureIsolatedKeychain,
  grantKeychainToolAccess,
  readIsolatedKeychain,
  readJsonFile,
  runCapture,
  stripAnsi,
} from "./util";

const PROVIDER = "cursor" as const;
// Usage endpoint LEAF paths — the host comes from `resolveProviderUrl` (the
// auth-config CAPTURE default / captured origin), so the dashboard host lives
// in ONE place (`auth-config.ts`) like every other delegate.
const USAGE_PATH = "/aiserver.v1.DashboardService/GetCurrentPeriodUsage";
const PLAN_PATH = "/aiserver.v1.DashboardService/GetPlanInfo";
const REFRESH_LEEWAY_MS = 5 * 60_000;

const bin = (): string => cliBin(PROVIDER);
const env = (): Record<string, string> => cliEnv(PROVIDER);

// ─── Live model rows via the ACP bridge (cursor/list_available_models) ─────
const CURSOR_MODELS_TTL_MS = 5 * 60_000;
let cursorModelsCache: {
  at: number;
  entries: ReadonlyArray<TProviderModelEntry>;
} | null = null;
let cursorModelsInflight: Promise<ReadonlyArray<TProviderModelEntry> | null> | null =
  null;

const redactUrls = (value: string): string =>
  value.replace(/(https?:\/\/[^\s?]+)\?\S*/g, "$1?<redacted>");

/** Live-verified: `cursor-agent login` prints a deep-control URL on stdout. */
const parseAuthUrl = (raw: string): string | null => {
  const clean = stripAnsi(raw);
  return (
    clean.match(/https?:\/\/(?:www\.)?cursor\.com\/\S+/)?.[0] ??
    clean.match(/https?:\/\/\S*\/(?:oauth\/)?authorize\S*/)?.[0] ??
    null
  );
};

const statusForWindows = (
  windows: ReadonlyArray<TProviderUsageWindow>,
): "allowed" | "allowed_warning" | "rejected" => {
  const peak = windows.reduce(
    (max, window) => Math.max(max, window.percent_used),
    0,
  );
  return peak >= 100 ? "rejected" : peak >= 80 ? "allowed_warning" : "allowed";
};

const numberOf = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
};

const stringOf = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

const objectOf = (value: unknown): Readonly<Record<string, unknown>> | null =>
  value !== null && typeof value === "object"
    ? (value as Readonly<Record<string, unknown>>)
    : null;

const percentFrom = (
  usage: Readonly<Record<string, unknown>>,
): number | null => {
  const direct = numberOf(usage.totalPercentUsed);
  if (direct !== null) return direct;
  const limit = numberOf(usage.limit);
  if (limit === null || limit <= 0) return null;
  const totalSpend = numberOf(usage.totalSpend);
  const remaining = numberOf(usage.remaining);
  const used = totalSpend ?? (remaining === null ? null : limit - remaining);
  return used === null ? null : (used / limit) * 100;
};

/** Reduce Cursor's dashboard usage and plan payloads into the common snapshot. */
export const parseCursorUsage = (
  usageBody: unknown,
  planBody: unknown,
): TProviderUsageSnapshot => {
  const usageRoot = objectOf(usageBody);
  const planRoot = objectOf(planBody);
  const planUsage = objectOf(usageRoot?.planUsage);
  const spendLimitUsage = objectOf(usageRoot?.spendLimitUsage);
  const planInfo = objectOf(planRoot?.planInfo);
  const planName = stringOf(planInfo?.planName);

  const planPercent = planUsage === null ? null : percentFrom(planUsage);
  const pooledLimit = numberOf(spendLimitUsage?.pooledLimit);
  const pooledUsed = numberOf(spendLimitUsage?.pooledUsed);
  const individualLimit = numberOf(spendLimitUsage?.individualLimit);
  const individualUsed = numberOf(spendLimitUsage?.individualUsed);
  const teamPlan =
    planName?.toLowerCase() === "team" ||
    stringOf(spendLimitUsage?.limitType)?.toLowerCase() === "team" ||
    (pooledLimit ?? 0) > 0;
  const spendPercent = teamPlan
    ? pooledLimit !== null && pooledLimit > 0 && pooledUsed !== null
      ? (pooledUsed / pooledLimit) * 100
      : null
    : individualLimit !== null && individualLimit > 0 && individualUsed !== null
      ? (individualUsed / individualLimit) * 100
      : null;
  const percent = spendPercent ?? planPercent;
  if (percent === null) {
    return {
      kind: "unavailable",
      reason: "Cursor reported no usable billing-cycle quota for this plan.",
      link: "https://cursor.com/dashboard",
    };
  }
  const end = numberOf(usageRoot?.billingCycleEnd);
  const window: TProviderUsageWindow = {
    label: "Billing cycle",
    percent_used: Math.max(0, Math.min(100, percent)),
    reset_at_ms: end,
  };
  return {
    kind: "quota",
    status: statusForWindows([window]),
    ...(planName !== null ? { plan: planName } : {}),
    windows: [window],
    note: "Cursor — read locally via cursor-agent",
  };
};

/**
 * Live-verified: macOS cursor-agent stores tokens as generic-password items
 * (services `cursor-access-token` / `cursor-refresh-token`, account `cursor-user`).
 *
 * Read them ONLY from the ISOLATED login keychain (the one under the CLI's
 * isolated HOME), exactly like claude_code: `readIsolatedKeychain` targets the
 * keychain by explicit path, never the user's real login keychain — so a
 * missing item is a quiet `null` ("not signed in"), never a "keychain not
 * found" error or a macOS GUI prompt, and nothing is created or mutated on a
 * read path beyond ensuring our own isolated keychain file exists.
 */
const readMacKeychainSecret = (service: string): Promise<string | null> =>
  readIsolatedKeychain(cliHome(PROVIDER), service);

type TCursorFileStore = {
  readonly access_token?: string;
  readonly accessToken?: string;
  readonly refresh_token?: string;
  readonly refreshToken?: string;
};

/** Live-verified (cursor-agent 2026.07.23): Linux file store is the XDG path
 *  `$XDG_CONFIG_HOME/cursor/auth.json` (= `<home>/.config/cursor/auth.json` with
 *  HOME + XDG_CONFIG_HOME pinned to the isolated home), camelCase tokens.
 *  `cliConfigDir("cursor")` resolves to that dir. */
const readFileTokens = async (): Promise<{
  readonly accessToken: string;
  readonly refreshTokenPresent: boolean;
} | null> => {
  const store = await readJsonFile<TCursorFileStore>(
    join(cliConfigDir(PROVIDER), "auth.json"),
  );
  const accessToken = store?.access_token ?? store?.accessToken;
  if (typeof accessToken !== "string" || accessToken.length === 0) return null;
  const refreshToken = store?.refresh_token ?? store?.refreshToken;
  return {
    accessToken,
    refreshTokenPresent:
      typeof refreshToken === "string" && refreshToken.length > 0,
  };
};

const triggerRefresh = async (): Promise<void> => {
  // cursor-agent's token store is the macOS keychain, and securityd refuses a
  // Seatbelt-confined caller; unconfined on macOS, confined on Linux
  // (file-backed store) — `sandbox/policy.ts`.
  await spawnRefresh([bin(), "status"], env(), {
    probe: unwrapKeychainSpawn(PROVIDER),
  });
};

const refresh = makeRefresher({
  leewayMs: REFRESH_LEEWAY_MS,
  trigger: triggerRefresh,
});

const readToken = async (): Promise<{
  readonly accessToken: string;
  readonly refreshTokenPresent: boolean;
} | null> => {
  const stored =
    platform() === "darwin"
      ? await (async (): Promise<{
          readonly accessToken: string;
          readonly refreshTokenPresent: boolean;
        } | null> => {
          const accessToken = await readMacKeychainSecret(
            "cursor-access-token",
          );
          if (accessToken === null) return null;
          const refreshToken = await readMacKeychainSecret(
            "cursor-refresh-token",
          );
          return { accessToken, refreshTokenPresent: refreshToken !== null };
        })()
      : await readFileTokens();
  if (stored === null) return null;
  const outcome = stored.refreshTokenPresent
    ? await refresh(jwtExpiryMs(stored.accessToken))
    : "fresh";
  if (outcome !== "awaited") return stored;
  // CLI remains the sole token-store owner. Re-read after a hard-expiry refresh.
  return platform() === "darwin"
    ? await (async (): Promise<typeof stored> => {
        const accessToken = await readMacKeychainSecret("cursor-access-token");
        if (accessToken === null) return stored;
        const refreshToken = await readMacKeychainSecret(
          "cursor-refresh-token",
        );
        return { accessToken, refreshTokenPresent: refreshToken !== null };
      })()
    : ((await readFileTokens()) ?? stored);
};

const INSTALL_HINT =
  "Cursor Agent not found — re-run the OpenLLM daemon installer to add it.";
const CONNECTED_DETAIL = "signed in via Cursor Agent";
const IN_PROGRESS_DETAIL =
  "Cursor sign-in already in progress — finish authorizing in your browser; this updates automatically.";

const isInstalled = async (): Promise<boolean> =>
  (await cliInstallState(PROVIDER)).installed;
const isConnected = async (): Promise<boolean> => (await readToken()) !== null;
const slot = loginSlot(PROVIDER);

const connectDirect = makeStreamConnect({
  provider: PROVIDER,
  slot,
  installed: isInstalled,
  installHint: INSTALL_HINT,
  connected: isConnected,
  connectedDetail: CONNECTED_DETAIL,
  inProgressDetail: IN_PROGRESS_DETAIL,
  argv: () => [bin(), "login"],
  env: () => ({ ...cliEnv(PROVIDER), NO_OPEN_BROWSER: "1" }),
  stream: "stdout",
  parse: (buffer) => {
    const url = parseAuthUrl(buffer);
    return url === null ? null : { url, code: "" };
  },
  // After a successful login lands the tokens, grant command-line tools
  // prompt-free access to the isolated keychain items (claude_code parity) so
  // the daemon's later `security` reads never pop a GUI prompt.
  onConnected: () => grantKeychainToolAccess(cliHome(PROVIDER)),
  onStart: () => {
    // Ensure the ISOLATED login keychain exists before the CLI spawns — a CLI
    // run under the isolated HOME with no keychain there wedges on macOS's
    // "Keychain Not Found" dialog (same failure claude_code guards against).
    // Best-effort + non-blocking; the pre-spawn `connected()` probe usually
    // has already ensured it (readIsolatedKeychain ensures on every read).
    void ensureIsolatedKeychain(cliHome(PROVIDER)).catch(() => {});
    logInfo("cursor-connect", "spawning `cursor-agent login`");
  },
  onParsed: (url) =>
    logInfo("cursor-connect", "parsed authorize URL; surfacing to dashboard", {
      urlLen: url.length,
    }),
  onParseFail: (captured) =>
    logError(
      "cursor-connect",
      "no authorize URL parsed from cursor-agent login",
      {
        stderrLen: captured.length,
        stderrSample: redactUrls(captured.slice(0, 400)),
      },
    ),
  pendingDetail: (url) =>
    `Authorize Cursor in the browser window that opened — or open ${url}. This page updates automatically once you're done.`,
  failDetail:
    "Couldn't start Cursor sign-in. Retry, or run `cursor-agent login` on the box.",
});

const cancelConnect = makeCancelConnect(PROVIDER, slot, {
  cancelled: "Cursor sign-in cancelled",
  none: "no sign-in was in progress",
});

const dashboardHeaders = (accessToken: string): Record<string, string> => ({
  authorization: `Bearer ${accessToken}`,
  "content-type": "application/json",
  "connect-protocol-version": "1",
});

export const cursorDelegate: TProviderDelegate = {
  slug: PROVIDER,
  connect: connectDirect,
  cancelConnect,

  status: async () => {
    const { installed, version } = await cliInstallState(PROVIDER);
    const token = installed ? await readToken() : null;
    if (token !== null) clearPendingAuth(PROVIDER);
    const pending = token === null ? getPendingAuth(PROVIDER) : null;
    return {
      provider: PROVIDER,
      connected: token !== null,
      cli_installed: installed,
      ...(version !== null ? { cli_version: version } : {}),
      ...(pending !== null
        ? { pending_auth: { url: pending.url, code: pending.code } }
        : {}),
      ...(token === null
        ? {
            detail:
              pending !== null
                ? pendingAuthDetail(pending)
                : installed
                  ? "cursor-agent installed but not signed in"
                  : "cursor-agent not installed",
          }
        : {
            last_login_at_ms: null,
            ...accountHashField(
              PROVIDER,
              jwtSubject(token.accessToken)?.split("|").at(-1) ?? undefined,
            ),
          }),
    };
  },

  usage: async (): Promise<TProviderUsageSnapshot> => {
    const token = await readToken();
    if (token === null)
      return { kind: "unavailable", reason: "not signed in to Cursor" };
    try {
      const [usage, plan] = await Promise.all([
        fetch(await resolveProviderUrl(PROVIDER, USAGE_PATH), {
          method: "POST",
          headers: dashboardHeaders(token.accessToken),
          body: "{}",
          signal: AbortSignal.timeout(MODEL_LIST_FETCH_TIMEOUT_MS),
        }),
        fetch(await resolveProviderUrl(PROVIDER, PLAN_PATH), {
          method: "POST",
          headers: dashboardHeaders(token.accessToken),
          body: "{}",
          signal: AbortSignal.timeout(MODEL_LIST_FETCH_TIMEOUT_MS),
        }),
      ]);
      if (!usage.ok || !plan.ok) {
        const failed = !usage.ok ? usage : plan;
        return {
          kind: "unavailable",
          reason:
            failed.status === 401
              ? "Cursor authorization was rejected — re-sign in via `cursor-agent login`."
              : failed.status === 403
                ? "No active Cursor subscription on this account."
                : `Cursor couldn't report usage (HTTP ${failed.status}).`,
          link: "https://cursor.com/dashboard",
        };
      }
      return parseCursorUsage(await usage.json(), await plan.json());
    } catch (error) {
      return {
        kind: "unavailable",
        reason:
          error instanceof Error ? error.message : "Cursor usage fetch failed",
        link: "https://cursor.com/dashboard",
      };
    }
  },

  // Cursor model discovery is ACP-only: a short-lived `cursor-agent acp`
  // session's `cursor/list_available_models` extension request (VERIFIED
  // LIVE) returns `{ models: [{ value, name }] }`. Cached 5 min (like grok's
  // modelRows); null on any failure — never an empty list.
  listModels: async (): Promise<ReadonlyArray<TProviderModelEntry> | null> => {
    if (
      cursorModelsCache !== null &&
      Date.now() - cursorModelsCache.at < CURSOR_MODELS_TTL_MS
    ) {
      return cursorModelsCache.entries;
    }
    if (cursorModelsInflight === null) {
      cursorModelsInflight =
        (async (): Promise<ReadonlyArray<TProviderModelEntry> | null> => {
          const rows = await listCursorModelsViaAcp({ bin: bin(), env: env() });
          if (rows === null) return null;
          const entries: TProviderModelEntry[] = rows.map((row) => ({
            provider_model_id: row.value,
            ...(row.name !== null ? { display_name: row.name } : {}),
          }));
          return entries.length > 0 ? entries : null;
        })().finally(() => {
          cursorModelsInflight = null;
        });
    }
    const entries = await cursorModelsInflight;
    if (entries !== null) {
      cursorModelsCache = { at: Date.now(), entries };
    }
    return entries;
  },

  credentialForUpstream: async () => {
    const token = await readToken();
    if (token === null)
      throw new Error("cursor: not signed in (no stored credential)");
    // Cursor has no manual HTTP inference path — the ACP bridge
    // (native-runtime/cursor-acp.ts) serves inference and never calls this.
    // Resolve the auth-config default target for diagnostics/contract parity,
    // then reject before any request can be issued to the dashboard endpoint.
    const url = await resolveUpstreamUrl(PROVIDER);
    throw new Error(
      `cursor is served by the ACP bridge (cursor-agent acp); there is no manual upstream transport (configured target: ${new URL(url).origin})`,
    );
  },

  logout: async () => {
    if ((await cliInstallState(PROVIDER)).installed) {
      await runCapture([bin(), "logout"], env());
    }
    // CLI owns its Keychain/file credentials; never delete them directly.
    const cleared = (await readToken()) === null;
    return cleared
      ? { ok: true, detail: "signed out of Cursor" }
      : { ok: false, detail: "credential still present after logout" };
  },
};
