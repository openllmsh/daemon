/**
 * Cursor subscription delegate through the official `cursor-agent` CLI.
 *
 * ⚠️ RESEARCH-UNVERIFIED: Cursor's CLI/store details below are derived from
 * openusage and public CLI research, not a live cursor-agent installation.
 * Cursor inference is ACP-only (`cursor-agent acp`); this delegate deliberately
 * exposes login/status/usage only until the daemon ACP bridge is implemented.
 */
import { platform } from "node:os";
import { join } from "node:path";
import type {
  TProviderUsageSnapshot,
  TProviderUsageWindow,
} from "@openllmsh/protocol";
import { MODEL_LIST_FETCH_TIMEOUT_MS } from "@openllmsh/protocol";
import { cliInstallState } from "../cli-install";
import { cliBin, cliConfigDir, cliEnv } from "../cli-paths";
import { logError, logInfo } from "../logger";
import {
  clearPendingAuth,
  getPendingAuth,
  pendingAuthDetail,
} from "../pending-auth";
import { accountHashField } from "./account-id";
import { resolveUpstreamUrl } from "./auth-config";
import { jwtExpiryMs, jwtSubject } from "./jwt";
import { makeStreamConnect } from "./login-direct";
import { loginSlot } from "./login-flow";
import { makeRefresher, spawnRefresh } from "./refresh";
import type { TProviderDelegate } from "./types";
import { readJsonFile, runCapture, stripAnsi } from "./util";

const PROVIDER = "cursor" as const;
const CURSOR_ORIGIN = "https://api2.cursor.sh";
const USAGE_PATH = "/aiserver.v1.DashboardService/GetCurrentPeriodUsage";
const PLAN_PATH = "/aiserver.v1.DashboardService/GetPlanInfo";
const REFRESH_LEEWAY_MS = 5 * 60_000;

const bin = (): string => cliBin(PROVIDER);
const env = (): Record<string, string> => cliEnv(PROVIDER);

const redactUrls = (value: string): string =>
  value.replace(/(https?:\/\/[^\s?]+)\?\S*/g, "$1?<redacted>");

/** ⚠️ RESEARCH-UNVERIFIED: tolerate cursor.com and generic OIDC authorize URLs. */
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

/** ⚠️ RESEARCH-UNVERIFIED: macOS Cursor tokens use generic-password services. */
const readMacKeychainSecret = (service: string): Promise<string | null> =>
  runCapture(["security", "find-generic-password", "-s", service, "-w"]);

type TCursorFileStore = {
  readonly access_token?: string;
  readonly accessToken?: string;
  readonly refresh_token?: string;
  readonly refreshToken?: string;
};

/** ⚠️ RESEARCH-UNVERIFIED: Linux credential persistence path/shape. */
const readFileTokens = async (): Promise<{
  readonly accessToken: string;
  readonly refreshTokenPresent: boolean;
} | null> => {
  const store = await readJsonFile<TCursorFileStore>(
    join(cliConfigDir(PROVIDER), "credentials.json"),
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
  await spawnRefresh([bin(), "status"], env());
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
  env,
  parse: (buffer) => {
    const url = parseAuthUrl(buffer);
    return url === null ? null : { url, code: "" };
  },
  onStart: () => logInfo("cursor-connect", "spawning `cursor-agent login`"),
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

const dashboardHeaders = (accessToken: string): Record<string, string> => ({
  authorization: `Bearer ${accessToken}`,
  "content-type": "application/json",
  "connect-protocol-version": "1",
});

export const cursorDelegate: TProviderDelegate = {
  slug: PROVIDER,
  connect: connectDirect,

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
        fetch(`${CURSOR_ORIGIN}${USAGE_PATH}`, {
          method: "POST",
          headers: dashboardHeaders(token.accessToken),
          body: "{}",
          signal: AbortSignal.timeout(MODEL_LIST_FETCH_TIMEOUT_MS),
        }),
        fetch(`${CURSOR_ORIGIN}${PLAN_PATH}`, {
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

  // Cursor model discovery is ACP-only (`cursor/list_available_models`).
  // ⚠️ RESEARCH-UNVERIFIED until the ACP bridge implementation lands.

  credentialForUpstream: async () => {
    const token = await readToken();
    if (token === null)
      throw new Error("cursor: not signed in (no stored credential)");
    // Cursor has no manual HTTP inference path. Resolve the auth-config default
    // target for diagnostics/contract parity, then reject before any request can
    // be issued to the dashboard endpoint.
    const url = await resolveUpstreamUrl(PROVIDER);
    throw new Error(
      `cursor inference requires the ACP bridge (cursor-agent acp); manual upstream inference is not implemented (configured target: ${new URL(url).origin})`,
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
