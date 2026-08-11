/**
 * OpenCode Go delegate.
 *
 * OpenCode Go is a flat-fee subscription ($10/mo) fronting open coding models
 * through an OpenAI-compatible gateway (`https://opencode.ai/zen/go/v1`). Unlike
 * the other subscription providers there is NO OAuth / device-code flow and no
 * vendor CLI to drive: the credential is a static workspace key the user obtains
 * at `https://opencode.ai/go` and OpenCode stores in its local `auth.json`.
 *
 * So this delegate is the daemon subscription class with a PASTE-BACK login
 * (mode `paste_code`, like claude's headless flow) rather than a spawned CLI:
 *   - `connect()` arms a pending paste; the dashboard renders a key input.
 *   - `submitLoginCode(key)` writes the key into an ISOLATED OpenCode
 *     `auth.json` under `~/.openllm/cli/opencode_go/.../auth.json` (the same
 *     format + `OPENCODE_DATA_DIR` layout OpenCode itself uses — so a real
 *     `opencode` CLI pointed there would read the same credential — never the
 *     user's real OpenCode home).
 *   - `credentialForUpstream()` reads that key back and the coreless walker
 *     forwards it handrolled (`UPSTREAM_WIRE.opencode_go = "openai"`) with a
 *     bare `Authorization: Bearer` — no `x-opencode-*` headers required
 *     (curl-verified against the live gateway).
 *
 * No refresh (the key is static) and no network usage API (OpenCode's own
 * usage is computed from local SQLite logs — out of scope here), so `usage()`
 * is `unavailable`.
 */
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { TProviderUsageSnapshot } from "@openllmsh/protocol";
import { MODEL_LIST_FETCH_TIMEOUT_MS } from "@openllmsh/protocol";
import { cliInstallState } from "../cli-install";
import { cliConfigDir } from "../cli-paths";
import {
  clearPendingAuth,
  getPendingAuth,
  pendingAuthDetail,
  setPendingAuth,
} from "../pending-auth";
import { accountHashField } from "./account-id";
import type { TProviderDelegate } from "./types";
import { readJsonFile } from "./util";

const PROVIDER = "opencode_go" as const;

// The versioned gateway root. `credentialForUpstream` targets its
// `/chat/completions` leaf (the walker POSTs `cred.url` verbatim); `listModels`
// reads `/models`. Kept in sync with the registry `defaultBaseUrl`.
const GATEWAY_BASE = "https://opencode.ai/zen/go/v1";

// Where the user enables the subscription + copies the key.
const ENABLE_URL = "https://opencode.ai/go";

// OpenCode's auth.json keys the entry by the provider id `opencode-go` (hyphen),
// value `{ type: "api", key }`. We persist exactly that shape under the isolated
// data dir so the credential is indistinguishable from a real OpenCode login.
const AUTH_ENTRY_KEY = "opencode-go";

type TOpenCodeAuthEntry = {
  readonly type?: string;
  readonly key?: string;
};
type TOpenCodeAuthStore = Readonly<Record<string, TOpenCodeAuthEntry>>;

/** Isolated `auth.json` path — `<home>/.local/share/opencode/auth.json`. */
const authPath = (): string => join(cliConfigDir(PROVIDER), "auth.json");

/** The stored Go key, or null when not signed in. */
const readKey = async (): Promise<string | null> => {
  const store = await readJsonFile<TOpenCodeAuthStore>(authPath());
  const key = store?.[AUTH_ENTRY_KEY]?.key;
  return typeof key === "string" && key.length > 0 ? key : null;
};

/** Persist the pasted key into the isolated store (mode 0600), creating the
 *  data dir on first login. */
const writeKey = async (key: string): Promise<void> => {
  const dir = cliConfigDir(PROVIDER);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const body: TOpenCodeAuthStore = {
    [AUTH_ENTRY_KEY]: { type: "api", key },
  };
  await writeFile(authPath(), `${JSON.stringify(body, null, 2)}\n`, {
    mode: 0o600,
  });
};

export const opencodeGoDelegate: TProviderDelegate = {
  slug: PROVIDER,

  // No CLI to spawn for the login itself — connect just arms the paste. The
  // CLI must still be present so the isolated run-view has something to link
  // (and so Connect is gated the same way as the other subscription cards).
  connect: async () => {
    if (!(await cliInstallState(PROVIDER)).installed) {
      return {
        connected: false,
        detail:
          "OpenCode CLI not found — re-run the OpenLLM daemon installer to add it, or `curl -fsSL https://opencode.ai/install | bash`.",
      };
    }
    if ((await readKey()) !== null) {
      return { connected: true, detail: "signed in to OpenCode Go" };
    }
    setPendingAuth(PROVIDER, {
      url: ENABLE_URL,
      code: "",
      mode: "paste_code",
    });
    return { connected: false, pending: true };
  },

  // The pasted value IS the key (already unsealed by the control relay). Persist
  // it; a blank paste leaves the flow alive for a retry.
  submitLoginCode: async (key) => {
    const trimmed = key.trim();
    if (trimmed.length === 0) {
      return { ok: false, detail: "no key entered" };
    }
    await writeKey(trimmed);
    clearPendingAuth(PROVIDER);
    return { ok: true, detail: "OpenCode Go key saved" };
  },

  cancelConnect: async () => {
    clearPendingAuth(PROVIDER);
    return { ok: true, detail: "OpenCode Go sign-in cancelled" };
  },

  status: async () => {
    const { installed, version } = await cliInstallState(PROVIDER);
    const key = installed ? await readKey() : null;
    if (key !== null) clearPendingAuth(PROVIDER);
    const pending = key === null ? getPendingAuth(PROVIDER) : null;
    return {
      provider: PROVIDER,
      connected: key !== null,
      // Real install state — the daemon installer background-provisions
      // `opencode` (packages/daemon/install.sh), and the card surfaces the
      // install one-liner when missing. The credential itself is still a
      // pasted key; the CLI is the isolation/session surface, not the login.
      cli_installed: installed,
      ...(version !== null ? { cli_version: version } : {}),
      ...(key !== null
        ? {
            last_login_at_ms: null,
            // Stable per-credential identity (the key is the account), hashed
            // via `account-id.ts` so cost rows attribute to the right meter.
            ...accountHashField(PROVIDER, key),
          }
        : pending !== null
          ? {
              pending_auth: {
                url: pending.url,
                code: pending.code,
                ...(pending.mode !== undefined ? { mode: pending.mode } : {}),
              },
              detail: pendingAuthDetail(pending),
            }
          : {
              detail: installed
                ? "not signed in to OpenCode Go"
                : "opencode CLI not installed",
            }),
    };
  },

  usage: async (): Promise<TProviderUsageSnapshot> => ({
    kind: "unavailable",
    reason:
      "OpenCode Go doesn't expose a usage API — track your plan caps at opencode.ai/go.",
    link: ENABLE_URL,
  }),

  // The gateway's `/models` is servable without auth, but we send the bearer
  // when present for parity. Live ids let `live-merge` surface models the static
  // catalog omits. Null on any failure (never an empty list).
  listModels: async () => {
    const key = await readKey();
    try {
      const resp = await fetch(`${GATEWAY_BASE}/models`, {
        method: "GET",
        headers: {
          accept: "application/json",
          ...(key !== null ? { authorization: `Bearer ${key}` } : {}),
        },
        signal: AbortSignal.timeout(MODEL_LIST_FETCH_TIMEOUT_MS),
      });
      if (!resp.ok) return null;
      const body = (await resp.json()) as {
        data?: ReadonlyArray<Readonly<Record<string, unknown>>>;
      };
      const rows = body.data ?? [];
      const entries = rows.flatMap((m) =>
        typeof m.id === "string" && m.id.length > 0
          ? [{ provider_model_id: m.id }]
          : [],
      );
      return entries.length > 0 ? entries : null;
    } catch {
      return null;
    }
  },

  credentialForUpstream: async () => {
    const key = await readKey();
    if (key === null) {
      throw new Error("opencode_go: not signed in (no stored credential)");
    }
    return {
      access_token: key,
      // Bare Bearer is accepted — no `x-opencode-*` headers required.
      headers: {},
      url: `${GATEWAY_BASE}/chat/completions`,
      ...accountHashField(PROVIDER, key),
    };
  },

  logout: async () => {
    await rm(authPath(), { force: true }).catch(() => {});
    const cleared = (await readKey()) === null;
    return cleared
      ? { ok: true, detail: "signed out of OpenCode Go" }
      : { ok: false, detail: "credential still present after logout" };
  },
};
