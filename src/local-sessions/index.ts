/**
 * Local session index: vendor history + `~/.openllm/run` live.json +
 * in-memory device PTYs, merged for `list_local_sessions`.
 */

import type { TDeviceSessionCli, TLocalCliSession } from "@openllmsh/protocol";
import { readClaudeHistory } from "./claude";
import { readCodexHistory } from "./codex";
import { readGrokHistory } from "./grok";
import { readLiveRuns } from "./live-run";
import { readOpencodeHistory } from "./opencode";
import { TITLE_MAX } from "./title";
import type { THistorySession, TLiveRun } from "./types";
import {
  deviceCliOfClientId,
  isListableDeviceCli,
  openllmClientIdOf,
} from "./types";

export * from "./types";

const DEFAULT_LIMIT = 30;
const HARD_CAP = 100;

/** Optional injectors for tests. */
export type TLocalSessionsDeps = {
  readonly readHistory?: (
    cli: TDeviceSessionCli,
    limit: number,
  ) => THistorySession[];
  readonly readLive?: (cli: TDeviceSessionCli) => TLiveRun[];
  /** In-memory device PTYs from session-host (same process). */
  readonly deviceSessions?: () => ReadonlyArray<{
    readonly id: string;
    readonly cli: TDeviceSessionCli;
    readonly live: boolean;
    readonly title?: string | null;
    readonly vendor_session_id?: string | null;
    readonly cwd?: string | null;
    readonly started_at_ms: number;
  }>;
};

const defaultHistory = (
  cli: TDeviceSessionCli,
  limit: number,
): THistorySession[] => {
  switch (cli) {
    case "claude_code":
      return readClaudeHistory(limit);
    case "chatgpt":
      return readCodexHistory(limit);
    case "grok":
      return readGrokHistory(limit);
    case "opencode":
      return readOpencodeHistory(limit);
    default:
      return [];
  }
};

const defaultLive = (cli: TDeviceSessionCli): TLiveRun[] => {
  const clientId = openllmClientIdOf(cli);
  if (clientId === null) return [];
  return readLiveRuns(clientId);
};

export const clampLimit = (limit: number | undefined): number => {
  if (limit === undefined || !Number.isFinite(limit)) return DEFAULT_LIMIT;
  const n = Math.floor(limit);
  if (n < 1) return 1;
  return Math.min(n, HARD_CAP);
};

/**
 * List local sessions for one device CLI. Never throws — empty on missing
 * stores or read errors.
 */
export const readLocalSessions = (
  cli: TDeviceSessionCli,
  opts: { readonly limit?: number; readonly deps?: TLocalSessionsDeps } = {},
): TLocalCliSession[] => {
  const limit = clampLimit(opts.limit);
  const deps = opts.deps ?? {};
  // Defense-in-depth: every current DeviceSessionCli is listable; keep the
  // guard so a future non-listable slug fails closed to empty rather than
  // half-reading an unknown store.
  if (!isListableDeviceCli(cli)) return [];

  const history = (deps.readHistory ?? defaultHistory)(cli, limit);
  const liveRuns = (deps.readLive ?? defaultLive)(cli);
  const device = deps.deviceSessions?.() ?? [];

  type TRow = {
    id: string;
    title: string;
    cwd: string | null;
    updated_at_ms: number;
    live: boolean;
    host: "local" | "device" | null;
    openllm_session_id: string | null;
    attachable: boolean;
  };

  const byKey = new Map<string, TRow>();
  const byOpenllmId = new Map<string, string>();

  const mergeRows = (previous: TRow, row: TRow): TRow => ({
    id: row.id.length > 0 ? row.id : previous.id,
    title:
      row.title !== "Untitled" && row.title.length > 0
        ? row.title
        : previous.title,
    cwd: row.cwd ?? previous.cwd,
    updated_at_ms: Math.max(row.updated_at_ms, previous.updated_at_ms),
    live: row.live || previous.live,
    host: row.host ?? previous.host,
    openllm_session_id: row.openllm_session_id ?? previous.openllm_session_id,
    attachable: row.attachable || previous.attachable,
  });

  const put = (row: TRow, key: string): void => {
    const openllmId = row.openllm_session_id;
    const existingKey =
      openllmId !== null && openllmId.length > 0
        ? byOpenllmId.get(openllmId)
        : undefined;
    const targetKey = existingKey ?? key;
    const previous = byKey.get(targetKey);
    const merged = previous === undefined ? row : mergeRows(previous, row);
    byKey.set(targetKey, merged);
    if (openllmId !== null && openllmId.length > 0) {
      byOpenllmId.set(openllmId, targetKey);
    }
  };

  for (const h of history) {
    put(
      {
        id: h.id,
        title: h.title,
        cwd: h.cwd,
        updated_at_ms: h.updated_at_ms,
        live: false,
        host: null,
        openllm_session_id: null,
        attachable: false,
      },
      `vendor:${h.id}`,
    );
  }

  for (const live of liveRuns) {
    if (deviceCliOfClientId(live.client) !== cli) continue;
    // Key priority: vendor id (merge with vendor history) → openllm id (merge
    // with the in-memory device loop's `openllm:${id}`) → pid. Without the
    // openllm fallback, a device live.json with no vendor id would key by pid
    // and duplicate the same session's in-memory device row.
    const vendorKey =
      live.vendor_session_id !== null
        ? `vendor:${live.vendor_session_id}`
        : live.openllm_session_id !== null && live.openllm_session_id.length > 0
          ? `openllm:${live.openllm_session_id}`
          : `live:${live.pid}`;
    const attachable =
      live.host === "device" &&
      live.openllm_session_id !== null &&
      live.openllm_session_id.length > 0;
    put(
      {
        id: live.vendor_session_id ?? `live-${live.pid}`,
        title: live.title ?? "Untitled",
        cwd: live.cwd,
        updated_at_ms: live.started_at_ms,
        live: true,
        host: live.host,
        openllm_session_id: live.openllm_session_id,
        attachable,
      },
      vendorKey,
    );
  }

  for (const s of device) {
    if (s.cli !== cli) continue;
    const vendorKey =
      s.vendor_session_id !== null &&
      s.vendor_session_id !== undefined &&
      s.vendor_session_id.length > 0
        ? `vendor:${s.vendor_session_id}`
        : `openllm:${s.id}`;
    put(
      {
        id: s.vendor_session_id ?? s.id,
        title: s.title ?? "Untitled",
        cwd: s.cwd ?? null,
        updated_at_ms: s.started_at_ms,
        live: s.live,
        host: s.live ? "device" : null,
        openllm_session_id: s.id,
        attachable: s.live,
      },
      vendorKey,
    );
  }

  return [...byKey.values()]
    .sort((a, b) => {
      // Attachable live first, then other live, then by recency.
      if (a.attachable !== b.attachable) return a.attachable ? -1 : 1;
      if (a.live !== b.live) return a.live ? -1 : 1;
      return b.updated_at_ms - a.updated_at_ms;
    })
    .slice(0, limit)
    .map((r) => ({
      id: r.id,
      title: r.title.slice(0, TITLE_MAX),
      cwd: r.cwd,
      updated_at_ms: r.updated_at_ms,
      cli,
      live: r.live,
      host: r.host,
      openllm_session_id: r.openllm_session_id,
      attachable: r.attachable,
    }));
};
