/**
 * Scan `~/.openllm/run/<client>/<pid>/live.json` for process-live launches.
 *
 * A dir is live only when (1) the pid is still alive and (2) its command
 * still looks like openllm / a vendor CLI. Stale dirs are left for the CLI's
 * own reap (or cleaned best-effort when clearly dead).
 */

import {
  existsSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { basename, join } from "node:path";
import { runClientRoot } from "./paths";
import type { TLiveRun, TOpenllmClientId } from "./types";

const LIVE_JSON = "live.json";

/** Local copy of session-host's vendor-command check — avoids an import cycle. */
const vendorNames = [
  "claude",
  "codex",
  "kimi",
  "grok",
  "cursor-agent",
  "opencode",
  "openllm",
  "openllmc",
];

const looksLikeVendorCommand = (command: string): boolean => {
  const executable = command.trim().split(/\s+/, 1)[0];
  if (executable === undefined || executable === "") return false;
  const name = basename(executable).toLowerCase();
  return vendorNames.some(
    (vendor) => name === vendor || name.startsWith(`${vendor}-`),
  );
};

const pidAlive = (pid: number): boolean => {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

const commandOf = (pid: number): string | null => {
  try {
    const out = Bun.spawnSync(["ps", "-p", String(pid), "-o", "command="], {
      stdout: "pipe",
      stderr: "ignore",
    }).stdout.toString();
    const text = out.trim();
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
};

const parseLiveJson = (
  raw: string,
  client: TOpenllmClientId,
  dirPid: number,
): TLiveRun | null => {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const o = value as Record<string, unknown>;
  if (o.version !== 1) return null;
  const pid = typeof o.pid === "number" ? o.pid : dirPid;
  if (!Number.isInteger(pid) || pid <= 0) return null;
  const cwd = typeof o.cwd === "string" && o.cwd.length > 0 ? o.cwd : null;
  if (cwd === null) return null;
  const host = o.host === "device" || o.host === "local" ? o.host : "local";
  const started =
    typeof o.started_at_ms === "number" && Number.isFinite(o.started_at_ms)
      ? o.started_at_ms
      : 0;
  const openllmId =
    typeof o.openllm_session_id === "string" && o.openllm_session_id.length > 0
      ? o.openllm_session_id
      : null;
  const vendorId =
    typeof o.vendor_session_id === "string" && o.vendor_session_id.length > 0
      ? o.vendor_session_id
      : null;
  const title =
    typeof o.title === "string" && o.title.length > 0 ? o.title : null;
  return {
    client,
    pid,
    cwd,
    started_at_ms: started,
    host,
    openllm_session_id: openllmId,
    vendor_session_id: vendorId,
    title,
  };
};

/** Live runs for one openllm client id. */
export const readLiveRuns = (client: TOpenllmClientId): TLiveRun[] => {
  const root = runClientRoot(client);
  if (!existsSync(root)) return [];
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return [];
  }
  const out: TLiveRun[] = [];
  for (const name of entries) {
    const dirPid = Number.parseInt(name, 10);
    if (!Number.isInteger(dirPid) || dirPid <= 0) continue;
    const dir = join(root, name);
    try {
      if (!statSync(dir).isDirectory()) continue;
    } catch {
      continue;
    }
    const livePath = join(dir, LIVE_JSON);
    if (!existsSync(livePath)) continue;
    let raw: string;
    try {
      raw = readFileSync(livePath, "utf8");
    } catch {
      continue;
    }
    const live = parseLiveJson(raw, client, dirPid);
    if (live === null) continue;
    if (!pidAlive(live.pid)) {
      // Best-effort: drop clearly dead run dirs so the index stays small.
      // The CLI also reaps on next launch; never throw.
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
      continue;
    }
    const cmd = commandOf(live.pid);
    if (cmd === null || !looksLikeVendorCommand(cmd)) {
      // PID reused by something else — do not treat as our session.
      continue;
    }
    // Dir name should match pid; tolerate mismatch if live.json pid is live.
    if (basename(dir) !== String(live.pid) && !pidAlive(dirPid)) {
      continue;
    }
    out.push(live);
  }
  return out;
};
