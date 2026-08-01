/**
 * Grok local sessions from ~/.grok/sessions/<cwd-encoded>/<id>/summary.json.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { grokSessionsDir } from "./paths";
import { truncate } from "./title";
import type { THistorySession } from "./types";

export const parseUpdatedMs = (raw: unknown, fallback: number): number => {
  if (typeof raw === "string") {
    const t = Date.parse(raw);
    if (Number.isFinite(t)) return t;
  }
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  return fallback;
};

export const readGrokHistory = (limit: number): THistorySession[] => {
  const root = grokSessionsDir();
  if (!existsSync(root)) return [];

  const summaryFiles: Array<{ path: string; mtime: number }> = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > 6) return;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of names) {
      // Skip search index / non-session layout files.
      if (name === "session_search.sqlite" || name.endsWith(".lock")) continue;
      const abs = join(dir, name);
      try {
        const st = statSync(abs);
        if (st.isDirectory()) walk(abs, depth + 1);
        else if (name === "summary.json" && st.isFile()) {
          summaryFiles.push({ path: abs, mtime: st.mtimeMs });
        }
      } catch {
        /* skip */
      }
    }
  };
  walk(root, 0);

  const sessions: THistorySession[] = [];
  for (const s of summaryFiles) {
    try {
      const raw = JSON.parse(readFileSync(s.path, "utf8")) as {
        info?: { id?: string; cwd?: string };
        session_summary?: string;
        updated_at?: string;
        created_at?: string;
      };
      const id = raw.info?.id;
      if (typeof id !== "string" || id.length === 0) continue;
      const summary =
        typeof raw.session_summary === "string" ? raw.session_summary : "";
      sessions.push({
        id,
        title: summary.length > 0 ? truncate(summary) : "Untitled",
        cwd: typeof raw.info?.cwd === "string" ? raw.info.cwd : null,
        updated_at_ms: parseUpdatedMs(
          raw.updated_at,
          parseUpdatedMs(raw.created_at, s.mtime),
        ),
        cli: "grok",
      });
    } catch {
      /* skip */
    }
  }

  return sessions
    .sort((a, b) => b.updated_at_ms - a.updated_at_ms)
    .slice(0, limit);
};
