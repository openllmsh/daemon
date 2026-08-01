/**
 * Grok local sessions from ~/.grok/sessions/<cwd-encoded>/<id>/summary.json.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { grokSessionsDir } from "./paths";
import type { THistorySession } from "./types";

const TITLE_MAX = 80;

const truncate = (s: string): string => {
  const t = s.replace(/\s+/g, " ").trim();
  if (t.length === 0) return "Untitled";
  return t.length <= TITLE_MAX ? t : `${t.slice(0, TITLE_MAX - 1)}...`;
};

const parseUpdatedMs = (raw: unknown, fallback: number): number => {
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
  const summaries: Array<{ path: string; mtime: number }> = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > 6 || summaries.length >= limit * 4) return;
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
        else if (name === "summary.json") {
          summaries.push({ path: abs, mtime: st.mtimeMs });
        }
      } catch {
        /* skip */
      }
    }
  };
  walk(root, 0);
  summaries.sort((a, b) => b.mtime - a.mtime);
  const out: THistorySession[] = [];
  for (const s of summaries) {
    if (out.length >= limit) break;
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
      out.push({
        id,
        title: summary.length > 0 ? truncate(summary) : "Untitled",
        cwd: typeof raw.info?.cwd === "string" ? raw.info.cwd : null,
        updated_at_ms: parseUpdatedMs(raw.updated_at ?? raw.created_at, s.mtime),
        cli: "grok",
      });
    } catch {
      /* skip */
    }
  }
  return out;
};
