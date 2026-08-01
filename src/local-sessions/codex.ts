/**
 * Codex local sessions from `~/.codex/state_5.sqlite` `threads` table.
 * Falls back to scanning recent rollout jsonl files when the DB is missing
 * or the schema drifts.
 */

import { Database } from "bun:sqlite";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { codexSessionsDir, codexStateDbPath } from "./paths";
import type { THistorySession } from "./types";

const TITLE_MAX = 80;

const truncate = (s: string): string => {
  const t = s.replace(/\s+/g, " ").trim();
  if (t.length === 0) return "Untitled";
  return t.length <= TITLE_MAX ? t : `${t.slice(0, TITLE_MAX - 1)}...`;
};

const titleOf = (row: {
  title?: unknown;
  name?: unknown;
  first_user_message?: unknown;
  preview?: unknown;
}): string => {
  for (const key of ["title", "name", "first_user_message", "preview"] as const) {
    const v = row[key];
    if (typeof v === "string" && v.trim().length > 0) return truncate(v);
  }
  return "Untitled";
};

const readFromDb = (limit: number): THistorySession[] | null => {
  const path = codexStateDbPath();
  if (!existsSync(path)) return null;
  try {
    const db = new Database(path, { readonly: true, create: false });
    try {
      const rows = db
        .query(
          `SELECT id, title, name, first_user_message, preview, cwd,
                  COALESCE(updated_at_ms, updated_at * 1000, 0) AS updated_ms
           FROM threads
           WHERE COALESCE(archived, 0) = 0
           ORDER BY COALESCE(recency_at_ms, recency_at * 1000, updated_at_ms, updated_at * 1000, 0) DESC
           LIMIT ?`,
        )
        .all(limit) as Array<Record<string, unknown>>;
      const out: THistorySession[] = [];
      for (const row of rows) {
        const id = typeof row.id === "string" ? row.id : null;
        if (id === null) continue;
        const cwd = typeof row.cwd === "string" ? row.cwd : null;
        const updated =
          typeof row.updated_ms === "number" ? row.updated_ms : 0;
        out.push({
          id,
          title: titleOf(row),
          cwd,
          updated_at_ms: updated,
          cli: "chatgpt",
        });
      }
      return out;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
};

/** Fallback: walk recent rollout-*.jsonl under sessions/YYYY/MM/DD/. */
const readFromRollouts = (limit: number): THistorySession[] => {
  const root = codexSessionsDir();
  if (!existsSync(root)) return [];
  const files: Array<{ path: string; mtime: number }> = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > 4 || files.length >= limit * 3) return;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of names) {
      const abs = join(dir, name);
      try {
        const st = statSync(abs);
        if (st.isDirectory()) walk(abs, depth + 1);
        else if (name.startsWith("rollout-") && name.endsWith(".jsonl")) {
          files.push({ path: abs, mtime: st.mtimeMs });
        }
      } catch {
        /* skip */
      }
    }
  };
  walk(root, 0);
  files.sort((a, b) => b.mtime - a.mtime);
  const out: THistorySession[] = [];
  for (const f of files.slice(0, limit * 2)) {
    if (out.length >= limit) break;
    try {
      const first = readFileSync(f.path, "utf8").split("\n", 1)[0];
      if (first === undefined) continue;
      const row = JSON.parse(first) as {
        type?: string;
        payload?: {
          session_id?: string;
          id?: string;
          cwd?: string;
          timestamp?: string;
        };
      };
      if (row.type !== "session_meta" || row.payload === undefined) continue;
      const id = row.payload.session_id ?? row.payload.id;
      if (typeof id !== "string" || id.length === 0) continue;
      out.push({
        id,
        title: "Untitled",
        cwd: typeof row.payload.cwd === "string" ? row.payload.cwd : null,
        updated_at_ms: f.mtime,
        cli: "chatgpt",
      });
    } catch {
      /* skip */
    }
  }
  return out;
};

export const readCodexHistory = (limit: number): THistorySession[] => {
  const fromDb = readFromDb(limit);
  if (fromDb !== null && fromDb.length > 0) return fromDb;
  return readFromRollouts(limit);
};
