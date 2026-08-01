/**
 * Claude Code local sessions from ~/.claude/history.jsonl.
 *
 * Each line is a prompt event: { display, timestamp, project, sessionId }.
 * We group by sessionId, take the latest display as title and max timestamp
 * as updated_at, and use project as cwd. Avoids scanning the large
 * projects/<slug>/*.jsonl tree.
 */

import { existsSync, readFileSync } from "node:fs";
import { claudeHistoryPath } from "./paths";
import { truncate } from "./title";
import type { THistorySession } from "./types";

export const readClaudeHistory = (limit: number): THistorySession[] => {
  const path = claudeHistoryPath();
  if (!existsSync(path)) return [];
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  type TAgg = {
    title: string;
    cwd: string | null;
    updated_at_ms: number;
  };
  const byId = new Map<string, TAgg>();
  for (const line of text.split("\n")) {
    if (line.length === 0) continue;
    let row: unknown;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    if (row === null || typeof row !== "object") continue;
    const o = row as Record<string, unknown>;
    const id = typeof o.sessionId === "string" ? o.sessionId : null;
    if (id === null || id.length === 0) continue;
    const ts =
      typeof o.timestamp === "number" && Number.isFinite(o.timestamp)
        ? o.timestamp
        : 0;
    const display = typeof o.display === "string" ? o.display : "";
    const project = typeof o.project === "string" ? o.project : null;
    const prev = byId.get(id);
    if (prev === undefined || ts >= prev.updated_at_ms) {
      byId.set(id, {
        title:
          display.length > 0 ? truncate(display) : (prev?.title ?? "Untitled"),
        cwd: project ?? prev?.cwd ?? null,
        updated_at_ms: ts,
      });
    } else if (prev.cwd === null && project !== null) {
      byId.set(id, { ...prev, cwd: project });
    }
  }
  return [...byId.entries()]
    .map(([id, v]) => ({
      id,
      title: v.title,
      cwd: v.cwd,
      updated_at_ms: v.updated_at_ms,
      cli: "claude_code" as const,
    }))
    .sort((a, b) => b.updated_at_ms - a.updated_at_ms)
    .slice(0, limit);
};
