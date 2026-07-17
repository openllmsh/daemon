/**
 * Shared helpers for official-CLI delegation — now a BARREL over the
 * single-topic modules it used to open-code (split per
 * `docs/proposals/sub-method-simplified-execution.md` §3):
 *
 *   - `spawn.ts`          capture runs, login spawns (pipe + PTY), ANSI strip,
 *                         browser open, spawn env/cwd hygiene
 *   - `headless-login.ts` Claude remote paste-back login
 *   - `keychain.ts`       isolated macOS login keychain
 *
 * Every existing `./util` import keeps working; new code may import the
 * specific module directly.
 *
 * ⚠️ UNVERIFIED AGAINST LIVE CLIs. The credential-store paths, file
 * shapes, and login commands are derived from public docs + upstream
 * source research (2025-2026); each delegate is marked accordingly. See
 * the per-delegate `RESEARCH` notes.
 *
 * Bright line (proposal §6): nothing read from a CLI's store may be sent
 * off-box. These helpers feed the LOCAL runner + the local usage panel
 * only.
 */

export * from "./headless-login";
export * from "./keychain";
export * from "./spawn";

/** Read + JSON-parse a file, or null if absent / unparseable. */
export const readJsonFile = async <T>(path: string): Promise<T | null> => {
  try {
    const file = Bun.file(path);
    if (!(await file.exists())) return null;
    return (await file.json()) as T;
  } catch {
    return null;
  }
};

/** Tolerant epoch parser — accepts ms-int, sec-float, or ISO string. */
export const toEpochMs = (raw: unknown): number | null => {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    // Heuristic: < 1e12 is seconds, else ms.
    return raw < 1e12 ? Math.round(raw * 1000) : Math.round(raw);
  }
  if (typeof raw === "string") {
    const ms = Date.parse(raw);
    return Number.isFinite(ms) ? ms : null;
  }
  return null;
};
