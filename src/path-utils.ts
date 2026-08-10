/**
 * Shared filesystem-path helpers for the daemon.
 */
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";

/**
 * Standard user bin dirs the daemon prepends to a spawned integration's PATH.
 * The daemon runs as a background service with a minimal inherited PATH, so
 * user-installed CLIs the bundled scripts call (`claude` lands in ~/.local/bin;
 * `bun` lands in ~/.bun/bin via the official installer; many tools live under
 * Homebrew) aren't found and a script that relies on one half-applies or acks
 * `status:error`. Every entry is within the OS-sandbox working set (`/opt`,
 * `/usr`, ~/.local/bin, ~/.bun — see `sandbox/working-set/`), so a spawn never
 * hits a Landlock denial; absent dirs are simply ignored by the shell. Evaluated
 * once at module load (`homedir()` is stable for the process).
 */
export const DEFAULT_BIN_DIRS: readonly string[] = [
  "/opt/homebrew/bin",
  "/usr/local/bin",
  `${homedir()}/.local/bin`,
  `${homedir()}/.bun/bin`,
];

/**
 * Every existing location of `cmd` across the daemon's effective search space,
 * in priority order — a multi-hit `which -a` that doesn't depend on a shell.
 * Scans (deduped): the process's own PATH entries, then `DEFAULT_BIN_DIRS`
 * (the daemon's minimal service PATH often lacks the user dirs), then the
 * system dirs (`/usr/bin`, `/bin`) so a system-wide / distro / sudo install is
 * always found. Existence-checked only — callers exec the result, so a
 * non-executable hit fails loudly there rather than being silently skipped.
 */
export const resolveOnPath = (cmd: string): string[] => {
  const dirs = [
    ...(process.env.PATH?.split(delimiter) ?? []),
    ...DEFAULT_BIN_DIRS,
    "/usr/bin",
    "/bin",
  ].filter((d) => d.length > 0);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const dir of dirs) {
    const p = join(dir, cmd);
    if (seen.has(p)) continue;
    seen.add(p);
    if (existsSync(p)) out.push(p);
  }
  return out;
};
