/**
 * `openllmd logs [-f] [-n N]` — show or follow daemon logs.
 *
 * launchd writes daemon stdout/stderr to state-dir files, not journald. Linux
 * prefers the user systemd journal when its unit is registered, then falls back
 * to the same state-dir files for from-source and non-systemd installations.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  daemonStderrLogFilePath,
  daemonStdoutLogFilePath,
  logFilePath,
} from "./env";

/** Initial tail length when `-n`/`--lines` isn't given. */
export const DEFAULT_LOG_LINES = 200;
const UNIT = "openllmd.service";

export type TLogsOpts = { readonly follow: boolean; readonly lines: number };

export type TLogSource =
  | { readonly kind: "journal" }
  | { readonly kind: "files"; readonly paths: readonly string[] }
  | { readonly kind: "missing"; readonly paths: readonly string[] };

/**
 * Parse `logs` args: `-f`/`--follow`, and `-n N` / `--lines N` / `-n10` for the
 * initial line count. Returns null on a malformed/unknown token so the caller
 * prints usage and exits non-zero. Pure — unit-testable without spawning.
 */
export const parseLogsArgs = (args: readonly string[]): TLogsOpts | null => {
  let follow = false;
  let lines = DEFAULT_LOG_LINES;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-f" || a === "--follow") {
      follow = true;
      continue;
    }
    let raw: string | undefined;
    if (a === "-n" || a === "--lines") {
      raw = args[++i];
    } else if (a.startsWith("-n")) {
      raw = a.slice(2);
    } else {
      return null;
    }
    if (raw === undefined) return null;
    const n = Number.parseInt(raw, 10);
    if (!Number.isInteger(n) || n < 0 || String(n) !== raw.trim()) return null;
    lines = n;
  }
  return { follow, lines };
};

/** Resolve the concrete log source without spawning, for tests and diagnostics. */
export const resolveLogSource = (
  platform: NodeJS.Platform,
  journalIsAvailable: boolean,
  exists: (path: string) => boolean = existsSync,
): TLogSource => {
  if (platform !== "darwin" && journalIsAvailable) return { kind: "journal" };
  // stdout/stderr are the supervisor-owned logs. The structured app log remains
  // a useful fallback for foreground/from-source runs that have not created them.
  const candidates = [
    daemonStdoutLogFilePath(),
    daemonStderrLogFilePath(),
    logFilePath(),
  ];
  const paths = candidates.filter(exists);
  return paths.length > 0
    ? { kind: "files", paths }
    : { kind: "missing", paths: candidates };
};

/** journalctl present AND the unit known to the user manager (exit 0). */
const journalAvailable = (): boolean => {
  try {
    const unitRegistered =
      spawnSync(
        "systemctl",
        ["--user", "show", "--property", "LoadState", UNIT],
        {
          stdio: "ignore",
        },
      ).status === 0;
    if (!unitRegistered) return false;
    return (
      spawnSync("journalctl", ["--user", "--unit", UNIT, "-n", "0"], {
        stdio: "ignore",
      }).status === 0
    );
  } catch {
    return false;
  }
};

const tailFiles = (opts: TLogsOpts, paths: readonly string[]): number => {
  const args = ["-n", String(opts.lines)];
  if (opts.follow) args.push("-F");
  args.push(...paths);
  return spawnSync("tail", args, { stdio: "inherit" }).status ?? 0;
};

const tailJournal = (opts: TLogsOpts): number => {
  const args = ["--user", "--unit", UNIT, "-n", String(opts.lines)];
  if (opts.follow) args.push("-f");
  return spawnSync("journalctl", args, { stdio: "inherit" }).status ?? 0;
};

/** Read the tail of locally available daemon log files for non-interactive diagnostics. */
export const readRecentLogLines = (maxLines = 300): readonly string[] => {
  const source = resolveLogSource(process.platform, false);
  if (source.kind !== "files") return [];
  const output = spawnSync("tail", ["-n", String(maxLines), ...source.paths], {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return typeof output.stdout === "string"
    ? output.stdout.split("\n").filter((line) => line.length > 0)
    : [];
};

/** Run the `logs` subcommand. `args` is everything after `logs`. Exits. */
export const runLogs = (args: readonly string[]): never => {
  const opts = parseLogsArgs(args);
  if (opts === null) {
    process.stderr.write("usage: openllmd logs [-f] [-n N]\n");
    process.exit(2);
  }
  const source = resolveLogSource(process.platform, journalAvailable());
  if (source.kind === "missing") {
    process.stderr.write(
      `no daemon logs found; looked in:\n${source.paths.map((path) => `  ${path}`).join("\n")}\n`,
    );
    process.exit(1);
  }
  const code =
    source.kind === "journal"
      ? tailJournal(opts)
      : tailFiles(opts, source.paths);
  process.exit(code);
};
