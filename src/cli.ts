/**
 * `openllmd` command-line dispatch.
 *
 * The same binary is BOTH the long-running daemon (run with no args by the
 * launch agent / systemd unit) AND a small management CLI. `runCli()` handles
 * the management subcommands and returns `true` when one was handled (the
 * caller must NOT boot the server); it returns `false` only for the bare
 * no-arg invocation, which is the server boot path.
 *
 *   openllmd                      run the daemon (used by the service)
 *   openllmd start                register + start in self-restore mode
 *   openllmd stop                 stop + disable self-restore
 *   openllmd status               show service + run status
 *   openllmd restart              stop then start
 *   openllmd logs [-f] [-n N]     show or follow the daemon log
 *   openllmd auto-update <on|off|status>  opt in/out of self-update (default on)
 *   openllmd sessions <on|off|status>  opt in/out of remote terminal sessions (default off)
 *   openllmd uninstall [--yes]    remove the daemon + ALL state (credentials)
 *   openllmd completion <shell>   emit / install shell completion
 *   openllmd -h | --help          show help
 *   openllmd -v | --version       show version
 */
import { isAbsolute } from "node:path";
import { autoUpdateEnabled, setAutoUpdate } from "./auto-update-pref";
import { COMMANDS, FLAGS } from "./commands";
import { runCompletion } from "./completion";
import { logError } from "./logger";
import { runLogs } from "./logs";
import { ptySessionsEnabled, setPtySessions } from "./pty-sessions-pref";
import { runSandboxExec } from "./sandbox/exec";
import {
  serviceRestart,
  serviceStart,
  serviceStatus,
  serviceStop,
} from "./service";
import { runSessionHostProcess } from "./session-host-proc";
import { runUninstall } from "./uninstall";
import { DAEMON_VERSION } from "./version";

const COL = 36;
const row = (left: string, desc: string): string =>
  `  ${left.padEnd(COL)}${desc}`;

// Rendered from the shared command/flag definitions so help and completion
// (completion.ts, same source) can't drift.
const HELP = `openllmd — OpenLLM local daemon (v${DAEMON_VERSION})

Usage:
  openllmd [command]

Commands:
${row("(none)", "Run the daemon in the foreground (used by the service)")}
${COMMANDS.map((c) => row(c.args ? `${c.name} ${c.args}` : c.name, c.description)).join("\n")}

Flags:
${FLAGS.map((f) => row(f.name, f.description)).join("\n")}

State lives under ~/.openllm (override with OPENLLM_DAEMON_STATE_DIR).
`;

/**
 * The daemon's user arguments. Bun keeps the entry path at `argv[1]` in BOTH
 * forms — a from-source run (`bun src/main.ts …` → `argv[1]` is the script) and
 * a compiled standalone binary (`argv[1]` is the embedded `/$bunfs/root/…`
 * entry) — so user args always start at index 2.
 */
const userArgs = (): string[] => process.argv.slice(2);

/**
 * Opt in/out of automatic self-updates (or print the current state), then exit.
 * Auto-update is OPT-OUT — a fresh daemon keeps itself current until disabled
 * here or from the dashboard. See `auto-update-pref.ts`.
 */
const runAutoUpdate = (args: readonly string[]): never => {
  const sub = args[0];
  // Each form takes at most one argument — reject trailing junk
  // (`auto-update on typo`) instead of silently ignoring it.
  if (args.length <= 1) {
    if (sub === "on" || sub === "off") {
      setAutoUpdate(sub === "on");
      process.stdout.write(
        `auto-update ${sub === "on" ? "enabled" : "disabled"}\n`,
      );
      process.exit(0);
    }
    if (sub === undefined || sub === "status") {
      process.stdout.write(
        `auto-update is ${autoUpdateEnabled() ? "on" : "off"}\n`,
      );
      process.exit(0);
    }
  }
  process.stderr.write("usage: openllmd auto-update <on|off|status>\n");
  process.exit(2);
};

/**
 * Opt in/out of remote terminal sessions (or print the current state), then
 * exit. This preference is local-only because a remote PTY is RCE-grade.
 */
const runSessions = (args: readonly string[]): never => {
  const sub = args[0];
  if (args.length <= 1) {
    if (sub === "on" || sub === "off") {
      const persisted = setPtySessions(sub === "on");
      if (!persisted) {
        process.stderr.write(
          "failed to persist the sessions preference to the env file\n",
        );
        process.exit(1);
      }
      process.stdout.write(
        `sessions ${sub === "on" ? "enabled" : "disabled"}\n`,
      );
      process.exit(0);
    }
    if (sub === undefined || sub === "status") {
      process.stdout.write(
        `sessions are ${ptySessionsEnabled() ? "enabled" : "disabled"} (local-only preference; run: openllmd sessions on)\n`,
      );
      process.exit(0);
    }
  }
  process.stderr.write("usage: openllmd sessions <on|off|status>\n");
  process.exit(2);
};

export const runCli = (): boolean => {
  const args = userArgs();
  if (args.length === 0) return false; // bare invocation → boot the server

  // The per-child sandbox shim (`sandbox/exec.ts`): apply the working-set
  // sandbox to THIS re-exec'd process, then run the tail argv. Matched BEFORE
  // the `--help`/`--version` scans — the tail may legitimately contain
  // `-h`/`-v`. Nothing heavy loads on this path (no Effect, no env file, no
  // network).
  if (args[0] === "--sandbox-exec") {
    const sep = args.indexOf("--");
    const tail = sep >= 0 ? args.slice(sep + 1) : [];
    if (tail.length === 0) {
      process.stderr.write("--sandbox-exec: missing command\n");
      process.exit(2);
    }
    // `--home <realHome>` (shim flags live BEFORE the `--`): the daemon's real
    // home, used ONLY to build the working set — most call sites spawn the shim
    // with the child's isolated `HOME`. See `sandbox/exec.ts` `HOME_FLAG`.
    const homeFlag = args.indexOf("--home");
    const homeValue =
      homeFlag >= 0 && (sep < 0 || homeFlag < sep)
        ? args[homeFlag + 1]
        : undefined;
    const home =
      homeValue !== undefined && homeValue !== "--" && isAbsolute(homeValue)
        ? homeValue
        : undefined;
    // apply + spawn + mirror exit. `runSandboxExec` never resolves; guard a
    // REJECTION (an unexpected throw before the exit mirror) so it can't
    // become an unhandled rejection / silent success.
    runSandboxExec(tail, home !== undefined ? { home } : undefined).catch(
      (err: unknown) => {
        process.stderr.write(
          `--sandbox-exec: ${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exit(1);
      },
    );
    return true;
  }

  // Internal durable-session host. Deliberately omitted from COMMANDS/help:
  // phase 1c starts it detached, so it must never bootstrap the daemon. This
  // must precede global flag scans because parser values can legitimately be
  // `-h` or `-v` (for example a title or vendor argument).
  if (args[0] === "__session-host") {
    return runSessionHostProcess(args.slice(1));
  }

  if (args.includes("-h") || args.includes("--help") || args[0] === "help") {
    process.stdout.write(HELP);
    process.exit(0);
  }
  if (
    args.includes("--version") ||
    args.includes("-v") ||
    args[0] === "version"
  ) {
    process.stdout.write(`openllmd v${DAEMON_VERSION}\n`);
    process.exit(0);
  }

  const rest = args.slice(1);
  switch (args[0]) {
    case "start":
      serviceStart();
      process.exit(0);
      break;
    case "stop":
      serviceStop();
      process.exit(0);
      break;
    case "restart":
      serviceRestart();
      process.exit(0);
      break;
    case "status":
      // Async (it probes the running daemon's /status over loopback). Mirror the
      // plugin/setup pattern: the promise process.exit()s when done and
      // returning true prevents the server boot path.
      serviceStatus()
        .then(() => process.exit(0))
        .catch((err) => {
          logError("cli", err);
          process.exit(1);
        });
      return true;
    case "logs":
      runLogs(rest);
      break;
    case "auto-update":
      runAutoUpdate(rest);
      break;
    case "sessions":
      runSessions(rest);
      break;
    case "uninstall":
      runUninstall(rest);
      break;
    case "completion":
      runCompletion(rest);
      break;
    default:
      process.stderr.write(`unknown command: ${args[0]}\n\n${HELP}`);
      process.exit(2);
  }
  return true;
};
