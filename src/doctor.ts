/** Best-effort, secret-safe diagnostics for `openllmd doctor`. */
import { autoUpdateEnabled } from "./auto-update-pref";
import {
  childProcessMatchesRecord,
  listChildRegistryRecords,
} from "./child-supervisor/registry";
import { getCloudState } from "./config";
import { daemonPort, isDevMode, stateDir } from "./env";
import { readRecentLogLines } from "./logs";
import { supervisorPid, supervisorState } from "./service";
import { computeStatus } from "./status";
import { DAEMON_VERSION } from "./version";

export type TDoctorProcess = {
  readonly pid: number;
  readonly ppid: number;
  readonly rssKiB: number;
  readonly command: string;
};

const safe = async <T>(read: () => Promise<T>, fallback: T): Promise<T> => {
  try {
    return await read();
  } catch {
    return fallback;
  }
};

/** Parse the portable subset emitted by `ps -axo pid=,ppid=,rss=,command=`. */
export const parseProcessSnapshot = (
  output: string,
): readonly TDoctorProcess[] =>
  output
    .split("\n")
    .map((line) => line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/))
    .flatMap((match) => {
      if (match === null) return [];
      return [
        {
          pid: Number.parseInt(match[1], 10),
          ppid: Number.parseInt(match[2], 10),
          rssKiB: Number.parseInt(match[3], 10),
          command: match[4],
        },
      ];
    });

const processSnapshot = (): readonly TDoctorProcess[] => {
  try {
    const output = Bun.spawnSync(["ps", "-axo", "pid=,ppid=,rss=,command="], {
      stdout: "pipe",
      stderr: "ignore",
    });
    if (output.exitCode !== 0) return [];
    return parseProcessSnapshot(new TextDecoder().decode(output.stdout));
  } catch {
    return [];
  }
};

const redact = (value: string): string =>
  value
    .replace(/sk-llm-[A-Za-z0-9._-]+/g, "sk-llm-[REDACTED]")
    // Vendor key prefixes (Anthropic sk-ant-, OpenAI sk-proj-, OpenRouter
    // sk-or-, GitHub tokens) — doctor output is copyable, so a leaked isolated
    // credential in a log line or status detail must never survive.
    .replace(
      /\b(sk-(?:ant|proj|or)|ghp|gho|github_pat)[-_][A-Za-z0-9._-]+/g,
      "$1-[REDACTED]",
    )
    // Compact JWTs (access/refresh tokens often embed one).
    .replace(/\beyJ[A-Za-z0-9._-]{20,}/g, "[REDACTED_JWT]")
    // Account email addresses (identity, not a secret, but still PII).
    .replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, "[REDACTED_EMAIL]")
    .replace(/(bearer\s+)[A-Za-z0-9._-]+/gi, "$1[REDACTED]")
    .replace(
      /([?&](?:token|access_token|refresh_token|code)=)[^\s&]+/gi,
      "$1[REDACTED]",
    );

const latestRelayWarnings = (): readonly string[] =>
  readRecentLogLines()
    .filter(
      (line) =>
        line.includes('"scope":"control-channel"') &&
        (line.includes('"level":"warn"') || line.includes('"level":"error"')),
    )
    .slice(-5)
    .map(redact);

const formatProvider = (connection: {
  readonly provider: string;
  readonly cli_installed: boolean;
  readonly cli_version?: string;
  readonly connected: boolean;
  readonly detail?: string;
}): string =>
  `  ${connection.provider}: CLI ${connection.cli_installed ? (connection.cli_version === undefined ? "installed" : `installed (${connection.cli_version})`) : "missing"}; auth ${connection.connected ? "connected" : "not connected"}${connection.detail ? ` (${redact(connection.detail)})` : ""}`;

/** Gather and render a copyable diagnosis. Every external read is best-effort. */
export const runDoctor = async (): Promise<string> => {
  const port = daemonPort();
  const [status, listening] = await Promise.all([
    safe(() => computeStatus(), null),
    safe(async () => {
      const response = await fetch(`http://127.0.0.1:${port}/status`, {
        signal: AbortSignal.timeout(1500),
      });
      return response.ok;
    }, false),
  ]);
  const processes = processSnapshot();
  // `openllmd doctor` runs as a SEPARATE process, so process.pid is the CLI, not
  // the daemon — use the supervisor-reported daemon PID. When none is live,
  // process metrics are rendered unavailable rather than measuring the CLI.
  const daemonPid = ((): number | null => {
    try {
      return supervisorPid();
    } catch {
      return null;
    }
  })();
  const daemon =
    daemonPid === null
      ? undefined
      : processes.find((candidate) => candidate.pid === daemonPid);
  const children =
    daemonPid === null
      ? []
      : processes.filter((candidate) => candidate.ppid === daemonPid);
  const records = listChildRegistryRecords();
  const byKind = new Map<string, number>();
  for (const record of records) {
    byKind.set(record.kind, (byKind.get(record.kind) ?? 0) + 1);
  }
  const stale = records.filter((record) => !childProcessMatchesRecord(record));
  const orphanedProbes = processes.filter(
    (process) =>
      process.ppid === 1 &&
      /(?:--version\b|\bclaude\b|\bcodex\b|\bkimi\b)/i.test(process.command),
  );
  const warnings = latestRelayWarnings();
  const kindSummary =
    [...byKind.entries()]
      .map(([kind, count]) => `${kind}=${count}`)
      .join(", ") || "none";
  const childRssKiB = children.reduce(
    (total, child) => total + child.rssKiB,
    0,
  );
  const supervisor = (() => {
    try {
      return supervisorState();
    } catch {
      return "unavailable";
    }
  })();

  return [
    "OpenLLM daemon doctor",
    "",
    "Daemon",
    `  version: ${DAEMON_VERSION}`,
    `  listening: ${listening ? `yes (127.0.0.1:${port})` : `no (127.0.0.1:${port})`}`,
    `  service supervisor: ${supervisor}`,
    `  cloud state: ${status?.cloud_state ?? getCloudState()}`,
    "",
    "Child supervisor",
    `  tracked disposable children: ${records.length} (${kindSummary})`,
    `  stale registry records: ${stale.length}`,
    `  orphaned vendor/version probes (ppid=1): ${orphanedProbes.length}`,
    "",
    "Processes",
    `  daemon RSS: ${daemon === undefined ? "unavailable" : `${daemon.rssKiB} KiB`}`,
    `  direct children: ${daemonPid === null ? "unavailable" : `${children.length}; total RSS: ${childRssKiB} KiB`}`,
    "",
    "Relay / control channel",
    `  connected: ${status?.cloud_state === "ok" && listening ? "likely" : "not confirmed"}`,
    ...(warnings.length === 0
      ? ["  recent warnings: none found"]
      : ["  recent warnings:", ...warnings.map((warning) => `    ${warning}`)]),
    "",
    "Vendor CLI health",
    ...(status === null
      ? ["  unavailable (daemon status probe failed)"]
      : status.connections.map(formatProvider)),
    "",
    "Environment",
    `  OS/arch: ${process.platform}/${process.arch}`,
    `  runtime: Bun ${Bun.version}`,
    `  state dir: ${stateDir()}`,
    `  auto-update: ${autoUpdateEnabled() ? "on" : "off"}`,
    `  mode: ${isDevMode() ? "dev" : "production"}`,
    "",
  ].join("\n");
};
