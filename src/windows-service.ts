import { spawnSync as admittedSpawnSync } from "./windows-process";
import { WINDOWS_SERVICE_RUN_FLAG } from "./windows-scm";

const NAME = "OpenLLMD";
// Bun's Windows execFileSync shim can hang before starting PowerShell in a
// compiled daemon. Use Bun's native process API with bounded execution.
const run = (executable: string, args: string[], timeout: number): string => {
  const result = admittedSpawnSync([executable, ...args], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
    timeout,
  });
  if (result.exitCode !== 0)
    throw new Error(`Windows service helper failed (${result.exitCode})`);
  return result.stdout.toString().trim();
};
const ps = (script: string): string =>
  run(
    "powershell.exe",
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ],
    10000,
  );
const sc = (...args: string[]): void => {
  run("sc.exe", args, 15000);
};
const quote = (value: string): string =>
  `"${value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
const literal = (value: string): string => `'${value.replaceAll("'", "''")}'`;
// P4-F: the service runs the daemon binary in-process; binPath must include the
// SCM entry flag so StartServiceCtrlDispatcherW runs before daemon init.
const serviceCommand = (binary: string): string =>
  `${quote(binary)} ${WINDOWS_SERVICE_RUN_FLAG}`;

const parseScmQueryState = (output: string): string => {
  const match = output.match(/STATE\s*:\s*\d+\s+(\S+)/);
  return match?.[1] ?? "unknown";
};

const queryServiceStatus = (): { registered: boolean; state: string } => {
  const query = admittedSpawnSync(["sc.exe", "query", NAME], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
    timeout: 10000,
  });
  const output = `${query.stdout.toString()}${query.stderr.toString()}`;
  if (/FAILED\s+1060/.test(output)) {
    return { registered: false, state: "not registered" };
  }
  if (query.exitCode !== 0) {
    throw new Error(
      "Windows service query unavailable; registration state is unknown",
    );
  }
  return { registered: true, state: parseScmQueryState(output) };
};

/** Strip optional SCM double-quotes around the executable portion; compare paths case-insensitively on Windows. */
const normalizeServicePath = (value: string): string => {
  const trimmed = value.trim();
  if (!trimmed.startsWith('"')) return trimmed;
  const closing = trimmed.indexOf('"', 1);
  if (closing > 0)
    return (trimmed.slice(1, closing) + trimmed.slice(closing + 1)).trim();
  return trimmed.slice(1);
};

const servicePathsEqual = (registered: string, expected: string): boolean =>
  normalizeServicePath(registered).toLowerCase() ===
  normalizeServicePath(expected).toLowerCase();

const requireServiceOwnership = (command: string | undefined): void => {
  if (
    command === undefined ||
    !servicePathsEqual(command, serviceCommand(process.execPath))
  )
    throw new Error("Existing OpenLLMD service has a different executable");
};

export const windowsSupervisor = (): {
  registered: boolean;
  pid: number | null;
  state: string;
  command?: string;
} => {
  const status = queryServiceStatus();
  if (!status.registered) {
    return { registered: false, pid: null, state: status.state };
  }
  try {
    const details = JSON.parse(
      ps(
        `$s=Get-CimInstance Win32_Service -Filter "Name='${NAME}'";$p=$null;if($s.ProcessId -gt 0){$p=Get-CimInstance Win32_Process -Filter ("ProcessId="+$s.ProcessId)|Where-Object {$_.ExecutablePath -eq ${literal(process.execPath)}}|Select-Object -First 1};@{pid=$(if($p){$p.ProcessId}else{$null});command=$s.PathName;startMode=$s.StartMode}|ConvertTo-Json -Compress`,
      ),
    ) as { pid: number | null; command?: string; startMode?: string };
    const startSuffix =
      details.startMode !== undefined ? `; start=${details.startMode}` : "";
    return {
      registered: true,
      pid: details.pid ?? null,
      state: `${status.state}${startSuffix}`,
      command: details.command,
    };
  } catch {
    throw new Error(
      "Windows service query unavailable; registration state is unknown",
    );
  }
};

export const startWindowsService = (binary: string): void => {
  // This host already runs OpenLLM as SYSTEM. Never silently change a user's
  // security identity or request/store a service-account password.
  if (
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value") !==
    "S-1-5-18"
  )
    throw new Error(
      "Windows persistent service registration currently requires the existing SYSTEM identity",
    );
  const command = serviceCommand(binary);
  const prior = windowsSupervisor();
  if (
    prior.registered &&
    prior.command !== undefined &&
    !servicePathsEqual(prior.command, command)
  )
    throw new Error("Existing OpenLLMD service has a different executable");
  if (!prior.registered)
    sc(
      "create",
      NAME,
      "binPath=",
      command,
      "start=",
      "auto",
      "obj=",
      "LocalSystem",
      "DisplayName=",
      "OpenLLM Daemon",
    );
  else sc("config", NAME, "start=", "auto");
  sc(
    "failure",
    NAME,
    "reset=",
    "86400",
    "actions=",
    "restart/10000/restart/30000/restart/60000",
  );
  sc("failureflag", NAME, "1");
  if (!prior.state.toUpperCase().startsWith("RUNNING")) sc("start", NAME);
};

export const stopWindowsService = (): void => {
  const prior = windowsSupervisor();
  if (!prior.registered) return;
  requireServiceOwnership(prior.command);
  sc("config", NAME, "start=", "disabled");
  try {
    if (!prior.state.toUpperCase().startsWith("STOPPED")) sc("stop", NAME);
    const end = Date.now() + 20000;
    while (Date.now() < end) {
      if (windowsSupervisor().state.toUpperCase().startsWith("STOPPED")) return;
      Bun.sleepSync(100);
    }
    throw new Error("Windows service did not stop within its deadline");
  } catch (error) {
    // A failed stop must not silently disable automatic recovery.
    sc(
      "config",
      NAME,
      "start=",
      prior.state.includes("start=Auto")
        ? "auto"
        : prior.state.includes("start=Disabled")
          ? "disabled"
          : "demand",
    );
    throw error;
  }
};
export const uninstallWindowsService = (): string | null => {
  if (!windowsSupervisor().registered) return null;
  stopWindowsService();
  sc("delete", NAME);
  return NAME;
};
