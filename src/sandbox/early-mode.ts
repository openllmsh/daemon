/** Internal modes must finish before daemon modules load. */
const internal = process.argv[1]?.startsWith("--sandbox-")
  ? process.argv[1]
  : process.argv[2];
if (
  process.platform === "linux" &&
  (internal === "--sandbox-helper" || internal === "--sandbox-guardian")
) {
  const { runLinuxInternal } =
    require("./linux-native") as typeof import("./linux-native");
  runLinuxInternal(internal === "--sandbox-guardian");
}
if (process.platform === "linux" && internal === "--sandbox-probe") {
  const { readFileSync, existsSync } =
    require("node:fs") as typeof import("node:fs");
  try {
    const status = readFileSync("/proc/self/status", "utf8");
    const capabilities = status.match(/^Cap\w+:.*$/gm) ?? [];
    const result = {
      sandboxProbe: true,
      pid: process.pid,
      maps: readFileSync("/proc/self/maps", "utf8").length > 0,
      globalProcAbsent: [
        "sys",
        "net",
        "cpuinfo",
        "meminfo",
        "stat",
        "uptime",
        "loadavg",
      ].every((name) => !existsSync(`/proc/${name}`)),
      capabilitiesEmpty:
        capabilities.length === 5 &&
        capabilities.every((line) => /:\s+0+$/.test(line)),
    };
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exit(
      result.pid === 2 &&
        result.maps &&
        result.globalProcAbsent &&
        result.capabilitiesEmpty
        ? 0
        : 1,
    );
  } catch {
    process.exit(1);
  }
}
