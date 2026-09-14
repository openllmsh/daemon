import { realpathSync } from "node:fs";

/** Build a Bun.spawn command, accounting for Windows command-script shims. */
export const spawnCommand = (
  platform: NodeJS.Platform,
  target: string,
  args: readonly string[],
): string[] => {
  if (platform !== "win32") return [target, ...args];
  // The isolated vendor run-view may have an extensionless symlink name.
  // Inspect the real launcher before choosing its interpreter.
  try { target = realpathSync(target); } catch { /* spawn reports absence */ }
  if (/\.(cmd|bat)$/i.test(target)) return ["cmd.exe", "/d", "/c", target, ...args];
  if (/\.ps1$/i.test(target)) return ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", target, ...args];
  return [target, ...args];
};
