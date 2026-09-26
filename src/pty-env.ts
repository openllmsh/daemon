import { randomUUID } from "node:crypto";

/**
 * Environment allowlist for a PTY child. Credentials, loader variables, and
 * unrelated daemon state are intentionally not inherited by the terminal.
 *
 * v2.8 (F3): the runtime-session variables a POSIX child genuinely needs are
 * forwarded EXPLICITLY — never a wildcard `OPENLLM_*` (that would leak
 * `OPENLLM_API_KEY` and friends into the shell). The fixed base covers the
 * shell/locale/identity vars; the runtime set covers dbus/systemd/XDG/ssh-agent
 * session wiring that a minimal allowlist would silently break on Linux.
 * Windows uses this same function for its ConPTY path.
 */

/** Runtime-session vars forwarded to a PTY child (F3). Explicit, not wildcard. */
export const PTY_RUNTIME_ENV_KEYS = [
  "OPENLLM_DAEMON_STATE_DIR",
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
  "SSH_AUTH_SOCK",
] as const;

export const workerEnv = (
  overrides: Record<string, string>,
  platform: NodeJS.Platform = process.platform,
  inherited: NodeJS.ProcessEnv = process.env,
): Record<string, string> => {
  const normalize = (
    source: Record<string, string | undefined>,
  ): Record<string, string | undefined> =>
    platform === "win32"
      ? Object.fromEntries(
          Object.entries(source).map(([key, value]) => [
            key.toUpperCase(),
            value,
          ]),
        )
      : source;
  const base = normalize(inherited);
  const selected = normalize(overrides);
  const env: Record<string, string> = {};
  for (const key of [
    "PATH",
    "HOME",
    "TMPDIR",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SHELL",
    "USER",
    "LOGNAME",
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
  ]) {
    const name = platform === "win32" ? key.toUpperCase() : key;
    const value = selected[name] ?? base[name];
    if (value !== undefined) env[name] = value;
  }
  // F3: forward the runtime-session vars explicitly (override-before-inherited).
  for (const key of PTY_RUNTIME_ENV_KEYS) {
    const name = platform === "win32" ? key.toUpperCase() : key;
    const value = selected[name] ?? base[name];
    if (value !== undefined) env[name] = value;
  }
  for (const key of ["OPENLLM_DEVICE_SESSION_ID", "OPENLLM_DEVICE_TITLE"]) {
    if (selected[key] !== undefined) env[key] = selected[key] as string;
  }
  return env;
};

/** Launch environment for the native POSIX shim. */
export const nativePtyEnv = (
  overrides: Record<string, string>,
  sessionId = overrides.OPENLLM_DEVICE_SESSION_ID ?? randomUUID(),
): Record<string, string> => ({
  ...workerEnv(overrides),
  TERM: "xterm-256color",
  BS_SESSION: "1",
  BS_SESSION_ID: sessionId,
});
