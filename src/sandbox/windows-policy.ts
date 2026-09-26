import { homedir } from "node:os";
import { join } from "node:path";
import { stateDir } from "../env";
import { childProtectedPaths, childWorkingSet } from "./child-policy";

/** Windows confined-task backend. AppContainer is retired; ACL is supported. */
export type WindowsTaskBackend = "acl" | "appcontainer";

export const WINDOWS_TASK_BACKEND_ENV = "OPENLLM_WINDOWS_TASK_BACKEND";

export const APPCONTAINER_BACKEND_RETIRED =
  "Windows AppContainer confinement requires the retired v2.8 worker executable; use the acl backend";

/** Resolve the confined-task backend from the environment (default: acl). */
export const resolveWindowsTaskBackend = (
  env: NodeJS.ProcessEnv = process.env,
): WindowsTaskBackend => {
  const raw = env[WINDOWS_TASK_BACKEND_ENV]?.trim().toLowerCase();
  if (raw === undefined || raw === "") return "acl";
  if (raw === "acl") return "acl";
  if (raw === "appcontainer") return "appcontainer";
  throw new Error(
    `Invalid ${WINDOWS_TASK_BACKEND_ENV}=${env[WINDOWS_TASK_BACKEND_ENV]}`,
  );
};

/** Per-task roots live under daemon state — outside AppContainer package dirs. */
export const windowsTaskParent = (home?: string): string =>
  join(stateDir(home), "windows-confined-tasks");

export type WindowsAclRightToken =
  | "(R)"
  | "(W)"
  | "(RX)"
  | "(M)"
  | "(OI)(CI)(M)"
  | "(OI)(CI)(W)"
  | "(OI)(CI)(RX)"
  | "(OI)(CI)(R,W)";

export type WindowsAclRule = {
  readonly path: string;
  readonly effect: "allow" | "deny";
  readonly rights: WindowsAclRightToken;
  readonly inherit: boolean;
  /** Stable label for tests and receipts (policy→ACL mapping). */
  readonly policy: string;
};

const windowsRuntimeWrite = (profileHome: string): string[] => {
  const local = join(profileHome, "AppData", "Local");
  const roaming = join(profileHome, "AppData", "Roaming");
  const temp = process.env.TEMP ?? join(local, "Temp");
  return [...new Set([temp, local, roaming])];
};

/** Credential and authority paths re-denied inside the profile (seatbelt parity). */
export const windowsSecretDenyPaths = (
  profileHome: string,
  daemonHome?: string,
): string[] => {
  const secrets = [
    join(profileHome, ".ssh"),
    join(profileHome, ".aws"),
    join(profileHome, ".gnupg"),
    join(profileHome, ".codex", "auth.json"),
    join(profileHome, ".claude", ".credentials.json"),
    join(profileHome, ".grok", "auth.json"),
    join(profileHome, ".config", "gcloud"),
    join(profileHome, ".config", "gh"),
  ];
  for (const protectedPath of childProtectedPaths(daemonHome)) {
    secrets.push(protectedPath);
  }
  return [...new Set(secrets)];
};

/**
 * Build the ordered ACL plan for windows-cmd-v1 (ACL file-policy backend).
 * Caller supplies the interactive user profile (`%USERPROFILE%`) and optional
 * daemon-home override for working-set resolution (POSIX shim parity).
 */
export const buildWindowsAclRules = (
  profileHome: string,
  daemonHome?: string,
): WindowsAclRule[] => {
  const ws = childWorkingSet(daemonHome);
  const rules: WindowsAclRule[] = [];

  rules.push({
    path: profileHome,
    effect: "deny",
    rights: "(OI)(CI)(W)",
    inherit: true,
    policy: "deny-foreign-writes-under-profile",
  });

  for (const path of windowsRuntimeWrite(profileHome)) {
    rules.push({
      path,
      effect: "allow",
      rights: "(OI)(CI)(M)",
      inherit: true,
      policy: "allow-windows-runtime-write",
    });
  }

  for (const path of ws.readWrite) {
    rules.push({
      path,
      effect: "allow",
      rights: "(OI)(CI)(M)",
      inherit: true,
      policy: "allow-working-set-read-write",
    });
  }

  for (const path of ws.readOnly) {
    rules.push({
      path,
      effect: "allow",
      rights: "(OI)(CI)(RX)",
      inherit: true,
      policy: "allow-working-set-read-only",
    });
  }

  for (const path of windowsSecretDenyPaths(profileHome, daemonHome)) {
    rules.push({
      path,
      effect: "deny",
      rights: "(OI)(CI)(R,W)",
      inherit: true,
      policy: "deny-secret-read-write",
    });
  }

  return rules;
};

/** Default profile home for policy construction on the controller host. */
export const defaultWindowsProfileHome = (): string =>
  process.env.USERPROFILE ?? homedir();
