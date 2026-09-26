import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, win32 as winPath } from "node:path";
import { spawnSync } from "../windows-process";
import type { WindowsAclRule } from "./windows-policy";
import { windowsTaskParent } from "./windows-policy";

export type WindowsAclManifest = {
  readonly v: 1;
  readonly taskId: string;
  readonly ownerSid: string;
  readonly backups: ReadonlyArray<{ path: string; backup: string }>;
};

export type IcaclsResult = { exitCode: number; stderr: string };

export type IcaclsRunner = (args: readonly string[]) => IcaclsResult;

/** Test seam: substitute icacls / PowerShell invocations on non-Windows hosts. */
let icaclsRunnerForTest: IcaclsRunner | undefined;

export const setIcaclsRunnerForTest = (
  runner: IcaclsRunner | undefined,
): void => {
  icaclsRunnerForTest = runner;
};

const icaclsPath = (path: string): string =>
  process.platform === "win32"
    ? winPath.normalize(path.replace(/\//g, "\\"))
    : path;

const defaultIcaclsRunner: IcaclsRunner = (args) => {
  const result = spawnSync(["icacls.exe", ...args], {
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  });
  return {
    exitCode: result.exitCode ?? 1,
    stderr: result.stderr?.toString() ?? "",
  };
};

const runIcacls = (args: readonly string[]): IcaclsResult =>
  (icaclsRunnerForTest ?? defaultIcaclsRunner)(args);

const requireIcacls = (args: readonly string[], context: string): void => {
  const { exitCode, stderr } = runIcacls(args);
  if (exitCode !== 0) {
    throw new Error(
      `Windows ACL ${context} failed (icacls exit ${exitCode}): ${stderr.trim()}`,
    );
  }
};

export const queryWindowsOwnerSid = (): string => {
  if (icaclsRunnerForTest) return "S-1-5-21-test-owner";
  const script =
    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value";
  const result = spawnSync(
    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
    { stdout: "pipe", stderr: "pipe", windowsHide: true },
  );
  const sid = result.stdout?.toString().trim() ?? "";
  if (result.exitCode !== 0 || !/^S-1-[-0-9]+$/.test(sid)) {
    throw new Error("Windows ACL owner SID query failed");
  }
  return sid;
};

const icaclsPrincipal = (ownerSid: string): string => `*${ownerSid}`;

const ruleToIcaclsArgs = (
  rule: WindowsAclRule,
  ownerSid: string,
): readonly string[] => {
  const verb = rule.effect === "allow" ? "/grant:r" : "/deny";
  const principal = `${icaclsPrincipal(ownerSid)}:${rule.rights}`;
  return [icaclsPath(rule.path), verb, principal];
};

export const planIcaclsInvocations = (
  rules: readonly WindowsAclRule[],
  ownerSid: string,
): string[][] => rules.map((rule) => [...ruleToIcaclsArgs(rule, ownerSid)]);

export type AclApplyState = {
  readonly manifestPath: string;
  readonly manifest: WindowsAclManifest;
  readonly taskRoot: string;
  readonly workDir: string;
};

const manifestName = ".acl-manifest.json";

export const newTaskId = (): string =>
  `openllm-task-${randomBytes(16).toString("hex")}`;

/** Best-effort sweep of stale task roots left after a crash (manifest-driven restore). */
export const sweepStaleWindowsTaskRoots = (
  parent: string,
  ownerSid: string,
): string[] => {
  const recovered: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(parent, { withFileTypes: true })
      .filter(
        (entry) =>
          entry.isDirectory() && /^openllm-task-[0-9a-f]{32}$/.test(entry.name),
      )
      .map((entry) => entry.name);
  } catch {
    return recovered;
  }
  for (const name of entries) {
    const taskRoot = join(parent, name);
    const manifestPath = join(taskRoot, manifestName);
    try {
      const manifest = JSON.parse(
        readFileSync(manifestPath, "utf8"),
      ) as WindowsAclManifest;
      if (manifest.v !== 1 || manifest.ownerSid !== ownerSid) continue;
      restoreWindowsAclManifest(manifest);
      rmSync(taskRoot, { recursive: true, force: true });
      recovered.push(taskRoot);
    } catch {
      // Leave unknown / corrupt roots for a later pass — never partial-restore.
    }
  }
  return recovered;
};

export const restoreWindowsAclManifest = (
  manifest: WindowsAclManifest,
): void => {
  for (const entry of [...manifest.backups].reverse()) {
    requireIcacls(
      [icaclsPath(entry.path), "/restore", icaclsPath(entry.backup)],
      `restore ${entry.path}`,
    );
    try {
      rmSync(entry.backup, { force: true });
    } catch {
      /* best-effort */
    }
  }
};

/**
 * Apply the ACL plan fail-closed: any icacls error aborts before returning.
 * Returns manifest + paths for the task runner to clean up.
 */
const rulePathExists = (path: string): boolean => {
  try {
    return existsSync(path);
  } catch {
    return false;
  }
};

const saveAclBackup = (path: string, backup: string): void => {
  const isDir = (() => {
    try {
      return statSync(path).isDirectory();
    } catch {
      return false;
    }
  })();
  const target = icaclsPath(path);
  const backupFile = icaclsPath(backup);
  const args = isDir
    ? [target, "/save", backupFile, "/T", "/C"]
    : [target, "/save", backupFile, "/C"];
  requireIcacls(args, `save ${path}`);
};

/** Rules whose targets exist on disk (or are created as part of task setup). */
export const filterApplicableAclRules = (
  rules: readonly WindowsAclRule[],
  workDir: string,
): WindowsAclRule[] => {
  return rules.filter(
    (rule) => rule.path === workDir || rulePathExists(rule.path),
  );
};

export const applyWindowsAclPlan = (
  rules: readonly WindowsAclRule[],
  ownerSid: string,
  home?: string,
): AclApplyState => {
  const parent = windowsTaskParent(home);
  mkdirSync(parent, { recursive: true });
  const taskId = newTaskId();
  const taskRoot = join(parent, taskId);
  const workDir = join(taskRoot, "work");
  mkdirSync(workDir, { recursive: true });

  const rulesWithWork: WindowsAclRule[] = [
    ...rules,
    {
      path: workDir,
      effect: "allow",
      rights: "(OI)(CI)(M)",
      inherit: true,
      policy: "allow-task-work-dir",
    },
  ];
  const applicable = filterApplicableAclRules(rulesWithWork, workDir);
  const backups: { path: string; backup: string }[] = [];
  const touched = new Set<string>();

  try {
    for (const rule of applicable) {
      if (touched.has(rule.path)) continue;
      touched.add(rule.path);
      const backup = join(taskRoot, `.acl-backup-${backups.length}.bin`);
      saveAclBackup(rule.path, backup);
      backups.push({ path: rule.path, backup });
    }

    for (const args of planIcaclsInvocations(applicable, ownerSid)) {
      requireIcacls(args, `apply ${args[0]}`);
    }
  } catch (error) {
    restoreWindowsAclManifest({ v: 1, taskId, ownerSid, backups });
    rmSync(taskRoot, { recursive: true, force: true });
    throw error;
  }

  const manifest: WindowsAclManifest = {
    v: 1,
    taskId,
    ownerSid,
    backups,
  };
  const manifestPath = join(taskRoot, manifestName);
  writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");

  return { manifestPath, manifest, taskRoot, workDir };
};

export const cleanupWindowsAclTask = (state: AclApplyState): void => {
  try {
    restoreWindowsAclManifest(state.manifest);
  } finally {
    try {
      rmSync(state.taskRoot, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
};
