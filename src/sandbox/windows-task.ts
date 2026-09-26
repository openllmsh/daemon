import { join } from "node:path";
import { spawn } from "../windows-process";
import {
  applyWindowsAclPlan,
  cleanupWindowsAclTask,
  queryWindowsOwnerSid,
  sweepStaleWindowsTaskRoots,
} from "./windows-acl";
import {
  APPCONTAINER_BACKEND_RETIRED,
  buildWindowsAclRules,
  defaultWindowsProfileHome,
  resolveWindowsTaskBackend,
  windowsTaskParent,
} from "./windows-policy";

const WINDOWS_TASK_INPUT_LIMIT = 65536;

const validateWindowsTaskInput = (script: Uint8Array): void => {
  if (
    !script.length ||
    script.length > WINDOWS_TASK_INPUT_LIMIT ||
    script.some((byte) => byte === 0 || byte > 127)
  ) {
    throw new Error("windows-cmd-v1 requires nonempty ASCII command input");
  }
};

const readTaskScript = async (): Promise<Buffer> => {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of Bun.stdin.stream()) {
    size += chunk.length;
    if (size > WINDOWS_TASK_INPUT_LIMIT)
      throw new Error("Task input exceeds 64 KiB");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};

const runWindowsAclTask = async (script: Buffer): Promise<number> => {
  const profileHome = defaultWindowsProfileHome();
  const ownerSid = queryWindowsOwnerSid();
  const recovered = sweepStaleWindowsTaskRoots(windowsTaskParent(), ownerSid);
  if (recovered.length > 0) {
    process.stderr.write(
      `openllmd confined-task: ${JSON.stringify({ t: "recovered_roots", roots: recovered })}\n`,
    );
  }

  const rules = buildWindowsAclRules(profileHome);
  const aclState = applyWindowsAclPlan(rules, ownerSid);
  const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
  if (!systemRoot) throw new Error("Windows system root unavailable");
  const cmd = join(systemRoot, "System32", "cmd.exe");
  const work = aclState.workDir;
  const temp = join(work, "tmp");
  const local = join(work, "AppData", "Local");
  const roaming = join(work, "AppData", "Roaming");

  process.stderr.write(
    `openllmd confined-task: ${JSON.stringify({
      t: "ready",
      profile: "windows-cmd-v1",
      backend: "acl",
      root: aclState.taskRoot,
      work,
      network: "none",
    })}\n`,
  );

  let exitCode = 78;
  try {
    const proc = spawn([cmd, "/d", "/q", "/c", script.toString("ascii")], {
      cwd: work,
      env: {
        SystemRoot: systemRoot,
        WINDIR: systemRoot,
        PATH: `${join(systemRoot, "System32")};${join(systemRoot, "System32", "WindowsPowerShell", "v1.0")}`,
        COMSPEC: cmd,
        HOME: work,
        USERPROFILE: work,
        APPDATA: roaming,
        LOCALAPPDATA: local,
        TEMP: temp,
        TMP: temp,
        TMPDIR: temp,
      },
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
      windowsHide: true,
    });
    exitCode = (await proc.exited) ?? 78;
  } finally {
    cleanupWindowsAclTask(aclState);
  }
  return exitCode;
};

/**
 * Windows confined-task entry (`windows-cmd-v1`). AppContainer remains retired;
 * the supported backend is ACL file-policy (no sidecar worker).
 */
export async function runWindowsConfinedTask(): Promise<number> {
  if (process.platform !== "win32")
    throw new Error("Windows AppContainer is required");

  const backend = resolveWindowsTaskBackend();
  if (backend === "appcontainer") {
    throw new Error(
      `${APPCONTAINER_BACKEND_RETIRED} (set ${"OPENLLM_WINDOWS_TASK_BACKEND"}=acl)`,
    );
  }

  const script = await readTaskScript();
  validateWindowsTaskInput(script);
  return runWindowsAclTask(script);
}
