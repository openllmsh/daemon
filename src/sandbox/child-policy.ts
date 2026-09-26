import { existsSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { CLI_PROVIDERS } from "../cli-paths";
import { stateDir } from "../env";
import { nodeSpawnSync as spawnSync } from "../windows-process";
import {
  daemonTempDir,
  daemonWorkingSet,
  type TWorkingSet,
} from "./working-set";

const canonical = (p: string): string => {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
};
const beneath = (p: string, root: string): boolean =>
  p === root || p.startsWith(`${root}/`);

const xcodeSelectEnvironment = (): NodeJS.ProcessEnv => {
  const env: NodeJS.ProcessEnv = { ...process.env, PATH: "/usr/bin:/bin" };
  for (const name of Object.keys(env)) if (name !== "PATH") delete env[name];
  return env;
};

/** Daemon authority is never a grant to a vendor child. Include aliases so
 * relocated state cannot fall through macOS's outside-home runtime allow. */
export const childProtectedPaths = (home?: string): string[] => {
  const state = stateDir(home);
  const explicit = process.env.OPENLLM_DAEMON_ENV_FILE;
  const paths = [
    state,
    ...(explicit && isAbsolute(explicit) ? [explicit] : []),
  ];
  return [...new Set(paths.flatMap((p) => [resolve(p), canonical(p)]))];
};

/** Only the current provider's isolated HOME selects its private root. A
 * symlink at any level fails closed instead of granting its external target. */
export const childWorkingSet = (home?: string): TWorkingSet => {
  const ws = daemonWorkingSet(home),
    protectedPaths = childProtectedPaths(home);
  const state = canonical(stateDir(home));
  const overlaps = (p: string): boolean =>
    [resolve(p), canonical(p)].some((a) =>
      protectedPaths.some((b) => beneath(a, b) || beneath(b, a)),
    );
  const broadRuntime = new Set(["/proc", "/run", "/var"]);
  const readOnly = ws.readOnly.filter(
    (p) => !broadRuntime.has(p) && !overlaps(p),
  );
  const runtime =
    process.platform === "darwin"
      ? [
          "/System",
          "/Library/Apple",
          "/Library/Developer",
          "/Library/Frameworks",
          "/private/etc",
          "/private/var/select",
          "/var/select",
        ]
      : ["/run/systemd/resolve", "/run/resolvconf"];
  readOnly.push(...runtime.filter((p) => existsSync(p) && !overlaps(p)));
  if (process.platform === "darwin") {
    // Read the administrator-selected toolchain, ignoring a caller's
    // DEVELOPER_DIR override. Grant this root-owned directory read-only.
    const selected = spawnSync("/usr/bin/xcode-select", ["-p"], {
      env: xcodeSelectEnvironment(),
      encoding: "utf8",
      timeout: 3000,
    });
    const developer = selected.status === 0 ? selected.stdout.trim() : "";
    if (
      isAbsolute(developer) &&
      existsSync(developer) &&
      !overlaps(developer) &&
      canonical(developer) !== "/" &&
      statSync(developer).uid === 0
    ) {
      readOnly.push(developer, canonical(developer));
      if (developer.endsWith(".app/Contents/Developer")) {
        for (const name of [
          "Info.plist",
          "version.plist",
          "SharedFrameworks",
          "Frameworks",
        ]) {
          const support = join(dirname(developer), name);
          if (existsSync(support) && !overlaps(support))
            readOnly.push(support, canonical(support));
        }
      }
    }
    if (existsSync("/private/var/db/xcode_select_link"))
      readOnly.push(
        "/private/var/db/xcode_select_link",
        "/var/db/xcode_select_link",
      );
  }
  const readWrite = ws.readWrite.filter(
    (p) =>
      canonical(p) !== canonical(dirname(process.execPath)) && !overlaps(p),
  );
  // The runtime image itself is readable, never its containing directory.
  readOnly.push(process.execPath);
  const scratch = daemonTempDir(home);
  if (canonical(scratch) !== join(state, "tmp"))
    throw new Error("Aliased child scratch rejected");
  readWrite.push(scratch);
  const selectedHome = process.env.HOME;
  for (const provider of CLI_PROVIDERS) {
    const root = join(state, "cli", provider),
      expected = join(root, "home");
    if (
      selectedHome !== expected &&
      selectedHome !== join(stateDir(home), "cli", provider, "home")
    )
      continue;
    if (
      !existsSync(expected) ||
      canonical(root) !== root ||
      canonical(expected) !== expected
    )
      throw new Error("Aliased provider home rejected");
    readWrite.push(root);
  }
  return {
    readOnly: [...new Set(readOnly)],
    readWrite: [...new Set(readWrite)],
  };
};

/** Consume daemon routing in the shim, then remove its authority before the
 * final exec. A vendor gateway retains its own vendor-specific environment. */
export const childEnvironment = (env: NodeJS.ProcessEnv): NodeJS.ProcessEnv => {
  const child = { ...env };
  for (const name of Object.keys(child)) {
    if (/^(?:OPENLLM_|PRIVATE_PLANE_|RELAY_|DEVICE_GRANT_)/i.test(name))
      delete child[name];
  }
  return child;
};
