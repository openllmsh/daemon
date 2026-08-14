import { existsSync } from "node:fs";
import { join } from "node:path";
import { isDevMode, stateDir } from "../env";

/**
 * Dev/prod-aware prefix for re-execing THIS daemon's own entrypoint. Mirrors the
 * durable session-host `daemonBinary()` logic so a supervised wrapper runs the
 * SAME code (and, in dev, the source runner under `bun --watch src/main.ts`)
 * rather than a possibly protocol-skewed installed binary. Paired with
 * `userArgs()` (`process.argv.slice(2)`): dev returns `[bun, script]`, prod
 * returns `[installed]`, so the subcommand always lands at args[0].
 */
export const daemonSelfInvocation = (): readonly string[] => {
  const sourceRunner = process.argv[1];
  const fallback =
    sourceRunner === undefined
      ? [process.execPath]
      : [process.execPath, sourceRunner];
  if (isDevMode()) return fallback;
  const installed = join(stateDir(), "bin", "openllmd");
  return existsSync(installed) ? [installed] : fallback;
};
