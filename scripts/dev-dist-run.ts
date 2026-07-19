#!/usr/bin/env bun

/**
 * Build + run the daemon as the COMPILED, OS-SANDBOXED dev binary. Spawned
 * by the dev orchestrator (`scripts/dev.ts --dist`, i.e. `bun run dev:dist`)
 * in place of the source-watch daemon — so you exercise the real
 * `bun --compile` runtime with Landlock/Seatbelt actually enforced, while
 * `bun run dev` keeps the unsandboxed 8787 daemon for iteration.
 *
 * Steps:
 *   1. `compile.ts --host` → a `0.0.0-dev` host binary, baking the dev
 *      cloud origin (OPENLLM_CLOUD_ORIGIN, default http://127.0.0.1:3000).
 *   2. exec the binary bare (→ `main()`, not `openllmd start` which refuses
 *      a dev build) with:
 *        OPENLLM_DAEMON_DEV=1     → port 8788 + ~/.openllm/.dev.env
 *        OPENLLM_DAEMON_SANDBOX=1 → opt the OS sandbox on for the dev build
 *
 * Restarting the `daemon` process in the dev footer re-runs this (rebuild
 * + relaunch). Standalone: `bun packages/daemon/scripts/dev-dist-run.ts`.
 */

import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(SCRIPT_DIR, "..");
const BINARY = join(PKG_ROOT, "dist", "openllmd");
const COMPILE = join(SCRIPT_DIR, "compile.ts");

const cloudOrigin = process.env.OPENLLM_CLOUD_ORIGIN ?? "http://127.0.0.1:3000";

console.log("[dev:dist] building compiled host daemon…");
const build = spawnSync("bun", [COMPILE, "--host"], {
  stdio: "inherit",
  env: { ...process.env, OPENLLM_CLOUD_ORIGIN: cloudOrigin },
});
if (build.status !== 0) process.exit(build.status ?? 1);
if (!existsSync(BINARY)) {
  console.error(`[dev:dist] no binary at ${BINARY}`);
  process.exit(1);
}

console.log("[dev:dist] launching sandboxed dev daemon on :8788…");
const child = spawn(BINARY, [], {
  stdio: "inherit",
  env: {
    ...process.env,
    OPENLLM_DAEMON_DEV: "1",
    OPENLLM_DAEMON_SANDBOX: "1",
  },
});
// Forward termination so the orchestrator's SIGTERM (restart / quit) reaches
// the binary, not just this wrapper.
const forward = (sig: NodeJS.Signals): void => {
  if (!child.killed) child.kill(sig);
};
process.on("SIGTERM", () => forward("SIGTERM"));
process.on("SIGINT", () => forward("SIGINT"));
child.on("exit", (code) => process.exit(code ?? 0));
