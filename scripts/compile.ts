#!/usr/bin/env bun

/**
 * Compile the daemon into source-free standalone binaries.
 *
 * `bun build --compile` inlines the transitive workspace imports
 * (@openllmsh/wire, @openllmsh/protocol, effect — NOT @openllm/core; the daemon
 * is coreless) following the symlinks Bun creates for `workspace:*` deps,
 * into a single executable that embeds the Bun runtime. `--minify
 * --bytecode` strips readable identifiers + original source text. No `.ts`
 * source ships. (The binary is runtime-dominated; the coreless win is not
 * shipping the proprietary pipeline + decoupling the daemon's release
 * cadence from `core`, not raw bytes.)
 *
 * Targets: the release list (`DAEMON_RELEASE_TARGETS`) — darwin-{arm64,
 * x64-baseline}, linux-{x64-baseline,arm64}. win32-x64 is off for
 * 2.8.0-beta.1 but remains buildable: `--target(s) win32-x64` on a native
 * Windows host still works.
 * x64 uses the `baseline` (Nehalem) tier — no AVX/AVX2/FMA required, runs on
 * any x86_64 CPU from 2008 onward.
 *
 * Usage:
 *   bun run packages/daemon/scripts/compile.ts            # the release targets
 *   bun run packages/daemon/scripts/compile.ts --host     # current host only
 *   bun run packages/daemon/scripts/compile.ts --targets darwin-arm64,linux-arm64 # explicit subset, in parallel
 *   bun run packages/daemon/scripts/compile.ts --version 1.2.3
 */
import {
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { $ } from "bun";
import type { TDaemonTarget } from "../release-types";
import {
  BUN_TARGET_TO_DAEMON_TARGET,
  DAEMON_COMPILE_TARGET,
  DAEMON_RELEASE_TARGETS,
  DAEMON_TARGETS,
  daemonRawFilename,
} from "../release-types";
import { assertRtcDependency } from "./rtc-dependency";

export { DAEMON_BINARY_SOURCES } from "../release-types";

// Resolve paths from THIS script's location, not the cwd. `scripts/` sits
// directly under the package root in BOTH layouts — the monorepo
// (`packages/daemon/scripts`) and the source-available mirror that subtree-
// splits `packages/daemon` to its own root (`openllmd/scripts`). Deriving the
// package root as the script dir's parent makes `bun run compile` work
// identically from either, instead of assuming a `packages/daemon/` cwd prefix
// that doesn't exist in the flattened mirror.
const PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(PKG_ROOT, "src", "main.ts");
const OUT_DIR = join(PKG_ROOT, "dist");

export const DEFAULT_CLOUD_ORIGIN = "https://www.openllm.sh";

/** Sentinel baked when compile is invoked with no `--version` (`compile:host`,
 *  `dev:dist`). Release + `daemon:dist` always pass a real version. */
export const DEV_VERSION_SENTINEL = "0.0.0-dev";

/**
 * Bun inlines `process.env.NODE_ENV` at compile time from the *compile host*
 * unless `--define` overrides it. CI/dev hosts are `development`, so a
 * published binary without this define ships the development gate as true
 * (doctor-report uploads blocked, localhost CORS open). Release versions
 * therefore bake `"production"`; the `0.0.0-dev` sentinel keeps
 * `"development"` so `dev:dist` / `compile:host` retain the documented
 * local-dev distinction. Runtime `NODE_ENV` cannot override the bake — same
 * as Bun's default inline. Source runs still read the live env.
 */
export const compileNodeEnv = (
  version: string,
): "development" | "production" =>
  version === DEV_VERSION_SENTINEL ? "development" : "production";

/** `--define` tokens shared by `buildOne` and compiled-binary tests. */
export const compileDefineArgs = (
  cloudOrigin: string,
  version: string,
): readonly string[] => [
  "--define",
  `__OPENLLM_CLOUD_ORIGIN_DEFAULT__=${JSON.stringify(cloudOrigin)}`,
  "--define",
  `__OPENLLM_DAEMON_VERSION__=${JSON.stringify(version)}`,
  "--define",
  `process.env.NODE_ENV=${JSON.stringify(compileNodeEnv(version))}`,
];

export const COMPILE_BUN_FLAGS = [
  "--compile",
  "--minify",
  "--sourcemap=none",
  "--bytecode",
] as const;

/** Production host compiler flags/defines shared by the phase gate. */
export const hostCompileArgs = (
  cloudOrigin: string,
  version: string,
): readonly string[] => [
  ...COMPILE_BUN_FLAGS,
  ...compileDefineArgs(cloudOrigin, version),
];

export const HOST_COMPILE_ARGS = hostCompileArgs(
  DEFAULT_CLOUD_ORIGIN,
  DEV_VERSION_SENTINEL,
);

/**
 * Validate the cloud origin BEFORE baking it into every shipped binary via
 * `--define`. An unvalidated value (audit §3 / §4b N1) lets a poisoned build
 * env point every daemon at a rogue origin, and an empty string is silently
 * accepted. So we fail closed:
 *
 * - empty / missing  → the public default (`https://www.openllm.sh`).
 * - the default      → accepted verbatim.
 * - `https://` with a hostname that is `openllm.sh`, a `*.openllm.sh`
 *   subdomain (e.g. `dev.openllm.sh` staging), or an OpenLLM-owned
 *   `openllm-<...>-quantide.vercel.app` preview → accepted (the documented
 *   dev/preview/self-host workflow; `dist.ts` bakes whatever
 *   `OPENLLM_CLOUD_ORIGIN` is set when packaging a self-host build).
 * - `http://` ONLY for `localhost` / `127.0.0.1` (local dev).
 * - anything else (a remote non-allow-listed host, or a non-http(s) scheme) →
 *   THROW, failing the compile.
 *
 * NOTE: this guards the COMPILE-TIME bake only. The runtime still lets the
 * `OPENLLM_CLOUD_ORIGIN` env var win (`packages/daemon/src/env.ts`), so dev /
 * preview daemons are normally re-pointed at runtime, not via the bake.
 */
// OpenLLM's own Vercel preview deployments, anchored to the `openllm` project +
// `quantide` team — the hostname-level twin of `PREVIEW_ORIGIN` in
// `packages/daemon/src/cors.ts` (keep the two in sync). A bare
// `.endsWith(".vercel.app")` would let a poisoned build env bake ANY stranger's
// `*.vercel.app` origin into shipped binaries.
export const OPENLLM_PREVIEW_HOST =
  /^openllm-[a-z0-9-]+-quantide\.vercel\.app$/;

export const isAllowedCloudHost = (host: string): boolean =>
  host === "localhost" ||
  host === "127.0.0.1" ||
  host === "openllm.sh" ||
  host.endsWith(".openllm.sh") ||
  OPENLLM_PREVIEW_HOST.test(host);

const resolveCloudOrigin = (): string => {
  const raw = process.env.OPENLLM_CLOUD_ORIGIN;
  if (raw === undefined || raw.length === 0) return DEFAULT_CLOUD_ORIGIN;
  if (raw === DEFAULT_CLOUD_ORIGIN) return raw;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(
      `OPENLLM_CLOUD_ORIGIN (${raw}) is not a valid URL — refusing to bake it into the daemon binary`,
    );
  }
  const isLoopback =
    url.hostname === "localhost" || url.hostname === "127.0.0.1";
  const schemeOk =
    url.protocol === "https:" || (url.protocol === "http:" && isLoopback);
  if (!schemeOk || !isAllowedCloudHost(url.hostname)) {
    throw new Error(
      `OPENLLM_CLOUD_ORIGIN (${raw}) is not allow-listed — must be https://openllm.sh, ` +
        `a *.openllm.sh subdomain, an openllm-<...>-quantide.vercel.app preview, ` +
        `or http://localhost|127.0.0.1; ` +
        `refusing to bake an unrecognised cloud origin into the daemon binary`,
    );
  }
  return raw;
};

/** Bun `--target` spellings for the DEFAULT (no-args) build, derived from the
 *  release list so the compiler set can never drift from what ships.
 *  `DAEMON_TARGETS` remains the accepted domain for explicit `--target(s)`. */
const TARGETS = DAEMON_RELEASE_TARGETS.map(
  (t) => DAEMON_COMPILE_TARGET[t],
) as readonly string[];

// Accept BOTH the release key (`win32-x64`) and the Bun spelling
// (`bun-windows-x64-baseline`); normalize through the typed mapping.
const isDaemonTarget = (raw: string): raw is TDaemonTarget =>
  DAEMON_TARGETS.some((target) => target === raw);

export const resolveTarget = (raw: string): string | null => {
  if (isDaemonTarget(raw)) return DAEMON_COMPILE_TARGET[raw];
  const key = BUN_TARGET_TO_DAEMON_TARGET[raw];
  return key === undefined ? null : DAEMON_COMPILE_TARGET[key];
};

const invalidCompileTarget = (target: string): Error =>
  new Error(
    `Invalid compile target "${target}" (expected a release key or Bun target)`,
  );

/** Resolve a comma-separated list of release keys to Bun compiler targets. */
export const resolveTargets = (raw: string): readonly string[] => {
  const releaseKeys = raw.split(",").map((target) => target.trim());
  if (releaseKeys.some((target) => target.length === 0)) {
    throw invalidCompileTarget("");
  }
  const resolved = releaseKeys.map((releaseKey) => {
    if (!isDaemonTarget(releaseKey)) throw invalidCompileTarget(releaseKey);
    return DAEMON_COMPILE_TARGET[releaseKey];
  });
  return [...new Set(resolved)];
};

export type TCompileSelection = {
  readonly hostOnly: boolean;
  readonly resolvedTarget: string | null;
  readonly targetSubset: readonly string[] | null;
};

/** Parse compile target modes while keeping all parallel builds on one path. */
export const resolveCompileSelection = (
  args: readonly string[],
): TCompileSelection => {
  const hostOnly = args.includes("--host");
  const targetIdx = args.indexOf("--target");
  const targetsIdx = args.indexOf("--targets");
  if (targetsIdx >= 0 && (targetIdx >= 0 || hostOnly)) {
    throw new Error("--targets is mutually exclusive with --target and --host");
  }

  const selectedTarget = targetIdx < 0 ? null : (args[targetIdx + 1] ?? "");
  const resolvedTarget =
    selectedTarget === null ? null : resolveTarget(selectedTarget);
  if (selectedTarget !== null && resolvedTarget === null) {
    throw invalidCompileTarget(selectedTarget);
  }

  const targetSubset =
    targetsIdx < 0 ? null : resolveTargets(args[targetsIdx + 1] ?? "");
  return { hostOnly, resolvedTarget, targetSubset };
};

const argv = process.argv.slice(2);
const { hostOnly, resolvedTarget, targetSubset } =
  resolveCompileSelection(argv);
const versionIdx = argv.indexOf("--version");
// The daemon has ONE version identity: the app/manifest tag the release CLI
// passes via `--version` (commands/daemon.ts always passes it). There is no
// separate daemon version number — a source build with no `--version` (e.g.
// `bun run --cwd packages/daemon compile:host`) bakes the `"0.0.0-dev"`
// sentinel, which the runtime's
// dev guards (self-update / sandbox / service registration) key on to skip
// production behaviour. The vestigial `package.json` version was overwritten at
// build and only ever disagreed with the pin, so it is no longer read here.
const version =
  versionIdx >= 0
    ? (argv[versionIdx + 1] ?? DEV_VERSION_SENTINEL)
    : DEV_VERSION_SENTINEL;

const outfileFor = (target: string): string => {
  const key = BUN_TARGET_TO_DAEMON_TARGET[target];
  if (key === undefined)
    throw new Error(`compile target has no release key: ${target}`);
  return `${OUT_DIR}/${daemonRawFilename(key)}`;
};

const buildOne = async (
  target: string | null,
  cloudOrigin: string,
): Promise<string> => {
  const outfile =
    target === null
      ? `${OUT_DIR}/openllmd${process.platform === "win32" ? ".exe" : ""}`
      : outfileFor(target);
  const targetArgs = target === null ? [] : ["--target", target];
  const defines = compileDefineArgs(cloudOrigin, version);
  // Bun 1.3.14 cross-built Windows bytecode crashes before main on the
  // supported Server 2019 baseline host. The same source without it passes,
  // so a Windows target (or a `--host` build on Windows) drops `--bytecode`;
  // every other platform keeps the source-hiding flag.
  const windowsBuild =
    target?.includes("windows") ||
    (target === null && process.platform === "win32");
  const bunFlags =
    windowsBuild || argv.includes("--no-bytecode")
      ? COMPILE_BUN_FLAGS.filter((flag) => flag !== "--bytecode")
      : COMPILE_BUN_FLAGS;
  // Bun's standalone compiler uses process-local intermediate names. Separate
  // both cwd and outfile directories so concurrent targets cannot collide.
  const scratch = mkdtempSync(join(OUT_DIR, ".compile-"));
  const staged = join(scratch, basename(outfile));
  try {
    await $`bun build ${ENTRY} \
      ${bunFlags} \
      ${defines} \
      ${targetArgs} \
      --outfile ${staged}`.cwd(scratch);
    // Emit a gzip sidecar for DISTRIBUTION. The embedded Bun runtime is most of
    // the ~100MB and compresses ~66%, so the published GitHub asset is the `.gz`
    // (faster upload, less org storage). The release pins the sha256 of the
    // DECOMPRESSED binary, and install.sh + self-update decompress before
    // verifying — so the integrity gate is independent of gzip's
    // non-determinism. The raw binary stays for local runs + the sha source.
    writeFileSync(`${staged}.gz`, gzipSync(readFileSync(staged), { level: 9 }));
    renameSync(staged, outfile);
    renameSync(`${staged}.gz`, `${outfile}.gz`);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  return outfile;
};

/**
 * Windows qualification is native-only in Phase 2. `target === null` means
 * the all-target request (the release list — Windows is off for
 * 2.8.0-beta.1, so it passes on POSIX), while an array represents an
 * explicit subset. The `--host` path is checked separately by its host
 * platform.
 */
export const assertNativeWindowsBuild = (
  target: string | readonly string[] | null,
  hostPlatform: NodeJS.Platform = process.platform,
): void => {
  const includesWindowsTarget = (candidate: string): boolean =>
    candidate === "win32-x64" || candidate.includes("windows");
  const includesWindows =
    target === null
      ? DAEMON_RELEASE_TARGETS.some((releaseTarget) =>
          includesWindowsTarget(DAEMON_COMPILE_TARGET[releaseTarget]),
        )
      : typeof target === "string"
        ? includesWindowsTarget(target)
        : target.some(includesWindowsTarget);
  if (includesWindows && hostPlatform !== "win32") {
    throw new Error(
      "win32-x64 must be built on a native Windows host (Phase 2 build route); " +
        `refusing to cross-compile from ${hostPlatform}`,
    );
  }
};

const main = async (): Promise<void> => {
  assertRtcDependency();
  // Resolve (+ validate) the bake origin lazily inside main so importing this
  // module (e.g. from a unit test of `isAllowedCloudHost`) has no side effects.
  const cloudOrigin = resolveCloudOrigin();
  // A Windows target must be built ON Windows (native build + execution is the
  // qualification route). This check runs before creating output directories
  // or entering any compiler task, including the all-target request.
  const buildTargets = targetSubset ?? TARGETS;
  const guardTarget = hostOnly ? "host" : (resolvedTarget ?? targetSubset);
  assertNativeWindowsBuild(guardTarget, process.platform);
  await $`mkdir -p ${OUT_DIR}`;
  if (resolvedTarget) {
    console.log(
      `built ${resolvedTarget} → ${await buildOne(resolvedTarget, cloudOrigin)}`,
    );
    return;
  }
  if (hostOnly) {
    const out = await buildOne(null, cloudOrigin);
    console.log(`built host binary → ${out}`);
    return;
  }
  // Every parallel compiler has private intermediates. Wait for all cleanup
  // before reporting an error so a failed build leaves no active writers.
  const t0 = Date.now();
  const builds = await Promise.allSettled(
    buildTargets.map(async (target) => {
      const out = await buildOne(target, cloudOrigin);
      console.log(`built ${target} → ${out}`);
    }),
  );
  const failed = builds.find((build) => build.status === "rejected");
  if (failed?.status === "rejected") throw failed.reason;
  console.log(
    `compiled ${buildTargets.length} targets in ${Date.now() - t0}ms`,
  );
};

// Only run the build when executed directly (`bun compile.ts`), not when
// imported by a test. Keeps the module import-safe for unit testing the pure
// host allow-list above.
if (import.meta.main) {
  await main();
}
