/**
 * Daemon version. Injected at compile time by scripts/compile.ts via
 * `--define __OPENLLM_DAEMON_VERSION__`. Declared as a global (not
 * `process.env`) so the bundler substitutes the identifier cleanly;
 * falls back to a dev sentinel when run from source.
 */
declare const __OPENLLM_DAEMON_VERSION__: string | undefined;

const bakedVersion: string = (() => {
  try {
    return typeof __OPENLLM_DAEMON_VERSION__ === "string"
      ? __OPENLLM_DAEMON_VERSION__
      : "0.0.0-dev";
  } catch {
    return "0.0.0-dev";
  }
})();

// A live binding, not a snapshot: `isReleaseBuild` / `isDevMode` read it per
// call, so the test seam below can pose as a release binary without a
// recompile. Compile-time constant in every shipped binary regardless.
export let DAEMON_VERSION: string = bakedVersion;

/** Test seam: pose as a release build (`"2.8.0"`, …) or restore the baked
 *  value with `null`. Callers that cached `DAEMON_VERSION` at module scope
 *  keep their snapshot — only per-call readers see the override. */
export const setDaemonVersionForTest = (version: string | null): void => {
  DAEMON_VERSION = version ?? bakedVersion;
};
