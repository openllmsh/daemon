export { workerEnv } from "./pty-env";
export type { TPtySpawnArgs } from "./session-core";

/** Production PTY backends. `bun` remains only as the fake-test label. */
export type TPtyBackend = "native" | "conpty" | "bun";

export class UnsupportedPtyBackendError extends Error {
  readonly requested: string;

  constructor(requested: string, platform: NodeJS.Platform = process.platform) {
    super(
      platform === "win32" && requested === "native"
        ? "POSIX native PTY backend is unsupported on Windows"
        : `unsupported PTY backend: ${requested}`,
    );
    this.name = "UnsupportedPtyBackendError";
    this.requested = requested;
  }
}

/**
 * The pinned TS-side ConPTY kill contract, ported from the retired C# sidecar
 * wrapper: SIGTERM reaches the root child first and SIGKILL escalation follows
 * after this grace window. Single definition — native-pty.ts consumes it for
 * the win32 TERM→KILL escalation and windows-pty.ts re-exports it as the
 * stable contract surface.
 */
export const WINDOWS_PTY_KILL_GRACE_MS = 250;

/**
 * Stable Phase 2 Windows qualification marker. The G3 fail-closed gate
 * (scripts/assert-pty-fail-closed.ts) pins the marker string so the Phase 2
 * `unavailable-until-phase3` evidence label can never silently return: the
 * Phase 3 in-process ConPTY spawner (windows-pty.ts → native-pty.ts)
 * replaced the explicit rejection — nothing throws the retired unavailable
 * error anymore (the error class is deleted; ptySupported() flipped to true
 * on the P3-3 win11 guest smoke).
 */
export const WINDOWS_PTY_UNAVAILABLE =
  "PTY is unavailable on Windows in this build (unavailable-until-phase3)";

/**
 * Resolve the production backend selector without an alternative backend.
 * POSIX accepts only "" / "auto" / "native" and defaults to the compiled C
 * shim; Windows accepts only "" / "auto" / "conpty" and resolves to the
 * in-process ConPTY route (live since Phase 3 — the win11 guest smoke
 * verified spawn/echo/write/resize/SIGTERM-grace end-to-end). Every explicit
 * legacy or unknown value fails closed with UnsupportedPtyBackendError.
 */
export const requestedPtyBackend = (): TPtyBackend => {
  const raw = process.env.OPENLLM_PTY_BACKEND?.trim().toLowerCase() ?? "";
  if (process.platform === "win32") {
    if (raw === "" || raw === "auto" || raw === "conpty") return "conpty";
    throw new UnsupportedPtyBackendError(raw);
  }
  if (raw === "" || raw === "auto" || raw === "native") return "native";
  throw new UnsupportedPtyBackendError(raw);
};

/**
 * PTY support for this host. POSIX: the native shim is compiled in, so support
 * is always true (compile/load failure is a fail-closed spawn error, not a
 * support flag). Windows: TRUE since Phase 3 — the in-process ConPTY shim
 * (pty-win.c) passed the guest smoke on the win11 VM (build 28000):
 * spawn/echo/write/resize/SIGTERM-grace all green (mission evidence:
 * phase3-conpty). A compile/load failure stays a fail-closed spawn error.
 */
export const ptySupported = (): boolean => true;
