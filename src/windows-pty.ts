import * as nativePtyModule from "./native-pty";
import type { TPtyLike, TPtySpawnArgs } from "./session-core";

export { WINDOWS_PTY_KILL_GRACE_MS } from "./bs-pty";

/**
 * Phase 3: the Windows PTY entry is IMPLEMENTED — in-process ConPTY through
 * the same native PTY binding the POSIX backend uses (packages/pty-native
 * compiles pty-win.c on win32 against the frozen PTY_SYMBOLS ABI; the loader
 * selected the source at build time). session-core routes win32 here; the
 * spawn delegates to NativePty behind the unchanged `TPtySpawnArgs` seam and
 * returns the same `TPtyLike` result.
 *
 * TS-side ConPTY semantics preserved from the retired C# sidecar wrapper:
 *   - `WINDOWS_PTY_KILL_GRACE_MS` (250 ms): SIGTERM reaches the root child
 *     first, then SIGKILL escalation after the grace window — native-pty's
 *     TERM→KILL escalation consumes this same constant on win32 (one
 *     definition in bs-pty.ts, re-exported here as the stable contract);
 *   - argv[0] and cwd pass through to the shim, which validates the
 *     Windows-absolute rule (drive-letter or UNC) and rejects anything else
 *     with EINVAL — no POSIX path rule leaks into the spawn;
 *   - the retired sidecar executable is never consulted and Bun.Terminal is
 *     never used — a sidecar-route regression stays a test failure (G3).
 */
export const windowsPtySpawner = (args: TPtySpawnArgs): Promise<TPtyLike> =>
  nativePtyModule.nativePtySpawner(args);
