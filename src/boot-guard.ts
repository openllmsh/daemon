/**
 * Crash-loop circuit breaker — the cross-platform half of the "cap on retry"
 * (the systemd native start-limit in `service.ts` is the Linux backstop;
 * launchd has no equivalent, so this is the only ceiling on macOS).
 *
 * The supervisor relaunches the daemon on EVERY exit (systemd `Restart=always`,
 * launchd `KeepAlive`). A persistent boot failure — port permanently in use, a
 * corrupt binary, a config the daemon rejects at startup — therefore respawns
 * forever: each boot re-runs the sandbox/FFI setup and writes log lines, so the
 * loop floods `openllmd.log` and pegs the CPU with nothing to show for it.
 *
 * `guardCrashLoop()` records each boot's timestamp in `state.json` and, if
 * too many boots land inside a short window, declares a crash loop: it disables
 * self-restore (so the supervisor stops relaunching) and exits cleanly. Recover
 * by fixing the cause and running `openllmd restart`. The decision is a pure
 * function (`shouldPark`) so the threshold is unit-testable without a real boot.
 *
 * Best-effort + never throws on its OWN I/O (mirrors `logger.ts`): if the
 * boot history can't be read/written the guard simply can't fire — the daemon
 * boots anyway and, on Linux, systemd's start-limit still bounds the churn.
 */
import { logError } from "./logger";
import { serviceStop } from "./service";
import { readBootHistory, writeBootHistory } from "./state-file";

/** How far back a boot counts toward the crash-loop tally. */
export const CRASH_WINDOW_MS = 3 * 60 * 1000;
/** Boots within {@link CRASH_WINDOW_MS} that trip the breaker. ~10 boots in 3
 *  min ≈ one every 18s — well past any legitimate restart cadence (self-update
 *  is rare; the supervisor's backoff stretches a real crash loop to roughly this
 *  rate), but reached quickly once a boot fails persistently. */
export const CRASH_LIMIT = 10;

/**
 * Pure crash-loop decision. Appends `now` to the prior boot timestamps, drops
 * any that fell out of the window, and reports whether the surviving count has
 * reached the limit. Returns the trimmed list so the caller persists a bounded
 * history (it never grows without bound).
 */
export const shouldPark = (
  bootTimestamps: readonly number[],
  now: number,
): { recent: number[]; park: boolean } => {
  // `t <= now` drops future-dated entries: a clock rollback (or a corrupt
  // history) would otherwise make `now - t` negative — counted as in-window —
  // and could falsely park the daemon.
  const recent = [...bootTimestamps, now].filter(
    (t) => t <= now && now - t < CRASH_WINDOW_MS,
  );
  return { recent, park: recent.length >= CRASH_LIMIT };
};

/**
 * Record this boot and, if we've crash-looped, disable self-restore + exit so
 * the supervisor stops relaunching us. Call ONCE at the very start of boot,
 * before the sandbox + listener. Either returns (boot proceeds) or exits the
 * process (loop broken). As the first `state.json` reader each boot, this is
 * also what triggers the one-shot legacy-file migration (`state-file.ts`).
 */
export const guardCrashLoop = (): void => {
  const now = Date.now();
  const { recent, park } = shouldPark(readBootHistory(), now);
  writeBootHistory(recent);
  if (!park) return;
  logError(
    "boot-guard",
    `crash loop detected — ${recent.length} restarts within ${Math.round(
      CRASH_WINDOW_MS / 1000,
    )}s. Disabling self-restore so it stops thrashing; fix the cause (see the error above) then run \`openllmd restart\`.`,
  );
  try {
    // Disable self-restore (launchctl disable+bootout / systemctl --user
    // disable --now) so the supervisor won't relaunch after we exit.
    serviceStop();
  } catch {
    // best-effort — even if disabling fails, exiting still clears this churn.
  }
  // Clear the window so the eventual `openllmd restart` starts from a clean
  // slate rather than re-tripping the guard on its first boot.
  writeBootHistory([]);
  process.exit(0);
};

/**
 * Clears crash-loop history after the daemon reaches a confirmed healthy boot.
 * Keeps transient failures from converting into a sticky parked state.
 */
export const markHealthyBoot = (): void => {
  try {
    writeBootHistory([]);
  } catch {
    // best-effort + never throws
  }
};
