export const DEFAULT_TERMINATE_GRACE_MS = 2_000;

const pause = (ms: number): Promise<void> =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

export const signalGroup = (pgid: number, signal: NodeJS.Signals): boolean => {
  // `kill(-1, sig)` is a broadcast to EVERY signallable process and `kill(0,
  // sig)` targets our OWN group — neither is ever a supervised child, so a
  // bogus pgid must never reach process.kill.
  if (!Number.isInteger(pgid) || pgid <= 1) return false;
  try {
    process.kill(-pgid, signal);
    return true;
  } catch (error) {
    // ESRCH: the group is already gone. EPERM: the pgid was recycled to a
    // process we don't own — we must NOT keep signalling it (and cannot). Both
    // mean "stop", never a throw that would crash the reaper.
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ESRCH" || code === "EPERM") return false;
    throw error;
  }
};

export const terminateProcessGroup = async (
  pgid: number,
  graceMs: number = DEFAULT_TERMINATE_GRACE_MS,
  isStillOwned?: () => boolean,
): Promise<void> => {
  if (!signalGroup(pgid, "SIGTERM")) return;
  await pause(Math.max(0, graceMs));
  if (isStillOwned !== undefined && !isStillOwned()) return;
  signalGroup(pgid, "SIGKILL");
};
