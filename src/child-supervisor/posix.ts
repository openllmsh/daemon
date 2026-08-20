export const DEFAULT_TERMINATE_GRACE_MS = 2_000;

const pause = (ms: number): Promise<void> =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * `kill(-pgid)` errno that means "this is not a group we can (or should)
 * signal". ESRCH: gone. EPERM: the pgid was recycled to a process we don't
 * own (macOS also surfaces this on a just-SIGKILL'd detached group while the
 * zombie is unreaped). Neither is a throw.
 */
export const isUnsignallableProcessGroup = (error: unknown): boolean => {
  const code =
    error instanceof Error && "code" in error
      ? (error as NodeJS.ErrnoException).code
      : undefined;
  return code === "ESRCH" || code === "EPERM";
};

const assertSafePgid = (pgid: number): boolean =>
  Number.isInteger(pgid) && pgid > 1;

export const signalGroup = (
  pgid: number,
  signal: NodeJS.Signals | 0,
): boolean => {
  // `kill(-1, sig)` is a broadcast to EVERY signallable process and `kill(0,
  // sig)` targets our OWN group — neither is ever a supervised child, so a
  // bogus pgid must never reach process.kill.
  if (!assertSafePgid(pgid)) return false;
  try {
    process.kill(-pgid, signal);
    return true;
  } catch (error) {
    if (isUnsignallableProcessGroup(error)) return false;
    throw error;
  }
};

/** Existence probe: `kill(-pgid, 0)`. Same ESRCH/EPERM contract as signalGroup. */
export const processGroupExists = (pgid: number): boolean =>
  signalGroup(pgid, 0);

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
