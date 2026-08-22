/**
 * User-caused auth-action tracker (LEAF module).
 *
 * Records when the user intentionally started, completed, or cancelled a login
 * or logout, so the session-lost notifier can suppress a falling edge the user
 * themselves caused (browser login/out churn) instead of treating it as an
 * unprompted drop worth emailing about.
 *
 * Deliberately a LEAF — it imports NOTHING from `./delegation` or
 * `./delegation/login-flow`. `login-flow` records actions here, so if this
 * lived in `auth-session-lost` (which imports `./delegation`) the chain
 * `login-flow -> auth-session-lost -> delegation -> chatgpt -> loginSlot`
 * would put `loginSlot` in the temporal dead zone at module load
 * ("Cannot access 'loginSlot' before initialization").
 */

/** Last time the user intentionally started, completed, or cancelled auth. */
const lastUserAuthActionAt = new Map<string, number>();

/** Record a user-caused authentication action for notifier churn suppression. */
export const noteUserAuthAction = (slug: string, now = Date.now()): void => {
  lastUserAuthActionAt.set(slug, now);
};

/** Whether a user-caused authentication action occurred within `windowMs`. */
export const recentUserAuthAction = (
  slug: string,
  windowMs: number,
  now = Date.now(),
): boolean => {
  const actionAt = lastUserAuthActionAt.get(slug);
  return actionAt !== undefined && now - actionAt <= windowMs;
};

/** Test-only: clear all recorded user actions. */
export const resetUserAuthActionsForTests = (): void => {
  lastUserAuthActionAt.clear();
};
