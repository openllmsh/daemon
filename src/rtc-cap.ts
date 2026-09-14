import { logWarn } from "./logger";

const DEFAULT_MAX_SESSIONS = 8;
const MAX_SESSIONS_LIMIT = 256;
let lastRaw: string | undefined;
let effectiveCap = DEFAULT_MAX_SESSIONS;

/**
 * OPENLLM_RTC_MAX_SESSIONS: positive decimal integer, capped at 256; default 8.
 * Cache the last env value so an invalid configuration warns once, rather than
 * on every offer. Reading again still picks up an env change without a restart.
 */
export const maxConcurrentRtc = (): number => {
  const raw = process.env.OPENLLM_RTC_MAX_SESSIONS;
  if (raw === lastRaw) return effectiveCap;
  lastRaw = raw;
  effectiveCap = DEFAULT_MAX_SESSIONS;
  if (raw === undefined) return effectiveCap;

  const trimmed = raw.trim();
  const parsed = Number(trimmed);
  if (!/^\d+$/.test(trimmed) || !Number.isSafeInteger(parsed) || parsed < 1) {
    logWarn("rtc-host", "invalid OPENLLM_RTC_MAX_SESSIONS; using default", {
      cap: DEFAULT_MAX_SESSIONS,
    });
    return effectiveCap;
  }
  effectiveCap = Math.min(parsed, MAX_SESSIONS_LIMIT);
  return effectiveCap;
};
