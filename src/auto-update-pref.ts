/**
 * Daemon auto-update opt-out preference — stored in the single config file
 * the shared env file (`~/.openllm/.env`) as `OPENLLM_DAEMON_AUTO_UPDATE` (`1`/`0`), alongside every other
 * daemon config (no separate flag file).
 *
 * Self-update is OPT-OUT (on by default): a freshly installed daemon keeps
 * itself current automatically, and the user can DISABLE it (from the
 * dashboard's daemon section, `openllmd auto-update off`, or
 * `OPENLLM_DAEMON_AUTO_UPDATE=0`) to pin the installed version. The value is
 * read fresh on every self-update check + status push — `setAutoUpdate` keeps
 * both the env file and the in-process env in sync, so a toggle takes effect on
 * the next tick without a restart.
 *
 * Precedence: an explicit `OPENLLM_DAEMON_AUTO_UPDATE` (set in the environment,
 * or loaded from the env file by `loadEnvFile`) decides; absent it, ON.
 */
import { loadEnvFile, writeEnvFileVars } from "./env";
import { logWarn, safeDiagnosticMessage } from "./logger";

/** The env-file key the preference lives under. */
const AUTO_UPDATE_KEY = "OPENLLM_DAEMON_AUTO_UPDATE";

/**
 * The accepted preference words, compared case-insensitively after a trim.
 * `1`/`0` stay canonical; `true`/`false`, `yes`/`no`, and `on`/`off` cover
 * the usual forms (TCB-4). Anything else is unrecognized: the caller keeps
 * the safe default (ON).
 */
const TRUE_WORDS = new Set(["1", "true", "yes", "on"]);
const FALSE_WORDS = new Set(["0", "false", "no", "off"]);

/**
 * Values already warned about, deduplicated per normalized value and capped:
 * the preference is read on every self-update check and status push, so an
 * unrecognized value warns ONCE — not on every tick — and the cap keeps an
 * env file rewritten with fresh junk from growing the set without bound.
 */
const WARNED_VALUES_MAX = 16;
const warnedValues = new Set<string>();

/** Parse a flag value to bool; null when unrecognized/absent. */
const parseFlag = (raw: string | undefined): boolean | null => {
  const v = raw?.trim().toLowerCase();
  if (v === undefined || v === "") return null;
  if (TRUE_WORDS.has(v)) return true;
  if (FALSE_WORDS.has(v)) return false;
  if (!warnedValues.has(v) && warnedValues.size < WARNED_VALUES_MAX) {
    warnedValues.add(v);
    logWarn(
      "auto-update",
      safeDiagnosticMessage`unrecognized OPENLLM_DAEMON_AUTO_UPDATE value — the default (on) applies`,
      { value: v.slice(0, 64) },
    );
  }
  return null;
};

/** Whether automatic daemon self-update is enabled. Default TRUE (opt-out). */
export const autoUpdateEnabled = (): boolean => {
  // In dev, `.dev.env` overrides non-selector process env defaults; in prod, an
  // explicitly-set env value remains authoritative.
  loadEnvFile();
  const fromEnv = parseFlag(process.env[AUTO_UPDATE_KEY]);
  if (fromEnv !== null) return fromEnv;
  return true; // default ON until explicitly opted out
};

/**
 * Persist the auto-update opt-in into the env file (`0600`, merge) and update
 * the in-process env so the next check sees it immediately.
 */
export const setAutoUpdate = (enabled: boolean): void => {
  const value = enabled ? "1" : "0";
  if (!writeEnvFileVars({ [AUTO_UPDATE_KEY]: value })) {
    logWarn(
      "auto-update",
      safeDiagnosticMessage`failed to persist preference to the env file`,
    );
  }
  process.env[AUTO_UPDATE_KEY] = value;
};
