/**
 * Local-first gateway preference — stored in the shared env file
 * (`~/.openllm/.env`) as `OPENLLM_LOCAL_GATEWAY` (`1`/`0`), alongside every
 * other daemon config. See `docs/proposals/local-first-gateway.md` §3.
 *
 * OPT-OUT (on by default): a client whose base URL points at the daemon
 * (`http://127.0.0.1:8787`) is served locally via the signed-plan flow —
 * subscription hops run on the box, BYOK hops forward to the origin only
 * when the plan requires it. Disabling it turns the daemon's direct `/v1/*`
 * surface into a transparent passthrough to the origin (today's cloud flow,
 * verbatim), so toggling never requires re-running the client setups.
 *
 * Read fresh on every direct request + status push — `setLocalGateway`
 * keeps both the env file and the in-process env in sync, so the dashboard
 * toggle takes effect immediately without a restart.
 */
import { loadEnvFile, writeEnvFileVars } from "./env";
import { logWarn } from "./logger";

/** The env-file key the preference lives under. */
const LOCAL_GATEWAY_KEY = "OPENLLM_LOCAL_GATEWAY";

/** Parse a flag value to bool; null when unrecognized/absent. Same
 *  convention as `DAEMON_PLAN_CACHE` cloud-side: only an explicit
 *  `0`/`false` disables. */
const parseFlag = (raw: string | undefined): boolean | null => {
  const v = raw?.trim().toLowerCase();
  if (v === undefined || v.length === 0) return null;
  if (v === "0" || v === "false") return false;
  return true;
};

/** Whether local-first gateway mode is enabled. Default TRUE (opt-out). */
export const localGatewayEnabled = (): boolean => {
  loadEnvFile(); // idempotent; sets unset vars only
  return parseFlag(process.env[LOCAL_GATEWAY_KEY]) ?? true;
};

/**
 * Persist the preference into the env file (`0600`, merge) and update the
 * in-process env so the next direct request sees it immediately.
 */
export const setLocalGateway = (enabled: boolean): void => {
  const value = enabled ? "1" : "0";
  if (!writeEnvFileVars({ [LOCAL_GATEWAY_KEY]: value })) {
    logWarn("local-gateway", "failed to persist preference to the env file");
  }
  process.env[LOCAL_GATEWAY_KEY] = value;
};
