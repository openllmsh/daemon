/**
 * Daemon runtime configuration.
 *
 * Everything lives in ONE file — `~/.openllm/.env` (resolved via
 * `envFilePath()`). It's the single source the
 * installed service (systemd `EnvironmentFile=` / the macOS launch agent's
 * `OPENLLM_DAEMON_ENV_FILE`) boots from — and it is SHARED with the other
 * OpenLLM tools on the box: the CLI (`openllm`) reads the same file for
 * the cloud origin + API key.
 *
 * DEV mode (`OPENLLM_DAEMON_DEV=1`) is ISOLATED: `envFilePath()` resolves
 * `<stateDir>/.dev.env` instead, so a source-run dev daemon never clobbers
 * the installed daemon's config — all dev writes (`setApiKey`,
 * `setCloudOrigin`, the minted device id, the auto-update pref) land in
 * `.dev.env`, the default port is `8788` (vs prod `8787`), the cloud origin
 * defaults to the local Next server, and `.dev.env` overrides inherited process
 * env values (except the dev-mode / env-file / state-dir selectors) so Bun's
 * repository `.env` cannot shadow local daemon configuration. The ONLY thing
 * read from the shared `.env` is a live, read-only `OPENLLM_API_KEY` fallback
 * when `.dev.env` is keyless — so dev reuses the already-paired key without
 * copying it. The shared file is never written in dev.
 *
 * The keys the env file holds:
 *
 * - `OPENLLM_API_KEY`     — the user's `sk-llm-...` key. Authenticates
 *                            every cloud control-plane call. OPTIONAL at
 *                            boot: the daemon installs WITHOUT a key and
 *                            the dashboard sets it afterwards via the
 *                            control surface (`POST /config/api-key`).
 *                            Persisted to the env file so it survives
 *                            restarts / HMR. Never leaves the box.
 * - `OPENLLM_DEVICE_ID`   — stable opaque per-machine UUID, minted into
 *                            the env file on first boot. Carries no PII.
 * - `OPENLLM_CLOUD_ORIGIN`— openllm.sh origin for config pull + request
 *                            recording + API-key-hop forwarding. Baked in
 *                            at compile time via --define, overridable.
 * - `OPENLLM_DASHBOARD_ORIGIN` — allowed CORS origin for the control
 *                            surface (the dashboard). Defaults to the
 *                            cloud origin. Access control is the
 *                            localhost bind + this origin lock; there is
 *                            no separate control token at this stage.
 * - `OPENLLM_DAEMON_STATE_DIR` — where .env + state live
 *                            (default `~/.openllm`).
 * - `OPENLLM_DAEMON_AUTO_UPDATE` — self-update opt-out flag (`1`/`0`,
 *                            default ON). Read/written by
 *                            `auto-update-pref.ts`; lives here so ALL daemon
 *                            config is in the one file.
 * - `OPENLLM_UPDATE_CHANNEL` — reserved for a future update channel. Published
 *                            prerelease binary replacement remains disabled
 *                            until artifact routing is separate from the
 *                            credentialed cloud origin and has its own digest
 *                            policy. Stable binaries ignore this key.
 * - `OPENLLM_SESSION_IDLE_TIMEOUT_MIN` — detached PTY idle-reap window in
 *                            minutes (default `60`; `0` disables). Read by
 *                            `session-host.ts` from this same env file.
 * - `OPENLLM_LOG_LEVEL`   — most-verbose level written to `openllmd.log`
 *                            (`error` | `warn` | `info` | `debug`, default
 *                            `info` — so `debug` is OFF unless set). Read by
 *                            `logger.ts` from this same env file.
 *
 * Pre-launch standalone API-key files are intentionally ignored; native
 * onboarding is the only credential source.
 */
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { parseOpenllmDaemonPort } from "@openllmsh/protocol";
import type { TUpdateRouteConfig } from "@openllmsh/protocol/update-policy";
import { resolveUpdateSetting } from "@openllmsh/protocol/update-policy";
import { processStartIdentity } from "../../pty-native/session/local-runtime";
// NOTE: logger.ts imports `stateDir` from this module — a benign cycle, since
// both sides only dereference the other's exports lazily inside functions.
import { logWarn, safeDiagnosticMessage } from "./logger";
import { DAEMON_VERSION } from "./version";

export type TDaemonEnv = {
  /** The user's `sk-llm-...` key, or null until the dashboard sets it. */
  readonly apiKey: string | null;
  readonly cloudOrigin: string;
  readonly dashboardOrigin: string;
};

/**
 * Extract the public id half of a `sk-llm-{id}.{secret}` key. The daemon
 * never imports `@openllm/vault`; this is a shape-only parse (id only —
 * secret is ignored). Returns null on any mismatch.
 */
export const parseApiKeyId = (raw: string): string | null => {
  if (!raw.startsWith("sk-llm-")) return null;
  const rest = raw.slice("sk-llm-".length);
  const dot = rest.indexOf(".");
  if (dot <= 0 || dot === rest.length - 1) return null;
  const id = rest.slice(0, dot);
  return id.length > 0 ? id : null;
};

/**
 * This daemon's api key id (the `key_id` grants must target). Null when
 * keyless or the stored key is malformed.
 */
export const daemonApiKeyId = (): string | null => {
  const key = daemonEnv().apiKey;
  if (key === null) return null;
  return parseApiKeyId(key);
};

/**
 * Compile-time default for the cloud origin, injected by
 * scripts/compile.ts via `--define __OPENLLM_CLOUD_ORIGIN_DEFAULT__`.
 * Declared as a global (NOT `process.env`) so the bundler replaces the
 * identifier without clobbering the runtime `process.env` read below —
 * the env var must still win for local testing. Falls back to the public
 * origin when run from source (no define).
 */
declare const __OPENLLM_CLOUD_ORIGIN_DEFAULT__: string | undefined;
const compiledCloudOrigin = (): string => {
  try {
    return typeof __OPENLLM_CLOUD_ORIGIN_DEFAULT__ === "string"
      ? __OPENLLM_CLOUD_ORIGIN_DEFAULT__
      : "https://www.openllm.sh";
  } catch {
    return "https://www.openllm.sh";
  }
};

/**
 * Dev posture is a BUILD property, not a runtime switch. The only builds that
 * may honor `OPENLLM_DAEMON_DEV` are source runs and `0.0.0-dev` sentinel
 * builds (`compile:host` / `dev:dist` — see `DEV_VERSION_SENTINEL` in
 * `scripts/compile.ts`). A release binary bakes a real
 * `__OPENLLM_DAEMON_VERSION__`, so it can never be flipped into permissive
 * dev behavior (local cloud origin, dev env-file isolation, dev token file)
 * by an environment variable.
 */
export const isReleaseBuild = (): boolean => DAEMON_VERSION !== "0.0.0-dev";

let warnedIgnoredDevFlag = false;

/**
 * Dev mode (`OPENLLM_DAEMON_DEV=1`, set by `bun run dev:daemon`). Lets
 * the daemon boot from source with `bun --watch` without a full install:
 * the cloud origin defaults to the local Next server and a failed/absent
 * cloud bootstrap is non-fatal. The API key is NOT defaulted — you set a
 * real one from the dashboard's Providers tab (same as production), which
 * also exercises that flow during development. Never set in production —
 * release builds refuse it outright (one-time warning).
 */
export const isDevMode = (): boolean => {
  if (process.env.OPENLLM_DAEMON_DEV !== "1") return false;
  if (isReleaseBuild()) {
    if (!warnedIgnoredDevFlag) {
      warnedIgnoredDevFlag = true;
      logWarn(
        "env",
        "release build ignores OPENLLM_DAEMON_DEV — dev mode is a build property",
      );
    }
    return false;
  }
  return true;
};

/**
 * The cloud origin must be HTTPS — plain HTTP is accepted only for a loopback
 * gateway (`http://127.0.0.1`/`http://localhost`, the dev Next server and
 * same-box test clouds). Anything else would put the user's `sk-llm` bearer —
 * and self-update downloads — on the wire in cleartext for a network MITM.
 * Same predicate the CLI enforces (`cli/src/self-update.ts`).
 */
export const isSecureOrigin = (raw: string): boolean => {
  try {
    const url = new URL(raw);
    if (url.protocol === "https:") return true;
    return (
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1")
    );
  } catch {
    return false;
  }
};

/**
 * Dev-mode `.dev.env` loading is special: when `OPENLLM_DAEMON_DEV=1`, existing
 * process env vars must be treated as defaults, and file values are honored as
 * overrides so ad-hoc `bun dev` env injection can't block local testing.
 *
 * Production preserves the original behavior: config file values are ignored when
 * already-present in process.env, so explicitly set vars stay source-of-truth.
 *
 * The three selector keys must never be overwritten by file values:
 * `OPENLLM_DAEMON_DEV` (mode), `OPENLLM_DAEMON_ENV_FILE` (path override), and
 * `OPENLLM_DAEMON_STATE_DIR` (state root).
 */
const LOAD_ENV_FILE_NO_OVERRIDE_KEYS = new Set([
  "OPENLLM_DAEMON_DEV",
  "OPENLLM_DAEMON_ENV_FILE",
  "OPENLLM_DAEMON_STATE_DIR",
]);

/**
 * In DEV mode, `.dev.env` is authoritative for all keys except those that select
 * the loaded file/path itself. In non-dev, the file is still additive-only.
 */
function shouldWriteEnvVar(key: string, devMode: boolean): boolean {
  if (LOAD_ENV_FILE_NO_OVERRIDE_KEYS.has(key)) return false;
  if (!devMode) return process.env[key] === undefined;
  return true;
}

// Dev-only fallback for the cloud origin — points at the local Next
// server. (The dashboard origin falls back through `cloudOrigin`, and the
// API key is intentionally absent — set it from the UI like a real user.)
const DEV_CLOUD_ORIGIN = "http://127.0.0.1:3000";

/**
 * Root for the daemon's local state (`.env`, the isolated vendor CLIs
 * under `cli/<provider>/`, …). Defaults to `~/.openllm`; override with
 * `OPENLLM_DAEMON_STATE_DIR`. Exported so cli-paths.ts nests under it.
 *
 * `home` overrides the base for the `homedir()` default — needed ONLY by the
 * `--sandbox-exec` shim, which runs with the CHILD's `HOME` (an isolated CLI
 * home) and must still resolve the DAEMON's state dir. See
 * `sandbox/exec.ts` `HOME_FLAG`.
 */
export const stateDir = (home?: string): string => {
  const override = process.env.OPENLLM_DAEMON_STATE_DIR;
  return override !== undefined && override.length > 0 && isAbsolute(override)
    ? override
    : join(home ?? homedir(), ".openllm");
};

/** The structured log file, isolated from the installed daemon in dev mode. */
export const logFilePath = (): string =>
  join(stateDir(), isDevMode() ? "openllmd.dev.log" : "openllmd.log");

/** Native stdout capture written by the installed launchd/systemd service. */
export const daemonStdoutLogFilePath = (): string =>
  join(stateDir(), "openllmd.out.log");

/** Native stderr capture written by the installed launchd/systemd service. */
export const daemonStderrLogFilePath = (): string =>
  join(stateDir(), "openllmd.err.log");

/**
 * An explicit daemon env-file override is valid only when it is an absolute,
 * nonempty path. This is a service boundary: launchd and systemd must never be
 * handed an empty or cwd-relative config path, and runtime reads/writes must
 * resolve the same file that a registered service will use.
 */
const daemonEnvFileOverride = (): string | null => {
  const override = process.env.OPENLLM_DAEMON_ENV_FILE;
  return override !== undefined && override.length > 0 && isAbsolute(override)
    ? override
    : null;
};

/**
 * The SHARED OpenLLM env/config file. A valid absolute
 * `OPENLLM_DAEMON_ENV_FILE` wins (the macOS launch agent points us here because
 * launchd can't read a native `EnvironmentFile`); otherwise it's `.env` under
 * the state dir — the same path systemd's `EnvironmentFile=` and the installer
 * write to, and the one `bun dev:daemon` auto-loads. Shared product-wide: the
 * CLI (`openllm`) reads the same file for `OPENLLM_CLOUD_ORIGIN` /
 * `OPENLLM_API_KEY`, so a re-pair or a custom origin applies to every OpenLLM
 * tool on the box. In DEV mode this resolves `.dev.env` instead — the isolated
 * dev config — so dev never reads/writes the installed daemon's file (see
 * header).
 */
export const envFilePath = (): string =>
  daemonEnvFileOverride() ??
  join(stateDir(), isDevMode() ? ".dev.env" : ".env");

/**
 * The SHARED (prod/installed) env file — always `.env`, NEVER dev-resolved.
 *
 * Two callers depend on this staying prod-forced regardless of `isDevMode()`:
 *   1. `loadApiKey`'s live, read-only `OPENLLM_API_KEY` fallback in dev.
 *   2. Service INSTALLATION (`renderPlist` / `renderUnit` / `writeEnvFileIfNeeded`
 *      in `service.ts`). Installing a service is inherently a PRODUCTION action,
 *      so the unit/plist must pin `.env` — using the dev-aware `envFilePath()`
 *      would freeze `.dev.env` into a permanent prod service definition if the
 *      install ran with `OPENLLM_DAEMON_DEV=1` in the environment, so the
 *      installed daemon would then boot from dev config forever.
 */
export const sharedEnvFilePath = (): string => join(stateDir(), ".env");

/**
 * The env-file path a SERVICE INSTALL should pin — an explicit
 * `OPENLLM_DAEMON_ENV_FILE` still wins (a custom install may point elsewhere),
 * but the dev-mode `.dev.env` branch is NEVER taken: installing is a production
 * action, so absent an explicit override it forces the shared `.env`. This is
 * the ONLY difference from `envFilePath()` — which resolves `.dev.env` under
 * `OPENLLM_DAEMON_DEV=1` and would otherwise freeze dev config into the plist /
 * systemd unit. Used by `service.ts` renderers + `writeEnvFileIfNeeded`.
 */
export const serviceEnvFilePath = (): string =>
  daemonEnvFileOverride() ?? sharedEnvFilePath();

/**
 * Load the daemon's `KEY=value` env file into `process.env`.
 *
 * In production, file values only fill already-missing vars. In dev, the file is an
 * override source: values from `.dev.env` replace any pre-set vars (with the
 * exception of selector vars in `LOAD_ENV_FILE_NO_OVERRIDE_KEYS`) so ad-hoc
 * process env from `bun` startup cannot block local testing.
 *
 * Resolved via `envFilePath()` — the single config file. systemd injects the same
 * file via `EnvironmentFile=` before exec (so this read is a harmless no-op there);
 * the macOS launch agent and `bun dev:daemon` rely on this read to load it. No-op
 * when the file is missing. Synchronous (boot-time, before anything reads env).
 */
export const loadEnvFile = (): void => {
  let text: string;
  try {
    text = readFileSync(envFilePath(), "utf-8");
  } catch {
    return;
  }
  // Read mode before processing entries: selector values from the file never
  // apply, so its ordering cannot change whether later ordinary keys override.
  const devMode = isDevMode();
  for (const [key, value] of parseEnvLines(text)) {
    if (shouldWriteEnvVar(key, devMode)) process.env[key] = value;
  }
};

/** Parse `KEY=value` lines (comments + blanks ignored) into a map. Shared by
 *  `loadEnvFile` and the dev-mode shared-file API-key fallback. */
const parseEnvLines = (text: string): Map<string, string> => {
  const out = new Map<string, string>();
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    out.set(trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim());
  }
  return out;
};

/**
 * Upsert `KEY=value` pairs into the env file, preserving every other line
 * (comments, unrelated keys, ordering). Creates the file `0600` when absent.
 * This is how runtime-resolved secrets/ids (`OPENLLM_API_KEY`,
 * `OPENLLM_DEVICE_ID`) and re-pointed config (`OPENLLM_CLOUD_ORIGIN`,
 * `OPENLLM_DAEMON_PORT`) get persisted back to the one file both dev and the
 * service boot from. Returns true on successful write, false on failure.
 *
 * `targetPath` defaults to `envFilePath()` (dev-aware). The service installer
 * passes `serviceEnvFilePath()` so it seeds the PROD `.env` even under the dev
 * flag — see `serviceEnvFilePath` / `service.ts writeEnvFileIfNeeded`.
 */
const lockWait = (): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
};

/**
 * Shared env-file lock protocol `openllm-env-lock/v1` — the SAME protocol the
 * shell installers implement in `packages/daemon/install.sh` and
 * `packages/cli/install.sh` (the block is duplicated verbatim there; keep all
 * three in sync).
 *
 * The lock is the DIRECTORY `<envfile>.lock.d`: `mkdir` is atomic on every
 * POSIX filesystem (flock does not exist on macOS). Ownership is a record
 * published atomically INSIDE the directory — written to `owner.tmp.<pid>`
 * then renamed to `owner`:
 *
 *   kind=openllm-env-lock/v1 pid=<pid> start=<start identity> nonce=<hex>
 *
 * `start` is the owner's `ps -o lstart=` identity under LC_ALL=C TZ=UTC with
 * whitespace collapsed to single spaces (`processStartIdentity`, normalised
 * the same way) — it distinguishes a LIVE-but-reused pid from the real owner
 * (PID reuse). A `-` records an owner that could not read its own identity.
 *
 * A held lock is STALE only when its marked owner record names a dead pid,
 * or a live pid whose current start identity differs from the recorded one.
 * A lock dir with no/unreadable/unmarked owner is HELD — the one exception
 * is a dir older than the stale window that still has no complete owner
 * (a holder killed between `mkdir` and publish), which may be reclaimed.
 *
 * Reclaim is an atomic `mv` of the lock dir to `<envfile>.lock.stale.<pid>.
 * <nonce>` — exactly one contender wins the rename. The winner re-reads the
 * owner INSIDE the quarantine: if it turns out to be live after all (it was
 * published between the check and the move), it is moved back — but only
 * when `.lock.d` still does not exist (rename is a no-replace), otherwise
 * it stays quarantined. Either way acquisition is retried. Quarantine dirs
 * older than the stale window are deleted during acquisition passes when
 * their contents are only `owner.tmp.*` publish residue (or empty — the
 * crash-between-mkdir-and-publish shape) or a complete marked owner record.
 *
 * Release moves `.lock.d` to `<envfile>.lock.rel.<pid>.<nonce>` first, then
 * verifies the nonce inside matches before deleting — a holder whose lock
 * was stolen/replaced never deletes a successor's lock: the moved dir holds
 * the successor's record, the nonce differs, and it is moved back.
 *
 * The pre-dir `.env.lock` FILE format is still honoured for one release:
 * a legacy file lock can never prove its owner's start identity, so it is
 * HELD only inside the bounded reclaim window ({@link envLockStaleMs}) —
 * while a recorded pid is alive or its content is unparseable — and is
 * reclaimed past the window even when the pid is still alive. A dead-pid
 * record is reclaimed ONLY by atomic rename to a unique quarantine name —
 * the live path is never unlinked directly — then re-read inside the
 * quarantine: a record that turns out to be live AND young is put back with
 * a no-replace restore, never over a successor lock file.
 */
const ENV_LOCK_KIND = "openllm-env-lock/v1";
const ENV_LOCK_MARKER = `kind=${ENV_LOCK_KIND}`;

// Both knobs share the installers' exact rule: decimal digits AND > 0 —
// "0" (or anything non-numeric, including "0x10"/"1e3") falls back to the
// defaults, never a zero-length window.
const envLockStaleMs = (): number => {
  const raw = process.env.OPENLLM_ENV_LOCK_STALE_SECS;
  if (raw !== undefined && /^[0-9]+$/.test(raw) && Number(raw) > 0) {
    return Number(raw) * 1000;
  }
  return 600_000;
};

const envLockWaitMs = (): number => {
  const raw = process.env.OPENLLM_ENV_LOCK_WAIT_SECS;
  if (raw !== undefined && /^[0-9]+$/.test(raw) && Number(raw) > 0) {
    return Number(raw) * 1000;
  }
  return 10_000;
};

export type TEnvLockOwner =
  | {
      readonly state: "marked";
      readonly pid: number;
      readonly start: string;
      readonly nonce: string;
    }
  | { readonly state: "unmarked"; readonly pid: number | null };

/**
 * Read `<dir>/owner`. Unmarked covers a missing, unreadable or foreign
 * record. Exported so the parity tests can feed the installers' shared bash
 * `env_lock_read_owner` the same records and compare verdicts — the field
 * rules are identical on both sides by contract.
 */
export const envLockReadOwner = (dir: string): TEnvLockOwner => {
  let text = "";
  try {
    text = readFileSync(join(dir, "owner"), "utf-8").trim();
  } catch {
    text = "";
  }
  const marked = text.match(
    /^kind=openllm-env-lock\/v1 pid=([0-9]+) start=(.+) nonce=([0-9a-fA-F]+)$/,
  );
  if (marked !== null) {
    return {
      state: "marked",
      pid: Number(marked[1]),
      start: marked[2],
      nonce: marked[3],
    };
  }
  // Unmarked — still surface any parseable pid for the live-pid guard, with
  // the same token rule as the bash side: the first whitespace-bounded
  // `pid=<digits>` token, else a leading bare-pid token.
  const pidField =
    text.match(/(?:^|\s)pid=([0-9]+)(?:\s|$)/)?.[1] ??
    text.match(/^([0-9]+)(?:\s|$)/)?.[1];
  const pid = pidField === undefined ? Number.NaN : Number(pidField);
  return {
    state: "unmarked",
    pid: Number.isInteger(pid) && pid > 0 ? pid : null,
  };
};

/** Is `pid` a live process? EPERM means it exists but is owned by another user. */
const envLockOwnerAlive = (pid: number): boolean => {
  // kill(0,0) probes the caller's OWN process group — never a real owner.
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
};

/**
 * The owner's start identity, normalised exactly like the shell side
 * (`ps -o lstart=` under LC_ALL=C TZ=UTC, whitespace collapsed). Tri-state:
 * a string identity, null for a confirmed-dead pid, undefined when unknown.
 */
const envLockStartIdentity = (pid: number): string | null | undefined => {
  const raw = processStartIdentity(pid);
  if (typeof raw !== "string") return raw;
  const value = raw.trim().replace(/\s+/g, " ");
  return value.length > 0 ? value : undefined;
};

/** The shared staleness predicate — identical rules on both sides. */
const envLockDirIsStale = (dir: string): boolean => {
  const owner = envLockReadOwner(dir);
  if (owner.state === "marked") {
    if (!envLockOwnerAlive(owner.pid)) return true;
    if (owner.start === "-") {
      // The start identity can never be proven ("-"): the lock is held only
      // inside the same bounded window an ownerless dir gets — past it a
      // live-but-unidentifiable pid no longer wedges the lock.
      try {
        return Date.now() - lstatSync(dir).mtimeMs >= envLockStaleMs();
      } catch {
        return false;
      }
    }
    // PID reuse: only a REAL recorded start compared against a successfully
    // read current identity can prove the holder is gone. Anything unknown
    // keeps the lock held.
    const current = envLockStartIdentity(owner.pid);
    return current !== null && current !== undefined && current !== owner.start;
  }
  // Unmarked: HELD unless the dir is old AND still has no complete owner —
  // and never while a parseable pid in it is still alive.
  let ageMs = Number.NaN;
  try {
    ageMs = Date.now() - lstatSync(dir).mtimeMs;
  } catch {
    return false;
  }
  if (!(ageMs >= envLockStaleMs())) return false;
  if (owner.pid !== null && envLockOwnerAlive(owner.pid)) return false;
  return true;
};

/** Move an apparently-stale lock dir aside; only one contender's rename wins. */
const envLockQuarantine = (
  lockDir: string,
  stem: string,
  nonce: string,
): void => {
  const quarantine = `${stem}.stale.${process.pid}.${nonce}`;
  try {
    renameSync(lockDir, quarantine);
  } catch {
    return; // another contender moved it first, or it was released.
  }
  // Re-read inside the quarantine: a live owner that raced publication is
  // restored — but never over an existing lock dir (no-replace).
  if (envLockDirIsStale(quarantine)) return;
  try {
    lstatSync(lockDir);
    return; // a successor lock exists — leave it quarantined.
  } catch {
    // absent
  }
  try {
    renameSync(quarantine, lockDir);
  } catch {
    // raced — leave it quarantined.
  }
};

/**
 * Delete old quarantine/release dirs whose contents are only `owner.tmp.*`
 * publish residue (or NOTHING — a holder killed between the lock mkdir and
 * the owner publish, then quarantined) or a complete marked owner record.
 * Anything foreign — an unmarked owner, an unrelated file — keeps the dir.
 * Exported as a protocol seam for the regression tests.
 */
export const envLockSweepQuarantine = (
  parentDir: string,
  baseName: string,
): void => {
  let entries: string[] = [];
  try {
    entries = readdirSync(parentDir);
  } catch {
    return;
  }
  const staleMs = envLockStaleMs();
  for (const entry of entries) {
    if (
      !entry.startsWith(`${baseName}.lock.stale.`) &&
      !entry.startsWith(`${baseName}.lock.rel.`)
    )
      continue;
    const path = join(parentDir, entry);
    let isDir = false;
    let mtimeMs = 0;
    try {
      const stat = lstatSync(path);
      isDir = stat.isDirectory();
      mtimeMs = stat.mtimeMs;
    } catch {
      continue;
    }
    if (!isDir || Date.now() - mtimeMs < staleMs) continue;
    // Contents must be limited to the owner record (+ an unfinished tmp).
    // An OWNERLESS residue — a holder killed between the lock mkdir and the
    // publish, then quarantined — is swept too when all it holds is
    // `owner.tmp.*` files (or nothing); anything foreign keeps it.
    let clean = true;
    let hasOwner = false;
    try {
      for (const child of readdirSync(path)) {
        if (child === "owner") hasOwner = true;
        else if (!child.startsWith("owner.tmp.")) clean = false;
      }
    } catch {
      clean = false;
    }
    if (!clean) continue;
    if (hasOwner && envLockReadOwner(path).state !== "marked") continue;
    for (const child of readdirSync(path)) {
      try {
        unlinkSync(join(path, child));
      } catch {
        // best effort
      }
    }
    try {
      rmdirSync(path);
    } catch {
      // best effort
    }
  }
};

/**
 * Adjudicate a legacy lock file that was ALREADY moved into quarantine:
 * re-read the CAPTURED record (the file may have been swapped between the
 * caller's first read and the rename). A live pid means the moved file is a
 * real lock — but it carries no provable start identity, so it is restored
 * only while still inside the bounded reclaim window; a live pid PAST the
 * window is dropped like a dead one. The restore is a no-replace
 * (hardlink), never over a successor lock file. A dead/unparseable record
 * is deleted — inside the quarantine, never on the live path. Returns true
 * when the legacy path still blocks acquisition (a live record was found).
 * Exported as a protocol seam for the regression tests.
 */
export const envLockLegacyResolveQuarantine = (
  quarantinePath: string,
  legacyPath: string,
): boolean => {
  let movedText = "";
  try {
    movedText = readFileSync(quarantinePath, "utf-8");
  } catch {
    movedText = "";
  }
  const movedPid = Number(movedText.trim().split(/\s+/)[0]);
  let withinWindow = false;
  if (
    Number.isInteger(movedPid) &&
    movedPid > 0 &&
    envLockOwnerAlive(movedPid)
  ) {
    // No provable start identity: a live pid may hold the lock only inside
    // the bounded window (an unreadable age stays conservative); past it
    // the captured record is dropped, not restored.
    withinWindow = true;
    try {
      withinWindow =
        Date.now() - lstatSync(quarantinePath).mtimeMs < envLockStaleMs();
    } catch {
      // keep the conservative default
    }
  }
  if (withinWindow) {
    try {
      // `link` is a true no-replace rename: it fails outright when a
      // successor lock file already occupies the path.
      linkSync(quarantinePath, legacyPath);
      try {
        unlinkSync(quarantinePath);
      } catch {
        // best effort — the record is restored either way
      }
    } catch {
      // Either a successor holds the path or the fs took no hardlink. An
      // O_EXCL create is the same strict no-replace guarantee (rename would
      // not be — it silently replaces a successor that lands mid-check).
      let restored = false;
      let fd = -1;
      try {
        fd = openSync(legacyPath, "wx");
        writeFileSync(fd, movedText);
        closeSync(fd);
        fd = -1;
        restored = true;
      } catch {
        if (fd >= 0) {
          try {
            closeSync(fd);
          } catch {
            // best effort
          }
          // A half-written file must not masquerade as a lock — remove
          // only OUR fresh create, never whatever a successor wrote.
          try {
            unlinkSync(legacyPath);
          } catch {
            // best effort
          }
        }
      }
      if (restored) {
        try {
          unlinkSync(quarantinePath);
        } catch {
          // best effort
        }
      } else {
        try {
          lstatSync(legacyPath);
          // Occupied by a successor — the captured copy is obsolete.
          try {
            unlinkSync(quarantinePath);
          } catch {
            // best effort
          }
        } catch {
          // Path free but the restore itself failed — keep the captured
          // record quarantined so a later pass can retry.
        }
      }
    }
    return true;
  }
  try {
    unlinkSync(quarantinePath);
  } catch {
    // best effort
  }
  return false;
};

/**
 * The legacy `.env.lock` FILE format (pre-dir protocol): the record can
 * never prove its owner's start identity, so it is HELD only inside the
 * bounded reclaim window — while a recorded pid is alive or its content is
 * unparseable — and reclaimed past the window even on a live pid. A
 * dead-pid record is reclaimed WITHOUT check-then-unlink on the live path:
 * an atomic rename to a unique quarantine name (exactly one contender
 * wins), then {@link envLockLegacyResolveQuarantine} re-reads the captured
 * file — so a live lock swapped in mid-check, or a successor's fresh file,
 * can never be unlinked by us. Returns true while the legacy file still
 * blocks acquisition.
 */
const envLockLegacyHeld = (legacyPath: string, nonce: string): boolean => {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    let text: string;
    try {
      text = readFileSync(legacyPath, "utf-8");
    } catch (error) {
      return (error as NodeJS.ErrnoException).code !== "ENOENT";
    }
    const pid = Number(text.trim().split(/\s+/)[0]);
    const pidProvenDead =
      Number.isInteger(pid) && pid > 0 && !envLockOwnerAlive(pid);
    if (!pidProvenDead) {
      // A live pid — or a record that cannot be parsed at all — can never
      // prove the owner's start identity: the lock is held only inside the
      // bounded reclaim window, past which it is reclaimed like a stale dir.
      let ageMs = Number.NaN;
      try {
        ageMs = Date.now() - lstatSync(legacyPath).mtimeMs;
      } catch {
        // the file exists but its age is unknown — stay held
      }
      if (!(ageMs >= envLockStaleMs())) return true;
    }
    const quarantine = `${legacyPath}.stale.${process.pid}.${nonce}.${attempt}`;
    try {
      renameSync(legacyPath, quarantine);
    } catch {
      continue; // it vanished or another contender moved it — re-read
    }
    if (envLockLegacyResolveQuarantine(quarantine, legacyPath)) return true;
    // Verified dead and deleted — loop to re-check for a successor file.
  }
  return true; // could not stabilise this pass — treat as still held
};

/**
 * Publish OUR owner record inside the just-mkdir'd lock dir — NO-REPLACE.
 * A publisher paused between the mkdir and this call may have been
 * quarantined and its path re-taken by a successor, and `rename` would
 * silently stamp over the successor's record. `link` fails outright on an
 * existing owner; the O_EXCL create carries the same guarantee where
 * hardlinks do not work. Returns true ONLY when the live record afterwards
 * carries OUR nonce — the dir may be swapped even after a successful link,
 * so holding is never assumed from the write alone. A return of false means
 * "did not acquire" (a successor owns this path — retry from the top);
 * a throw means the tmp write itself failed. Exported as a protocol seam
 * for the regression tests.
 */
export const envLockPublishOwner = (
  lockDir: string,
  nonce: string,
): boolean => {
  const start = envLockStartIdentity(process.pid) ?? "-";
  const record = `${ENV_LOCK_MARKER} pid=${process.pid} start=${start} nonce=${nonce}\n`;
  const tmp = join(lockDir, `owner.tmp.${process.pid}`);
  const ownerPath = join(lockDir, "owner");
  writeFileSync(tmp, record, "utf-8");
  let published = false;
  try {
    linkSync(tmp, ownerPath);
    published = true;
  } catch {
    // EEXIST means a successor owns this dir — never replace its record.
    // Any other failure (no hardlink support) gets the same no-replace
    // guarantee from an O_EXCL create.
    let fd = -1;
    try {
      fd = openSync(ownerPath, "wx");
      writeFileSync(fd, record);
      closeSync(fd);
      fd = -1;
      published = true;
    } catch {
      if (fd >= 0) {
        try {
          closeSync(fd);
        } catch {
          // best effort
        }
        // A half-written create must not masquerade as an owner — remove
        // only OUR fresh file, never a successor's record.
        try {
          unlinkSync(ownerPath);
        } catch {
          // best effort
        }
      }
    }
  }
  try {
    unlinkSync(tmp);
  } catch {
    // best effort — swept later either way
  }
  if (!published) return false;
  const now = envLockReadOwner(lockDir);
  return now.state === "marked" && now.nonce === nonce;
};

/** Serialize env-file read/modify/write operations across daemon processes. */
const withEnvFileLock = (
  targetPath: string,
  operation: () => boolean,
): boolean => {
  const stem = `${targetPath}.lock`;
  const lockDir = `${stem}.d`;
  const parentDir = dirname(targetPath);
  const baseName = basename(targetPath);
  const nonce = randomUUID().replace(/-/g, "");
  const deadline = Date.now() + envLockWaitMs();
  let sweeps = 0;
  let acquired = false;
  // Bounded cleanup once per acquire so quarantined residue cannot linger
  // until the next contested acquire (identical trigger on the bash side).
  envLockSweepQuarantine(parentDir, baseName);
  while (Date.now() < deadline) {
    if (envLockLegacyHeld(stem, nonce)) {
      lockWait();
      continue;
    }
    try {
      mkdirSync(lockDir);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
      sweeps += 1;
      if (sweeps % 25 === 0) envLockSweepQuarantine(parentDir, baseName);
      try {
        if (envLockDirIsStale(lockDir)) {
          envLockQuarantine(lockDir, stem, nonce);
        }
      } catch {
        // Another writer may have released/replaced it; retry normally.
      }
      lockWait();
      continue;
    }
    // Publish the owner record atomically inside the new lock dir —
    // NO-REPLACE: if our dir was quarantined and the path re-taken by a
    // successor while we were paused, the publish must fail rather than
    // stamp over the successor's record.
    let published: boolean;
    try {
      published = envLockPublishOwner(lockDir, nonce);
    } catch {
      // The tmp write itself failed — drop the lock WE made rather than
      // hold it unmarked.
      try {
        unlinkSync(join(lockDir, `owner.tmp.${process.pid}`));
      } catch {
        // best effort
      }
      try {
        rmdirSync(lockDir);
      } catch {
        // best effort
      }
      return false;
    }
    if (!published) {
      // A successor owns the dir at this path (or it was swapped
      // mid-publish) — NOT ours to remove. Retry acquisition from the top.
      lockWait();
      continue;
    }
    acquired = true;
    break;
  }
  if (!acquired) return false;
  try {
    return operation();
  } finally {
    // Release = rename to `.rel.<pid>.<nonce>` first, then delete ONLY when
    // the owner record inside is provably ours — a stolen/replaced lock
    // holds a successor's record, which we put back instead of deleting.
    const released = `${stem}.rel.${process.pid}.${nonce}`;
    try {
      renameSync(lockDir, released);
      const owner = envLockReadOwner(released);
      if (owner.state === "marked" && owner.nonce === nonce) {
        for (const child of readdirSync(released)) {
          try {
            unlinkSync(join(released, child));
          } catch {
            // best effort
          }
        }
        try {
          rmdirSync(released);
        } catch {
          // best effort
        }
      } else {
        try {
          lstatSync(lockDir);
        } catch {
          try {
            renameSync(released, lockDir);
          } catch {
            // leave it quarantined
          }
        }
      }
    } catch {
      // The lock dir vanished under us (stolen/quarantined) — nothing held.
    }
  }
};

const isSafeEnvTarget = (targetPath: string): boolean => {
  try {
    const target = lstatSync(targetPath);
    return target.isFile() && !target.isSymbolicLink();
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
};

const updatedEnvLines = (
  existing: readonly string[],
  updates: Readonly<Record<string, string>>,
): string[] => {
  const pending = new Map(Object.entries(updates));
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of existing) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) {
      out.push(line);
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq <= 0) {
      out.push(line);
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    // Only treat keys the caller actually supplied as updates. A bare
    // `updates[key]` read would resolve inherited Object.prototype names
    // (`constructor`, `toString`, …) to functions and rewrite those lines.
    if (!Object.hasOwn(updates, key)) {
      out.push(line);
      continue;
    }
    const value = updates[key];
    if (value === undefined) {
      out.push(line);
      continue;
    }
    // Keep one canonical occurrence at the first position and remove conflicting
    // duplicates. Unrelated lines retain their original spelling and order.
    if (!seen.has(key)) {
      out.push(`${key}=${value}`);
      seen.add(key);
      pending.delete(key);
    }
  }
  while (out.length > 0 && out[out.length - 1].trim().length === 0) out.pop();
  for (const [key, value] of pending) out.push(`${key}=${value}`);
  return out;
};

/**
 * Codes a win32 directory fsync fails with although the rename is durable.
 * Node/libuv can only open a directory read-only (FILE_FLAG_BACKUP_SEMANTICS),
 * and FlushFileBuffers needs a GENERIC_WRITE handle, so it returns
 * ERROR_ACCESS_DENIED, which libuv maps to EPERM (nodejs/node#3879). NTFS
 * journals the rename's metadata, so there is nothing further to flush.
 */
const WIN32_UNSUPPORTED_DIR_FSYNC = new Set(["EPERM", "EISDIR", "EINVAL"]);

/**
 * Flush the directory entry created by a rename. POSIX failures are always
 * reported; on win32 only the "directory fsync unsupported" codes are ignored.
 */
const fsyncDirectory = (dir: string): void => {
  const directoryFd = openSync(dir, "r");
  try {
    fsyncSync(directoryFd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (
      process.platform === "win32" &&
      code !== undefined &&
      WIN32_UNSUPPORTED_DIR_FSYNC.has(code)
    )
      return;
    throw error;
  } finally {
    closeSync(directoryFd);
  }
};

/**
 * Rename-swap `content` onto `targetPath` through a unique same-directory
 * `0600` temporary file. The caller MUST hold `withEnvFileLock(targetPath)`
 * and MUST already have accepted the target — the target is re-validated
 * immediately before the swap so a symlink planted mid-write is still
 * refused. fsyncs the file and the directory so a crash can't resurrect an
 * absent or torn write.
 */
const replaceFileAtomic0600 = (
  targetPath: string,
  content: string,
): boolean => {
  const parentDir = dirname(targetPath);
  const temporaryPath = join(
    parentDir,
    `.${basename(targetPath) || "env"}.${randomUUID()}.tmp`,
  );
  let temporaryFd: number | null = null;
  try {
    temporaryFd = openSync(temporaryPath, "wx", 0o600);
    writeFileSync(temporaryFd, content, "utf-8");
    fsyncSync(temporaryFd);
    closeSync(temporaryFd);
    temporaryFd = null;
    // Re-check immediately before replacement to reject a target swapped for
    // a symlink by another local process while this writer held the lock.
    if (!isSafeEnvTarget(targetPath)) return false;
    renameSync(temporaryPath, targetPath);
    chmodSync(targetPath, 0o600);
    fsyncDirectory(parentDir);
    return true;
  } finally {
    if (temporaryFd !== null) closeSync(temporaryFd);
    try {
      unlinkSync(temporaryPath);
    } catch {
      // The rename consumed it, or creation failed.
    }
  }
};

/**
 * Atomically create-or-replace a private `0600` file without following a
 * pre-existing symlink or other non-regular target (existing targets are
 * required to be regular files; a symlink — or anything else — is refused
 * outright rather than written through). The write path shared by the env
 * upsert and the per-boot local caller token.
 */
export const writePrivateFileAtomic = (
  targetPath: string,
  content: string,
): boolean => {
  try {
    mkdirSync(dirname(targetPath), { recursive: true, mode: 0o700 });
    return withEnvFileLock(
      targetPath,
      () =>
        isSafeEnvTarget(targetPath) &&
        replaceFileAtomic0600(targetPath, content),
    );
  } catch {
    return false;
  }
};

/**
 * Atomically upsert env values without following links or losing concurrent
 * updates. Existing targets are required to be regular files and every success
 * leaves a private `0600` file.
 */
export const writeEnvFileVars = (
  updates: Readonly<Record<string, string>>,
  targetPath: string = envFilePath(),
): boolean => {
  if (Object.values(updates).some((value) => /[\r\n\0]/.test(value)))
    return false;
  try {
    mkdirSync(dirname(targetPath), { recursive: true, mode: 0o700 });
    return withEnvFileLock(targetPath, () => {
      if (!isSafeEnvTarget(targetPath)) return false;
      let existing: string[] = [];
      try {
        existing = readFileSync(targetPath, "utf-8").split("\n");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") return false;
      }
      const content = `${updatedEnvLines(existing, updates).join("\n")}\n`;
      return replaceFileAtomic0600(targetPath, content);
    });
  } catch {
    return false;
  }
};

/** The default loopback port for the daemon's `/v1/*` + `/whoami` surface. */
export const DEFAULT_DAEMON_PORT = 8787;

/** Dev-mode default port — distinct from prod so a source-run dev daemon can
 *  coexist with the installed daemon on `8787`. */
export const DEV_DEFAULT_DAEMON_PORT = 8788;

/**
 * The loopback port the daemon listens on (`OPENLLM_DAEMON_PORT`, default
 * `8787`; `8788` in dev mode). Single source — `main.ts` binds it and
 * `status.ts` publishes it on `TDaemonStatus.port` so the dashboard can probe
 * `/whoami` for locality. See
 * `docs/proposals/this-machine-detection-audit.md`.
 */
export const daemonPort = (): number => {
  // `main()` resolves the port before anything else calls `daemonEnv()`, so load
  // the env file here too — otherwise a port supplied via `OPENLLM_DAEMON_ENV_FILE`
  // is ignored for the actual bind. Idempotent (respects DEV override semantics).
  loadEnvFile();
  const fallback = isDevMode() ? DEV_DEFAULT_DAEMON_PORT : DEFAULT_DAEMON_PORT;
  const raw = process.env.OPENLLM_DAEMON_PORT;
  if (raw === undefined) return fallback;
  return parseOpenllmDaemonPort(raw, fallback);
};

let cachedDeviceId: string | null = null;

/**
 * A stable per-machine id, minted once and persisted in the env file as
 * `OPENLLM_DEVICE_ID`. Opaque (a random uuid) — carries no PII. Used to bind
 * the daemon's presence token to this device
 * (`docs/proposals/daemon-presence-without-heartbeat.md`); survives restarts
 * so the token stays constant.
 */
export const deviceId = (): string => {
  if (cachedDeviceId !== null) return cachedDeviceId;
  loadEnvFile();
  const fromEnv = process.env.OPENLLM_DEVICE_ID?.trim();
  if (fromEnv !== undefined && fromEnv.length > 0) {
    cachedDeviceId = fromEnv;
    return fromEnv;
  }
  // Mint a fresh id and persist it in the env file (single source).
  const id = randomUUID();
  writeEnvFileVars({ OPENLLM_DEVICE_ID: id });
  process.env.OPENLLM_DEVICE_ID = id;
  cachedDeviceId = id;
  return id;
};

/**
 * The persisted API key, if any. `OPENLLM_API_KEY` is loaded from the env file
 * or set explicitly in the environment. Returns null when it is absent — the
 * daemon remains keyless until native onboarding stores one. Callers run
 * `loadEnvFile` before this (via `daemonEnv`).
 *
 * DEV mode adds a LIVE, read-only fallback: when `.dev.env` is keyless, the
 * shared `.env`'s `OPENLLM_API_KEY` is used (parsed key-only — never a blanket
 * merge, which would leak the prod origin/port/device-id into dev) and never
 * written anywhere, so dev reuses the paired key without forking it.
 */
const loadApiKey = (): string | null => {
  const fromEnv = process.env.OPENLLM_API_KEY?.trim();
  if (fromEnv !== undefined && fromEnv.length > 0) return fromEnv;
  if (isDevMode()) {
    try {
      const shared = parseEnvLines(readFileSync(sharedEnvFilePath(), "utf-8"))
        .get("OPENLLM_API_KEY")
        ?.trim();
      if (shared !== undefined && shared.length > 0) return shared;
    } catch {
      // no shared file — keyless
    }
  }
  return null;
};

let cached: TDaemonEnv | null = null;

export const daemonEnv = (): TDaemonEnv => {
  if (cached !== null) return cached;
  loadEnvFile();
  // In dev, default the cloud origin to the local Next server rather than
  // the compiled-in production origin.
  const originDefault = isDevMode() ? DEV_CLOUD_ORIGIN : compiledCloudOrigin();
  // Precedence: an explicit env var (the installed prod daemon sets it, and a
  // dev-adopted origin persists here via `setCloudOrigin`) wins; then the
  // default.
  // Refuse an insecure configured origin (http:// off-loopback, or an
  // unparseable value): the daemon sends `Bearer <apiKey>` to this origin on
  // every cloud call and self-updates from it, so honoring cleartext HTTP is
  // key exfiltration plus a MITM code-exec path. Fall back to the secure
  // compiled/dev default rather than wedging the process — the key is then
  // only ever sent over TLS (or to a loopback dev gateway).
  const configuredOrigin = (
    process.env.OPENLLM_CLOUD_ORIGIN ?? originDefault
  ).replace(/\/+$/, "");
  let cloudOrigin = configuredOrigin;
  if (!isSecureOrigin(cloudOrigin)) {
    logWarn(
      "env",
      `refusing insecure OPENLLM_CLOUD_ORIGIN (${configuredOrigin}) — the cloud origin must be https (http is allowed only for 127.0.0.1/localhost); using ${originDefault} instead`,
    );
    cloudOrigin = originDefault;
  }
  cached = {
    apiKey: loadApiKey(),
    cloudOrigin,
    dashboardOrigin: (
      process.env.OPENLLM_DASHBOARD_ORIGIN ?? cloudOrigin
    ).replace(/\/+$/, ""),
  };
  return cached;
};

/** Resolved update-channel inputs; compiled cloud defaults are not explicit. */
export const daemonUpdateRoute = (): TUpdateRouteConfig => {
  loadEnvFile();
  const env = daemonEnv();
  return {
    channel: resolveUpdateSetting(
      process.env.OPENLLM_UPDATE_CHANNEL,
      undefined,
    ),
    gatewayOrigin: env.cloudOrigin,
    gatewayOriginExplicit:
      (process.env.OPENLLM_CLOUD_ORIGIN?.trim().length ?? 0) > 0,
  };
};

/**
 * Test-only: clear the memoized {@link daemonEnv} cache so the next call
 * re-reads `process.env`. Mirrors `resetSessionsForTest`. Never called in
 * production.
 */
export const resetDaemonEnvCacheForTest = (): void => {
  cached = null;
};

/** Apply a credential only after its durable env-file write has succeeded. */
export const applyPersistedApiKey = (key: string): void => {
  process.env.OPENLLM_API_KEY = key;
  const current = daemonEnv();
  cached = { ...current, apiKey: key };
};

/** Read one value from an exact env file without merging it into process state. */
export const envFileValue = (
  targetPath: string,
  key: string,
): string | null => {
  try {
    return parseEnvLines(readFileSync(targetPath, "utf-8")).get(key) ?? null;
  } catch {
    return null;
  }
};

/**
 * Persist a new API key (set from the dashboard) into the env file (`0600`) and
 * update the in-memory cache so the next cloud call uses it immediately. Pass
 * `null`/empty to clear it. The env file is the single source.
 */
export const setApiKey = (key: string | null): void => {
  const trimmed = key?.trim() ?? "";
  writeEnvFileVars({ OPENLLM_API_KEY: trimmed });
  process.env.OPENLLM_API_KEY = trimmed;
  // Refresh the cache in place so callers don't need to re-resolve env.
  const current = daemonEnv();
  cached = { ...current, apiKey: trimmed.length > 0 ? trimmed : null };
};

export const hasApiKey = (): boolean => daemonEnv().apiKey !== null;

/**
 * Per-boot shared secret for first-party LOCAL callers of `/v1/*` (SP-1).
 * Minted once per daemon process (rotating on every restart bounds a leaked
 * token's lifetime to one boot) and persisted `0600` under the state dir, so
 * every OpenLLM component running as this OS user — the `openllm` CLI, the
 * vendor-CLI launch envs it writes, the native runtime, and the daemon's own
 * mux dispatch — can read and present it. Other local users (a different
 * uid) and anything off-box cannot; a blind cross-site POST cannot guess it.
 *
 * The dev daemon gets a sibling file so it never clobbers the installed
 * daemon's token (same split as `.env` vs `.dev.env`).
 */
const LOCAL_CALLER_TOKEN_FILE = "local-caller-token";

/** Where the local caller token is persisted (0600, same-uid readers only). */
export const localCallerTokenFilePath = (): string =>
  join(
    stateDir(),
    isDevMode() ? `${LOCAL_CALLER_TOKEN_FILE}.dev` : LOCAL_CALLER_TOKEN_FILE,
  );

let cachedLocalCallerToken: string | null = null;

const persistLocalCallerToken = (token: string, filePath: string): void => {
  if (!writePrivateFileAtomic(filePath, token)) {
    logWarn(
      "env",
      safeDiagnosticMessage`failed to persist the local caller token`,
    );
  }
};

const pathEntryExists = (path: string): boolean => {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
};

export const localCallerToken = (): string => {
  const filePath = localCallerTokenFilePath();
  if (cachedLocalCallerToken !== null) {
    // The file is the handoff to sibling first-party components — if it
    // vanished (external cleanup, or a test re-pointed the state dir)
    // re-persist the SAME token rather than silently diverging. A symlink
    // standing in its place is never written through: the atomic writer
    // refuses unsafe targets and the in-memory token stays authoritative.
    if (!pathEntryExists(filePath)) {
      persistLocalCallerToken(cachedLocalCallerToken, filePath);
    }
    return cachedLocalCallerToken;
  }
  const token = randomBytes(32).toString("hex");
  persistLocalCallerToken(token, filePath);
  cachedLocalCallerToken = token;
  return token;
};

/**
 * Timing-safe check that `value` equals this daemon's local caller token.
 * Used by the `/v1/*` caller-auth design: first-party clients present the
 * token, and `forward.ts` swaps it for the real `sk-llm` key before the
 * cloud sees it (the token is meaningless upstream).
 */
export const isLocalCallerCredential = (value: string): boolean => {
  const expected = localCallerToken();
  if (value.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(value), Buffer.from(expected));
  } catch {
    return false;
  }
};

/**
 * Timing-safe check that `value` equals this daemon's configured API key —
 * the second accepted `/v1/*` credential. Vendor CLIs the daemon launches
 * inherit `OPENLLM_API_KEY` and already present it as their Bearer /
 * `x-api-key`, so the keyless-device gate must accept it or first-party
 * inference breaks. Null-safe: a keyless daemon (signed-out device, dev
 * bootstrap) matches nothing.
 */
export const isDaemonApiKeyCredential = (value: string): boolean => {
  const expected = daemonEnv().apiKey;
  if (expected === null || value.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(value), Buffer.from(expected));
  } catch {
    return false;
  }
};

/**
 * Re-point the daemon's cloud origin at runtime (DEV only — gated by the
 * caller in `control.ts`). PERSISTS the choice (so it survives a restart)
 * and updates the in-memory cache so the next bootstrap, usage record, and
 * API-key-hop forward target the new origin. Lets one local dev daemon serve
 * whichever deployment's dashboard it last followed (a preview, prod, or
 * localhost) without a reinstall. No-op on an empty origin.
 */
export const setCloudOrigin = (origin: string): void => {
  const trimmed = origin.replace(/\/+$/, "");
  if (trimmed.length === 0) return;
  // Never persist an origin the daemon must refuse at read time (NET-4):
  // http:// is accepted only for loopback dev gateways.
  if (!isSecureOrigin(trimmed)) {
    logWarn(
      "env",
      `refusing to set insecure OPENLLM_CLOUD_ORIGIN (${trimmed}) — the cloud origin must be https (http is allowed only for 127.0.0.1/localhost)`,
    );
    return;
  }
  // Persist into the shared env file (single source; `loadEnvFile` is source-aware
  // in dev), so mirror into process.env too. A failed write is surfaced but
  // non-fatal — the in-memory update below still applies for this process; only
  // restart durability is lost.
  if (!writeEnvFileVars({ OPENLLM_CLOUD_ORIGIN: trimmed })) {
    logWarn(
      "env",
      safeDiagnosticMessage`failed to persist OPENLLM_CLOUD_ORIGIN to the env file`,
    );
  }
  process.env.OPENLLM_CLOUD_ORIGIN = trimmed;
  const current = daemonEnv();
  cached = { ...current, cloudOrigin: trimmed, dashboardOrigin: trimmed };
};
