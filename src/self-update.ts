/**
 * Daemon self-update.
 *
 * The daemon ships as a compiled binary at `process.execPath`, supervised by
 * launchd (`KeepAlive`) / systemd (`Restart=always`) — so EXITING relaunches it
 * within ~2s. On each cloud bootstrap the daemon learns the published version
 * (`latest_version`); when it differs from the compiled `DAEMON_VERSION` we
 * download the matching target binary, verify its SHA-256 against the published
 * checksum, atomically swap it in, wait for in-flight `/v1` requests to drain,
 * then exit so the supervisor relaunches the new binary.
 *
 * Policy: CONVERGE to the published version, but NEVER DOWNGRADE — the
 * published version must be strictly newer (`update-policy.ts`). Rollback is
 * exclusively the explicit `.prev` restore below (`boot-guard.ts` after a
 * post-swap crash loop), not a cloud republish.
 *
 * Trust + safety: only managed compiled binaries self-update (a from-source dev
 * run reports `0.0.0-dev` and is skipped); the download is rejected unless its
 * SHA-256 matches the published digest (the same checksum the install script
 * verifies); the swap is atomic (same-dir temp + rename); and a persisted
 * attempt marker + cooldown bounds restart loops if a release is mis-published.
 *
 * Failure classes are treated differently on purpose: a DETERMINISTIC artifact
 * failure (SHA-256 mismatch, size cap, decompression, malformed digest, failed
 * pre-swap probe) permanently rejects that version on this host — re-fetching
 * the same bytes can never heal it — while a transient network error only
 * earns the bounded exponential backoff.
 */

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  openSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { gunzipSync } from "node:zlib";
import type { TUpdateRouteConfig } from "@openllmsh/protocol/update-policy";
import {
  evaluateUpdatePolicy,
  mayReplaceProductVersion,
} from "@openllmsh/protocol/update-policy";
import { DAEMON_RELEASE } from "../manifest";
import type { TDaemonTarget } from "../release-types";
import { DAEMON_TARGETS } from "../release-types";
import { autoUpdateEnabled } from "./auto-update-pref";
import type { TSupervisedChild } from "./child-supervisor";
import { drainDisposableChildren, superviseSpawn } from "./child-supervisor";
import { spawnCommand } from "./command";
import { getCloudState } from "./config";
import { endDaemonApply, tryBeginDaemonApply } from "./delegation/login-flow";
import { spawnCwd, spawnEnv } from "./delegation/spawn";
import { daemonEnv, daemonUpdateRoute } from "./env";
import { hardenMacBinary } from "./harden-binary";
import { logError, logInfo, logWarn, safeDiagnosticMessage } from "./logger";
import {
  autoUpdateSuspended,
  isUpdateRejected,
  recentlyAttempted,
  recordAttempt,
  rejectUpdateVersion,
} from "./state-file";
import { DAEMON_VERSION } from "./version";
import { nodeSpawnSync } from "./windows-process";

// Cap on how long we hold the restart waiting for `/v1` requests to drain.
const DRAIN_MAX_MS = 30_000;
const DRAIN_POLL_MS = 250;
// How long a completed daemon swap waits for an in-flight CLI converge (its
// probe child must not be drained mid-swap — UP-3).
const CLI_SWAP_DRAIN_WAIT_MS = 15_000;
// Download bounds (NR2-2): a hung CONNECTION still dies fast, but a slow link
// gets generous time. The stall bound kills a download that stops making
// progress; the total cap bounds worst-case runtime; neither rejects the
// artifact — a transport failure is transient, only backoff applies (TD-4).
const DOWNLOAD_CONNECT_MS = 60_000;
const DOWNLOAD_STALL_MS = 60_000;
const DOWNLOAD_TOTAL_MS = 15 * 60_000;
/**
 * Hard cap on a downloaded artifact (compressed AND decompressed). The real
 * binaries are ~40 MB gz / ~90 MB raw; 256 MiB leaves headroom while refusing
 * a hostile or corrupt endpoint before it can fill memory.
 */
export const MAX_BINARY_BYTES = 256 * 1024 * 1024;
/** Cap on the small `.sha256` digest body. */
const DIGEST_MAX_BYTES = 4_096;
/** Bound on the pre-swap `<binary> --version` health probe. */
const VERSION_PROBE_TIMEOUT_MS = 10_000;
const VERSION_PROBE_MAX_BYTES = 4_096;

/** What `openllmd --version` prints (`openllmd v2.8.0`). */
const DAEMON_VERSION_OUT = /openllmd v(\S+)/;

/**
 * A download-stage failure that can NEVER heal by re-fetching the same
 * version: oversized payload, corrupt/undecodable gzip, or a malformed
 * digest body. Distinct from a plain `Error` (transient network fault) so
 * the apply pipeline can permanently reject the version instead of just
 * backing off — after the backoff cap an unclassified failure would
 * re-download forever.
 */
export class DeterministicArtifactError extends Error {
  /**
   * Content-derived discriminator for the artifact that failed — used as the
   * rejection key when the advertised sha256 isn't known (e.g. a malformed
   * digest body: sha256 of the bad body). A corrected re-publish yields a
   * different key and is allowed through.
   */
  readonly artifactKey?: string;

  constructor(message: string, artifactKey?: string) {
    super(message);
    this.artifactKey = artifactKey;
  }
}

/** The rollback copy kept next to an updated binary (`<dest>.prev`). */
export const prevBinaryPath = (dest: string): string => `${dest}.prev`;

/**
 * Write the `.prev` rollback copy ATOMICALLY: same-dir pid temp → fsync →
 * rename (plus a best-effort dir fsync). A direct `copyFileSync(dest, prev)`
 * could leave a torn/empty `.prev` behind on power loss or a full disk —
 * exactly the corrupt-backup case `restorePreviousBinary` now probes for.
 * `copyFileSync` preserves the source mode, so the rollback copy lands
 * runnable at the same permission bits. Throws on failure — callers refuse
 * the swap (never update without a rollback path).
 */
export const writePrevBinaryAtomic = (
  src: string,
  prev: string = prevBinaryPath(src),
): void => {
  const tmp = join(dirname(prev), `.openllm.prev.${process.pid}.tmp`);
  try {
    copyFileSync(src, tmp);
    const fd = openSync(tmp, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, prev);
    try {
      const dirFd = openSync(dirname(prev), "r");
      try {
        fsyncSync(dirFd);
      } finally {
        closeSync(dirFd);
      }
    } catch {
      // best-effort dir durability — the file fsync above already holds
    }
  } catch (err) {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
    throw err;
  }
};

/** What a runnable product binary prints for `--version`
 *  (`openllm v…`, `openllmc v…`, `openllmd v…`). */
const PRODUCT_VERSION_OUT = /openllmd?c? v(\S+)/;

/** Bound on the `.prev` health probe before a restore. */
const RESTORE_PROBE_TIMEOUT_MS = 10_000;
const RESTORE_PROBE_MAX_BYTES = 4_096;

/**
 * Prove a `.prev` copy actually RUNS before it is restored: a torn or
 * truncated backup must not replace the current binary (the caller falls
 * through to the park path instead). `<prev> --version` is the right probe —
 * it works on every binary generation we ever shipped, including ones that
 * predate `--self-test`.
 */
const probeRunnablePrev = (path: string): boolean => {
  try {
    // Mandatory-admission spawn (`windows-process` is the sanctioned shim —
    // raw Bun.spawnSync is forbidden in daemon src). `nodeSpawnSync` keeps
    // the probe synchronous so `restorePreviousBinary` stays usable from the
    // sync crash-loop guard.
    const proc = nodeSpawnSync(path, ["--version"], {
      timeout: RESTORE_PROBE_TIMEOUT_MS,
      maxBuffer: RESTORE_PROBE_MAX_BYTES,
    });
    if (proc.error !== undefined || proc.status !== 0) return false;
    const out = Buffer.concat([
      proc.stdout ?? Buffer.alloc(0),
      proc.stderr ?? Buffer.alloc(0),
    ]).toString("utf-8");
    return PRODUCT_VERSION_OUT.test(out);
  } catch {
    return false;
  }
};

/**
 * Swap the `.prev` rollback copy back over `dest` (atomic rename — the copy
 * is consumed, so this fires once per backup). The backup is PROBED first:
 * a `.prev` that can't report its own version is corrupt and stays put so
 * the caller parks instead of installing a second dead binary. Best-effort:
 * false on any failure or missing backup. Shared by the crash-loop rollback
 * (`boot-guard.ts`) and the CLI converger's broken-install self-heal.
 */
export const restorePreviousBinary = (
  dest: string,
  opts?: { readonly probe?: (path: string) => boolean },
): boolean => {
  const prev = prevBinaryPath(dest);
  try {
    if (!existsSync(prev)) return false;
    if (!(opts?.probe ?? probeRunnablePrev)(prev)) return false;
    renameSync(prev, dest); // prev already carries the original binary's mode
    hardenMacBinary(dest);
    return true;
  } catch {
    return false;
  }
};

/** The manual remedy printed on every refused update — one clear line. */
export const manualUpdateRemedy = (origin: string): string =>
  `to update manually, re-run the installer: curl -fsSL ${origin}/install | bash`;

/** Is `pid` a live (or unverifiable, EPERM) process on this host? */
const pidAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
};

// Staging-temp name shapes swept below. Both updater families stage next to
// the destination binary so a crash mid-update leaves the ~90 MB temp in the
// install dir (FSS-16/FSS-17) — dead-pid files are orphans and are removed.
const UPDATE_TEMP_RE =
  /^\.openllm[cd]?\.(?:update|prev)\.(\d+)(?:\.[^.]*)?\.tmp$/;
const CLI_NEXT_TEMP_RE = /^\.openllm\.next-(\d+)(?:-.*)?$/;

/**
 * Remove staging temps left in `dir` by a DEAD updater process (its pid is
 * encoded in the file name). A live pid's file is never touched — that is
 * the in-flight download of a concurrent updater. Best-effort; never throws.
 */
export const sweepStaleUpdateTemps = (dir: string): void => {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const match = UPDATE_TEMP_RE.exec(entry) ?? CLI_NEXT_TEMP_RE.exec(entry);
    if (match === null) continue;
    const pid = Number(match[1]);
    if (!(pid > 0) || pidAlive(pid)) continue;
    try {
      rmSync(join(dir, entry), { force: true });
    } catch {
      // best-effort residue cleanup
    }
  }
};

/** fsync one file's bytes to stable storage. Throws on failure. */
export const fsyncFileSync = (path: string): void => {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
};

/**
 * fsync a directory so rename dirents survive a crash (FSS-18). Best-effort:
 * some filesystems refuse directory fsync — never throws.
 */
export const fsyncDirBestEffort = (dir: string): void => {
  try {
    fsyncFileSync(dir);
  } catch {
    // best-effort — e.g. a filesystem without directory fsync
  }
};

/**
 * What one binary probe (`<path> --version` / `--self-test`) proved.
 *
 * The three-way split is the load-bearing part of the whole updater
 * (RT-2/TD-5/UP-2/UP-3/FSS-05):
 *
 *  - `ok`           — exit 0 within the bound; `out` is trimmed stdout.
 *  - `failed`       — DETERMINISTIC artifact failure: nonzero exit, a crash
 *                     signal (SIGSEGV/SIGBUS/SIGILL/SIGABRT/SIGFPE), output
 *                     overflow, or a spawn-level refusal (ELOOP/ENOEXEC —
 *                     re-probing the same bytes can never change it).
 *  - `inconclusive` — TRANSIENT/environmental: timeout, a non-crash signal
 *                     (SIGTERM/SIGKILL — e.g. the idle-child drain racing the
 *                     probe), or an environmental spawn error (ENOENT/EACCES/
 *                     EAGAIN/EMFILE/ENOMEM/ETXTBSY). NEVER a reason to reject
 *                     or roll back — the bytes were not judged.
 */
export type TBinaryProbeVerdict =
  | { readonly kind: "ok"; readonly out: string }
  | { readonly kind: "failed"; readonly detail: string }
  | { readonly kind: "inconclusive"; readonly detail: string };

const PROBE_CRASH_SIGNALS = new Set([
  "SIGSEGV",
  "SIGBUS",
  "SIGILL",
  "SIGABRT",
  "SIGFPE",
  "SIGSYS",
  "SIGTRAP",
]);
const PROBE_TRANSIENT_SPAWN_CODES = new Set([
  "EAGAIN",
  "ENOMEM",
  "EMFILE",
  "ENFILE",
  "EACCES",
  "EPERM",
  "ENOENT",
  "EIO",
  "ETXTBSY",
]);

/**
 * Run `<path> <flag>` once under the child supervisor and classify the
 * outcome as ok / deterministic-failure / inconclusive (above). The child
 * runs UNWRAPPED (`kind:"probe"` — a fixed-argv read-only probe, the same
 * trust class `runCapture` used) and holds a task LEASE for its whole
 * lifetime (UP-3): a graceful `drainDisposableChildren` spares leased
 * children, so a daemon restart cannot kill a live update probe — and even
 * an external kill lands as `inconclusive`, never a rejection.
 *
 * `TMPDIR` is repointed at the binary's own directory: the probe must not
 * depend on a usable system temp (FSS-05) — the staged file already proves
 * that directory is writable.
 */
export const probeBinaryVerdict = async (
  path: string,
  flag: "--version" | "--self-test",
  opts?: { timeoutMs?: number; maxBytes?: number },
): Promise<TBinaryProbeVerdict> => {
  const timeoutMs = opts?.timeoutMs ?? VERSION_PROBE_TIMEOUT_MS;
  const maxBytes = opts?.maxBytes ?? VERSION_PROBE_MAX_BYTES;
  let child: TSupervisedChild;
  try {
    child = superviseSpawn(spawnCommand(process.platform, path, [flag]), {
      kind: "probe",
      stdin: "ignore",
      stdout: "pipe",
      stderr: "ignore",
      cwd: spawnCwd(undefined),
      env: spawnEnv({ TMPDIR: dirname(path) }),
    });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== undefined && PROBE_TRANSIENT_SPAWN_CODES.has(code)) {
      return {
        kind: "inconclusive",
        detail: `probe spawn failed: ${code}`,
      };
    }
    return {
      kind: "failed",
      detail: `probe spawn failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  const endTask = child.beginTask();
  let timer: ReturnType<typeof setTimeout> | null = null;
  const run = (async (): Promise<TBinaryProbeVerdict> => {
    try {
      const stdout = child.subprocess.stdout;
      if (
        stdout === null ||
        stdout === undefined ||
        typeof stdout === "number"
      ) {
        await child.terminate();
        return { kind: "inconclusive", detail: "probe stdout was not piped" };
      }
      const reader = stdout.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      let overflow = false;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          overflow = true;
          break;
        }
        chunks.push(value);
      }
      await child.subprocess.exited;
      const signal = child.subprocess.signalCode;
      if (signal !== null) {
        return PROBE_CRASH_SIGNALS.has(signal)
          ? { kind: "failed", detail: `probe crashed on ${signal}` }
          : { kind: "inconclusive", detail: `probe killed by ${signal}` };
      }
      const code = child.subprocess.exitCode;
      if (code !== 0) {
        return { kind: "failed", detail: `probe exited ${code}` };
      }
      if (overflow) {
        return { kind: "failed", detail: "probe output overflow" };
      }
      return {
        kind: "ok",
        out: Buffer.concat(chunks).toString("utf-8").trim(),
      };
    } catch (err) {
      return {
        kind: "inconclusive",
        detail: `probe failed to complete: ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
  })();
  try {
    const winner = await Promise.race([
      run,
      new Promise<"timeout">((resolve) => {
        timer = setTimeout(() => resolve("timeout"), timeoutMs);
      }),
    ]);
    if (winner === "timeout") {
      try {
        await child.terminate();
      } catch {
        // best-effort — the supervisor reaps it regardless
      }
      return {
        kind: "inconclusive",
        detail: `probe timed out after ${timeoutMs}ms`,
      };
    }
    return winner;
  } finally {
    if (timer !== null) clearTimeout(timer);
    endTask();
  }
};

/** Per-download bounds: stall = no bytes for this long; total = hard cap. */
export type TDownloadBounds = {
  readonly stallMs?: number;
  readonly totalMs?: number;
};

/**
 * Stream a response body with a hard byte cap — count while reading so an
 * oversized payload is rejected BEFORE it is buffered (content-length is an
 * early hint only; a lying endpoint is still caught by the count).
 *
 * NR2-2: the byte cap is joined by a STALL bound (no chunk for `stallMs` →
 * abort) and a TOTAL cap (`totalMs` elapsed → abort). Both throw plain
 * `Error`s — transport faults are transient and earn only backoff, never a
 * permanent artifact rejection (TD-4). Only oversize stays deterministic.
 */
const readBodyCapped = async (
  res: Response,
  maxBytes: number,
  label: string,
  bounds?: TDownloadBounds,
): Promise<Buffer> => {
  // Hash whatever arrives so an oversize rejection can still be keyed to the
  // exact bytes that failed (a corrected re-publish gets a different prefix
  // and is allowed through — the round-3 version+digest reject key).
  const keyHash = createHash("sha256");
  const declared = Number(res.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > maxBytes) {
    try {
      await res.body?.cancel();
    } catch {
      // best-effort abort
    }
    throw new DeterministicArtifactError(
      `${label} exceeds the ${maxBytes}-byte cap`,
    );
  }
  if (res.body === null) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  const stallMs = bounds?.stallMs ?? DOWNLOAD_STALL_MS;
  const totalMs = bounds?.totalMs ?? DOWNLOAD_TOTAL_MS;
  const deadline = Date.now() + totalMs;
  let total = 0;
  for (;;) {
    let stallTimer: ReturnType<typeof setTimeout> | null = null;
    const stalled = new Promise<"stalled">((resolve) => {
      stallTimer = setTimeout(() => resolve("stalled"), stallMs);
    });
    try {
      const read = await Promise.race([reader.read(), stalled]);
      if (read === "stalled") {
        try {
          await reader.cancel();
        } catch {
          // best-effort abort
        }
        throw new Error(`${label} stalled — no bytes for ${stallMs}ms`);
      }
      if (read.done) break;
      total += read.value.byteLength;
      keyHash.update(read.value);
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // best-effort abort
        }
        throw new DeterministicArtifactError(
          `${label} exceeds the ${maxBytes}-byte cap`,
          keyHash.digest("hex"),
        );
      }
      if (Date.now() > deadline) {
        try {
          await reader.cancel();
        } catch {
          // best-effort abort
        }
        throw new Error(`${label} exceeded its ${totalMs}ms total budget`);
      }
      chunks.push(read.value);
    } finally {
      if (stallTimer !== null) clearTimeout(stallTimer);
    }
  }
  return Buffer.concat(chunks);
};

// ─── In-flight `/v1` request tracking (for wait-until-idle restart) ──────────
let inFlightCount = 0;
export const beginRequest = (): void => {
  inFlightCount += 1;
};
export const endRequest = (): void => {
  if (inFlightCount > 0) inFlightCount -= 1;
};
export const inFlight = (): number => inFlightCount;

/**
 * Wrap a streaming response body so `onDone` fires EXACTLY once when the stream
 * finishes — normal end, error, or client cancel. A `/v1` response body keeps
 * flowing after the fetch handler returns, so this is how the in-flight count
 * stays accurate for long streams (and the wait-until-idle restart actually
 * waits for them).
 */
export const trackBodyDone = (
  body: ReadableStream<Uint8Array>,
  onDone: () => void,
): ReadableStream<Uint8Array> => {
  const reader = body.getReader();
  let settled = false;
  const finish = (): void => {
    if (!settled) {
      settled = true;
      onDone();
    }
  };
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          finish();
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (err) {
        finish();
        controller.error(err);
      }
    },
    cancel(reason) {
      finish();
      return reader.cancel(reason);
    },
  });
};

/**
 * Resolve the POSIX release target used by the daemon's rename-swap updater.
 * Windows artifacts exist, but applying one over a running executable is not a
 * Phase 2 capability, so Windows is rejected before the canonical mapping.
 */
export const selfUpdateTargetForHost = (
  platform: NodeJS.Platform,
  architecture: string,
): TDaemonTarget | null => {
  if (platform === "win32") return null;
  const arch =
    architecture === "x64"
      ? "x64-baseline"
      : architecture === "arm64"
        ? "arm64"
        : null;
  if (arch === null) return null;
  const t = `${platform}-${arch}`;
  return (DAEMON_TARGETS as readonly string[]).includes(t)
    ? (t as TDaemonTarget)
    : null;
};

/** This process's supported self-update target, preserving the existing API. */
export const currentTarget = (): TDaemonTarget | null =>
  selfUpdateTargetForHost(process.platform, process.arch);

export const mayUpdateDaemonVersion = (
  currentVersion: string,
  latestVersion: string | null,
  route: TUpdateRouteConfig,
): boolean =>
  mayReplaceProductVersion({ currentVersion, latestVersion, ...route });

/**
 * Shared by the daemon self-updater and the CLI converger
 * (`cli-self-update.ts`). The body is streamed and counted, so a payload
 * larger than `maxBytes` is refused before it is fully buffered.
 */
export const fetchBinary = async (
  url: string,
  maxBytes: number = MAX_BINARY_BYTES,
  bounds?: TDownloadBounds & { readonly connectMs?: number },
): Promise<Buffer> => {
  const res = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(bounds?.connectMs ?? DOWNLOAD_CONNECT_MS),
  });
  if (!res.ok) throw new Error(`binary download failed: ${res.status}`);
  const buf = await readBodyCapped(res, maxBytes, "binary download", bounds);
  // The published asset is gzipped (`openllmd-<target>.gz`); decompress when the
  // gzip magic bytes (0x1f 0x8b) are present, tolerating a raw binary too. The
  // sha256 is checked against the DECOMPRESSED bytes (what runs), so the gate is
  // gzip-determinism-independent. `maxOutputLength` bounds a gzip bomb too.
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      return Buffer.from(gunzipSync(buf, { maxOutputLength: maxBytes }));
    } catch (err) {
      throw new DeterministicArtifactError(
        `binary decompression failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
        createHash("sha256").update(buf).digest("hex"),
      );
    }
  }
  return buf;
};

// The `.sha256` endpoint returns `"<hex>  openllmd-<target>\n"` — take the hex.
// Shared by the daemon self-updater and the CLI converger (`cli-self-update.ts`).
export const fetchDigest = async (
  url: string,
  bounds?: TDownloadBounds & { readonly connectMs?: number },
): Promise<string> => {
  const res = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(bounds?.connectMs ?? DOWNLOAD_CONNECT_MS),
  });
  if (!res.ok) throw new Error(`checksum download failed: ${res.status}`);
  const text = (
    await readBodyCapped(res, DIGEST_MAX_BYTES, "checksum download", bounds)
  )
    .toString("utf-8")
    .trim();
  const hex = text.split(/\s+/)[0] ?? "";
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    // Key the rejection to the BAD BODY (sha256 of what was served): a
    // corrected re-publish serves a valid digest, hashes differently, and is
    // allowed — while THIS broken response stays rejected.
    throw new DeterministicArtifactError(
      "checksum response was not a sha-256 digest",
      createHash("sha256").update(text).digest("hex"),
    );
  }
  return hex.toLowerCase();
};

const waitUntilIdle = async (): Promise<void> => {
  const deadline = Date.now() + DRAIN_MAX_MS;
  while (inFlight() > 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, DRAIN_POLL_MS));
  }
};

/**
 * UP-3: the CLI converger's probe+swap must not race the idle drain on a
 * daemon restart — a probe killed mid-run used to look like a dead binary and
 * got a good CLI release rejected. The probe itself now holds a supervisor
 * task lease (the drain spares it), and this wait lets an in-flight swap
 * region land before we reap anything. Bounded; a wedged converger cannot
 * hold the restart forever.
 */
const waitForCliSwapRegion = async (): Promise<void> => {
  try {
    const { cliSwapInFlight } = await import("./cli-self-update");
    const inFlightSwap = cliSwapInFlight();
    if (inFlightSwap === null) return;
    await Promise.race([
      inFlightSwap,
      new Promise((resolve) => setTimeout(resolve, CLI_SWAP_DRAIN_WAIT_MS)),
    ]);
  } catch {
    // best-effort — the drain must not be gated on a broken import
  }
};

// Re-entrancy guard: a bootstrap-refresh tick and a force-update command could
// both fire `maybeSelfUpdate`; only one swap+exit should run.
let updating = false;

// The Windows self-update warning fires on every bootstrap tick (main.ts calls
// `maybeSelfUpdate` per tick); log it ONCE per process — the unavailability is
// a fixed property of the build, not per-tick news.
let windowsUnavailableWarned = false;

// The auto-update suspension (state file unwritable) logs once per process —
// the condition is sticky, not per-tick news. Reset by the state-file's own
// probe succeeding (the suspension lifts itself).
let guardSuspensionWarned = false;

/**
 * Exclusive apply lease for a daemon swap. `alreadyHeld` is the explicit
 * `update` command (scheduler apply lane). Passive/catch-up acquire here or
 * skip when auth/apply already owns the process. Successful `process.exit`
 * never reaches the release.
 */
export const withSelfUpdateApply = async (
  alreadyHeld: boolean,
  work: () => Promise<void>,
): Promise<void> => {
  const acquired = alreadyHeld ? false : tryBeginDaemonApply();
  if (!alreadyHeld && !acquired) return;
  try {
    await work();
  } finally {
    if (acquired) endDaemonApply();
  }
};

/**
 * Outcome of one update apply. `updated` means the verified+probed binary was
 * swapped in and the attempt recorded; every `failed` variant also recorded
 * its try so the next one backs off.
 */
export type TSelfUpdateOutcome =
  | { readonly kind: "updated" }
  | {
      readonly kind: "failed";
      readonly stage:
        | "download"
        | "checksum"
        | "write"
        | "probe"
        | "probe-inconclusive"
        | "rejected";
      readonly detail?: string;
    }
  /**
   * The cross-process swap lock was held by another updater (manual
   * `openllm self-update` racing this converger). Not a failure — nothing
   * was attempted, so nothing is recorded; the next tick retries.
   */
  | { readonly kind: "busy" };

/**
 * Download → verify → probe → backup → swap `dest` to the binary serving
 * `target` at `latest`, from `origin`. Stage boundaries so each failure mode
 * is recorded distinctly (TCB-2: an unrecorded failure re-downloads ~40 MB on
 * every bootstrap tick):
 *
 *   1. fetch binary (size-capped stream) + digest;
 *   2. sha256 must match — a mismatch means a mis-publish, record + back off;
 *   3. stage to a pid temp and probe `<tmp> --version` — a binary that cannot
 *      exec or reports the wrong version is REJECTED (never re-downloaded);
 *   4. copy the CURRENT binary to `<dest>.prev` before the atomic rename —
 *      the rollback copy `boot-guard.ts` restores after a post-swap crash loop;
 *   5. record the try (success too — a swap that doesn't converge must back
 *      off on the relaunched binary's next tick).
 */
export const applyDaemonSelfUpdate = async (args: {
  readonly dest: string;
  readonly latest: string;
  readonly target: TDaemonTarget;
  readonly origin: string;
  readonly maxBytes?: number;
  readonly probeVersion?: (path: string) => Promise<string | null>;
  /**
   * Test seam: a full verdict probe (default `probeBinaryVerdict`). Present
   * so a regression can simulate a kill/timeout — `probeVersion` (string or
   * null) cannot express "inconclusive".
   */
  readonly probeVerdict?: (
    path: string,
    flag: "--version" | "--self-test",
  ) => Promise<TBinaryProbeVerdict>;
  /** Test seam: shorten the probe bound instead of waiting 10 s. */
  readonly probeTimeoutMs?: number;
  /** Test seam: tighten the download stall/total/connect bounds. */
  readonly download?: TDownloadBounds & { readonly connectMs?: number };
}): Promise<TSelfUpdateOutcome> => {
  const { dest, latest, target, origin } = args;
  const maxBytes = args.maxBytes ?? MAX_BINARY_BYTES;
  const verdictProbe =
    args.probeVerdict ??
    ((path: string, flag: "--version" | "--self-test") =>
      probeBinaryVerdict(path, flag, { timeoutMs: args.probeTimeoutMs }));
  // FSS-16: unique staging name (UP-1-safe) + sweep temps a dead updater left.
  sweepStaleUpdateTemps(dirname(dest));
  const tmp = join(
    dirname(dest),
    `.openllmd.update.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
  );
  try {
    const base = `${origin}/api/daemon/binary/${target}`;
    // The tiny digest fetch comes FIRST: the advertised artifact sha256 is
    // the rejection key, so it must be known before anything else can be
    // judged (and before the ~40 MB binary download is spent on an artifact
    // already proven bad).
    let expected: string;
    try {
      expected = await fetchDigest(`${base}.sha256`, args.download);
    } catch (err) {
      recordAttempt("daemon", latest, {
        digest:
          err instanceof DeterministicArtifactError
            ? err.artifactKey
            : undefined,
      });
      if (err instanceof DeterministicArtifactError) {
        // Malformed/oversized digest body: deterministic — reject keyed to
        // the content that failed (sha256 of the bad body), so a corrected
        // re-publish of the same version is allowed through.
        rejectUpdateVersion("daemon", latest, err.artifactKey ?? "");
      }
      return {
        kind: "failed",
        stage: "download",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    if (isUpdateRejected("daemon", latest, expected)) {
      // The currently advertised artifact is already proven bad on this
      // host — do not spend the ~40 MB download again. A corrected
      // re-publish advertises a DIFFERENT digest and passes this gate.
      recordAttempt("daemon", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "rejected",
        detail: `v${latest} artifact ${expected.slice(0, 12)}… previously failed deterministic checks`,
      };
    }
    let bin: Buffer;
    try {
      bin = await fetchBinary(base, maxBytes, args.download);
    } catch (err) {
      recordAttempt("daemon", latest, { digest: expected });
      if (err instanceof DeterministicArtifactError) {
        // Deterministic failure (oversize / bad gzip): the advertised
        // artifact itself is bad — reject keyed to its digest so a
        // corrected re-publish is allowed through.
        rejectUpdateVersion("daemon", latest, expected);
      }
      return {
        kind: "failed",
        stage: "download",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    const actual = createHash("sha256").update(bin).digest("hex");
    if (actual !== expected) {
      // A checksum mismatch is a mis-published artifact: deterministic —
      // reject permanently instead of retrying the same bytes after backoff.
      rejectUpdateVersion("daemon", latest, expected);
      recordAttempt("daemon", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "checksum",
        detail: `expected ${expected}, got ${actual}`,
      };
    }
    try {
      writeFileSync(tmp, bin, { mode: 0o755 });
      chmodSync(tmp, 0o755); // force mode regardless of umask
      // FSS-18: fsync the staged bytes BEFORE the rename — the swap is only
      // durable if the file's contents are on stable storage first.
      fsyncFileSync(tmp);
    } catch (err) {
      recordAttempt("daemon", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "write",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
    // Sign/dequarantine BEFORE the probe so the staged binary can exec on
    // Apple Silicon (unsigned arm64 binaries are SIGKILLed on spawn).
    hardenMacBinary(tmp);
    if (args.probeVersion !== undefined) {
      // Legacy contract (tests): a string is the probe output; null is a
      // completed run that produced no version banner — a deterministic
      // artifact failure. Timeouts/kills are impossible to express here;
      // the verdict path below is the production probe.
      const out = await args.probeVersion(tmp);
      if (out?.match(DAEMON_VERSION_OUT)?.[1] !== latest) {
        rejectUpdateVersion("daemon", latest, expected);
        recordAttempt("daemon", latest, { digest: expected });
        return {
          kind: "failed",
          stage: "probe",
          detail:
            out === null
              ? "binary did not run"
              : `expected v${latest}, got ${out.trim().slice(0, 200)}`,
        };
      }
    } else {
      const verdict = await verdictProbe(tmp, "--version");
      if (verdict.kind === "inconclusive") {
        // UP-2/TD-5: the probe never judged the bytes (timeout, drain kill,
        // broken probe environment) — record the try and back off, but do
        // NOT reject the artifact. A good release must not be convicted by
        // an unreliable probe.
        recordAttempt("daemon", latest, { digest: expected });
        return {
          kind: "failed",
          stage: "probe-inconclusive",
          detail: verdict.detail,
        };
      }
      const probed =
        verdict.kind === "ok"
          ? (verdict.out.match(DAEMON_VERSION_OUT)?.[1] ?? null)
          : null;
      if (probed !== latest) {
        // A bad artifact cannot heal by re-downloading the same bytes — it
        // would loop a ~40 MB download forever. Reject this artifact outright.
        rejectUpdateVersion("daemon", latest, expected);
        recordAttempt("daemon", latest, { digest: expected });
        return {
          kind: "failed",
          stage: "probe",
          detail:
            verdict.kind === "failed"
              ? `binary did not run: ${verdict.detail}`
              : `expected v${latest}, got ${verdict.out.slice(0, 200)}`,
        };
      }
    }
    // Keep the working binary next to the new one (`<dest>.prev`) so a
    // post-swap crash loop can roll back (see `boot-guard.ts`). Written via
    // temp + fsync + rename so a crash mid-copy can't leave a torn backup.
    try {
      writePrevBinaryAtomic(dest);
    } catch (err) {
      // Backup failed — do NOT swap without a rollback path (TCB-3): a bad
      // publish would crash-loop with no recovery. Record + back off.
      recordAttempt("daemon", latest, { digest: expected });
      return {
        kind: "failed",
        stage: "write",
        detail: `rollback backup failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
    renameSync(tmp, dest); // atomic on POSIX; running process keeps old inode
    // FSS-18: fsync the directory so the rename's dirent survives a crash —
    // otherwise power loss could resurrect the old binary (or lose both).
    fsyncDirBestEffort(dirname(dest));
    hardenMacBinary(dest); // dequarantine + ad-hoc sign so arm64 can exec it
    recordAttempt("daemon", latest, { digest: expected });
    return { kind: "updated" };
  } catch (err) {
    recordAttempt("daemon", latest);
    return {
      kind: "failed",
      stage: "write",
      detail: err instanceof Error ? err.message : String(err),
    };
  } finally {
    // FSS-16: no staging temp survives ANY exit path — success (renamed away),
    // probe failure, backup failure, or an unexpected throw mid-pipeline.
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort temp cleanup
    }
  }
};

/**
 * Update to `latest` (the cloud's published version) when it differs from this
 * binary, then exit so the supervisor relaunches it. No-op (returns) when not
 * applicable — auto-update opted out, running from source, already converged,
 * cloud snapshot stale, unknown target, version rejected, or still inside a
 * previous try's backoff. Never throws into the caller.
 *
 * Self-update is OPT-OUT (on by default): the automatic callers (boot + each
 * bootstrap tick) are gated on {@link autoUpdateEnabled}, which only returns
 * false once the user has explicitly disabled it. An EXPLICIT user request —
 * the dashboard's "update now" command — passes `force: true` to run the
 * convergence even when disabled. See `packages/daemon/src/auto-update-pref.ts`.
 */
export const maybeSelfUpdate = async (
  latest: string | null,
  opts?: { readonly force?: boolean; readonly applyHeld?: boolean },
): Promise<void> => {
  if (process.platform === "win32") {
    // Windows self-update is checked on every bootstrap tick; only the FIRST
    // tick logs — a per-tick warning is noise, the condition never changes.
    if (!windowsUnavailableWarned) {
      windowsUnavailableWarned = true;
      logWarn(
        "self-update",
        "daemon self-update is unavailable on Windows during Phase 2; install a current Windows daemon package instead",
      );
    }
    return;
  }
  if (updating) return;
  // Opt-out gate: skip automatic updates only when the user disabled them
  // (default on). A forced (explicit) check bypasses it — the user asked for
  // this one update.
  if (opts?.force !== true && !autoUpdateEnabled()) return;
  // Only managed compiled binaries self-update; a from-source run is `0.0.0-dev`.
  if (DAEMON_VERSION === "0.0.0-dev") return;
  if (latest === null || latest.length === 0) return;
  if (latest === DAEMON_VERSION) return; // already converged
  // Fail closed (round-3): a deterministic-failure reject that could not be
  // persisted means OTHER processes can retry the bad artifact — this process
  // must not join the churn. Suspended until a state write lands (the gate
  // probes a real write each call, so a transient full-disk window heals).
  if (autoUpdateSuspended()) {
    if (!guardSuspensionWarned) {
      guardSuspensionWarned = true;
      logWarn(
        "self-update",
        "update state is not writable — auto-update suspended until rejection guards can be persisted",
      );
    }
    return;
  }
  const origin = daemonEnv().cloudOrigin;
  // Never act on a stale snapshot: while the cloud isn't `ok`,
  // `latest_version` is last-good data and the binary endpoints are the same
  // service that's failing — a forced (explicit user) check may still try.
  if (opts?.force !== true && getCloudState() !== "ok") return;
  const verdict = evaluateUpdatePolicy({
    currentVersion: DAEMON_VERSION,
    latestVersion: latest,
    ...daemonUpdateRoute(),
  });
  if (!verdict.allow) {
    logInfo(
      "self-update",
      `refusing ${DAEMON_VERSION} → ${latest}: ${verdict.reason ?? "update policy"} — ${manualUpdateRemedy(origin)}`,
    );
    return;
  }
  const target = currentTarget();
  if (target === null) {
    // No prebuilt binary for this arch — point at the source repo (build from
    // source / request the arch) via DAEMON_RELEASE.repo.
    logWarn(
      "self-update",
      `unsupported host ${process.platform}-${process.arch} — no prebuilt openllmd for this arch; see https://github.com/${DAEMON_RELEASE.repo}`,
    );
    return;
  }
  if (isUpdateRejected("daemon", latest)) {
    logInfo(
      "self-update",
      `v${latest} was rejected on this host (failed its post-download check or crash-looped) — it will not be reinstalled; ${manualUpdateRemedy(origin)}`,
    );
    return;
  }
  if (recentlyAttempted("daemon", latest)) return;

  await withSelfUpdateApply(opts?.applyHeld === true, async () => {
    updating = true;
    try {
      const outcome = await applyDaemonSelfUpdate({
        dest: process.execPath,
        latest,
        target,
        origin,
      });
      if (outcome.kind === "updated") {
        logInfo(
          "self-update",
          `updated ${DAEMON_VERSION} → ${latest}; restarting when idle`,
        );
        await waitUntilIdle();
        // UP-3: let a concurrent CLI converge finish its swap region before
        // the drain — its probe holds a task lease, but its remaining swap
        // work must still land before this process exits.
        await waitForCliSwapRegion();
        // The binary has already swapped; bounded cleanup must not prevent the exit
        // that lets launchd/systemd start the replacement daemon.
        await drainDisposableChildren();
        process.exit(0);
      }
      if (outcome.kind === "busy") {
        // The daemon swap is not under the CLI lock today — the type is
        // shared with the CLI converger — but handle it so a future lock
        // can't fall through to the failure log below.
        logInfo(
          "self-update",
          "another update holds the swap lock — retrying on the next tick",
        );
        return;
      }
      if (outcome.stage === "checksum") {
        logError(
          "self-update",
          safeDiagnosticMessage`checksum mismatch — refusing update`,
          { target, latest, detail: outcome.detail ?? "" },
        );
      } else if (outcome.stage === "probe") {
        logError(
          "self-update",
          `downloaded v${latest} failed its pre-swap --version check (${outcome.detail ?? "unknown"}) — rejected; ${manualUpdateRemedy(origin)}`,
          { target, latest },
        );
      } else if (outcome.stage === "probe-inconclusive") {
        // TD-5/UP-2: a transient probe (timeout/kill/env) — attempt recorded,
        // backoff applied, artifact NOT rejected. Not an error.
        logWarn(
          "self-update",
          `pre-swap probe of v${latest} was inconclusive (${outcome.detail ?? "unknown"}) — backing off without rejecting the artifact`,
          { target, latest },
        );
      } else {
        logError("self-update", outcome.detail ?? outcome.stage, {
          target,
          latest,
          stage: outcome.stage,
        });
      }
    } catch (err) {
      logError("self-update", err, { target, latest });
    } finally {
      updating = false; // allow a retry on the next bootstrap tick
    }
  });
};
