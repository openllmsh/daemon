/**
 * Provision the daemon's isolated view of the vendor CLIs WITHOUT duplicating
 * any bytes on disk. There is ONE binary per CLI — the user's NON-isolated copy
 * — and the isolated path under `<stateDir>/cli/<provider>/` is always a
 * SYMLINK to it. Isolation is preserved by the RUN env (`cliEnv` points
 * HOME/config at the isolated dir), not by a separate binary, so credentials +
 * config never collide with the user's personal `~/.claude` / `~/.codex` /
 * `~/.kimi-code` while the binary itself is shared.
 *
 * Single install path (no reverse copy): if the user already has the CLI (or
 * ran the integrations setup first, which installs it), it's reused as-is;
 * otherwise the OFFICIAL vendor installer runs ONCE for the non-isolated
 * location. Either way the isolated path is then symlinked to it:
 *   claude → https://claude.ai/install.sh
 *   codex  → https://chatgpt.com/codex/install.sh
 *   kimi   → https://code.kimi.com/kimi-code/install.sh
 */
import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import type { TCliProvider } from "./cli-paths";
import {
  cliBin,
  cliConfigDir,
  cliEnv,
  cliHome,
  cliRoot,
  hostCliCandidates,
  hostInstallEnv,
} from "./cli-paths";
import { runCapture } from "./delegation/util";
import { logInfo } from "./logger";
import { DEFAULT_BIN_DIRS } from "./path-utils";
import { daemonTempDir } from "./sandbox/working-set";

const INSTALL_SCRIPT: Readonly<Record<TCliProvider, string>> = {
  claude_code: "https://claude.ai/install.sh",
  chatgpt: "https://chatgpt.com/codex/install.sh",
  kimi_code: "https://code.kimi.com/kimi-code/install.sh",
  // The official Grok Build curl installer. Verified live (2026-06-30): the URL
  // serves the real install script over HTTP 200 — it is NOT Cloudflare-walled,
  // and grok ships no npm package, so curl is the only install path.
  grok: "https://x.ai/cli/install.sh",
};

/** Hard ceiling for a vendor install — a stalled download/install is killed so
 *  it can't wedge the daemon's serial control loop. Generous (binaries are
 *  100MB+), short enough to fail visibly rather than hang forever. */
const INSTALL_TIMEOUT_MS = 5 * 60_000;

export type TCliInstallState = {
  readonly installed: boolean;
  readonly version: string | null;
};

/** Is the isolated binary present + executable? Best-effort version read. */
export const cliInstallState = async (
  provider: TCliProvider,
): Promise<TCliInstallState> => {
  const bin = cliBin(provider);
  if (!existsSync(bin)) return { installed: false, version: null };
  const out = await runCapture([bin, "--version"], cliEnv(provider));
  const version = out?.match(/\d+\.\d+\.\d+/)?.[0] ?? null;
  return { installed: true, version };
};

export type TCliInstallResult = {
  readonly installed: boolean;
  readonly version: string | null;
  /** Trimmed installer output (last lines), for surfacing failures. */
  readonly output: string;
};

/** Create the isolated provider dirs (root + home + config) before a write. */
const ensureIsolatedDirs = async (provider: TCliProvider): Promise<void> => {
  await mkdir(cliRoot(provider), { recursive: true });
  await mkdir(cliHome(provider), { recursive: true });
  await mkdir(cliConfigDir(provider), { recursive: true });
};

export type TEnsureHostResult = {
  /** Path to the user's non-isolated CLI binary, or null if it couldn't be
   *  provisioned. */
  readonly path: string | null;
  /** Installer output tail when an install was attempted and failed. */
  readonly output: string;
};

type TInstallRun = {
  readonly timedOut: boolean;
  readonly output: string;
};

/**
 * Run a vendor installer pipeline (`curl … | bash`) under a HARD timeout that
 * can actually reap it.
 *
 * The installer is a shell PIPELINE that spawns more processes (curl, an inner
 * `bash`, the vendor installer's own children). Killing only the DIRECT child
 * (the `bash -c` wrapper) leaves those orphaned, and a single survivor that
 * inherited the stdout/stderr pipe keeps it open — so an EOF-bounded
 * `await stream.text()` NEVER returns, `installCli` never resolves, the
 * `cli_install` handler's `finally` never clears `installing`, and the dashboard
 * card wedges on "Installing…" forever (past the timeout). Two defences make the
 * bound real:
 *   1. `detached: true` runs the pipeline in its OWN process group, so a SIGKILL
 *      to `-pid` (the group) reaps the WHOLE tree — curl, both bashes, and the
 *      installer's children — closing every inherited pipe.
 *   2. We resolve off the wrapper's `exit` (the authoritative "finished"), NOT
 *      off stream EOF, then kill the group to sweep any leaked descendant — so a
 *      survivor holding the pipe can never defer resolution.
 *
 * Exported for the regression test, which points `url` at a `file://` fake
 * installer that backgrounds a pipe-holding survivor (the production wedge).
 */
export const runInstallScript = (
  url: string,
  env: NodeJS.ProcessEnv,
): Promise<TInstallRun> =>
  new Promise<TInstallRun>((resolve) => {
    // Pass the URL through an ENV VAR referenced as a quoted `"$INSTALL_URL"`
    // rather than interpolating it into the command string. `runInstallScript`
    // is exported (for the regression test), so a caller-supplied `url` must
    // never be able to break out of the `bash -c` and inject shell — the env-var
    // indirection makes that impossible regardless of the url's contents.
    const child = spawn("bash", ["-c", 'curl -fsSL "$INSTALL_URL" | bash'], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...env, INSTALL_URL: url },
      // Run in the daemon-owned temp dir, never the daemon's inherited cwd `/`:
      // a vendor installer launched at `/` walks the filesystem root (tripping
      // macOS's TCC network-volume prompt on `/Volumes/*`). The dir is granted
      // read-write by the sandbox working set.
      cwd: daemonTempDir(),
      detached: true,
    });

    let output = "";
    const append = (b: Buffer): void => {
      output += b.toString();
    };
    child.stdout?.on("data", append);
    child.stderr?.on("data", append);
    // A broken pipe after we kill the group must not throw out of the stream.
    child.stdout?.on("error", () => {});
    child.stderr?.on("error", () => {});

    let settled = false;
    let timedOut = false;
    let killTimer: ReturnType<typeof setTimeout> | null = null;
    let graceTimer: ReturnType<typeof setTimeout> | null = null;

    // Kill the ENTIRE process group, not just the wrapper. With `detached` the
    // child is its group leader, so `-pid` addresses the whole pipeline. ESRCH
    // (already reaped) is expected and ignored.
    const killGroup = (): void => {
      if (typeof child.pid !== "number") return;
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        // group already gone
      }
    };

    const finish = (): void => {
      if (settled) return;
      settled = true;
      if (killTimer !== null) clearTimeout(killTimer);
      if (graceTimer !== null) clearTimeout(graceTimer);
      // Sweep any leaked background descendant so nothing lingers on the pipe.
      killGroup();
      resolve({ timedOut, output: output.trim() });
    };

    // Schedule the post-exit / post-timeout resolution, replacing any prior arm.
    const armFinish = (ms: number): void => {
      if (graceTimer !== null) clearTimeout(graceTimer);
      graceTimer = setTimeout(finish, ms);
    };

    killTimer = setTimeout(() => {
      timedOut = true;
      killGroup(); // forces the wrapper's `exit`, which calls `finish`…
      armFinish(2_000); // …belt-and-braces if `exit` somehow never fires.
    }, INSTALL_TIMEOUT_MS);

    // spawn itself failed (e.g. no `bash` on PATH) — return with the buffer.
    child.on("error", finish);
    // Resolve off `exit` (process done) not `close` (waits for stream EOF, which
    // a pipe-holding survivor can defer forever). A short grace drains already-
    // buffered `data` before we read `output`.
    child.on("exit", () => {
      armFinish(250);
    });
  });

/**
 * Ensure the user's NON-isolated vendor CLI exists, returning its binary path.
 * The SINGLE install path: if the CLI is already present (the user had it, or
 * the integrations setup installed it first) it's reused untouched; otherwise
 * the OFFICIAL vendor installer runs ONCE for the default (non-isolated)
 * location. No isolated copy is ever downloaded.
 *
 * The install runs with a NEAR-default env (so the binary lands in the user's
 * own `~/.local/bin` etc.) with three sandbox-driven adjustments:
 *   - `TMPDIR` → the daemon temp dir, so the installer's `mktemp` doesn't
 *     EACCES on the ungranted `/tmp`;
 *   - `PATH` gets `DEFAULT_BIN_DIRS` prepended — a background daemon inherits
 *     a minimal PATH, and codex's `add_to_path` only skips its rc edit when
 *     its BIN_DIR (~/.local/bin) is ALREADY on PATH (no suppression knob);
 *   - `hostInstallEnv(provider)` — the per-vendor PATH-edit/prompt
 *     suppression knobs. The sandbox no longer grants the shell rc files, so
 *     PATH edits must be suppressed (kimi) or made unnecessary (codex); the
 *     dashboard surfaces the "add ~/.local/bin to PATH" note instead.
 * `candidates` and `localBinDir` are injectable for tests (the latter keeps the
 * canonicalize symlink out of the real `~/.local/bin` under test).
 */
export const ensureHostCli = async (
  provider: TCliProvider,
  candidates: readonly string[] = hostCliCandidates(provider),
  localBinDir: string = join(homedir(), ".local", "bin"),
): Promise<TEnsureHostResult> => {
  const present = candidates.find((c) => existsSync(c));
  if (present !== undefined) {
    // Reuse fast path (setup-first, or a pre-existing user install): still
    // canonicalize so a binary that landed OUTSIDE ~/.local/bin (kimi →
    // ~/.kimi-code/bin, grok → ~/.grok/bin) is reachable as `kimi`/`grok` in
    // the user's shell — the post-install path below does the same, and the
    // reuse flow must not skip it. Best-effort + non-clobbering (see
    // `canonicalizeIntoLocalBin`).
    canonicalizeIntoLocalBin(present, localBinDir);
    return { path: present, output: "" };
  }

  // Run the vendor installer in its own process group under a HARD,
  // group-killing timeout (see `runInstallScript`): a stalled download/install —
  // or a survivor descendant holding the pipe — can't wedge the serial control
  // loop forever, so the `cli_install` handler always returns and clears the
  // card's "Installing…" state. `runInstallScript` also pins the child cwd to
  // the daemon temp dir so the installer never walks the daemon's inherited `/`
  // (which trips macOS's TCC network-volume prompt on `/Volumes/*`).
  const { timedOut, output } = await runInstallScript(
    INSTALL_SCRIPT[provider],
    {
      ...process.env,
      TMPDIR: daemonTempDir(),
      // Prepend the standard user bin dirs: makes codex's `add_to_path`
      // early-return (BIN_DIR already on PATH → no rc edit) and lets the
      // installers find user-local tools despite the service's minimal PATH.
      PATH: [...DEFAULT_BIN_DIRS, process.env.PATH ?? ""]
        .filter((p) => p.length > 0)
        .join(":"),
      // Per-vendor rc-edit/prompt suppression (the sandbox no longer grants
      // the shell rc files — see `hostInstallEnv`).
      ...hostInstallEnv(provider),
    },
  );
  if (timedOut) {
    return {
      path: null,
      output: `timed out after ${INSTALL_TIMEOUT_MS / 1000}s installing ${provider}\n${output.slice(-400)}`,
    };
  }

  const installed = candidates.find((c) => existsSync(c));
  if (installed !== undefined) {
    // Shell-reachability parity: the vendor installers' shell-rc PATH edits
    // are suppressed now (the sandbox dropped the rc-file grants), so a CLI
    // that landed OUTSIDE ~/.local/bin (kimi → ~/.kimi-code/bin, grok →
    // ~/.grok/bin) would be invisible to the user's own shell. Canonicalize:
    // link it into ~/.local/bin (a granted workflow target — the same move
    // grok's installer makes) so one PATH dir serves every vendor CLI. The
    // daemon itself never needs this (it resolves absolute candidate paths);
    // this is purely so the USER can type `kimi`/`grok` in their terminal.
    canonicalizeIntoLocalBin(installed, localBinDir);
  }
  return {
    path: installed ?? null,
    output: installed !== undefined ? "" : output.slice(-500),
  };
};

/** Symlink a host CLI binary into `~/.local/bin/<name>` when it landed
 *  elsewhere. Best-effort: an EEXIST-with-real-file or a denied write must
 *  never fail the install (the binary itself is fine either way). */
const canonicalizeIntoLocalBin = (
  binPath: string,
  localBin: string = join(homedir(), ".local", "bin"),
): void => {
  if (binPath.startsWith(`${localBin}/`)) return; // already canonical
  const link = join(localBin, basename(binPath));
  try {
    mkdirSync(localBin, { recursive: true });
    // Replace only a stale SYMLINK; never clobber a real file the user put
    // there themselves.
    if (existsSync(link) && !lstatSync(link).isSymbolicLink()) return;
    rmSync(link, { force: true });
    symlinkSync(binPath, link);
    logInfo("cli-install", `linked ${link} → ${binPath} (shell reachability)`);
  } catch {
    // best-effort — the CLI still works via its absolute path.
  }
};

/**
 * Point the isolated CLI path (`cliBin(provider)`) at the host binary via a
 * SYMLINK — never a copy, so the isolated CLI takes no disk space. Replaces any
 * existing link/file at the isolated path so it always tracks the current host
 * binary (e.g. after the user updates their CLI).
 */
export const linkIsolatedCli = async (
  provider: TCliProvider,
  hostBin: string,
): Promise<void> => {
  await ensureIsolatedDirs(provider);
  const dst = cliBin(provider);
  await mkdir(dirname(dst), { recursive: true });
  await rm(dst, { force: true });
  symlinkSync(hostBin, dst);
};

/**
 * Provision the isolated CLI for `provider`. Idempotent. Order:
 *   1. isolated symlink already present + runnable → no-op;
 *   2. ensure the user's NON-isolated CLI exists (reuse, else official install);
 *   3. SYMLINK the isolated path to it (no copy — zero duplicate bytes).
 * Isolation comes from the run env (`cliEnv`), not a separate binary.
 */
export const installCli = async (
  provider: TCliProvider,
): Promise<TCliInstallResult> => {
  // Fast-path: the isolated path is ALREADY a symlink that resolves to a
  // runnable binary. A regular FILE here is a legacy COPY (from the older
  // copy-based daemon) — deliberately fall through so it gets replaced by a
  // symlink, reclaiming the duplicate bytes.
  const dst = cliBin(provider);
  if (existsSync(dst) && lstatSync(dst).isSymbolicLink()) {
    const existing = await cliInstallState(provider);
    if (existing.installed && existing.version !== null) {
      return { installed: true, version: existing.version, output: "" };
    }
  }

  // Ensure the single (non-isolated) binary exists — reuse or install once.
  const host = await ensureHostCli(provider);
  if (host.path === null) {
    return { installed: false, version: null, output: host.output };
  }

  // Point the isolated CLI at it (symlink — no duplicate data).
  await linkIsolatedCli(provider, host.path);

  const state = await cliInstallState(provider);
  if (state.installed && state.version !== null) {
    logInfo("cli-install", `linked isolated ${provider} CLI → host (no copy)`, {
      provider,
      host: host.path,
      version: state.version,
    });
  }
  return {
    installed: state.installed && state.version !== null,
    version: state.version,
    output:
      state.installed && state.version !== null
        ? ""
        : "isolated symlink did not resolve to a runnable binary",
  };
};
