/**
 * Spawn helpers for official-CLI delegation: capture runs, browser/PTY
 * login spawns, and terminal-output hygiene. Split out of `util.ts`
 * (which re-exports everything here — import from either).
 *
 * Bright line (proposal §6): nothing read from a CLI's store may be sent
 * off-box. These helpers feed the LOCAL runner + the local usage panel
 * only.
 */
import { existsSync } from "node:fs";
import { rm } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import type { TSuperviseSpawnOptions } from "../child-supervisor";
import { superviseSpawn } from "../child-supervisor";
import { spawnCommand } from "../command";
import { logError } from "../logger";
import { sandboxSpawnArgs } from "../sandbox/exec";
import { daemonTempDir } from "../sandbox/working-set";

/** Merge an env map onto the parent env for a spawned isolated CLI. */
export const spawnEnv = (
  env: Record<string, string> | undefined,
): Record<string, string | undefined> | undefined =>
  env === undefined ? undefined : { ...process.env, ...env };

/**
 * The working directory for a spawned isolated CLI. SECURITY: the daemon runs
 * with cwd `/` (launchd/systemd start it with no `WorkingDirectory`), and a
 * child inherits it. A vendor CLI launched at `/` enumerates project context
 * from the filesystem ROOT — statting `/Volumes/*`, which on macOS trips the
 * TCC "wants to access files on a network volume" consent prompt (attributed to
 * the daemon as the responsible parent) and needlessly walks the whole disk.
 *
 * So pin the cwd to the child's OWN isolated home (`env.HOME`, e.g.
 * `~/.openllm/cli/claude_code/home` for claude) — which `cliEnv` always sets and
 * the sandbox working set grants read-write — so the CLI's project scan is
 * confined to its empty isolated home, NEVER `/`. Falls back to the daemon-owned
 * temp dir (always created + granted) when no isolated HOME is present or the
 * home dir doesn't yet exist (a not-yet-created cwd would make `Bun.spawn`
 * `ENOENT`). Never returns `/`.
 */
export const spawnCwd = (env: Record<string, string> | undefined): string => {
  const home = env?.HOME;
  // Reject `/` explicitly: it "exists", so an env with `HOME=/` (or a daemon
  // whose HOME wasn't isolated) would otherwise pass the existsSync check and
  // re-introduce the exact root-cwd bug this helper exists to prevent.
  if (home !== undefined && home.length > 0 && home !== "/" && existsSync(home))
    return home;
  return daemonTempDir();
};

/**
 * Surface a child that was KILLED BY A SIGNAL (`signalCode` set) — the silent
 * failure mode behind "the flow doesn't trigger, no errors". The OS sandbox
 * SIGKILLs/SIGABRTs a child that hits a denied operation, and a plain exit-code
 * check misses it. Logging the command + signal at ERROR level puts the actual
 * culprit in `openllmd.err.log` instead of letting it vanish. Returns whether a
 * kill was detected (so callers can treat it as a definite failure). No-op for
 * a clean exit.
 */
export const logIfKilled = (
  argv: ReadonlyArray<string>,
  proc: {
    readonly signalCode: string | null;
    readonly exitCode: number | null;
  },
): boolean => {
  // The `--sandbox-exec` shim mirrors a signal death of its tail as exit code
  // `128 + N` (the daemon-side proc is the SHIM, so its signalCode is null) —
  // without this mapping a sandbox kill of a wrapped child is invisible here
  // and the spawn just looks like a quiet non-zero exit. A CLI can exit 130
  // by its own convention (ctrl-c), so this is a diagnostic breadcrumb, not a
  // hard verdict.
  const signal =
    proc.signalCode ??
    (proc.exitCode !== null && proc.exitCode > 128 && proc.exitCode <= 128 + 31
      ? (SIGNAL_NAMES[proc.exitCode - 128] ?? `signal ${proc.exitCode - 128}`)
      : null);
  if (signal === null) return false;
  logError("delegation", `child killed by ${signal}`, {
    command: argv[0],
    argv: [...argv],
    signal,
    // The dominant cause on a sandboxed daemon: the child hit a denied op.
    hint: "likely an OS sandbox denial — see DaemonStatus.sandbox / the sandbox working set",
  });
  return true;
};

/** Conventional signal number → name, for the shim's `128 + N` exit mirror. */
const SIGNAL_NAMES: Record<number, string> = {
  1: "SIGHUP",
  2: "SIGINT",
  3: "SIGQUIT",
  4: "SIGILL",
  5: "SIGTRAP",
  6: "SIGABRT",
  7: "SIGBUS",
  8: "SIGFPE",
  9: "SIGKILL",
  10: "SIGUSR1",
  11: "SIGSEGV",
  12: "SIGUSR2",
  13: "SIGPIPE",
  14: "SIGALRM",
  15: "SIGTERM",
};

/** Hard ceiling for one-shot vendor CLI captures and probes. */
export const DEFAULT_CAPTURE_TIMEOUT_MS = 5_000;

export type TRunCaptureOpts = {
  /** Skip the sandbox shim for a read-only probe that needs direct execution. */
  readonly probe?: boolean;
  /** Classify the disposable child independently of sandbox-shim behavior. */
  readonly kind?: "probe" | "vendor-capture";
  /** Hard ceiling for stdout capture plus child exit before group termination. */
  readonly timeoutMs?: number;
};

type TCaptureOutcome =
  | { readonly kind: "complete"; readonly out: string; readonly code: number }
  | { readonly kind: "timeout" };

/**
 * Run a command and capture trimmed stdout (best-effort). Returns null on
 * spawn failure, non-zero exit, or a timeout. stdin is ignored so it never
 * blocks. `env` is merged onto the parent env — used to run the isolated vendor
 * CLIs with their home pointed inside the OpenLLM dir.
 *
 * The stdout read and root child exit share one hard deadline. On expiry, use
 * the supervisor's process-group termination rather than `proc.kill()`: a
 * descendant holding the inherited stdout fd must be reaped for EOF to occur.
 */
export const runCapture = async (
  argv: ReadonlyArray<string>,
  env?: Record<string, string>,
  opts?: TRunCaptureOpts,
): Promise<string | null> => {
  try {
    const command = spawnCommand(
      process.platform,
      argv[0] ?? "",
      argv.slice(1),
    );
    const spawnOptions: TSuperviseSpawnOptions = {
      kind: opts?.kind ?? (opts?.probe === true ? "probe" : "vendor-capture"),
      stdin: "ignore",
      stdout: "pipe",
      stderr: "ignore",
      cwd: spawnCwd(env),
      ...(spawnEnv(env) !== undefined ? { env: spawnEnv(env) } : {}),
    };
    const child = superviseSpawn(
      sandboxSpawnArgs(command, { probe: opts?.probe }),
      spawnOptions,
    );
    const proc = child.subprocess;
    const stdout = proc.stdout;
    if (stdout === undefined || typeof stdout === "number") {
      await child.terminate();
      return null;
    }
    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
      const complete = Promise.all([
        new Response(stdout).text(),
        proc.exited,
      ]).then(
        ([out, code]): TCaptureOutcome => ({ kind: "complete", out, code }),
      );
      const timeout = new Promise<TCaptureOutcome>((resolve) => {
        timer = setTimeout(
          () => resolve({ kind: "timeout" }),
          opts?.timeoutMs ?? DEFAULT_CAPTURE_TIMEOUT_MS,
        );
      });
      const outcome = await Promise.race([complete, timeout]);
      if (outcome.kind === "timeout") {
        await child.terminate();
        return null;
      }
      logIfKilled(argv, proc);
      if (outcome.code !== 0) return null;
      const trimmed = outcome.out.trim();
      return trimmed.length > 0 ? trimmed : null;
    } finally {
      if (timer !== null) clearTimeout(timer);
    }
  } catch {
    return null;
  }
};

/** Run a binary's `--version` (best-effort). Returns null on failure.
 *  CONFINED (no `probe`): callers gate this behind a stat-signature cache
 *  (`bin-signature.ts`) so it spawns only when the binary changed, keeping the
 *  ~300ms shim cost off the hot status path without leaving it unconfined. */
export const cliVersion = (
  bin: string,
  env?: Record<string, string>,
): Promise<string | null> =>
  runCapture([bin, "--version"], env, { kind: "probe" });

export type TLoginResult = {
  readonly code: number;
  /** Combined stdout+stderr (trimmed), for surfacing failures. */
  readonly output: string;
  /** True when we abandoned the child (early `until` match or timeout) rather
   *  than it exiting on its own — its OUTPUT is still valid (the token/cred was
   *  produced first), it just never cleanly exited. */
  readonly abandoned: boolean;
};

export type TSpawnLoginOpts = {
  /** Hard ceiling: kill the child after this and return what was captured.
   *  A browser OAuth needs the user to sign in, so it's generous. */
  readonly timeoutMs?: number;
  /** When the COMBINED output matches this, the child has produced what we
   *  need (e.g. a printed verification prompt) — kill it and return immediately
   *  instead of waiting for it to exit. Vendor CLIs (themselves Bun/Node
   *  binaries) can hang in `__cxa_finalize`/atexit AFTER printing it, so waiting
   *  on `proc.exited` would block forever + pile up 99%-CPU runaways. We don't
   *  need the exit — only the output. */
  readonly until?: RegExp;
  /** Skip the `--sandbox-exec` wrap (see `TSandboxSpawnOpts.probe`). REQUIRED
   *  for children that must operate a macOS-keychain-backed credential store
   *  (claude/cursor status + refresh): securityd refuses keychain reads for a
   *  Seatbelt-confined caller, so a wrapped spawn reports "not signed in" and
   *  a wrapped refresh silently never persists the rotated token. */
  readonly probe?: boolean;
};

/** Default login ceiling — long enough for a human to complete the browser
 *  OAuth, short enough that a wedged child is reaped, not left forever. */
export const DEFAULT_LOGIN_TIMEOUT_MS = 5 * 60_000;

/** After `opts.until` first matches, wait this long for the rest of a
 *  chunk-split token to arrive before killing — so the captured token is the
 *  COMPLETE one even though the regex isn't boundary-anchored. */
export const UNTIL_SETTLE_MS = 400;

/**
 * Spawn a vendor CLI's login command and capture its output. The CLI opens the
 * user's browser; the user signs in and the CLI completes via its own localhost
 * callback, at which point the credential is in the CLI's OWN store. stdin is
 * ignored (browser-driven; headless daemon has no usable stdin).
 *
 * Robustness (load-bearing): we NEVER block indefinitely on the child exiting.
 * Output is STREAMED; if `opts.until` matches we kill the child and return
 * (the vendor CLI can hang in atexit AFTER printing the token — see
 * `TSpawnLoginOpts.until`), and a `timeoutMs` ceiling reaps a wedged child
 * regardless. Either way the captured output is returned — the caller re-reads
 * the store / parses the token from it.
 */
export const spawnLogin = async (
  argv: ReadonlyArray<string>,
  env?: Record<string, string>,
  opts?: TSpawnLoginOpts,
): Promise<TLoginResult> => {
  const proc = Bun.spawn(sandboxSpawnArgs(argv, { probe: opts?.probe }), {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    cwd: spawnCwd(env),
    ...(spawnEnv(env) !== undefined ? { env: spawnEnv(env) } : {}),
  });
  const dec = new TextDecoder();
  let out = "";
  let err = "";
  let abandoned = false;
  let killTimer: ReturnType<typeof setTimeout> | null = null;
  let settleTimer: ReturnType<typeof setTimeout> | null = null;
  const kill = (): void => {
    if (abandoned) return;
    abandoned = true;
    try {
      proc.kill("SIGTERM");
    } catch {
      // already gone
    }
  };

  killTimer = setTimeout(kill, opts?.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS);

  const pump = async (
    stream: ReadableStream<Uint8Array>,
    onChunk: (s: string) => void,
  ): Promise<void> => {
    const reader = stream.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value !== undefined) onChunk(dec.decode(value));
        // Early-return once the awaited output appears (the child may never exit
        // cleanly — it can WEDGE after printing the token). Match the COMBINED
        // stream so a token on either fd is seen. We don't kill immediately: a
        // token can arrive split across read chunks, so a SETTLE delay lets the
        // remaining bytes land before we kill + parse — capturing the FULL token
        // without needing a stricter (and more brittle) trailing-boundary regex.
        if (
          opts?.until !== undefined &&
          settleTimer === null &&
          !abandoned &&
          opts.until.test(`${out}\n${err}`)
        ) {
          settleTimer = setTimeout(kill, UNTIL_SETTLE_MS);
        }
      }
    } finally {
      reader.releaseLock();
    }
  };

  await Promise.all([
    pump(proc.stdout, (s) => {
      out += s;
    }),
    pump(proc.stderr, (s) => {
      err += s;
    }),
    proc.exited,
  ]);
  if (killTimer !== null) clearTimeout(killTimer);
  if (settleTimer !== null) clearTimeout(settleTimer);

  // Only surface a SIGNAL kill we did NOT cause (a sandbox/OS kill) — our own
  // `until`/timeout kill is expected and its output is valid.
  if (!abandoned) logIfKilled(argv, proc);
  // Join with a newline, NOT bare concatenation: a token printed as the last
  // bytes of stdout (no trailing newline) must not fuse with the first bytes
  // of stderr, or a greedy token match would swallow the spillover.
  return {
    code: proc.exitCode ?? -1,
    output: `${out}\n${err}`.trim(),
    abandoned,
  };
};

// OSC (ESC ] … BEL/ST), CSI (ESC [ … final), and lone ESC. Built from a
// string so the source stays free of raw control bytes.
const ANSI_RE = new RegExp(
  "\\u001b\\][^]*?(?:\\u0007|\\u001b\\\\)" +
    "|\\u001b\\[[0-9;?]*[ -/]*[@-~]" +
    "|\\u001b[@-Z\\\\-_]",
  "g",
);

/**
 * Strip ANSI/terminal control sequences (CSI colour codes, OSC, lone escapes)
 * from CLI output so a value parsed out of it isn't fused with rendering bytes.
 */
export const stripAnsi = (s: string): string => s.replace(ANSI_RE, "");

/**
 * Build the `script(1)` argv that runs `argv` under a PSEUDO-TERMINAL, writing
 * the terminal capture to `typescript` — or null on an OS without `script`
 * (caller falls back to a plain pipe spawn). Some vendor CLIs only run attached
 * to a real terminal (e.g. `kimi -p`'s raw-mode-gated print mode), emitting
 * NOTHING under a plain pipe. Shared by
 * {@link spawnLoginPty} (which POLLS the typescript for an `until` regex) and
 * the exec-fixture capture (which ignores the typescript — pass `/dev/null` —
 * and drives off its HTTP recorder instead).
 *
 * Subtleties baked in:
 *   - `-F` (BSD) / `-f` (util-linux, inside `-qfc`) is LOAD-BEARING: without it
 *     `script` BUFFERS the typescript and only flushes on close, so a poller
 *     reads empty until the child exits. `-F` flushes after every write.
 *   - `script` allocates the PTY at the DEFAULT 80×24 — window size is an ioctl
 *     (TIOCSWINSZ), NOT `COLUMNS`/`LINES` — so a TUI rendering a fixed-width box
 *     wraps a long value mid-line. We resize the slave with `stty` INSIDE the
 *     PTY (runs on the controlling tty before the real command via `exec`).
 *     `2>/dev/null` keeps an `stty`-less environment from breaking the flow.
 *   - BSD (`script -q <file> cmd…`) vs util-linux (`script -qfc "cmd" <file>`)
 *     differ in argument order.
 */
export const ptyScriptArgv = (
  argv: ReadonlyArray<string>,
  typescript: string,
): string[] | null => {
  const os = platform();
  if (os !== "darwin" && os !== "linux") return null;
  const escapeShellArg = (arg: string): string =>
    `'${arg.replace(/'/g, "'\\''")}'`;
  const cmd = argv.map(escapeShellArg).join(" ");
  const widen = `stty cols 1000 rows 50 2>/dev/null; exec ${cmd}`;
  return os === "darwin"
    ? ["script", "-F", "-q", typescript, "sh", "-c", widen]
    : ["script", "-qfc", widen, typescript];
};

/**
 * Like {@link spawnLogin}, but runs `argv` under a PSEUDO-TERMINAL (via
 * `script(1)`). Some vendor CLIs only work attached to a real terminal — e.g.
 * `kimi -p`'s raw-mode-gated print mode writes to its controlling terminal
 * (`/dev/tty`), so spawned with a plain pipe (no controlling TTY) it emits
 * NOTHING and the headless daemon captures `outputLen: 0`. A PTY makes it
 * actually run, and we capture its terminal output to a `script` typescript
 * file which we POLL — so `opts.until` returns the instant the match appears.
 *
 * Key subtleties, each load-bearing (see the harness in `tests/`):
 *   - stdin is `/dev/null` (`"ignore"`): a Bun pipe/stream/inherited stdin makes
 *     `script` block before it sets up the PTY (empirically 0 bytes captured).
 *   - the child does NOT EOF-exit despite `/dev/null`: it reads the PTY SLAVE,
 *     not `script`'s stdin, so its stdin stays open for the browser flow.
 *   - we read the typescript FILE, not `script`'s stdout: piping `script`'s
 *     stdout under `Bun.spawn` also yields 0 bytes.
 *   - BSD (`script -q <file> cmd…`) vs util-linux (`script -qfc "cmd" <file>`)
 *     differ; unsupported elsewhere → falls back to plain {@link spawnLogin}.
 */
export const spawnLoginPty = async (
  argv: ReadonlyArray<string>,
  env?: Record<string, string>,
  opts?: TSpawnLoginOpts,
): Promise<TLoginResult> => {
  const os = platform();
  if (os !== "darwin" && os !== "linux") return spawnLogin(argv, env, opts);

  const tsFile = join(
    daemonTempDir(),
    `openllmd-pty-${process.pid}-${Date.now().toString(36)}.log`,
  );
  await Bun.write(tsFile, "");
  // PTY argv (shared with the exec-fixture capture). Non-null here: the OS was
  // already gated to darwin/linux above. We POLL `tsFile` for `opts.until`.
  const scriptArgv = ptyScriptArgv(argv, tsFile) ?? [...argv];

  // Wrap the WHOLE `script(1)` argv — the PTY wrapper and the vendor CLI it
  // runs are one confined tree.
  const proc = Bun.spawn(sandboxSpawnArgs(scriptArgv, { probe: opts?.probe }), {
    stdin: "ignore",
    stdout: "ignore",
    stderr: "ignore",
    cwd: spawnCwd(env),
    ...(spawnEnv(env) !== undefined ? { env: spawnEnv(env) } : {}),
  });

  const deadline = Date.now() + (opts?.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS);
  const readFile = (): Promise<string> =>
    Bun.file(tsFile)
      .text()
      .catch(() => "");
  let abandoned = false;
  let captured = "";
  for (;;) {
    captured = await readFile();
    if (opts?.until?.test(stripAnsi(captured)) === true) {
      // Settle: let the rest of the token line render before we kill + parse.
      await new Promise((r) => setTimeout(r, UNTIL_SETTLE_MS));
      captured = await readFile();
      abandoned = true;
      proc.kill("SIGTERM");
      break;
    }
    if (proc.exitCode !== null || proc.signalCode !== null) break; // exited
    if (Date.now() >= deadline) {
      abandoned = true;
      proc.kill("SIGTERM");
      break;
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  await proc.exited;
  captured = await readFile(); // final read (token written just before exit)
  await rm(tsFile, { force: true }).catch(() => {});
  if (!abandoned) logIfKilled(scriptArgv, proc);
  return { code: proc.exitCode ?? -1, output: stripAnsi(captured), abandoned };
};

/**
 * Best-effort open a URL in the user's default browser (macOS `open`, Windows
 * `cmd /c start`, else `xdg-open`). Used by the browser / device-code login
 * flows to bring up the vendor's auth page FROM the daemon — some vendor CLIs
 * print the URL but their own auto-open doesn't reach the user's GUI session
 * when the daemon spawns them (e.g. codex). Never throws; the user can copy the
 * URL from the card.
 */
export const openUrl = (url: string): void => {
  // Never launch a real browser under the test runner (`bun test` sets
  // NODE_ENV=test) — a device/browser login test that reaches this line would
  // otherwise pop a tab on the developer's machine. Production is unaffected.
  if (process.env.NODE_ENV === "test") return;
  const os = platform();
  // Windows: `start` is a cmd builtin, so it must run via `cmd /c`; the empty
  // "" is the (required) window-title arg, and the URL is quoted so `cmd.exe`
  // doesn't treat an OAuth URL's `&` as a command separator.
  const argv: string[] =
    os === "darwin"
      ? ["open", url]
      : os === "win32"
        ? ["cmd", "/c", "start", "", `"${url}"`]
        : ["xdg-open", url];
  try {
    // Deliberately UNWRAPPED (no `sandboxSpawnArgs`): opening the user's
    // browser is a user-facing action like the session-PTY exemption — the
    // launcher must reach the real GUI session/LaunchServices state, and it
    // takes only the URL string (no filesystem payload to confine).
    Bun.spawn(argv, {
      stdin: "ignore",
      stdout: "ignore",
      stderr: "ignore",
      cwd: spawnCwd(undefined),
    });
  } catch {
    // best-effort — the user can copy the URL from the card detail
  }
};
