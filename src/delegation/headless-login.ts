/**
 * Headless paste-back login (Claude remote). Split out of `util.ts`
 * (which re-exports everything here — import from either).
 *
 * `claude auth login --claudeai` with DISPLAY unset prints a hosted-callback
 * authorize URL (platform.claude.com) + a `Paste code here if prompted >`
 * prompt, holds an in-process PKCE verifier, and consumes the pasted code on
 * stdin (a bad paste re-prompts; the process stays alive). Verified live
 * against claude v2.1.185. See
 * `docs/proposals/headless-claude-login-paste-back.md`.
 */
import { chmodSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { daemonTempDir } from "../sandbox/working-set";
import { spawnCwd, spawnEnv, stripAnsi } from "./spawn";

/** Parse the authorize URL the CLI prints for the no-browser fallback. */
const HEADLESS_URL_RE = /If the browser didn't open, visit:\s*(\S+)/;
/** The CLI's inline reject on a wrong/partial paste — it stays alive to retry. */
const HEADLESS_INVALID_RE = /Invalid code\b/i;
/** Ceiling on first seeing the authorize URL before giving up. */
const HEADLESS_URL_TIMEOUT_MS = 30_000;
/** Ceiling on one code submission resolving (exchange completes or rejects). */
const HEADLESS_SUBMIT_TIMEOUT_MS = 60_000;

export type THeadlessLogin = {
  /** The authorize URL to surface to the caller's browser (hosted-callback). */
  readonly url: string;
  /** Write a pasted authorization code to the live CLI's stdin and await the
   *  outcome. `ok:false` (e.g. an `Invalid code` reject) leaves the process
   *  ALIVE for a retry; `ok:true` means the CLI exchanged + exited. */
  readonly submitCode: (code: string) => Promise<{
    readonly ok: boolean;
    readonly detail: string;
  }>;
  /** Resolves when the login process exits (success, cancel, or expiry). */
  readonly done: Promise<void>;
  /** Kill the login process (cancel an in-flight paste-back). */
  readonly cancel: () => void;
};

let noBrowserShimDir: string | null | undefined;
/**
 * A directory holding no-op `open` / `xdg-open` scripts to PREPEND to a login
 * child's PATH so it can't pop a browser tab on the daemon's own machine
 * (claude opens via a PATH lookup — verified interceptable, unlike codex).
 * Best-effort: returns null if it can't be created (the login still works —
 * the printed URL + paste prompt are unaffected; at worst a tab opens on a
 * remote GUI box). Cached after the first success.
 */
const ensureNoBrowserShimDir = async (): Promise<string | null> => {
  if (noBrowserShimDir !== undefined) return noBrowserShimDir;
  try {
    const dir = join(daemonTempDir(), "no-browser");
    await mkdir(dir, { recursive: true });
    for (const name of ["open", "xdg-open"]) {
      const p = join(dir, name);
      await Bun.write(p, "#!/bin/sh\nexit 0\n");
      chmodSync(p, 0o755);
    }
    noBrowserShimDir = dir;
  } catch {
    noBrowserShimDir = null;
  }
  return noBrowserShimDir;
};

/**
 * Spawn `claude auth login --claudeai` (DISPLAY-stripped, browser suppressed)
 * for a REMOTE/headless box, parse the authorize URL it prints, and hold the
 * process open on a WRITABLE stdin so the pasted code can be fed back later.
 * Returns `{ error }` if no URL is emitted within the timeout.
 */
export const spawnHeadlessLogin = async (
  argv: ReadonlyArray<string>,
  env: Record<string, string>,
  opts?: { readonly urlTimeoutMs?: number },
): Promise<THeadlessLogin | { error: string }> => {
  const shimDir = await ensureNoBrowserShimDir();
  const baseEnv = spawnEnv(env) ?? { ...process.env };
  const childEnv: Record<string, string | undefined> = { ...baseEnv };
  // No GUI → the printed URL is the hosted-callback (platform.claude.com) one
  // the user can complete from another machine; also makes any browser-open a
  // no-op fallback.
  delete childEnv.DISPLAY;
  delete childEnv.WAYLAND_DISPLAY;
  if (shimDir !== null) {
    childEnv.PATH = `${shimDir}:${baseEnv.PATH ?? process.env.PATH ?? ""}`;
  }

  const proc = Bun.spawn([...argv], {
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    cwd: spawnCwd(env),
    env: childEnv,
  });

  const dec = new TextDecoder();
  let combined = "";
  const pump = async (stream: ReadableStream<Uint8Array>): Promise<void> => {
    const reader = stream.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value !== undefined) combined += dec.decode(value);
      }
    } finally {
      reader.releaseLock();
    }
  };
  // Drain both fds for the process's lifetime so a full pipe can't stall it.
  void pump(proc.stdout);
  void pump(proc.stderr);
  const done = proc.exited.then(() => {});

  const url = await new Promise<string | null>((resolve) => {
    let settled = false;
    const finish = (v: string | null): void => {
      if (settled) return;
      settled = true;
      clearInterval(poll);
      clearTimeout(timer);
      resolve(v);
    };
    const timer = setTimeout(
      () => finish(null),
      opts?.urlTimeoutMs ?? HEADLESS_URL_TIMEOUT_MS,
    );
    const poll = setInterval(() => {
      const m = stripAnsi(combined).match(HEADLESS_URL_RE);
      if (m !== null) finish(m[1]);
    }, 100);
    void proc.exited.then(() => finish(null));
  });

  if (url === null) {
    try {
      proc.kill();
    } catch {
      // already gone
    }
    const sample = stripAnsi(combined)
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 300);
    return {
      error:
        sample.length > 0
          ? sample
          : "claude auth login emitted no authorize URL",
    };
  }

  const submitCode = (
    code: string,
  ): Promise<{ ok: boolean; detail: string }> => {
    const mark = combined.length;
    try {
      proc.stdin.write(`${code}\n`);
      void proc.stdin.flush();
    } catch {
      return Promise.resolve({
        ok: false,
        detail: "login process is no longer accepting input",
      });
    }
    return new Promise((resolve) => {
      let settled = false;
      const finish = (r: { ok: boolean; detail: string }): void => {
        if (settled) return;
        settled = true;
        clearInterval(poll);
        clearTimeout(timer);
        resolve(r);
      };
      const timer = setTimeout(
        () => finish({ ok: false, detail: "timed out waiting for the code" }),
        HEADLESS_SUBMIT_TIMEOUT_MS,
      );
      // A wrong/partial paste prints `Invalid code` and the process stays
      // alive — surface a retryable failure without killing the flow.
      const poll = setInterval(() => {
        if (HEADLESS_INVALID_RE.test(stripAnsi(combined.slice(mark)))) {
          finish({
            ok: false,
            detail:
              "Invalid code — copy the full code from the page and paste it again.",
          });
        }
      }, 100);
      // A valid code → the CLI exchanges and exits.
      void proc.exited.then(() =>
        finish(
          proc.exitCode === 0
            ? { ok: true, detail: "signed in" }
            : { ok: false, detail: `login exited ${proc.exitCode ?? -1}` },
        ),
      );
    });
  };

  const cancel = (): void => {
    try {
      proc.kill();
    } catch {
      // already gone
    }
  };

  return { url, submitCode, done, cancel };
};
