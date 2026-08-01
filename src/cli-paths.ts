/**
 * Filesystem layout + isolated-run environment for the daemon's OWN copies
 * of the vendor CLIs. Each CLI is installed under
 * `<stateDir>/cli/<provider>/` and ALWAYS run with its home/config pointed
 * inside that dir, so it never reads or writes the user's personal
 * `~/.claude` / `~/.codex` / `~/.kimi-code` state (which they may be using
 * interactively). The Claude harness
 * (`tests/matrix/claude-harness/harness.ts`) runs the SAME isolated CLI
 * via `cliBin`/`cliEnv` rather than installing its own.
 *
 *   <stateDir>/cli/<provider>/
 *     bin/<binary>     the isolated CLI executable
 *     home/            the CLI's home/config + credentials (isolated)
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { TSubscriptionProviderSlug } from "@openllmsh/protocol";
import { stateDir } from "./env";
import { resolveOnPath } from "./path-utils";
import { daemonTempDir } from "./sandbox/working-set";

/** The providers with an isolated CLI — exactly the closed
 *  `SubscriptionProviderSlug` vocabulary of the control schema, so a slug
 *  that reaches a CLI path provably came through the typed command union. */
export type TCliProvider = TSubscriptionProviderSlug;

// Where the vendor installer drops the binary, RELATIVE to the provider
// root, plus the CLI's command name as invoked from a shell (what a PATH
// scan looks for). (Run/install env knobs live in `cliEnv` below, not here.)
type TCliSpec = {
  readonly binRel: string;
  readonly cmd: string;
};

const SPECS: Readonly<Record<TCliProvider, TCliSpec>> = {
  // `claude install` (run by claude.ai/install.sh under our HOME) places
  // the launcher at $HOME/.local/bin/claude.
  claude_code: { binRel: "home/.local/bin/claude", cmd: "claude" },
  // codex install.sh with CODEX_INSTALL_DIR=<root>/bin → <root>/bin/codex.
  chatgpt: { binRel: "bin/codex", cmd: "codex" },
  // kimi install.sh with KIMI_INSTALL_DIR=<root> → <root>/bin/kimi.
  kimi_code: { binRel: "bin/kimi", cmd: "kimi" },
  // grok (Grok Build, x.ai/cli) is HOME-rooted like claude, so its isolated
  // symlink lives under the isolated HOME's bin, paralleling claude's launcher.
  // NB: this is only where the ISOLATED SYMLINK is created — the real installer
  // drops the host launcher at ~/.grok/bin/grok (see `hostCliCandidates`), and
  // that is what gets symlinked here.
  grok: { binRel: "home/.local/bin/grok", cmd: "grok" },
  // ⚠️ RESEARCH-UNVERIFIED: Cursor's official installer is reported to place
  // this launcher at ~/.local/bin/cursor-agent.
  cursor: { binRel: "home/.local/bin/cursor-agent", cmd: "cursor-agent" },
};

/** The closed runtime list of CLI providers — derived from `SPECS` keys so it
 *  can never drift from the `Record<TCliProvider, …>` (adding a provider to the
 *  type forces a `SPECS` entry, which appears here automatically). Consumers that
 *  must iterate every provider (e.g. the sandbox exec-dir resolver in
 *  `working-set.ts`) use this instead of re-listing the slugs. */
export const CLI_PROVIDERS = Object.keys(SPECS) as readonly TCliProvider[];

export const cliRoot = (provider: TCliProvider): string =>
  join(stateDir(), "cli", provider);

/** The CLI's isolated home/config dir (passed as the CLI's home env). */
export const cliHome = (provider: TCliProvider): string =>
  join(cliRoot(provider), "home");

/** Absolute path to the installed isolated binary. */
export const cliBin = (provider: TCliProvider): string =>
  join(cliRoot(provider), SPECS[provider].binRel);

/**
 * Candidate paths to the user's EXISTING non-isolated vendor CLI, in priority
 * order — `cli-install.ts` `cliInstallState` returns the first that exists and
 * SYMLINKS the isolated path to it (no copy, zero duplicate bytes). The daemon
 * NEVER installs the CLI; installs are user-run + unsandboxed. The single binary
 * on disk is the non-isolated one; the isolated CLI is always a link to it.
 *
 * Static vendor-default locations come FIRST (the official installer's drop
 * point wins), then a generic PATH scan (`resolveOnPath`) appended as the
 * fallback — so a CLI installed anywhere else (system-wide `/usr/bin`,
 * Homebrew, an npm-prefix global, `claude migrate-installer`, a distro
 * package) is still found instead of being reported not-installed. The scan
 * is generic across every provider, closing the class of bug rather than one
 * path (see issue #203).
 *
 * The symlink target must be EXEC-able under the OS sandbox: the codex home
 * (`~/.codex`, a read-write working-set setup target), claude's binary dir
 * (`~/.local/share/claude`, read+exec in `working-set.ts`), grok's bin dirs
 * (`~/.grok/{bin,downloads}`, read+exec) + anything outside `$HOME` all
 * qualify. Any OTHER in-`$HOME` location (kimi's `~/.kimi-code/bin`, a
 * non-standard dir a PATH scan surfaces) is covered too: `working-set.ts`
 * seeds `resolveCliExecDirs` from THIS list and follows the real symlink
 * chain, granting read+exec on whatever dirs the binary actually lives in
 * (bounded — never `$HOME`/root/a sensitive root).
 */
export const hostCliCandidates = (provider: TCliProvider): string[] => {
  const home = homedir();
  const vendorDefaults = ((): string[] => {
    switch (provider) {
      case "claude_code":
        // The official installer's launcher → resolves to
        // ~/.local/share/claude/versions/<v> (the self-contained binary).
        return [join(home, ".local", "bin", "claude")];
      case "chatgpt":
        return [
          join(home, ".local", "bin", "codex"),
          join(home, ".codex", "bin", "codex"),
        ];
      case "kimi_code":
        return [
          join(home, ".kimi-code", "bin", "kimi"),
          join(home, ".local", "bin", "kimi"),
        ];
      // The official x.ai/cli installer's default BIN_DIR is ~/.grok/bin
      // (`BIN_DIR="${GROK_BIN_DIR:-$HOME/.grok/bin}"`), and it only adds a
      // ~/.local/bin/grok symlink WHEN ~/.grok/bin isn't already on PATH — so
      // the primary location must come first, with ~/.local/bin/grok as the
      // conditional fallback. (Verified against the live installer 2026-06-30.)
      case "grok":
        return [
          join(home, ".grok", "bin", "grok"),
          join(home, ".local", "bin", "grok"),
        ];
      // ⚠️ RESEARCH-UNVERIFIED: best-known Cursor installer launcher path;
      // `resolveOnPath` below covers other installation layouts.
      case "cursor":
        return [join(home, ".local", "bin", "cursor-agent")];
    }
  })();
  const out: string[] = [];
  const seen = new Set<string>();
  for (const p of [...vendorDefaults, ...resolveOnPath(SPECS[provider].cmd)]) {
    if (seen.has(p)) continue;
    seen.add(p);
    out.push(p);
  }
  return out;
};

// ─── device-session env (interactive CLI, real user home) ───────────
//
// Device chat sessions (feature §2.2) run the user's REAL interactive CLI
// with the real `$HOME` / PATH so credentials and vendor session stores
// work without re-login. There is no per-session workspace under
// `~/.openllm/sessions/` — cwd is `$HOME` (or a validated resume cwd).
// Sandbox HOME rewrite / seatbelt grants stay for auto-update and
// login/auth triggers only.
//
// Legacy helpers `sessionRoot` / `sessionWorkspace` remain exported for
// any residual callers/tests but are unused by session-host.

/** @deprecated Device PTYs no longer use a sessions workspace root. */
export const sessionRoot = (): string => join(stateDir(), "sessions");

/** @deprecated Prefer `$HOME` / resume cwd via session-host.resolveSessionCwd. */
export const sessionWorkspace = (sessionId: string): string =>
  join(sessionRoot(), sessionId);

/**
 * Environment overrides for a DEVICE SESSION spawn. Keeps the real HOME so
 * vendor CLIs read the user's actual login/settings; only sets TERM and a
 * daemon temp dir. PATH is inherited via `spawnEnv`. Session-host layers
 * `OPENLLM_DEVICE_SESSION_ID` on top for live.json indexing.
 *
 * `daemonTempDir` must succeed — a missing temp root would leave vendor CLIs
 * writing under an unusable TMPDIR and surface as opaque spawn failures.
 */
export const sessionEnv = (_provider: TCliProvider): Record<string, string> => {
  const tmp = daemonTempDir();
  // daemonTempDir swallows mkdir errors; fail closed before spawn if unusable.
  if (!existsSync(tmp)) {
    throw new Error(`daemon temp dir missing: ${tmp}`);
  }
  return {
    HOME: homedir(),
    TMPDIR: tmp,
    TERM: "xterm-256color",
  };
};

/**
 * The CLI's home/config root as the CLI itself sees it (the value of its
 * home env var). Delegates derive their credential-store paths from this
 * so the read location and the `cliEnv` run location never drift.
 *   claude → <home>/.claude   codex → <home>/.codex   kimi → <home>/.kimi-code
 */
export const cliConfigDir = (provider: TCliProvider): string => {
  const home = cliHome(provider);
  switch (provider) {
    case "claude_code":
      return join(home, ".claude");
    case "chatgpt":
      return join(home, ".codex");
    case "kimi_code":
      return join(home, ".kimi-code");
    // grok caches its OAuth token at <home>/.grok/auth.json.
    case "grok":
      return join(home, ".grok");
    // ⚠️ RESEARCH-UNVERIFIED: cursor-agent stores CLI channel configuration
    // under ~/.cursor; credentials are read separately from the host keychain.
    case "cursor":
      return join(home, ".cursor");
  }
};

/**
 * Environment overrides that (1) isolate the CLI's runtime home and
 * (2) — at INSTALL time — redirect where the vendor script drops the
 * binary. Merge onto `process.env` for every spawn of an isolated CLI.
 *
 * All three get `HOME` pointed at the isolated home (isolates Claude's
 * binary + state, and is the floor for the others). Codex/Kimi also get
 * their explicit install-dir + home knobs and PATH-edit suppression so
 * the installer doesn't touch the user's shell profiles.
 *
 * ALL three additionally get `TMPDIR` pointed at the daemon-owned temp dir
 * (`<state>/tmp`). The OS sandbox (`./sandbox/working-set.ts`) does NOT grant
 * the system `/tmp` — only `<state>/tmp`. The codex + kimi vendor installers
 * stage their download/extract in `mktemp -d`, which falls back to `/tmp`
 * when `TMPDIR` is unset; under the sandbox that first `mktemp -d` EACCESes
 * and the `set -e` script exits with no binary. (Claude was unaffected: its
 * installer stages under `$HOME`, already granted.) Pinning `TMPDIR` at the
 * granted daemon temp dir keeps every isolated spawn's temp inside the
 * working set, so the install lands the binary on a remote/sandboxed box too.
 */
export const cliEnv = (provider: TCliProvider): Record<string, string> => {
  const home = cliHome(provider);
  const root = cliRoot(provider);
  const config = cliConfigDir(provider);
  // The daemon-owned, sandbox-granted staging dir for `mktemp -d` (see above).
  const tmp = daemonTempDir();
  switch (provider) {
    case "claude_code":
      return {
        HOME: home,
        TMPDIR: tmp,
        // Claude reads its config/credentials from CLAUDE_CONFIG_DIR
        // (defaults to $HOME/.claude); pin it to the isolated home so
        // login/status/usage all use it, never the user's.
        CLAUDE_CONFIG_DIR: config,
      };
    case "chatgpt":
      return {
        HOME: home,
        TMPDIR: tmp,
        CODEX_HOME: config,
        CODEX_INSTALL_DIR: join(root, "bin"),
        // Skip interactive prompts during the scripted install.
        CODEX_NON_INTERACTIVE: "1",
      };
    case "kimi_code":
      return {
        HOME: home,
        TMPDIR: tmp,
        KIMI_CODE_HOME: config,
        KIMI_INSTALL_DIR: root,
        // Don't edit the user's shell rc files.
        KIMI_NO_MODIFY_PATH: "1",
      };
    // grok is HOME-rooted (like claude): it reads/writes its config +
    // `auth.json` under <home>/.grok, so pinning HOME isolates it from the
    // user's real ~/.grok. The host binary lives at its DEFAULT location
    // (~/.grok/bin, installed out of band by the user-run installer) and the
    // isolated path is a symlink to it — the daemon only runs it, never installs.
    case "grok":
      return {
        HOME: home,
        TMPDIR: tmp,
      };
    // ⚠️ RESEARCH-UNVERIFIED: Cursor appears HOME-rooted for its ~/.cursor
    // configuration. Its macOS Keychain credentials remain host-managed.
    case "cursor":
      return {
        HOME: home,
        TMPDIR: tmp,
      };
  }
};
