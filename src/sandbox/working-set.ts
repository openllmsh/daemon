/**
 * The daemon's filesystem working set — the SINGLE allow-list both sandbox
 * backends consume (the Landlock ruleset in `./landlock.ts`, and the systemd
 * unit hardening rendered by `service.ts`). Derived from the existing path
 * helpers (`env.ts` / `cli-paths.ts`), never re-hardcoded, so a relocated
 * state dir or a new provider home is picked up here automatically. See
 * `docs/proposals/daemon-os-sandbox-and-typed-control.md` §3.1.
 *
 * Everything the daemon legitimately touches is deliberately centralised:
 *
 *   read-write
 *     - the state dir (`~/.openllm`): daemon.env (0600, holds the key + device
 *       id + config) and update-state, logs, the isolated vendor CLIs under `cli/<provider>/`
 *       (homes + binaries + config), AND the daemon binary itself + its
 *       atomic-swap temp (`bin/openllmd`, `.openllmd.update.<pid>.tmp` —
 *       the installer places the binary inside the state dir);
 *     - the executable's real directory (belt-and-braces when `execPath`
 *       lives outside the state dir — a manual install);
 *     - the claude-code integration footprint — SCOPED to the subtrees the
 *       SHA-gated skill/plugin/setup scripts actually write
 *       (`~/.claude/{skills,plugins,commands,hooks,plugin-state,downloads}`
 *       + the `settings.json` FILE + `~/.claude.json`), NEVER the whole
 *       `~/.claude`: the user's real Claude OAuth token
 *       (`~/.claude/.credentials.json` on Linux) sits at that root and must
 *       stay outside the working set on BOTH backends (the
 *       2026-07-03 working-set-exposure audit §5-A parity fix).
 *
 *   read-only
 *     - the system trees the runtime + spawned tools (`bash`, `curl`, the
 *       vendor CLIs' loaders) need: `/usr`, `/lib*`, `/bin`, `/sbin`, `/opt`,
 *       `/etc` (resolv.conf + TLS trust), `/proc`, `/sys`, `/run`, `/var`;
 *     - `~/.bun/bin` (exec `bun` — read+exec only; the RW half of the old
 *       whole-tree `~/.bun` grant survives only as `~/.bun/install/cache`,
 *       the dir `bun install` populates during plugin installs).
 *
 *   deny (implicit — everything else, notably the rest of `$HOME`)
 *     - `~/.ssh`, `~/.aws`, `~/.gnupg`, browser profiles, documents,
 *       `~/.claude/.credentials.json` (outside the scoped `~/.claude` grants),
 *       the shell rc files (`~/.zshrc` etc.), and WRITES to the provider-CLI
 *       binary dirs (`~/.local/bin`, `~/.local/share/claude`, `~/.grok/bin` are
 *       read+exec only — the daemon runs the CLIs but never installs or updates
 *       them; that is user-run + unsandboxed) and `~/.bun/bin`
 *       (launcher-trojan guard). Known residuals (documented in the audit,
 *       closed by the §3 broker): `~/.codex/auth.json` +
 *       `~/.kimi-code/credentials/` remain inside still-granted setup-target
 *       dirs on Linux (Landlock has no deny rules); macOS re-denies them
 *       (`seatbelt.ts` `credentialDeny`).
 *
 * Note the system `/tmp` is deliberately NOT granted (granting it would leak
 * every other process's temp files — and the user unit no longer sets
 * `PrivateTmp=yes`, which broke `--user` units). Instead the daemon owns
 * `<state>/tmp` (`daemonTempDir()`, granted as part of the state dir) and
 * points every isolated CLI's `TMPDIR` at it (`cli-paths.ts` `cliEnv`), so the
 * codex/kimi installers' `mktemp -d` stages inside the working set rather than
 * EACCESing on the ungranted `/tmp`.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { stateDir } from "../env";
import { DAEMON_VERSION } from "../version";

export type TWorkingSet = {
  /** Paths (recursive) the daemon and its children may read AND write. */
  readonly readWrite: readonly string[];
  /** Paths (recursive) the daemon and its children may read + execute. */
  readonly readOnly: readonly string[];
};

/** Walk up to the nearest existing ancestor for each path. Landlock's
 *  `open(O_PATH)` fails on a missing path; granting a not-yet-created target
 *  directly is meaningless, but we must grant an existing ancestor so the
 *  bootstrap install/setup scripts can CREATE the missing target. For first-run
 *  bootstrap targets like ~/.claude that don't yet exist, this walks up to the
 *  existing parent (e.g. ~/.local/) and grants that, letting the install mkdir.
 *
 *  SECURITY: stops at the user's home directory AND at the filesystem root,
 *  returning the original path unchanged when the target doesn't exist and
 *  would climb to or above either. This prevents widening grants to the entire
 *  home directory — or the entire filesystem — when a bootstrap or system
 *  target is missing (e.g. `/lib64`, absent on arm64 Linux, would otherwise
 *  climb to `/` and grant the whole root tree). Callers must pre-create
 *  bootstrap targets or handle the grant failure. */
const existing = (paths: readonly string[]): string[] => {
  const home = homedir();
  // Secret-bearing roots whose SCOPED children must resolve EXACTLY — never by
  // climbing. A grant like `~/.bun/install/cache`, `~/.bun/bin`,
  // `~/.grok/{bin,downloads}`, `~/.config/raycast/ai`, or any `~/.claude/*`
  // subtree is pre-created best-effort in `daemonWorkingSet()`; if that
  // pre-create failed and the leaf is missing, DROP the grant rather than let
  // the ancestor-walk widen it back onto the parent, which holds the very
  // secrets the scoping exists to keep out: `~/.bun/bin` (write = §5-B
  // launcher trojan), `~/.grok/auth.json`, `~/.config`'s gcloud/gh tokens, and
  // `~/.claude/.credentials.json` (the §5-A Linux OAuth token at the
  // `~/.claude` root). `~/.cache`/`~/.local` are deliberately NOT sensitive —
  // `~/.cache/openllm` legitimately climbs to `~/.cache` (documented + tested,
  // no secrets there). The roots themselves are never grant entries, so this
  // only ever affects their children.
  const sensitiveRoots = [
    join(home, ".bun"),
    join(home, ".grok"),
    join(home, ".config"),
    join(home, ".claude"),
  ];
  const underSensitiveRoot = (p: string): boolean =>
    sensitiveRoots.some((root) => p.startsWith(`${root}/`));
  return paths.map((p) => {
    // Exact/no-climb for scoped grants beneath a secret-bearing root: a missing
    // leaf is DROPPED (returned unchanged → fails to grant safely), never
    // substituted by its parent.
    if (!existsSync(p) && underSensitiveRoot(p)) {
      return p;
    }
    let candidate = p;
    while (candidate !== "/" && !existsSync(candidate)) {
      const parent = dirname(candidate);
      // Stop climbing at home OR root: do NOT return home (or `/`) as the
      // granted ancestor when the original target didn't exist — that would
      // widen the grant to the whole home tree or the entire filesystem.
      // Return the original path instead so callers can pre-create it or handle
      // the missing grant.
      if ((parent === home || parent === "/") && candidate !== home) {
        return p; // original path (non-existent, will fail to grant)
      }
      candidate = parent;
    }
    return candidate;
  });
};

/**
 * Get the daemon's temp directory path (under the state dir). Creates it if
 * missing (mode 0o700). Returns the path even if creation fails — callers
 * can handle the failure as needed.
 */
export const daemonTempDir = (): string => {
  const daemonTmp = join(stateDir(), "tmp");
  try {
    mkdirSync(daemonTmp, { recursive: true, mode: 0o700 });
  } catch {
    // Creation failure is non-fatal — the sandbox will still apply, but
    // operations needing temp will fail. Callers can log/handle as needed.
  }
  return daemonTmp;
};

/**
 * The daemon's base working set (no user grants — the §3.4 consent flow
 * unions persisted grants in here when it lands). Resolved at call time so
 * `OPENLLM_DAEMON_STATE_DIR` overrides are honoured.
 */
export const daemonWorkingSet = (): TWorkingSet => {
  const home = homedir();
  const state = stateDir();
  // Daemon-owned temp directory under the state dir. The unit hardening no
  // longer sets PrivateTmp (removed due to --user unit compatibility issues),
  // so granting global /tmp would leak access to every other process's temp
  // files. Instead we create and use our own isolated temp under stateDir.
  const daemonTmp = daemonTempDir();
  // The integration scripts' staging dir ($HOME/.cache/openllm — see the grant
  // below). PRE-CREATE it (best-effort) so the grant lands on the real leaf:
  // `existing()` deliberately refuses to climb to bare $HOME, so on a fresh box
  // where ~/.cache itself is absent the leaf would otherwise stay ungranted and
  // the confined script's first mktemp would still EACCES. Mirrors how
  // `daemonTempDir()` pre-creates the daemon tmp above.
  const integrationTmp = join(home, ".cache", "openllm");
  try {
    mkdirSync(integrationTmp, { recursive: true, mode: 0o700 });
  } catch {
    // Best-effort — if creation fails, `existing()` still climbs to whatever
    // ancestor DOES exist (or returns the leaf, which fails to grant safely).
  }
  // Pre-create the vendor CLI install/config dirs the host-install + setup flows
  // write into (claude / codex / kimi). REQUIRED on Linux: Landlock can only
  // grant an EXISTING path (`existing()` drops a non-existent leaf rather than
  // widen the grant to bare $HOME), so on a fresh box `~/.kimi-code` etc. would
  // be UNgranted and the vendor installer's `mkdir -p ~/.kimi-code/bin` EACCESes
  // (the Linux EC2 failure). macOS Seatbelt grants by path pattern so it doesn't
  // need this — pre-creating is a harmless no-op there. Same pattern as the
  // daemonTempDir / integrationTmp pre-creation above.
  for (const d of [
    // claude-code: SCOPED subtrees only, never the whole ~/.claude — the
    // user's real OAuth token (`~/.claude/.credentials.json` on Linux) lives
    // at the root and must stay outside the working set (audit §5-A). These
    // are exactly what the SHA-gated scripts + the official installer write:
    //   skills/commands/hooks/plugins/plugin-state — skill+plugin installs;
    //   downloads — claude.ai/install.sh's staging dir.
    join(home, ".claude", "skills"),
    join(home, ".claude", "plugins"),
    join(home, ".claude", "commands"),
    join(home, ".claude", "hooks"),
    join(home, ".claude", "plugin-state"),
    join(home, ".codex"),
    join(home, ".kimi-code"),
    // grok (x.ai/cli): the daemon EXECS ~/.grok/bin/grok (the isolated CLI is a
    // symlink to it), so pre-create the bin dir for the READ+EXEC grant below to
    // land on a real leaf (NOT bare ~/.grok — `existing()` won't widen to $HOME;
    // the user's real ~/.grok/auth.json stays out of the working set). The
    // installer's ~/.grok/downloads staging dir is NOT granted — installs are
    // user-run + unsandboxed now.
    join(home, ".grok", "bin"),
    // raycast (non-isolated setup): the setup writes ~/.config/raycast/ai/
    // providers.yaml (+ its .openllm-bak backup). Pre-create the `ai` leaf so
    // the SCOPED grant below lands on a real path (NOT bare ~/.config —
    // `existing()` won't widen to it, and ~/.config holds gcloud/gh secrets the
    // deny-default must keep out).
    join(home, ".config", "raycast", "ai"),
    join(home, ".local", "bin"),
    join(home, ".local", "share", "claude"),
    // claude's XDG dirs — its native installer/runtime use the full XDG layout
    // ON LINUX (`~/.local/state/claude`, `~/.cache/claude`); absent on macOS.
    // Pre-creating makes the parents exist so the installer's mkdir succeeds,
    // and the grants below let claude write its state/cache. (`~/.claude` is the
    // config dir, granted above; `~/.local/share/claude` is the binary.)
    join(home, ".local", "state", "claude"),
    join(home, ".cache", "claude"),
  ]) {
    try {
      mkdirSync(d, { recursive: true });
    } catch {
      // best-effort — an ungranted leaf just means that vendor's install falls
      // back / fails visibly, not a daemon-boot failure.
    }
  }
  // ~/.claude/settings.json is granted as a FILE (never the whole ~/.claude —
  // see the scoped subtrees above). A Landlock file rule needs the file to
  // EXIST, and a file-scoped grant cannot authorize creating it (open(O_CREAT)
  // needs MAKE_REG on the PARENT dir, which stays ungranted) — so pre-create
  // an empty JSON object when absent. Every settings-merge script branches on
  // `[ -f ]` / parses the file, and `{}` merges cleanly on all of them. `wx`
  // never touches an existing file, so a populated settings.json is untouched.
  const claudeSettings = join(home, ".claude", "settings.json");
  try {
    // Explicit 0o600, not the process umask: these seed a user-config file
    // that carries the gateway API key once the setup merge runs — keep it
    // private from group/other regardless of the daemon's inherited umask.
    writeFileSync(claudeSettings, "{}\n", { flag: "wx", mode: 0o600 });
  } catch {
    // exists already (the common case) or ~/.claude itself couldn't be made —
    // either way the grant below lands on whatever is really there.
  }
  // Same for ~/.claude.json (the MCP-server registry the plugin installs merge
  // into): it's a FILE grant at the $HOME root, so a confined child can never
  // CREATE it (that needs MAKE_REG on the ungranted $HOME) and Landlock can't
  // grant a missing path. `wx` never touches an existing file.
  const claudeJson = join(home, ".claude.json");
  try {
    // 0o600 for the same reason as settings.json above — private by mode, not
    // by inherited umask.
    writeFileSync(claudeJson, "{}\n", { flag: "wx", mode: 0o600 });
  } catch {
    // exists already — the grant lands on the real file.
  }
  // bun's global install cache — the RW half of the split ~/.bun grant (bin is
  // read+exec only, below). Only pre-create it when bun IS installed: absent
  // bun means the plugin install fails its own `command -v bun` check, and
  // fabricating ~/.bun on a bun-less box would be pure noise.
  const bunCache = join(home, ".bun", "install", "cache");
  if (existsSync(join(home, ".bun"))) {
    try {
      mkdirSync(bunCache, { recursive: true });
    } catch {
      // best-effort — see the vendor-dir loop above.
    }
  }
  const readWrite = new Set<string>([
    // The whole state dir: daemon.env (config + key + device id) + logs + isolated CLI roots
    // (`cli/<provider>/{home,bin}` all nest under it — see `cli-paths.ts`)
    // + the installed binary and its self-update temp (`<state>/bin`).
    state,
    // Belt-and-braces for a binary installed OUTSIDE the state dir (manual
    // placement): self-update renames a temp over `process.execPath`, so its
    // real directory must be writable.
    dirname(process.execPath),
    // ── Integration / setup workflow targets ──────────────────────────
    // The SHA-gated skill/plugin/setup scripts the daemon runs (via `bash -s`)
    // configure the user's CLIs IN PLACE — including the NON-isolated codex /
    // kimi / claude setups (`packages/setup/{codex,kimi-code,claude-code}`)
    // and the plugin/skill installers (`packages/{plugin,skill}`). Every path
    // they write MUST be granted or the install fails under the sandbox.
    //   claude-code: SCOPED to the subtrees the scripts + installer write —
    //   NEVER the whole ~/.claude, whose root holds the user's real OAuth
    //   token on Linux (`.credentials.json`; audit §5-A credential-parity
    //   fix — Landlock has no deny rules, so the only way to keep the token
    //   out is to not grant its parent). settings.json is a FILE grant
    //   (pre-created above; `ruleAccessFor` masks it to file-applicable
    //   rights) — note a file-scoped grant can't take a cross-dir rename, so
    //   the merge scripts write it IN PLACE (`cat > settings.json`).
    join(home, ".claude", "skills"),
    join(home, ".claude", "plugins"),
    join(home, ".claude", "commands"),
    join(home, ".claude", "hooks"),
    join(home, ".claude", "plugin-state"),
    claudeSettings,
    join(home, ".claude.json"),
    //   codex (non-isolated setup): ~/.codex/config.toml + catalog json.
    join(home, ".codex"),
    //   kimi-code (non-isolated setup): ~/.kimi-code.
    join(home, ".kimi-code"),
    //   raycast (non-isolated setup): ONLY ~/.config/raycast/ai — the sole dir
    //   the setup writes (providers.yaml + its .openllm-bak). NOT the whole
    //   ~/.config (which holds gcloud/gh tokens the deny-default keeps out), nor
    //   even all of ~/.config/raycast (the user's extensions/state) — scoped to
    //   the `ai` leaf so the config write is granted and every other secret
    //   stays denied.
    join(home, ".config", "raycast", "ai"),
    //   (~/.grok/bin, ~/.local/bin, ~/.local/share/claude are READ+EXEC in the
    //   readOnly set below — the daemon EXECS the vendor CLIs there but never
    //   WRITES: installs + vendor self-update are user-run + unsandboxed now.
    //   ~/.grok/downloads + ~/.claude/downloads were installer STAGING dirs and
    //   are no longer granted at all.)
    //   bun's global install cache ONLY (the SPLIT ~/.bun grant — audit §5-B):
    //   the claude-context plugin install runs `bun install`, which populates
    //   ~/.bun/install/cache. The `bun` BINARY dir (~/.bun/bin) is read+exec in
    //   the readOnly set below — write access there would let a compromised
    //   daemon trojan the user's `bun` launcher. Absent when bun isn't
    //   installed — the install then fails its own `command -v bun` check,
    //   correctly. Holds no credentials.
    bunCache,
    //   claude's XDG STATE + CACHE dirs — the isolated claude WRITES these at
    //   RUN time (logs/state + cache) on Linux; absent on macOS. Scoped to the
    //   claude subdirs (not the whole `~/.local/state` / `~/.cache`) — no
    //   secrets there. (`~/.local/share/claude`, the BINARY dir, is read+exec in
    //   readOnly — the daemon execs but never writes it.)
    join(home, ".local", "state", "claude"),
    join(home, ".cache", "claude"),
    //   (NO shell rc / profile grants. They were the single worst tamper
    //   lever — an rc append is code exec in every future shell. The daemon no
    //   longer installs vendor CLIs, so there are no in-sandbox installer PATH
    //   edits to worry about: installs run in the UNSANDBOXED user context (the
    //   daemon install script), where the native installers do their normal
    //   rc/PATH edits.)
    //   the integration scripts' OWN staging dir: the shared script preamble
    //   (`packages/api/lib/scripts.ts` `pick_tmpdir`) points TMPDIR at
    //   `$HOME/.cache/openllm` (the root fs, to dodge the small /tmp tmpfs on
    //   cloud images), and EVERY install/uninstall does its `mktemp` +
    //   download/extract there. Without this grant a confined integration's
    //   first `mktemp` EACCESes → the `set -e` script exits 1 (the EC2
    //   install/uninstall failure). Pre-created above so the grant lands on the
    //   real leaf even when ~/.cache didn't previously exist.
    integrationTmp,
    // Daemon-owned temp directory (NOT global /tmp). Vendor install scripts
    // stage downloads here. Created above with 0o700 so it's isolated.
    daemonTmp,
    // Device nodes the runtime + EVERY spawned child need: `/dev/null` (the
    // stdio target when a spawn uses `stdout: "ignore"` — without this, Bun's
    // `posix_spawn` of `bash`/the vendor CLIs fails `EACCES` setting up the
    // redirect, so connect + integration installs silently break), `/dev/
    // urandom`, etc. Devices hold no secrets, so granting `/dev` is safe.
    "/dev",
  ]);
  const readOnly = new Set<string>([
    // ── Dev-source-only grant (NEVER the shipped binary) ───────────────
    // A source/dev run executes `bun packages/daemon/src/main.ts`, so the
    // runtime must READ the repo's `.ts` sources + hoisted `node_modules`
    // (e.g. `effect`) at import time. Both backends are read-WHITELISTs
    // (Landlock everywhere; macOS Seatbelt deny-by-default within `$HOME`), and
    // a dev checkout lives under `$HOME`, so the repo root must be granted or
    // the from-source daemon can't load its own modules under confinement. The
    // COMPILED binary (`DAEMON_VERSION !== "0.0.0-dev"`) is
    // a self-contained executable in the state dir, needs no source tree, and
    // gets NO such grant — production confinement is unchanged. The repo root
    // is derived from this module's own location, so it's correct regardless
    // of the daemon's cwd, and it's disjoint from `$HOME` secrets like
    // `~/.ssh`, so the confinement guarantee still holds.
    ...(DAEMON_VERSION === "0.0.0-dev"
      ? [resolve(import.meta.dir, "..", "..", "..", "..")]
      : []),
    // ── Provider-CLI binary dirs — READ+EXEC only ─────────────────────
    // The daemon RUNS the vendor CLIs (each isolated run-view is a symlink to
    // the host binary), so it must EXEC through these — but it never WRITES
    // them: installs are user-run + unsandboxed (the daemon install script),
    // and vendor self-update likewise happens out of band when the user re-runs
    // the installer. Read+exec, not read-write:
    //   ~/.local/bin        — the `claude`/`codex` launchers + the `openllmd`
    //                         PATH symlink (the daemon install script writes
    //                         this one, unsandboxed; the daemon only reads it);
    //   ~/.local/share/claude — the claude launcher resolves to
    //                         `versions/<v>` here; exec reads through to it;
    //   ~/.grok/bin         — grok's binary; the isolated grok symlink execs it.
    // The user's real ~/.grok/auth.json stays UNgranted (it's a sibling file,
    // not under ~/.grok/bin). `cliInstallState`'s auto-link writes only the
    // isolated symlink under the state dir (read-write), never these dirs.
    join(home, ".local", "bin"),
    join(home, ".local", "share", "claude"),
    join(home, ".grok", "bin"),
    // bun's BINARY dir — read+exec only (the split ~/.bun grant, audit §5-B):
    // the plugin install must EXEC `bun`, but a write grant here would let a
    // compromised daemon replace the user's `bun` launcher. The cache half
    // (~/.bun/install/cache) is read-write above. `existing()` returns the
    // path unchanged when bun isn't installed, and the missing-path rule is
    // skipped at apply time — correct (nothing to exec anyway).
    join(home, ".bun", "bin"),
    // Toolchain + loaders for spawned children (bash, curl, vendor CLIs).
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/opt",
    // resolv.conf, TLS trust store, locale data.
    "/etc",
    // Runtime introspection some tools expect.
    "/proc",
    "/sys",
    "/run",
    "/var",
  ]);
  // A read-write grant subsumes a read-only one — keep the lists disjoint.
  for (const rw of readWrite) readOnly.delete(rw);
  return {
    readWrite: existing([...readWrite]),
    readOnly: existing([...readOnly]),
  };
};
