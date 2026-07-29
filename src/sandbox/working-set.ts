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
 *     - the state dir (`~/.openllm`): the shared .env (0600, holds the key + device
 *       id + config) and state.json, logs, the isolated vendor CLIs under `cli/<provider>/`
 *       (homes + binaries + config), AND the daemon binary itself + its
 *       atomic-swap temp (`bin/openllmd`, `.openllmd.update.<pid>.tmp` —
 *       the installer places the binary inside the state dir);
 *     - the executable's real directory (belt-and-braces when `execPath`
 *       lives outside the state dir — a manual install);
 *     - the claude-code integration footprint — SCOPED to the subtrees the
 *       SHA-gated plugin/setup scripts actually write
 *       (`~/.claude/{skills,plugins,commands,hooks,plugin-state,downloads}`
 *       + the `settings.json` FILE + `~/.claude.json`), NEVER the whole
 *       `~/.claude`: the user's real Claude OAuth token
 *       (`~/.claude/.credentials.json` on Linux) sits at that root and must
 *       stay outside the working set on BOTH backends (the
 *       2026-07-03 working-set-exposure audit §5-A parity fix);
 *     - the grok-build setup's `~/.grok/config.toml` — a FILE grant, NEVER
 *       the `~/.grok` dir: the user's xAI session (`~/.grok/auth.json`) sits
 *       at that root and must stay outside the working set on BOTH backends
 *       (same posture as the scoped `~/.claude` grants);
 *     - the opencode setup's `~/.config/opencode` — SCOPED to that leaf only
 *       (never bare `~/.config`, which holds gcloud/gh tokens). The credential
 *       store at `~/.local/share/opencode/auth.json` is never granted; the
 *       setup writes the key inline under `provider.openllm.options.apiKey`.
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
 *       (launcher-trojan guard). Known residual (documented in the audit,
 *       closed by the §3 broker): `~/.codex/auth.json` remains inside a
 *       still-granted setup-target dir on Linux (Landlock has no deny rules);
 *       macOS re-denies it (`seatbelt.ts` `credentialDeny`).
 *
 * Note the system `/tmp` is deliberately NOT granted (granting it would leak
 * every other process's temp files — and the user unit no longer sets
 * `PrivateTmp=yes`, which broke `--user` units). Instead the daemon owns
 * `<state>/tmp` (`daemonTempDir()`, granted as part of the state dir) and
 * points every isolated CLI's `TMPDIR` at it (`cli-paths.ts` `cliEnv`), so the
 * codex/kimi installers' `mktemp -d` stages inside the working set rather than
 * EACCESing on the ungranted `/tmp`.
 */
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import {
  CLI_PROVIDERS,
  cliBin,
  hostCliCandidates,
} from "../cli-paths";
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
/** Secret-bearing `$HOME` roots whose contents must NEVER be granted wholesale.
 *  A scoped grant like `~/.bun/install/cache`, `~/.grok/{bin,downloads}`,
 *  `~/.config/raycast/ai`, or any `~/.claude/*` subtree is fine, but the BARE
 *  root holds the secrets the scoping exists to keep out: `~/.bun/bin` (write =
 *  §5-B launcher trojan), `~/.grok/auth.json`, `~/.config`'s gcloud/gh tokens,
 *  and `~/.claude/.credentials.json` (the §5-A Linux OAuth token). Shared by
 *  `existing()` (no-climb into a root when a scoped leaf is missing) and
 *  `resolveCliExecDirs()` (never grant a bare root a symlink chain resolves
 *  into). `~/.cache`/`~/.local` are deliberately NOT here — `~/.cache/openllm`
 *  legitimately climbs to `~/.cache` (documented + tested, no secrets). */
const SENSITIVE_ROOTS = (home: string): readonly string[] => [
  join(home, ".bun"),
  join(home, ".grok"),
  join(home, ".config"),
  join(home, ".claude"),
];

const existing = (paths: readonly string[]): string[] => {
  const home = homedir();
  const sensitiveRoots = SENSITIVE_ROOTS(home);
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

/** Max symlink hops to follow before giving up — bounds a pathological or
 *  cyclic chain (a real launcher is 0-2 hops). */
const MAX_SYMLINK_HOPS = 16;

/**
 * Resolve the directories a spawned vendor CLI must be able to READ+EXEC, by
 * FOLLOWING the launcher's symlink chain from `seed`. The daemon execs the
 * launcher and the kernel reads THROUGH every symlink to the real ELF, so each
 * dir along the way must be granted or the spawn EACCESes. Hardcoding these is
 * brittle — each vendor buries its real binary in a different, sometimes
 * version-specific, dir (claude `~/.local/share/claude/versions/<v>`, codex
 * `~/.codex/packages/standalone/releases/<v>-<arch>/bin` behind a `current` DIR
 * symlink, grok `~/.grok/downloads/grok-<arch>` behind `~/.grok/bin/grok`), and
 * a custom install dir (`GROK_BIN_DIR`, `CODEX_HOME`, …) moves them anywhere.
 * Following the ACTUAL chain is self-correcting.
 *
 * Two passes, both needed:
 *   1. per-hop walk (`lstat`→`readlink`) collecting `dirname()` of every node —
 *      catches FILE-symlink chains;
 *   2. `dirname(realpath(seed))` — catches INTERMEDIATE DIR symlinks a file walk
 *      steps over (codex's `current → releases/<v>`).
 *
 * Each collected dir is emitted in BOTH forms — the canonical (realpath'd) path
 * AND the RAW path as the chain spells it. The two backends enforce on different
 * things: Landlock resolves a rule to an INODE, so the canonical form is the only
 * one that matters, but macOS Seatbelt matches the PATH the kernel walks, and
 * that walk must be able to `stat()` every intermediate component AS WRITTEN.
 * Canonicalizing codex's `~/.codex/packages/standalone/current/bin` to its
 * `releases/<v>-<arch>/bin` target silently dropped the `current` symlink node
 * from the profile, so `seatbelt.ts`'s `homeAncestorPaths` never emitted a
 * metadata literal for it and every `codex` spawn — plus the `existsSync` probe
 * behind `cli_installed` — EPERM'd at that node, surfacing in the dashboard as
 * "ChatGPT (Codex) CLI not found on this machine" on a box where codex WAS
 * installed (audit `2026-07-25-codex-exec-dir-symlink-seatbelt.md`). Emitting the
 * raw path too keeps the ancestor walk honest; on Linux it is a duplicate rule
 * for the same inode, which Landlock ignores.
 *
 * SECURITY: emits READ+EXEC dir grants only (binaries, never credentials — auth
 * stores like `~/.grok/auth.json` are SIBLINGS, not under any bin/downloads
 * dir). Every candidate must EXIST and must not be `/`, `$HOME`, an ancestor of
 * `$HOME`, or a bare `SENSITIVE_ROOTS` entry — checked in BOTH forms, so neither
 * a raw nor a canonical bare/broken/hostile chain can widen the grant onto the
 * home tree, the filesystem root, or a secret-bearing root. All fs reads are
 * best-effort: a missing/broken/looping link just stops the walk with whatever
 * was safely collected (never throws).
 */
export const resolveCliExecDirs = (seed: string, home: string): string[] => {
  const out = new Set<string>();
  // Canonicalize the reference roots so the bound checks below survive
  // realpath-canonicalization of the CANDIDATE dirs (macOS resolves
  // `/var → /private/var`, and any tmp/home may itself sit behind a symlink — so
  // a raw-vs-realpath string compare would silently miss `$HOME`/a sensitive
  // root and wrongly grant it). Compare canonical-to-canonical throughout.
  const canon = (p: string): string => {
    try {
      return realpathSync(p);
    } catch {
      return p; // missing — keep raw; existsSync check below drops it anyway
    }
  };
  const canonHome = canon(home);
  // Both forms of every bound: a RAW path is granted alongside its canonical
  // one (see the doc comment), so a raw `$HOME`/ancestor/sensitive-root spelling
  // must be rejected just as hard as the canonical one.
  const forbidden = new Set<string>([canonHome, home, "/"]);
  for (const start of [canonHome, home]) {
    for (let a = dirname(start); a !== dirname(a); a = dirname(a)) {
      forbidden.add(a); // ancestors of home: /Users, / (mac); /home, / (linux)
    }
  }
  for (const root of SENSITIVE_ROOTS(home)) {
    forbidden.add(root);
    forbidden.add(canon(root));
  }
  const addExecDir = (dir: string): void => {
    if (!existsSync(dir)) return; // Landlock can't grant a missing path
    const real = canon(dir);
    // Reject $HOME, filesystem root, any ancestor of $HOME, or a bare
    // secret-bearing root — a bare/broken/hostile chain must never widen the
    // grant onto the home tree, `/`, or a credential root.
    if (forbidden.has(dir) || forbidden.has(real)) return;
    // The CANONICAL path (what Landlock enforces on, as an inode) AND the RAW
    // path (what Seatbelt's path walk stats, component by component). A Set
    // collapses the two when the dir carries no symlink.
    out.add(real);
    out.add(dir);
  };

  // Pass 1: per-hop symlink walk (does NOT follow — inspects each link itself).
  const seen = new Set<string>();
  let cur = seed;
  for (let hop = 0; hop < MAX_SYMLINK_HOPS; hop++) {
    if (seen.has(cur)) break; // cycle
    seen.add(cur);
    let st: ReturnType<typeof lstatSync>;
    try {
      st = lstatSync(cur);
    } catch {
      break; // missing / broken — stop; whatever was collected stands
    }
    addExecDir(dirname(cur));
    if (!st.isSymbolicLink()) break; // reached the real node
    let target: string;
    try {
      target = readlinkSync(cur);
    } catch {
      break;
    }
    cur = isAbsolute(target) ? target : resolve(dirname(cur), target);
  }

  // Pass 2: fully-resolved realpath (catches intermediate DIR symlinks).
  try {
    addExecDir(dirname(realpathSync(seed)));
  } catch {
    // seed missing / broken chain — pass 1 already collected what it could.
  }

  return [...out];
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
  // Pre-create the vendor-CLI dirs the daemon EXECS through. REQUIRED on
  // Linux: Landlock can only grant an EXISTING path (`existing()` drops a
  // missing leaf rather than widening the grant to bare $HOME), so a fresh box
  // would leave these ungranted and every vendor spawn would EACCES. macOS
  // Seatbelt grants by pattern, so pre-creating is a harmless no-op there.
  //
  // This list used to also pre-create every CLIENT CONFIG dir (~/.claude
  // subtrees, ~/.codex, ~/.config/{raycast/ai,opencode}) because the daemon ran
  // the registry install scripts, which edited those files IN PLACE under
  // confinement. It doesn't any more — `openllm <client>` applies the config at
  // RUN time, in the USER's own process, outside this sandbox — so none of them
  // are granted (or created) here. See
  // `docs/proposals/remove-registry-runtime-config-merge.md` §8.1.
  for (const d of [
    // grok (x.ai/cli): the daemon EXECS grok via ~/.grok/bin/grok, but that is
    // only a SYMLINK — the real ELF lives at ~/.grok/downloads/grok-<arch>. So
    // EXEC reads through to downloads/, and BOTH need READ+EXEC below.
    // Pre-create both so the grants land on real leaves (NOT bare ~/.grok —
    // the user's ~/.grok/auth.json must stay out of the working set).
    join(home, ".grok", "bin"),
    join(home, ".grok", "downloads"),
    join(home, ".local", "bin"),
    join(home, ".local", "share", "claude"),
    // claude's XDG dirs — its runtime writes these ON LINUX; absent on macOS.
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
  // NOTE: no client-config seeding here any more. The daemon used to
  // pre-create + FILE-grant ~/.claude/settings.json, ~/.claude.json,
  // ~/.claude/CLAUDE.md, ~/.grok/config.toml and
  // ~/.config/opencode/opencode.json so the registry install scripts could
  // merge into them under confinement. Those scripts are gone: a client's
  // config is composed at RUN time by `openllm <client>` in the user's own
  // process, and for session clients it is never written at all. The daemon
  // therefore needs ZERO third-party config grants — including for Raycast,
  // whose in-place writer is likewise a user-invoked CLI command, never a
  // daemon command (there is no control-channel command that could ask the
  // daemon to touch it).
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
    // The whole state dir: the shared .env (config + key + device id) + logs + isolated CLI roots
    // (`cli/<provider>/{home,bin}` all nest under it — see `cli-paths.ts`)
    // + the installed binary and its self-update temp (`<state>/bin`).
    state,
    // The canonical install-state file ($HOME/.openllm/state.json) — a FILE
    // grant, never the whole ~/.openllm dir: the runtime writes it in place
    // (settings.json posture). Hardcoded in the scripts, NOT derived from the
    // state dir; redundant with `state` in the default layout, load-bearing
    // when OPENLLM_DAEMON_STATE_DIR points elsewhere.
    // The scripts' write-once original-config backups ($HOME/.openllm/backups
    // — hardcoded in backup_once; pre-created above so the grant lands on the
    // real leaf even when the parent grant failed to create).
    // Legacy per-file install stamps — the migration fallback reads.
    // Belt-and-braces for a binary installed OUTSIDE the state dir (manual
    // placement): self-update renames a temp over `process.execPath`, so its
    // real directory must be writable.
    dirname(process.execPath),
    // ── NO client-config grants ───────────────────────────────────────
    // Every path that used to be granted here (~/.claude subtrees +
    // settings.json + ~/.claude.json + CLAUDE.md, ~/.codex,
    // ~/.grok/config.toml, ~/.config/raycast/ai, ~/.config/opencode) existed so
    // the daemon could run a registry install script that edited the user's
    // client config in place. There are no such scripts, and no
    // control-channel command that installs anything — so the daemon has no
    // business writing any of them. `openllm <client>` does that work in the
    // user's own unconfined process.
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
    //   ~/.grok/bin         — the grok launcher SYMLINK (bin/grok →
    //                         ../downloads/grok-<arch>); the isolated grok
    //                         symlink execs it;
    //   ~/.grok/downloads   — the REAL grok ELF the bin/grok symlink points at.
    //                         Exec of grok reads THROUGH bin/grok to this dir, so
    //                         it must be read+exec too (a dropped grant here
    //                         EACCESes every `grok` spawn — the connect/login
    //                         flow then never emits its device URL). Holds the
    //                         binary only, no credentials (auth.json is a sibling
    //                         under ~/.grok, left UNgranted).
    // The user's real ~/.grok/auth.json stays UNgranted (it's a sibling file, not
    // under bin/ or downloads/). `cliInstallState`'s auto-link writes only the
    // isolated symlink under the state dir (read-write), never these dirs.
    join(home, ".local", "bin"),
    join(home, ".local", "share", "claude"),
    join(home, ".grok", "bin"),
    join(home, ".grok", "downloads"),
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
  // DYNAMIC exec-dir resolution — the robustness backstop for the hardcoded
  // provider bin grants above. For every provider, FOLLOW the symlink chain of
  // its isolated run-view (`cliBin`, seeded lazily by `cliInstallState`) AND its
  // host launcher candidates (`hostCliCandidates`, present as soon as the CLI is
  // installed), and grant the real dir of every node read+exec. Self-correcting:
  // whatever non-standard / version-specific / custom-install dir a vendor buries
  // the ELF in (the grok `~/.grok/downloads` regression, codex's version dir
  // behind `current`, a user's `GROK_BIN_DIR`), exec-through is granted because
  // we followed the ACTUAL link. Additive — never removes the hardcoded floor;
  // `resolveCliExecDirs` bounds every grant (existing dirs only, never $HOME/root/
  // a bare sensitive root). Absent CLIs contribute nothing (missing seeds skip).
  for (const provider of CLI_PROVIDERS) {
    for (const seed of [...hostCliCandidates(provider), cliBin(provider)]) {
      for (const dir of resolveCliExecDirs(seed, home)) readOnly.add(dir);
    }
  }
  // A read-write grant subsumes a read-only one — keep the lists disjoint.
  for (const rw of readWrite) readOnly.delete(rw);
  return {
    readWrite: existing([...readWrite]),
    readOnly: existing([...readOnly]),
  };
};
