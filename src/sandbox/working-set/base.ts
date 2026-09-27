/**
 * Working-set FOUNDATIONS — shared helpers + the base grant set every daemon
 * sub-process layer sits on top of. See `./index.ts` for the composition and
 * `docs/proposals/daemon-subprocess-isolation.md` §3.1 for the layer split.
 *
 * This module holds the pieces that are NOT specific to any one sub-process
 * layer:
 *   - the `TWorkingSet` shape,
 *   - the path-safety helpers (`existing`, `SENSITIVE_ROOTS`) both layers and
 *     the sandbox backends rely on,
 *   - the dynamic vendor-CLI exec-dir resolver (`resolveCliExecDirs`) + the
 *     hardcoded vendor exec-dir floor (`vendorExecDirs`) — shared because BOTH
 *     the `auth-state` layer (login/usage delegation) and the
 *     `vendor-cli-tunnel` layer (device PTY sessions) exec the vendor CLIs,
 *   - `daemonTempDir`,
 *   - `baseWorkingSet()` — the state dir, the daemon-owned temp, the binary's
 *     own dir, `/dev`, and the read-only system trees: everything shared by all
 *     four layers (the parent supervisor lives here too).
 *
 * The layer modules (`auth-state.ts`, `browser-chat.ts`, `fleet.ts`,
 * `vendor-cli-tunnel.ts`) import from here; they NEVER import each other, so no
 * process can pull in another layer's working set (R2-T9).
 *
 * Original single-file rationale (2026-07-03 working-set-exposure audit
 * §5-A/B/C and the `daemon-os-sandbox-and-typed-control.md` §3.1 derivation)
 * moves here verbatim — it is load-bearing audit trail:
 *
 *   read-write
 *     - the state dir (`~/.openllm`): the shared .env (0600, holds the key + device
 *       id + config) and state.json, logs, the isolated vendor CLIs under `cli/<provider>/`
 *       (homes + binaries + config), AND the daemon binary itself + its
 *       atomic-swap temp (`bin/openllmd`, `.openllmd.update.<pid>.tmp` —
 *       the installer places the binary inside the state dir);
 *     - the executable's real directory (belt-and-braces when `execPath`
 *       lives outside the state dir — a manual install);
 *     - the claude XDG STATE + CACHE dirs (isolated claude writes these at run
 *       time on Linux; absent on macOS) — SCOPED to the claude subdirs;
 *     - bun's global install cache (`~/.bun/install/cache`) — the RW half of the
 *       split `~/.bun` grant (the bin dir is read+exec only).
 *
 *   read-only
 *     - the system trees the runtime + spawned tools (`bash`, `curl`, the
 *       vendor CLIs' loaders) need: `/usr`, `/lib*`, `/bin`, `/sbin`, `/opt`,
 *       `/etc` (resolv.conf + TLS trust), `/proc`, `/sys`, `/run`, `/var`;
 *     - the vendor-CLI binary dirs — READ+EXEC only (the daemon runs the CLIs
 *       but never installs or updates them; that is user-run + unsandboxed);
 *     - `~/.bun/bin` (exec `bun` — read+exec only, launcher-trojan guard).
 *
 *   deny (implicit — everything else, notably the rest of `$HOME`)
 *     - `~/.ssh`, `~/.aws`, `~/.gnupg`, browser profiles, documents,
 *       `~/.claude/.credentials.json`, the shell rc files (`~/.zshrc` etc.),
 *       and WRITES to the provider-CLI binary dirs.
 *
 * Note the system `/tmp` is deliberately NOT granted (granting it would leak
 * every other process's temp files — and the user unit no longer sets
 * `PrivateTmp=yes`, which broke `--user` units). Instead the daemon owns
 * `<state>/tmp` (`daemonTempDir()`, granted as part of the state dir) and
 * points every isolated CLI's `TMPDIR` at it (`cli-paths.ts` `cliEnv`), so the
 * codex/kimi installers' `mktemp -d` stages inside the working set rather than
 * EACCESing on the ungranted `/tmp`.
 */
import { randomBytes } from "node:crypto";
import type { Dir } from "node:fs";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  opendirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { TProcessStartIdentityReader } from "../../../../tunnel/session/local-runtime";
import {
  normalizeProcessStartIdentity,
  processIdentityStatus,
  processStartIdentity,
} from "../../../../tunnel/session/local-runtime";
import { CLI_PROVIDERS, cliBin, hostCliCandidates } from "../../cli-paths";
import { stateDir } from "../../env";
import { DAEMON_VERSION } from "../../version";

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
export const SENSITIVE_ROOTS = (home: string): readonly string[] => [
  join(home, ".bun"),
  join(home, ".grok"),
  join(home, ".config"),
  join(home, ".claude"),
];

/**
 * The home the CURRENT working-set build is centred on. `index.ts` runs
 * `existing()` AFTER `baseWorkingSet`, which records the boundary the
 * missing-leaf climb must not cross — the `homeOverride` inside the
 * `--sandbox-exec` shim, NOT `homedir()` (there the child's ISOLATED home; a
 * leaf missing under the real home would otherwise climb into and grant the
 * real home recursively). Defaults to `homedir()` so direct `existing()`
 * callers keep the old behaviour.
 */
let existingBoundaryHome = homedir();

export const existing = (
  paths: readonly string[],
  homeBoundary?: string,
): string[] => {
  const home = homeBoundary ?? existingBoundaryHome;
  const sensitiveRoots = SENSITIVE_ROOTS(home);
  const underSensitiveRoot = (p: string): boolean =>
    sensitiveRoots.some((root) => p.startsWith(`${root}/`));
  // Boundary a missing leaf must never climb PAST or return: `home` itself,
  // every ANCESTOR of home, and `/`. The climb previously stopped only at the
  // exact `homedir()`/`/` parents, so under the `--sandbox-exec` shim — where
  // the working set is built around the DAEMON's real home (`--home`) while
  // `homedir()` is the child's isolated home — a missing leaf under the real
  // home (e.g. `~/.bun/install/cache` on a bun-less box) climbed to the real
  // home and returned it as the grant, i.e. granted the real `$HOME`
  // recursively. Ancestors of `home` are likewise never a valid grant
  // (`/home`, `/Users`).
  const noGrant = new Set<string>([home, "/"]);
  for (let a = dirname(home); a !== dirname(a); a = dirname(a)) {
    noGrant.add(a);
  }
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
      // Stop climbing at home, an ancestor of home, OR root: do NOT return any
      // of those as the granted ancestor when the original target didn't exist
      // — that would widen the grant to the whole home tree, a home parent, or
      // the entire filesystem. Return the original path instead so callers can
      // pre-create it or handle the missing grant.
      if (noGrant.has(parent) && candidate !== home) {
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
 * Orphan window for entries under `<state>/tmp` that carry no child lease.
 * Vendor CLIs run with `TMPDIR` pointed at the root (`cli-paths.ts`
 * `cliEnv`/`sessionEnv`), and a CONFINED child additionally gets its own
 * leased subdir minted by the `--sandbox-exec` shim (see `daemonTempDir`).
 * Nothing else cleans the root — OS tmp cleaners (systemd-tmpfiles, the
 * macOS periodic job) do not touch `~/.openllm` — so installer staging dirs,
 * `cursor-agent` logs and claude scratch would accumulate forever (RG-2). An
 * unleased entry has no provable owner, so the window is deliberately long:
 * anything a live child still uses is rewritten far sooner, and an idle
 * writer only loses scratch that has been stale for a full day — the same
 * exposure an OS tmp reaper gives.
 */
export const DAEMON_TMP_ORPHAN_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Grace window for a LEASED dir whose recorded owner is proven dead
 * (`processIdentityStatus` → `"dead"`; `"unknown"` keeps the dir). The lease
 * is authoritative — the wait exists only for postmortem artifacts and for a
 * still-writing descendant that outlived its leaseholder (a SIGKILLed shim
 * can orphan its tail; the tail's writes keep the subtree mtime fresh, so the
 * dir survives until the writing actually stops).
 */
export const DAEMON_TMP_LEASE_GRACE_MS = 60 * 60 * 1000;

/** Lease file the `--sandbox-exec` shim writes inside a child's temp dir. */
const TMP_LEASE_FILE = ".openllm-lease.json";
const TMP_LEASE_MAX_BYTES = 4096;

/** Sweep cadence: once shortly after boot, then hourly — never on a request. */
const DAEMON_TMP_SWEEP_INTERVAL_MS = 60 * 60 * 1000;
const DAEMON_TMP_SWEEP_BOOT_DELAY_MS = 30_000;
const DAEMON_TMP_SWEEP_BOOT_DELAY_ENV = "OPENLLM_DAEMON_TMP_SWEEP_BOOT_MS";

/**
 * Per-round work bounds. The sweep runs synchronously on a daemon timer, so
 * an unbounded vendor leak must never stall the event loop: each round lists
 * at most ENTRY_CAP top-level entries off an `opendirSync` handle that stays
 * open across rounds (never a whole-listing `readdirSync`, never a sort — the
 * kernel-side cursor gives complete coverage across rounds without
 * materializing or ordering anything), bounds every subtree walk, and stops
 * at a wall-clock deadline checked between entries.
 */
const DAEMON_TMP_SWEEP_MAX_ENTRIES = 1024; // top-level entries listed / round
const DAEMON_TMP_SWEEP_MAX_NODES = 4096; // per-entry newest-mtime walk
const DAEMON_TMP_SWEEP_ROUND_NODES = 32768; // all entry walks in one round
const DAEMON_TMP_SWEEP_MAX_DELETES = 128; // top-level removals / round
const DAEMON_TMP_SWEEP_ROUND_MS = 250; // wall-clock budget / round

/** Bound on the registry listing (one small dir of `<pid>.json` records). */
const DAEMON_TMP_REGISTRY_MAX_RECORDS = 4096;

/**
 * Conservative expiry anchor for future-dated entries whose kernel birth time
 * is unavailable: the earliest sweep `now` this process has seen. A future
 * mtime (vendor stamp, clock rollback) makes an entry look fresh at every
 * sweep, so the age bound must never consult mtimes — and must not rely on a
 * finite tracking map either. Anchoring at first-sweep bounds every
 * future-dated entry's life to the process's first sweep; an entry created
 * late simply gets less grace, never more.
 */
let firstTmpSweepAt: number | null = null;

/**
 * The open top-level listing, kept BETWEEN rounds so the next round resumes
 * where this one stopped. The kernel cursor is why a full sorted snapshot is
 * unnecessary: a complete pass visits every extant entry once, in readdir
 * order, however large the dir — and deletions the sweep itself makes just
 * shrink what is left to visit. Reset on EOF, on error, and when the tmp root
 * changes (a different state dir, e.g. a fresh test fixture).
 */
let tmpSweepListing: {
  readonly root: string;
  /** dev+ino of the root the handle is open on — a tmp dir deleted and
   *  recreated at the same path must not be read through the dead inode's
   *  handle. */
  readonly dev: number;
  readonly ino: number;
  readonly dir: Dir;
} | null = null;

/**
 * One entry name read off the listing handle but not yet classified. A round
 * that exhausts its budget ends with a tail `readSync` to detect EOF; when
 * that read returns a live entry it is parked here so the cursor never
 * advances past work the round could not afford (the starvation shape the
 * list-then-scan split had). Belongs to the current handle/root — cleared
 * whenever the handle closes.
 */
let pendingTmpEntry: string | null = null;

const closeTmpSweepListing = (): void => {
  pendingTmpEntry = null;
  if (tmpSweepListing === null) return;
  try {
    tmpSweepListing.dir.closeSync();
  } catch {
    // already closed or invalidated
  }
  tmpSweepListing = null;
};

/**
 * Monotonic clock for the sweep's wall-clock budgets — `performance.now()`,
 * never `Date.now()`: an NTP step or manual clock change must neither stretch
 * a round (deadline drifts later) nor expire it instantly (every entry looks
 * undecidable for a round — harmless, but noisy). Seamed so a test can drive
 * the deadline inside a tree walk deterministically.
 */
let sweepNowImpl: () => number = (): number => performance.now();

export const setDaemonTmpSweepClockForTests = (
  fn: (() => number) | null,
): void => {
  sweepNowImpl = fn ?? ((): number => performance.now());
};

const sweepNow = (): number => sweepNowImpl();

/**
 * A lease: the pid + start identity of the shim process a confined vendor
 * child runs as. The pid is the one `superviseSpawn` registers (on Linux the
 * pdeathsig wrapper execs the shim in place, so the pid survives the chain).
 */
type TTmpLease = {
  readonly pid: number;
  readonly startIdentity: string;
};

/** Read + validate a dir's lease file. `null` = absent/invalid → orphan. */
const readTmpLease = (dir: string): TTmpLease | null => {
  const path = join(dir, TMP_LEASE_FILE);
  let raw: string;
  try {
    const st = lstatSync(path);
    if (!st.isFile() || st.isSymbolicLink() || st.size > TMP_LEASE_MAX_BYTES) {
      return null;
    }
    raw = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  try {
    const value: unknown = JSON.parse(raw);
    if (
      typeof value !== "object" ||
      value === null ||
      !("pid" in value) ||
      !("startIdentity" in value)
    ) {
      return null;
    }
    const { pid, startIdentity } = value as {
      pid: unknown;
      startIdentity: unknown;
    };
    if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
      return null;
    }
    if (typeof startIdentity !== "string" || startIdentity.length === 0) {
      return null;
    }
    return { pid, startIdentity };
  } catch {
    return null;
  }
};

/**
 * Newest mtime under `path`, following NO symlinks. A directory's own mtime
 * only tracks entries added/removed, not writes INSIDE them, so a dir whose
 * leaf files are fresh stays live. Iterates each level with `opendirSync`
 * under the shared node budget — never a whole-listing `readdirSync` — so a
 * huge leak tree cannot balloon memory. Returns `-Infinity` when `path`
 * cannot be statted and `+Infinity` when the walk exceeds the node budget OR
 * the round's wall-clock `deadline`: both keep the entry rather than delete
 * on a partial picture.
 */
const newestMtimeUnder = (
  path: string,
  budget: { left: number },
  deadline: number,
): number => {
  if (budget.left <= 0) return Number.POSITIVE_INFINITY;
  budget.left -= 1;
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(path);
  } catch {
    return Number.NEGATIVE_INFINITY; // raced away — parent decides
  }
  if (!st.isDirectory() || st.isSymbolicLink()) return st.mtimeMs;
  let newest = st.mtimeMs;
  let dir: Dir;
  try {
    dir = opendirSync(path);
  } catch {
    return newest;
  }
  try {
    for (;;) {
      // The wall-clock budget also applies INSIDE the walk: a tree that
      // outlives the round deadline is undecidable — kept, never deleted on
      // a partial picture (grok rework: the budget used to bind only the
      // space BETWEEN top-level entries, so one deep tree could stall the
      // daemon far past 250 ms).
      if (budget.left <= 0 || sweepNow() > deadline) {
        return Number.POSITIVE_INFINITY;
      }
      const child = dir.readSync();
      if (child === null) break;
      const t = newestMtimeUnder(join(path, child.name), budget, deadline);
      if (t === Number.POSITIVE_INFINITY) return t;
      if (t > newest) newest = t;
    }
  } catch {
    // Mid-listing read error: a partial picture is still usable — the mtimes
    // already seen stand, matching the "unreadable child contributes its own
    // mtime" behaviour of a failed `opendirSync`.
  } finally {
    try {
      dir.closeSync();
    } catch {
      // already closed
    }
  }
  return newest;
};

/** Identity of one top-level `<tmp>` entry at scan time. */
type TTmpEntryScan = {
  readonly dev: number;
  readonly ino: number;
  /** Kernel creation stamp; 0 when the filesystem does not report one. */
  readonly birthMs: number;
  /** A real directory — the only shape that can carry a lease. */
  readonly isDir: boolean;
  /** Valid lease inside a directory entry, else null. */
  readonly lease: TTmpLease | null;
};

const scanTmpEntry = (path: string): TTmpEntryScan | null => {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(path);
  } catch {
    return null;
  }
  const isDir = st.isDirectory() && !st.isSymbolicLink();
  return {
    dev: st.dev,
    ino: st.ino,
    birthMs: st.birthtimeMs,
    isDir,
    lease: isDir ? readTmpLease(path) : null,
  };
};

/**
 * Entry age in ms, or `-Infinity` when the mtime walk could not decide (a
 * raced-away stat or an over-budget tree is retried next round, never
 * deleted on a partial picture). Future-dated mtimes cannot extend an
 * entry's life: the anchor falls back to the kernel birth time, then to the
 * process's first sweep.
 */
const tmpEntryAgeMs = (
  scan: TTmpEntryScan,
  path: string,
  now: number,
  budget: { left: number },
  deadline: number,
): number => {
  // Per-entry ceiling inside the shared round budget: one runaway tree costs
  // at most DAEMON_TMP_SWEEP_MAX_NODES — it is kept as undecidable, but it
  // cannot burn the whole round's node allowance for its siblings.
  const entryCap = Math.min(
    budget.left,
    tmpSweepBudgetForTests?.entryNodes ?? DAEMON_TMP_SWEEP_MAX_NODES,
  );
  const entryBudget = { left: entryCap };
  const newest = newestMtimeUnder(path, entryBudget, deadline);
  budget.left -= entryCap - entryBudget.left;
  if (
    newest === Number.NEGATIVE_INFINITY ||
    newest === Number.POSITIVE_INFINITY
  ) {
    return Number.NEGATIVE_INFINITY;
  }
  if (newest > now) {
    const anchor =
      scan.birthMs > 0 && scan.birthMs <= now
        ? scan.birthMs
        : (firstTmpSweepAt ?? now);
    return now - anchor;
  }
  return now - newest;
};

/**
 * TEST SEAM — replace the `processStartIdentity` reader the lease check runs
 * through `processIdentityStatus`. Lets a test assert the dead/alive/unknown
 * outcomes deterministically. Never set in production.
 */
let identityReaderForTests: TProcessStartIdentityReader | null = null;

export const setDaemonTmpSweepIdentityReaderForTests = (
  reader: TProcessStartIdentityReader | null,
): void => {
  identityReaderForTests = reader;
};

const tmpLeaseStatus = (lease: TTmpLease): "alive" | "dead" | "unknown" =>
  processIdentityStatus(
    lease.pid,
    lease.startIdentity,
    identityReaderForTests ?? processStartIdentity,
  );

/**
 * Pids with a live record in the daemon's child registry
 * (`<state>/children/<pid>.json`), or `null` when the listing is truncated by
 * the record cap or fails mid-read — a pid past the cap would look
 * unregistered, so callers treat `null` as "registry unknown" and keep every
 * leased dir that round (codex rework). Read straight from the directory —
 * a record file existing IS the "still registered" signal (the boot prune
 * keeps the dir small). Ownership the daemon itself recorded: no `/proc` fd
 * scan, no `lsof`.
 */
const registryChildPids = (home?: string): Set<number> | null => {
  const cap =
    tmpSweepBudgetForTests?.registry ?? DAEMON_TMP_REGISTRY_MAX_RECORDS;
  const pids = new Set<number>();
  const children = join(stateDir(home), "children");
  // Bun's `opendirSync` is lazy — a missing registry surfaces on the first
  // `readSync`, not at open — so lstat first: an absent or non-directory
  // registry is DETERMINATE empty, never "unknown".
  try {
    const st = lstatSync(children);
    if (!st.isDirectory() || st.isSymbolicLink()) return pids;
  } catch {
    return pids; // no registry at all = genuinely no registered children
  }
  let dir: Dir;
  try {
    dir = opendirSync(children);
  } catch {
    return pids;
  }
  try {
    for (let i = 0; i < cap; i += 1) {
      const entry = dir.readSync();
      if (entry === null) return pids; // EOF inside the cap = complete listing
      const match = /^(\d+)\.json$/.exec(entry.name);
      if (match !== null) pids.add(Number(match[1]));
    }
    return null; // hit the cap with no EOF — the listing may be truncated
  } catch (error) {
    const code = (error as { readonly code?: unknown }).code;
    // The registry vanished mid-read (raced teardown) — same determinate
    // answer as absent: no live records exist to protect. Any OTHER failure
    // is indeterminate — never proves a lease's absence.
    return code === "ENOENT" || code === "ENOTDIR" ? pids : null;
  } finally {
    try {
      dir.closeSync();
    } catch {
      // already closed
    }
  }
};

/**
 * Delete check shared by the scan pass and the pre-delete re-verify. A leased
 * dir dies only when its owner is provably gone — a child still in the daemon
 * registry is never swept whatever the lease says, `alive`/`unknown` identity
 * keeps the dir, and a `dead` owner still gets the lease grace (an orphaned
 * descendant may keep writing; fresh mtimes hold it). An unleased entry dies
 * only past the long orphan window.
 */
const tmpEntryDeletable = (
  path: string,
  scan: TTmpEntryScan,
  now: number,
  registryPids: ReadonlySet<number> | null,
  budget: { left: number },
  deadline: number,
): boolean => {
  if (scan.lease !== null) {
    // A `null` registry means the listing was truncated or unreadable — a
    // registered pid may look absent, so keep every leased dir this round
    // rather than delete a live child's scratch on bad data.
    if (registryPids === null || registryPids.has(scan.lease.pid)) {
      return false;
    }
    if (tmpLeaseStatus(scan.lease) !== "dead") return false;
    return (
      tmpEntryAgeMs(scan, path, now, budget, deadline) >=
      DAEMON_TMP_LEASE_GRACE_MS
    );
  }
  return (
    tmpEntryAgeMs(scan, path, now, budget, deadline) >= DAEMON_TMP_ORPHAN_AGE_MS
  );
};

/**
 * TEST SEAM — runs on each delete candidate inside the scan→delete window,
 * so a test can freshen/recreate the entry or flip its lease and prove the
 * re-check drops it. Never set in production.
 */
let preRemoveHook: ((path: string) => void) | null = null;

export const setDaemonTmpSweepPreRemoveHookForTests = (
  fn: ((path: string) => void) | null,
): void => {
  preRemoveHook = fn;
};

/**
 * TEST SEAM — shrink the per-round work budgets so a small fixture exercises
 * the incremental scan/delete path. `null` restores the production bounds.
 */
let tmpSweepBudgetForTests: {
  readonly entries?: number;
  readonly deletes?: number;
  readonly nodes?: number;
  readonly ms?: number;
  /** Registry-listing cap — exercises the truncated-registry keep path. */
  readonly registry?: number;
  /** Per-entry tree-walk cap — exercises the per-entry node ceiling. */
  readonly entryNodes?: number;
} | null = null;

export const setDaemonTmpSweepBudgetForTests = (
  budget: typeof tmpSweepBudgetForTests,
): void => {
  tmpSweepBudgetForTests = budget;
};

/**
 * TEST SEAM — per-call counters from the last {@link sweepDaemonTempDir}
 * round: `listed` is how many top-level names were read off the directory
 * handle (the incremental-listing bound the rework requires), `scanned` how
 * many were statted, `probed` how many paid for the delete re-verify, and
 * `removed` the removal count.
 */
let lastTmpSweepStats = { listed: 0, scanned: 0, probed: 0, removed: 0 };

export const getDaemonTmpSweepStatsForTests = (): {
  readonly listed: number;
  readonly scanned: number;
  readonly probed: number;
  readonly removed: number;
} => ({ ...lastTmpSweepStats });

/**
 * TEST SEAM — whether the persistent top-level listing handle is currently
 * open. Proves the missing/invalid-root paths release the fd (a held handle
 * pins a deleted `<state>/tmp` inode until process exit).
 */
export const daemonTmpSweepListingOpenForTests = (): boolean =>
  tmpSweepListing !== null;

/**
 * Bounded sweep of `<state>/tmp`. Bounded + best-effort: never throws, never
 * follows symlinks, returns the number of top-level entries removed. Exported
 * for tests; the daemon reaches it via the timer `daemonTempDir` schedules —
 * never inside a request or on the spawn path.
 *
 * Per round: list a bounded slice of top-level entries off the persistent
 * `Dir` handle (coverage resumes where the last round stopped — a full pass
 * visits every extant entry once, so no listing is materialized and nothing
 * is sorted), classify each by its lease + subtree freshness, then delete a
 * bounded number of candidates. Every delete first re-verifies the entry —
 * same inode, still deletable by a FRESH lease read + identity probe — so a
 * child that revived or re-leased its dir inside the scan→delete window is
 * never swept under.
 *
 * The tmp ROOT must be a real directory: a symlinked `<state>/tmp` would
 * steer the listing+rm below into an unrelated tree.
 */
export const sweepDaemonTempDir = (
  home?: string,
  now: number = Date.now(),
): number => {
  const tmp = join(stateDir(home), "tmp");
  if (firstTmpSweepAt === null || now < firstTmpSweepAt) {
    firstTmpSweepAt = now;
  }
  // Refuse a root that is not a real directory. The daemon creates `tmp` as a
  // plain 0o700 dir and nothing legitimate replaces it with a link — an lstat
  // here is cheap insurance against the sweep's iteration+rm following a
  // symlinked root into an unrelated tree.
  let root: string;
  let rootDev = 0;
  let rootIno = 0;
  try {
    const st = lstatSync(tmp);
    // A missing or non-directory root means any previously opened listing
    // handle points at a dead inode — close it before returning so the
    // deleted dir is not held open until process exit (grok rework).
    if (!st.isDirectory() || st.isSymbolicLink()) {
      closeTmpSweepListing();
      return 0;
    }
    // Canonical root for every check below — entry paths and the lease
    // compare against the same resolved spelling the kernel reports (e.g.
    // `/var` → `/private/var` on macOS).
    root = realpathSync(tmp);
    rootDev = st.dev;
    rootIno = st.ino;
  } catch {
    closeTmpSweepListing();
    return 0;
  }
  // win32 is out of scope for this release's sweep (WINDOWS-2.8.1).
  if (process.platform === "win32") return 0;

  const entryCap =
    tmpSweepBudgetForTests?.entries ?? DAEMON_TMP_SWEEP_MAX_ENTRIES;
  const deleteCap =
    tmpSweepBudgetForTests?.deletes ?? DAEMON_TMP_SWEEP_MAX_DELETES;
  const roundNodes =
    tmpSweepBudgetForTests?.nodes ?? DAEMON_TMP_SWEEP_ROUND_NODES;
  const roundMs = tmpSweepBudgetForTests?.ms ?? DAEMON_TMP_SWEEP_ROUND_MS;
  const deadline = sweepNow() + roundMs;
  const budget = { left: roundNodes };
  lastTmpSweepStats = { listed: 0, scanned: 0, probed: 0, removed: 0 };

  const registryPids = registryChildPids(home);

  // (Re)open the listing handle when the root changed — a different state dir
  // (fresh test fixture), a renamed root, or a deleted+recreated tmp dir at
  // the same path (dev/ino mismatch — the old handle reads a dead inode).
  if (
    tmpSweepListing !== null &&
    (tmpSweepListing.root !== root ||
      tmpSweepListing.dev !== rootDev ||
      tmpSweepListing.ino !== rootIno)
  ) {
    closeTmpSweepListing();
  }
  if (tmpSweepListing === null) {
    try {
      tmpSweepListing = {
        root,
        dev: rootDev,
        ino: rootIno,
        dir: opendirSync(root),
      };
    } catch {
      closeTmpSweepListing();
      return 0;
    }
  }

  // Classify-as-you-read: each entry is scanned + judged the moment it comes
  // off the handle, so the cursor NEVER advances past work the round could
  // not afford. (The earlier list-then-scan split could read entryCap names,
  // burn the budget on the first few, and skip the rest — skipped entries
  // were left behind the cursor until it wrapped, i.e. starved for a whole
  // pass.) Every round processes at least one entry, so a deadline-exhausted
  // round still makes forward progress.
  const stale: { name: string; path: string; scan: TTmpEntryScan }[] = [];
  let cycleComplete = false;
  let listed = 0;
  while (listed < entryCap && stale.length < deleteCap) {
    if (listed > 0 && (sweepNow() > deadline || budget.left <= 0)) break;
    let entryName: string | null;
    if (pendingTmpEntry !== null) {
      entryName = pendingTmpEntry;
      pendingTmpEntry = null;
    } else {
      let entry: ReturnType<Dir["readSync"]>;
      try {
        entry = tmpSweepListing.dir.readSync();
      } catch {
        closeTmpSweepListing(); // handle died mid-pass — retry next round
        break;
      }
      if (entry === null) {
        cycleComplete = true;
        break;
      }
      entryName = entry.name;
    }
    listed += 1;
    lastTmpSweepStats.listed += 1;
    const path = join(root, entryName);
    const scan = scanTmpEntry(path);
    lastTmpSweepStats.scanned += 1;
    if (scan === null) continue;
    if (tmpEntryDeletable(path, scan, now, registryPids, budget, deadline)) {
      stale.push({ name: entryName, path, scan });
    }
  }
  if (cycleComplete) {
    closeTmpSweepListing();
  } else {
    // Tail read: a budget break leaves the cursor mid-listing, so check EOF
    // now — an exhausted listing closes the pass THIS round (the next round
    // would otherwise spend itself just re-opening and re-seeking). A live
    // entry is parked in `pendingTmpEntry`: already consumed off the cursor,
    // it must not be skipped — it is classified first next round.
    try {
      const tail = tmpSweepListing?.dir.readSync() ?? null;
      if (tail === null) {
        closeTmpSweepListing();
      } else {
        pendingTmpEntry = tail.name;
      }
    } catch {
      closeTmpSweepListing(); // handle died — retry next round
    }
  }

  if (stale.length === 0) return 0;
  // The delete phase gets its own budget slice: a scan that consumed the
  // shared deadline must not leave a round doing zero delete work.
  const deleteDeadline = sweepNow() + roundMs;
  let removed = 0;
  let probed = 0;
  for (const { path, scan } of stale) {
    if (probed >= deleteCap) break;
    if (probed > 0 && sweepNow() > deleteDeadline) break;
    probed += 1;
    lastTmpSweepStats.probed += 1;
    preRemoveHook?.(path);
    const recheck = scanTmpEntry(path);
    if (
      recheck === null ||
      recheck.dev !== scan.dev ||
      recheck.ino !== scan.ino ||
      !tmpEntryDeletable(
        path,
        recheck,
        now,
        registryPids,
        { left: DAEMON_TMP_SWEEP_MAX_NODES },
        deleteDeadline,
      )
    ) {
      continue; // vanished, recreated, freshened, or re-leased mid-window
    }
    try {
      rmSync(path, { recursive: true, force: true });
      removed += 1;
    } catch {
      // best-effort — a busy or permed entry is retried on the next sweep
    }
  }
  lastTmpSweepStats.removed = removed;
  return removed;
};

/**
 * True for the real `--sandbox-exec` shim process — the flag is the verb
 * itself (before the `--` separator). A `__child-supervisor-pdeathsig`
 * wrapper's argv may CARRY the same string inside its tail (after `--`), and
 * so may an unrelated child arg — neither is a shim.
 */
const isSandboxShimProcess = (): boolean => {
  const verb = process.argv.indexOf("--sandbox-exec");
  if (verb <= 0) return false;
  const sep = process.argv.indexOf("--");
  return sep < 0 || verb < sep;
};

/** One minted+leased temp dir per shim process. */
let shimTmpDirMinted = false;

/**
 * Inside the `--sandbox-exec` shim only: give THIS confined vendor child its
 * own temp dir under `<state>/tmp` and record its lease there. The shim is a
 * daemon re-exec that runs this code before spawning the vendor tail; the
 * daemon pinned `TMPDIR` at the shared tmp root (`cliEnv`/`sessionEnv`), so
 * the shim mints `child-<pid>-<rand>`, writes the lease file, and re-points
 * `process.env.TMPDIR` — `childEnvironment(process.env)` then hands the tail
 * the per-child dir. The lease's pid is the registered supervised pid, which
 * the sweep's registry + `processIdentityStatus` checks answer directly — no
 * `/proc` fd scans, no `lsof`. On any failure the child keeps the shared
 * root; its entries fall under the orphan window.
 */
const mintShimChildTmpDir = (tmpRoot: string): void => {
  if (shimTmpDirMinted) return;
  shimTmpDirMinted = true;
  const envTmp = process.env.TMPDIR;
  if (envTmp === undefined || envTmp.length === 0) return;
  let rootReal: string;
  let envReal: string;
  try {
    rootReal = realpathSync(tmpRoot);
    envReal = realpathSync(envTmp);
  } catch {
    return;
  }
  // Manage only the daemon's own layout: TMPDIR pinned at the tmp root. A
  // TMPDIR pointing elsewhere is a caller's choice — leave it alone.
  if (envReal !== rootReal) return;
  // No provable identity → no lease: the dir would be swept as an orphan
  // anyway, so minting is pointless without one.
  const identity = processStartIdentity(process.pid);
  if (identity === undefined || identity === null) return;
  const lease = `${JSON.stringify({
    v: 1,
    pid: process.pid,
    startIdentity: normalizeProcessStartIdentity(identity),
  })}\n`;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const dir = join(
      rootReal,
      `child-${process.pid.toString(36)}-${randomBytes(3).toString("hex")}`,
    );
    try {
      mkdirSync(dir, { mode: 0o700 });
    } catch {
      continue; // name collision or root trouble — try a fresh suffix
    }
    try {
      writeFileSync(join(dir, TMP_LEASE_FILE), lease, { mode: 0o600 });
      process.env.TMPDIR = dir;
    } catch {
      // Lease write failed — leave the dir unleased; the orphan window owns
      // it and the child keeps the shared root.
    }
    return;
  }
};

/**
 * The first `daemonTempDir` call (the boot working-set build) schedules the
 * `<state>/tmp` sweep: once shortly after boot, then hourly, on unref'd
 * timers. The sweep never runs inside a request or on the spawn path —
 * `daemonTempDir` itself is called from both. Inside `bun test` nothing is
 * scheduled (tests drive `sweepDaemonTempDir` synchronously).
 */
let tmpSweepScheduled = false;

const tmpSweepBootDelayMs = (): number => {
  const raw = process.env[DAEMON_TMP_SWEEP_BOOT_DELAY_ENV];
  if (raw === undefined || raw.length === 0)
    return DAEMON_TMP_SWEEP_BOOT_DELAY_MS;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 600_000
    ? parsed
    : DAEMON_TMP_SWEEP_BOOT_DELAY_MS;
};

const scheduleTmpSweep = (home?: string): void => {
  if (tmpSweepScheduled || underBunTestRunner()) return;
  tmpSweepScheduled = true;
  const tick = (): void => {
    try {
      sweepDaemonTempDir(home);
    } catch {
      // Maintenance must never take the daemon down.
    }
  };
  const boot = setTimeout(tick, tmpSweepBootDelayMs());
  boot.unref();
  const timer = setInterval(tick, DAEMON_TMP_SWEEP_INTERVAL_MS);
  timer.unref();
};

/**
 * Get the daemon's temp directory path (under the state dir). Creates it if
 * missing (mode 0o700). Returns the path even if creation fails — callers
 * can handle the failure as needed.
 */
export const daemonTempDir = (home?: string): string => {
  const daemonTmp = join(stateDir(home), "tmp");
  try {
    mkdirSync(daemonTmp, { recursive: true, mode: 0o700 });
  } catch {
    // Creation failure is non-fatal — the sandbox will still apply, but
    // operations needing temp will fail. Callers can log/handle as needed.
  }
  if (process.argv.includes("--sandbox-exec")) {
    // A confined child never sweeps the SHARED `<state>/tmp` — sweep duty is
    // the parent's. Instead the true shim mints its own leased dir.
    if (isSandboxShimProcess()) mintShimChildTmpDir(daemonTmp);
    return daemonTmp;
  }
  scheduleTmpSweep(home);
  return daemonTmp;
};

/**
 * Mint a daemon-owned subdir under `<state>/tmp` for a NON-shim daemon child
 * — a device-session PTY, which is deliberately unsandboxed so no shim exists
 * to self-lease (see `mintShimChildTmpDir` for the confined path). Returns
 * the minted dir (mode 0o700), or `null` when the root is unusable — callers
 * then keep the shared root. The dir is UNLEASED until
 * {@link leaseDaemonTmpDir} lands the child pid: until then the sweep treats
 * it as an ordinary orphan candidate — never as live-child scratch.
 */
export const mintDaemonTmpDir = (home?: string): string | null => {
  let rootReal: string;
  try {
    rootReal = realpathSync(daemonTempDir(home));
  } catch {
    return null;
  }
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const dir = join(rootReal, `pty-${randomBytes(4).toString("hex")}`);
    try {
      mkdirSync(dir, { mode: 0o700 });
      return dir;
    } catch {
      // name collision or a transient root failure — fresh suffix, then give up
    }
  }
  return null;
};

/**
 * Record `pid` + its start identity as the lease inside a dir minted by
 * {@link mintDaemonTmpDir}, binding the sweep's ownership check to the real
 * child — a live identity keeps the dir, a dead one starts the lease grace.
 * Best-effort: a failed write or an unresolvable identity leaves the dir
 * under the 24 h orphan window (still bounded, still not shared). Returns
 * whether the lease landed.
 */
export const leaseDaemonTmpDir = (dir: string, pid: number): boolean => {
  const identity = processStartIdentity(pid);
  if (identity === undefined || identity === null) return false;
  try {
    writeFileSync(
      join(dir, TMP_LEASE_FILE),
      `${JSON.stringify({
        v: 1,
        pid,
        startIdentity: normalizeProcessStartIdentity(identity),
      })}\n`,
      { mode: 0o600 },
    );
    return true;
  } catch {
    return false;
  }
};

/**
 * The hardcoded vendor-CLI exec-dir FLOOR + the dynamic `resolveCliExecDirs`
 * resolution, as a READ+EXEC set. Shared by the `auth-state` layer (the daemon
 * execs vendor CLIs for login/usage/credential delegation) AND the
 * `vendor-cli-tunnel` layer (device PTY sessions exec the same binaries). The
 * daemon RUNS the vendor CLIs but never WRITES them: installs are user-run +
 * unsandboxed, and vendor self-update happens out of band. Read+exec, not
 * read-write.
 *
 * Emits the hardcoded floor (grok bin/downloads, ~/.local/bin, cursor + claude
 * versioned dirs) AND, for every provider, the real dir of every node along its
 * isolated run-view symlink chain (`cliBin`) and its host launcher candidates
 * (`hostCliCandidates`) — self-correcting for whatever non-standard /
 * version-specific / custom-install dir a vendor buries its ELF in. Bounded by
 * `resolveCliExecDirs` (existing dirs only, never $HOME/root/a bare sensitive
 * root). Absent CLIs contribute nothing (missing seeds skip).
 */

/**
 * True inside the `bun test` runner. `daemonWorkingSet()` builds grant lists
 * for INSPECTION far more often than for enforcement — every test file,
 * `openllmd` subcommand, the doctor — and the vendor-floor pre-creation below
 * is its one side effect. Inside the test runner `homedir()` is the
 * developer's real `$HOME`, so the mkdirs pollute it on every `bun test`
 * (TH-4). `bun test` sets NODE_ENV=test AND runs each test file as `Bun.main`
 * (`*.test.ts`, `*.e2e.ts`, `*.live.ts`); NODE_ENV alone cannot discriminate —
 * a spawned `bun -e` child (the fresh-box probe in `daemon-sandbox.test.ts`,
 * which must still materialize the dirs) inherits it, but its `Bun.main` is
 * `[eval]`.
 */
export const underBunTestRunner = (): boolean =>
  process.env.NODE_ENV === "test" &&
  /\.(?:test|spec|e2e|live)\.[cm]?[tj]sx?$/.test(Bun.main);

export const vendorExecDirs = (home: string): string[] => {
  // Pre-create the vendor-CLI dirs the daemon EXECS through. REQUIRED on
  // Linux: Landlock can only grant an EXISTING path (`existing()` drops a
  // missing leaf rather than widening the grant to bare $HOME), so a fresh box
  // would leave these ungranted and every vendor spawn would EACCES. macOS
  // Seatbelt grants by pattern, so pre-creating is a harmless no-op there.
  // Never inside a test runner — `home` is then the developer's real `$HOME`
  // and the mkdirs pollute it on every `bun test` (TH-4).
  if (!underBunTestRunner()) {
    const floor = [
      // grok (x.ai/cli): the daemon EXECS grok via ~/.grok/bin/grok, but that is
      // only a SYMLINK — the real ELF lives at ~/.grok/downloads/grok-<arch>. So
      // EXEC reads through to downloads/, and BOTH need READ+EXEC. Pre-create
      // both so the grants land on real leaves (NOT bare ~/.grok — the user's
      // ~/.grok/auth.json must stay out of the working set).
      join(home, ".grok", "bin"),
      join(home, ".grok", "downloads"),
      // ⚠️ RESEARCH-UNVERIFIED: Cursor's launcher and versioned binaries live
      // under ~/.local, so grant only executable-bearing leaves, never ~/.cursor.
      join(home, ".local", "bin"),
      join(home, ".local", "share", "cursor-agent", "versions"),
      join(home, ".local", "share", "claude"),
    ];
    for (const d of floor) {
      try {
        mkdirSync(d, { recursive: true });
      } catch {
        // best-effort — an ungranted leaf just means that vendor's install falls
        // back / fails visibly, not a daemon-boot failure.
      }
    }
  }
  const dirs = new Set<string>([
    //   ~/.local/bin        — the `claude`/`codex` launchers + the `openllmd`
    //                         PATH symlink (the daemon install script writes
    //                         this one, unsandboxed; the daemon only reads it);
    join(home, ".local", "bin"),
    // ⚠️ RESEARCH-UNVERIFIED: Cursor's launcher resolves into this versioned
    // executable directory; hostCliCandidates + symlink resolution add any live path.
    join(home, ".local", "share", "cursor-agent", "versions"),
    //   ~/.local/share/claude — the claude launcher resolves to
    //                         `versions/<v>` here; exec reads through to it;
    join(home, ".local", "share", "claude"),
    //   ~/.grok/bin         — the grok launcher SYMLINK (bin/grok →
    //                         ../downloads/grok-<arch>); the isolated grok
    //                         symlink execs it;
    join(home, ".grok", "bin"),
    //   ~/.grok/downloads   — the REAL grok ELF the bin/grok symlink points at.
    //                         Exec of grok reads THROUGH bin/grok to this dir, so
    //                         it must be read+exec too (a dropped grant here
    //                         EACCESes every `grok` spawn — the connect/login
    //                         flow then never emits its device URL). Holds the
    //                         binary only, no credentials (auth.json is a sibling
    //                         under ~/.grok, left UNgranted).
    join(home, ".grok", "downloads"),
  ]);
  // Emit only dirs that EXIST. A missing leaf is not just a dead grant — it
  // makes `existing()` climb to a live ancestor: absent `~/.local/bin` on a box
  // WITH `~/.local` would grant the whole `~/.local` tree. A vendor whose dir
  // is missing is not installed, so there is nothing to exec anyway.
  for (const d of dirs) {
    if (!existsSync(d)) dirs.delete(d);
  }
  // DYNAMIC exec-dir resolution — the robustness backstop for the hardcoded
  // floor above. For every provider, FOLLOW the symlink chain of its isolated
  // run-view (`cliBin`, seeded lazily by `cliInstallState`) AND its host
  // launcher candidates (`hostCliCandidates`, present as soon as the CLI is
  // installed), and grant the real dir of every node read+exec.
  for (const provider of CLI_PROVIDERS) {
    for (const seed of [
      ...hostCliCandidates(provider, home),
      cliBin(provider, home),
    ]) {
      for (const dir of resolveCliExecDirs(seed, home)) dirs.add(dir);
    }
  }
  return [...dirs];
};

/**
 * The base grant set shared by ALL four sub-process layers (and the parent
 * supervisor). Resolved at call time so `OPENLLM_DAEMON_STATE_DIR` overrides
 * are honoured.
 *
 * `homeOverride` supplies the DAEMON's home explicitly instead of reading
 * `homedir()`. Load-bearing for the `--sandbox-exec` shim: it is spawned with
 * the CHILD's env, whose `HOME` points at an isolated CLI home
 * (`cli-paths.ts` `cliEnv`). Without the override the shim builds the working
 * set around THAT home — the real state dir is never granted and Seatbelt's
 * deny-`$HOME` read default lands on the isolated home itself, EPERM-ing the
 * very credential store the child was spawned to read. (Passing `HOME` through
 * the env instead does NOT work: Bun caches `os.homedir()` on first call, and
 * module-load code has already called it by then.)
 *
 * TODO(R2-M2): the whole `state` dir is granted here because it is genuinely
 * shared (auth-state, vendor-cli-tunnel, and the parent all sit under it) AND
 * to keep the M1.5 union byte-identical to the pre-split single builder. When
 * the `--sub` subprocesses actually drop the shared grant, decompose `state`
 * into its sub-paths (`<state>/cli` → auth-state, `<state>/run` +
 * `<state>/sessions` → vendor-cli-tunnel) so each subprocess carries only its
 * own slice.
 */
export const baseWorkingSet = (homeOverride?: string): TWorkingSet => {
  // `index.ts` runs `existing()` after this builder — record the home the
  // working set is being built around so the climb boundary is the OVERRIDE
  // home in the `--sandbox-exec` shim, not the child's isolated `homedir()`.
  existingBoundaryHome = homeOverride ?? homedir();
  const state = stateDir(homeOverride);
  // Daemon-owned temp directory under the state dir. The unit hardening no
  // longer sets PrivateTmp (removed due to --user unit compatibility issues),
  // so granting global /tmp would leak access to every other process's temp
  // files. Instead we create and use our own isolated temp under stateDir.
  const daemonTmp = daemonTempDir(homeOverride);
  const readWrite = new Set<string>([
    // The whole state dir: the shared .env (config + key + device id) + logs + isolated CLI roots
    // (`cli/<provider>/{home,bin}` all nest under it — see `cli-paths.ts`)
    // + the installed binary and its self-update temp (`<state>/bin`)
    // + the local-session registry (`<state>/run`, `<state>/sessions`).
    state,
    // Belt-and-braces for a binary installed OUTSIDE the state dir (manual
    // placement): self-update renames a temp over `process.execPath`, so its
    // real directory must be writable.
    dirname(process.execPath),
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
      ? [resolve(import.meta.dir, "..", "..", "..", "..", "..")]
      : []),
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
  return {
    readWrite: [...readWrite],
    readOnly: [...readOnly],
  };
};
