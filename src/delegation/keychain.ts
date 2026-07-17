/**
 * Isolated macOS login keychain. Split out of `util.ts` (which re-exports
 * everything here — import from either).
 *
 * On macOS, Claude Code stores its OAuth credential in the login Keychain
 * (there is NO file-based override — confirmed via the Claude Code docs).
 * Claude resolves the login keychain by HOME path, so running it with an
 * isolated HOME and no keychain there fails with the system dialog "A
 * keychain cannot be found to store <user>". The fix: give the isolated
 * HOME its OWN login keychain at `<home>/Library/Keychains/login.keychain-db`.
 *
 * We deliberately do NOT call `security default-keychain`/`list-keychains`:
 * those mutate the live securityd SESSION search list (not HOME-scoped),
 * which would pollute the user's real keychain environment. Instead we
 * create + unlock the keychain at the HOME-derived path (which Claude
 * finds on its own) and READ it back by EXPLICIT path (the `security` CLI
 * resolves the default via the session, not HOME, so the path is required).
 */
import { existsSync } from "node:fs";
import { mkdir, readdir, rename, rm } from "node:fs/promises";
import { platform } from "node:os";
import { dirname, join } from "node:path";
import { logError } from "../logger";
import { logIfKilled, spawnCwd } from "./spawn";

const MAC = platform() === "darwin";

const loginKeychainPath = (home: string): string =>
  join(home, "Library", "Keychains", "login.keychain-db");

const runSecurity = async (
  argv: ReadonlyArray<string>,
  home: string,
): Promise<boolean> => {
  try {
    const proc = Bun.spawn(["security", ...argv], {
      stdin: "ignore",
      stdout: "ignore",
      stderr: "ignore",
      cwd: spawnCwd({ HOME: home }),
      env: { ...process.env, HOME: home },
    });
    const code = await proc.exited;
    // A `security` child SIGKILLed by the sandbox leaves no keychain + no
    // trace — surface it so a later "Keychain Not Found" dialog is explained.
    logIfKilled(["security", ...argv], proc);
    return code === 0;
  } catch {
    return false;
  }
};

// Keychains we've already created+unlocked this process. Auto-lock is
// disabled, so a keychain stays unlocked for the daemon's lifetime — no
// need to re-spawn `security` on every status poll (which runs ~every 5s).
const ensuredKeychains = new Set<string>();

// In-flight ensures, keyed by keychain path. The status watcher fires every
// ~2.5s and is NOT serialized, so a slow `status()` lets ticks overlap; without
// this, concurrent callers would race `security create-keychain` on the same
// path and collide with `errSecDuplicateKeychain`. Overlapping callers instead
// await the SAME operation.
const inFlightKeychains = new Map<string, Promise<void>>();

// Throttle the create-failure log so a persistent failure doesn't spam the
// error stream on every ~2.5s status tick (it used to re-log forever because a
// failure never entered `ensuredKeychains`). One line per keychain per window.
const lastKeychainFailureLogMs = new Map<string, number>();
const KEYCHAIN_FAILURE_LOG_INTERVAL_MS = 5 * 60 * 1000;

const logKeychainFailure = (kc: string): void => {
  const now = Date.now();
  if (
    now - (lastKeychainFailureLogMs.get(kc) ?? 0) <
    KEYCHAIN_FAILURE_LOG_INTERVAL_MS
  )
    return;
  lastKeychainFailureLogMs.set(kc, now);
  logError(
    "keychain",
    "failed to create the isolated login keychain — claude login will pop the 'Keychain Not Found' dialog and hang",
    { keychain: kc },
  );
};

/**
 * macOS only: ensure an isolated, unlocked login keychain exists at
 * `<home>/Library/Keychains/login.keychain-db` so a CLI run with
 * `HOME=<home>` (e.g. `claude auth login`) can WRITE its credential
 * without the "Keychain Not Found" dialog. Empty password; auto-lock
 * disabled so subsequent reads don't prompt. Idempotent + process-cached;
 * concurrency-deduped; no-op off macOS.
 */
export const ensureIsolatedKeychain = async (home: string): Promise<void> => {
  if (!MAC) return;
  const kc = loginKeychainPath(home);
  // The cache skips re-spawning `security` on the hot path (the ~2.5s status
  // watcher), but ALWAYS re-verify the file still exists first — `existsSync`
  // is cheap (no spawn) and a missing keychain (deleted out from under us, or a
  // fresh install) must be recreated, or `claude auth login` later pops the
  // "Keychain Not Found" dialog.
  if (ensuredKeychains.has(kc) && existsSync(kc)) return;
  const pending = inFlightKeychains.get(kc);
  if (pending !== undefined) return pending;
  const op = ensureKeychainNow(home, kc).finally(() => {
    inFlightKeychains.delete(kc);
  });
  inFlightKeychains.set(kc, op);
  return op;
};

const ensureKeychainNow = async (home: string, kc: string): Promise<void> => {
  if (!existsSync(kc)) {
    ensuredKeychains.delete(kc); // stale cache entry — file is gone
    const dir = dirname(kc);
    await mkdir(dir, { recursive: true });
    // macOS `securityd` REFUSES to `create-keychain` at the RESERVED
    // `login.keychain-db` name when it sits inside the $HOME subtree under the
    // Seatbelt sandbox: it routes through the session login-keychain machinery,
    // which needs the real `~/Library/Keychains` the deny-$HOME read policy
    // blocks → `errSec 161` (no file) or a GUI auth prompt. So create +
    // configure at a NON-reserved staging name (which securityd treats as an
    // ordinary keychain), THEN atomically rename the finished file into place.
    // Claude finds `login.keychain-db` by default-resolution and our own reads
    // use the explicit path. See
    // docs/audit/2026-06-22-daemon-mac-sandbox-failures.md §3.
    const staging = join(dir, `.openllm-staging-${process.pid}.keychain-db`);
    // Sweep orphaned staging files from a prior run that crashed between
    // create + rename (the filename carries the pid, so they'd otherwise
    // accumulate). Best-effort.
    try {
      for (const f of await readdir(dir)) {
        if (f.startsWith(".openllm-staging-") && f.endsWith(".keychain-db")) {
          await rm(join(dir, f), { force: true });
        }
      }
    } catch {
      // dir unreadable / race — non-fatal
    }
    const created = await runSecurity(
      ["create-keychain", "-p", "", staging],
      home,
    );
    if (created) {
      // Disable auto-lock on the STAGING name (set-keychain-settings on the
      // reserved name pops "User canceled the operation" under the sandbox);
      // the setting persists in the file through the rename.
      await runSecurity(["set-keychain-settings", staging], home);
      try {
        await rename(staging, kc);
      } catch {
        await rm(staging, { force: true });
      }
    } else {
      await rm(staging, { force: true });
    }
    // If the file STILL isn't there, a later `claude auth login` will pop the
    // "Keychain Not Found" dialog and WEDGE. Surface it (throttled) so the real
    // cause is in openllmd.err.log without spamming every status tick.
    if (!existsSync(kc)) {
      logKeychainFailure(kc);
      return; // not ensured; retried next call
    }
  }
  // Unlock at the FINAL path (securityd keys unlock state by path, so re-unlock
  // after the rename). Unlocking the reserved name by explicit path is fine —
  // only `create-keychain` at it fails.
  await runSecurity(["unlock-keychain", "-p", "", kc], home);
  ensuredKeychains.add(kc);
};

/**
 * macOS only: grant command-line tools prompt-free access to the items in
 * the isolated keychain. Run AFTER a login writes them, so our later
 * `security find-generic-password` reads don't trigger the "security
 * wants to access the keychain" GUI prompt. Best-effort.
 */
export const grantKeychainToolAccess = async (home: string): Promise<void> => {
  if (!MAC) return;
  await runSecurity(
    [
      "set-key-partition-list",
      "-S",
      "apple-tool:,apple:",
      "-s",
      "-k",
      "",
      loginKeychainPath(home),
    ],
    home,
  );
};

/**
 * Discover every generic-password service name in the isolated keychain
 * that STARTS WITH `prefix`. Claude suffixes its keychain service with a
 * per-install hash (e.g. `Claude Code-credentials-753e4afa`) so multiple
 * configs don't collide, so an exact-name lookup misses it. `dump-keychain`
 * lists attributes only (no `-d`), so it doesn't prompt for secrets.
 */
const findKeychainServices = async (
  home: string,
  prefix: string,
): Promise<ReadonlyArray<string>> => {
  try {
    const proc = Bun.spawn(
      ["security", "dump-keychain", loginKeychainPath(home)],
      {
        stdout: "pipe",
        stderr: "ignore",
        cwd: spawnCwd({ HOME: home }),
        env: { ...process.env, HOME: home },
      },
    );
    const out = await new Response(proc.stdout).text();
    await proc.exited;
    const names = new Set<string>();
    for (const line of out.split("\n")) {
      const m = line.match(/"svce"<blob>="([^"]*)"/);
      if (m?.[1]?.startsWith(prefix) === true) {
        names.add(m[1]);
      }
    }
    return [...names];
  } catch {
    return [];
  }
};

const readKeychainSecret = async (
  home: string,
  service: string,
): Promise<string | null> => {
  try {
    const proc = Bun.spawn(
      [
        "security",
        "find-generic-password",
        "-s",
        service,
        "-w",
        loginKeychainPath(home),
      ],
      {
        stdout: "pipe",
        stderr: "ignore",
        cwd: spawnCwd({ HOME: home }),
        env: { ...process.env, HOME: home },
      },
    );
    const out = await new Response(proc.stdout).text();
    if ((await proc.exited) !== 0) return null;
    const trimmed = out.trim();
    return trimmed.length > 0 ? trimmed : null;
  } catch {
    return null;
  }
};

/**
 * Read a generic-password `-w` payload from the ISOLATED login keychain,
 * matching `servicePrefix` (Claude's service name carries a per-install
 * hash suffix, so we match by prefix and try each candidate). `validate`
 * rejects a wrong-but-matching item — the first valid payload wins.
 * Returns null off macOS / on any failure.
 */
export const readIsolatedKeychain = async (
  home: string,
  servicePrefix: string,
  validate?: (payload: string) => boolean,
): Promise<string | null> => {
  if (!MAC) return null;
  await ensureIsolatedKeychain(home); // ensure present + unlocked
  try {
    for (const service of await findKeychainServices(home, servicePrefix)) {
      const secret = await readKeychainSecret(home, service);
      if (secret === null) continue;
      if (validate !== undefined && !validate(secret)) continue;
      return secret;
    }
    return null;
  } catch {
    return null;
  }
};

/**
 * Update an existing generic-password item in the ISOLATED login keychain
 * (matching `servicePrefix` — Claude's suffixed service name) with a new
 * `payload`. Used to write a daemon-refreshed OAuth blob back so the
 * isolated CLI stays in sync (same access/refresh token + expiry).
 *
 * `-U` updates the item's secret IN PLACE. We deliberately do NOT pass
 * `-A`: that rewrites the item's ACL, which macOS gate-keeps behind a GUI
 * keychain-password prompt a headless daemon can't answer. Instead we
 * re-run the partition-list grant (password supplied inline via `-k ""`,
 * no prompt) so `security` keeps write access. Returns false off macOS /
 * when no matching item exists.
 */
export const writeIsolatedKeychain = async (
  home: string,
  servicePrefix: string,
  payload: string,
): Promise<boolean> => {
  if (!MAC) return false;
  await ensureIsolatedKeychain(home);
  await grantKeychainToolAccess(home); // authorize tool writes (no prompt)
  const service = (await findKeychainServices(home, servicePrefix))[0];
  if (service === undefined) return false;
  const account = process.env.USER ?? "";
  return runSecurity(
    [
      "add-generic-password",
      "-U",
      "-s",
      service,
      "-a",
      account,
      "-w",
      payload,
      loginKeychainPath(home),
    ],
    home,
  );
};
