/**
 * Shape of the committed daemon-release manifest (`./release.ts`). The data
 * module is rewritten by the release CLI (`bun run release:daemon`) after each
 * GitHub release; this
 * type stays hand-written so the manifest is type-checked.
 *
 * `DAEMON_TARGETS` is the SINGLE source of truth for the buildable targets —
 * `packages/release` imports it (rather than re-declaring the list), and the
 * union + the sha256 map key derive from it, so a missing or unknown-target
 * checksum is a compile error instead of silent drift.
 *
 * BridgeSessions PTY-backend assets ride the SAME daemon release (same tag,
 * same repo, asset name `bridgesessions-<target>.gz`). The daemon resolves the
 * PTY worker next to its own executable (`bundledBsPath()` in `src/bs-pty.ts`),
 * so the pair versions together. Optional per target: a target with no
 * published BS asset keeps the daemon's `bun` PTY backend, and installs skip
 * it there.
 */

export const DAEMON_TARGETS = [
  "darwin-arm64",
  "darwin-x64-baseline",
  "linux-x64-baseline",
  "linux-arm64",
] as const;

export type TDaemonTarget = (typeof DAEMON_TARGETS)[number];

export type TDaemonRelease = {
  /** GitHub `owner/repo` the binaries are released to. */
  readonly repo: string;
  /** Release tag, e.g. `v1.3.0-alpha.0`. Empty string until first publish. */
  readonly tag: string;
  /** Every buildable target — stable, independent of what's published yet. */
  readonly targets: readonly TDaemonTarget[];
  /** sha256 (hex) of each published asset, keyed by target. `Partial` so the
   *  pre-publish (`{}`) state is representable, but the `TDaemonTarget` key
   *  type rejects unknown/misspelled targets so the map can't silently drift
   *  from the supported set. */
  readonly sha256: Readonly<Partial<Record<TDaemonTarget, string>>>;
  /** sha256 of the published BridgeSessions PTY-backend binary per target
   *  (`bridgesessions-<target>.gz` asset on the SAME daemon release). OPTIONAL:
   *  the map may be `{}` (pre-first-BS-publish) or partial — a target without
   *  an entry has no BS asset, installs skip it, and the daemon falls back to
   *  its bundled `bun` PTY backend there. Same TDaemonTarget key type so the
   *  map cannot drift from the supported set. */
  readonly bridgesessions_sha256: Readonly<
    Partial<Record<TDaemonTarget, string>>
  >;
};
