/**
 * Shape of the committed daemon-release manifest (`./release.ts`). The data
 * module is rewritten by the release CLI (`bun run release:daemon`) after each
 * GitHub release; this type stays hand-written so the manifest is type-checked.
 *
 * `DAEMON_TARGETS` is the SINGLE source of truth for the buildable targets —
 * `packages/release` imports it (rather than re-declaring the list), and the
 * union + the sha256 map key derive from it, so a missing or unknown-target
 * checksum is a compile error instead of silent drift.
 *
 * v2.8: every target ships a real PTY backend. The PTY sidecar asset channel
 * is removed (G1) — the native PTY shim is compiled into the daemon binary,
 * so there is no separate PTY asset and no optional-asset loop.
 */

export const DAEMON_TARGETS = [
  "darwin-arm64",
  "darwin-x64-baseline",
  "linux-x64-baseline",
  "linux-arm64",
  "win32-x64",
] as const;

export type TDaemonTarget = (typeof DAEMON_TARGETS)[number];

/**
 * The targets this release actually builds, stages, hashes, and publishes —
 * the ONE switch every release/compile/stage/hash/publish/manifest path
 * iterates. `DAEMON_TARGETS` stays the buildable superset so the Windows code
 * still typechecks, but Windows is off for 2.8.0-beta.1: add "win32-x64" back
 * here (or iterate DAEMON_TARGETS) to re-enable it.
 */
export const DAEMON_RELEASE_TARGETS = DAEMON_TARGETS.filter(
  (target): target is Exclude<TDaemonTarget, "win32-x64"> =>
    target !== "win32-x64",
);

/**
 * The checked-in input closure for a compiled daemon. Release, CI receipt,
 * and merge-gate code all consume this list; it deliberately excludes the
 * private application packages and the generated release manifest.
 */
export const DAEMON_BINARY_SOURCES = [
  "packages/daemon/src",
  "packages/daemon/install.sh",
  "packages/daemon/release-types.ts",
  "packages/daemon/package.json",
  "packages/daemon/scripts/compile.ts",
  "packages/protocol",
  "packages/tunnel",
  "packages/wire",
  "packages/pty-native",
  "packages/daemon/patches",
  "bun.lock",
  "package.json",
] as const;

/** Bun `--target` compiler spelling for each release key. */
export const DAEMON_COMPILE_TARGET: Readonly<Record<TDaemonTarget, string>> = {
  "darwin-arm64": "bun-darwin-arm64",
  "darwin-x64-baseline": "bun-darwin-x64-baseline",
  "linux-x64-baseline": "bun-linux-x64-baseline",
  "linux-arm64": "bun-linux-arm64",
  "win32-x64": "bun-windows-x64-baseline",
};

/** Reverse map: Bun target spelling → release key (for `--target` selection). */
export const BUN_TARGET_TO_DAEMON_TARGET: Readonly<
  Record<string, TDaemonTarget>
> = Object.fromEntries(
  (Object.entries(DAEMON_COMPILE_TARGET) as [TDaemonTarget, string][]).map(
    ([key, bunTarget]) => [bunTarget, key],
  ),
) as Record<string, TDaemonTarget>;

/** The raw (decompressed) daemon binary filename for a release key.
 *  Windows carries the `.exe`; the staging raw is the extensionless copy. */
export const daemonRawFilename = (target: TDaemonTarget): string =>
  `openllmd-${target}${target === "win32-x64" ? ".exe" : ""}`;

/** The extensionless staging raw name (the distribution asset, minus `.gz`).
 *  Windows keeps the extensionless raw as an unchanged copy of the PE. */
export const daemonStagingRawName = (target: TDaemonTarget): string =>
  `openllmd-${target}`;

/** The gzip distribution asset name for a release key. */
export const daemonAssetFilename = (target: TDaemonTarget): string =>
  `${daemonStagingRawName(target)}.gz`;

/** The installed binary name on the target OS. */
export const daemonInstalledName = (target: TDaemonTarget): string =>
  target === "win32-x64" ? "openllmd.exe" : "openllmd";

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
};
