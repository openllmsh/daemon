/**
 * Manifest-driven device-state — which plugins/setups are installed on
 * THIS box, computed by running each registry item's own `install.sh -s` (the
 * unified state probe) and parsing its one-line JSON. Replaces the hardcoded
 * `integrations-detect.ts` filesystem scan: detection now lives in the BUNDLE
 * beside the install logic, so adding/removing a registry item is reflected
 * with NO daemon release. See
 * `docs/proposals/daemon-owned-state-stateless-relay.md` §4.2/§5.
 *
 * Cost-aware: the `-s` walk fetches + runs a script per item, so it is NOT run
 * on every status push (unlike the old cheap fs scan). Instead the result is
 * CACHED and refreshed on the agreed cadence — eager on boot, then on demand
 * (after an install/uninstall, or a manual refresh). `getInstalledIntegrations`
 * serves the cache to `computeStatus`; the walk updates it out of band.
 */
import type {
  TDaemonInstalledIntegration,
  TDaemonIntegrationKind,
} from "@openllmsh/protocol";
import { daemonEnv } from "./env";
import { runIntegration } from "./integrations";
import { logDebug, logWarn } from "./logger";

/** The cloud catalog endpoint per area — the registry manifest, served live, so
 *  the walk discovers exactly the items the gateway publishes. */
const CATALOG_PATH: Record<TDaemonIntegrationKind, string> = {
  plugin: "/api/plugins",
  setup: "/api/setup/options",
};

const FETCH_TIMEOUT_MS = 15_000;

/** Latest device-state snapshot. Served to `computeStatus`; replaced wholesale
 *  by `refreshDeviceState`, patched per-item by `probeIntegration`. */
let cache: TDaemonInstalledIntegration[] = [];

/** The cached install-state list (cheap; what `computeStatus` embeds). */
export const getInstalledIntegrations = (): TDaemonInstalledIntegration[] =>
  cache;

/** A parsed state-probe verdict: `installed` plus the optional `diverged`
 *  flag (installed but the managed config no longer matches what the current
 *  bundle would write — absent on older bundles that don't report it). */
export type TProbeVerdict = {
  readonly installed: boolean;
  readonly diverged?: boolean;
  readonly installedSha256?: string;
};

/** Parse the state verdict out of an `install.sh -s` run's output. The probe
 *  prints one JSON line (`{"installed":bool,"version":…,"diverged":bool?}`) on
 *  stdout; the wrapper's own diagnostics go to stderr, but `runIntegration`
 *  returns them concatenated, so scan for the JSON line. Null when no
 *  parseable verdict is present. `diverged` is carried through only when the
 *  script reported a boolean (older bundles omit it). */
export const parseState = (output: string): TProbeVerdict | null => {
  for (const line of output.split("\n").reverse()) {
    const t = line.trim();
    if (!t.startsWith("{") || !t.includes('"installed"')) continue;
    try {
      const j = JSON.parse(t) as {
        installed?: unknown;
        diverged?: unknown;
        installed_sha256?: unknown;
      };
      if (typeof j.installed === "boolean") {
        return {
          installed: j.installed,
          ...(typeof j.diverged === "boolean" ? { diverged: j.diverged } : {}),
          ...(typeof j.installed_sha256 === "string" &&
          j.installed_sha256.length > 0
            ? { installedSha256: j.installed_sha256 }
            : {}),
        };
      }
    } catch {
      // not the JSON line — keep scanning
    }
  }
  return null;
};

/** Back-compat boolean view of `parseState` (kept for existing tests). */
export const parseInstalled = (output: string): boolean | null =>
  parseState(output)?.installed ?? null;

/** Fetch the slugs/ids the gateway catalogs for one area. */
const fetchCatalogSlugs = async (
  kind: TDaemonIntegrationKind,
): Promise<string[]> => {
  const { cloudOrigin } = daemonEnv();
  const url = `${cloudOrigin}${CATALOG_PATH[kind]}`;
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) return [];
    const body = (await res.json()) as {
      data?: ReadonlyArray<{ slug?: unknown; id?: unknown }>;
    };
    return (body.data ?? [])
      .map((i) => (typeof i.slug === "string" ? i.slug : i.id))
      .filter((s): s is string => typeof s === "string" && s.length > 0);
  } catch {
    return [];
  }
};

/** Probe ONE item's state (`install.sh -s`) and patch its cache entry. Used
 *  after an install/uninstall so the next status push reflects the change
 *  without a full walk. `target` MUST match the one the install/uninstall ran
 *  against (defaults to `claude-code`) so the probe inspects the directory that
 *  actually changed. A null verdict (probe failed) leaves the cache as-is. */
export const probeIntegration = async (
  kind: TDaemonIntegrationKind,
  slug: string,
  target = "claude-code",
): Promise<void> => {
  const r = await runIntegration(kind, "state", slug, target);
  const verdict = parseState(r.output);
  if (verdict === null) {
    logWarn(
      "device-state",
      `state probe for ${kind}/${slug} returned no verdict`,
    );
    return;
  }
  const next = cache.filter((i) => !(i.kind === kind && i.slug === slug));
  const diverged =
    verdict.installed && verdict.installedSha256 !== undefined
      ? verdict.installedSha256 !== r.scriptSha256
      : verdict.diverged;
  next.push({
    kind,
    slug,
    installed: verdict.installed,
    ...(diverged === undefined ? {} : { diverged }),
  });
  cache = next;
};

/** Walk EVERY catalogued item, probe each `-s`, and replace the cache. Eager on
 *  boot + on a manual refresh. Items whose probe yields no verdict are dropped
 *  (the dashboard then offers both Install + Uninstall, which is safe — the
 *  scripts are idempotent). */
export const refreshDeviceState = async (): Promise<
  TDaemonInstalledIntegration[]
> => {
  const kinds: TDaemonIntegrationKind[] = ["plugin", "setup"];
  const perArea = await Promise.all(
    kinds.map(async (kind) => {
      const slugs = await fetchCatalogSlugs(kind);
      return Promise.all(
        slugs.map(async (slug) => {
          const r = await runIntegration(kind, "state", slug);
          const verdict = parseState(r.output);
          if (verdict === null) return null;
          const diverged =
            verdict.installed && verdict.installedSha256 !== undefined
              ? verdict.installedSha256 !== r.scriptSha256
              : verdict.diverged;
          return {
            kind,
            slug,
            installed: verdict.installed,
            ...(diverged === undefined ? {} : { diverged }),
          } satisfies TDaemonInstalledIntegration;
        }),
      );
    }),
  );
  cache = perArea
    .flat()
    .filter((i): i is TDaemonInstalledIntegration => i !== null);
  logDebug("device-state", `walk complete — ${cache.length} items probed`);
  return cache;
};
