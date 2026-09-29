/**
 * Behavior-neutral coordinator for resolving a host CLI candidate that may be
 * a version-manager shim (e.g. mise) rather than an ordinary executable.
 *
 * This module is ADDITIVE and, with zero adapters registered, is a pure
 * passthrough: `resolveManagerCandidate` returns the ordinary candidate
 * unchanged. It exists so a later adapter (mise, asdf, …) can be registered
 * without touching `cli-paths.ts` / `cli-install.ts` call sites again.
 *
 * Scope contract (see execution plan): resolution never inspects request- or
 * cwd-scoped state — it must select the same target regardless of the
 * daemon process's current working directory (global manager semantics).
 * Adapters run with a short bounded timeout, explicit argv only (no shell),
 * and must reject cyclic / self-referential / relative output.
 */
import { existsSync, realpathSync } from "node:fs";
import { basename, isAbsolute, sep } from "node:path";
import { runCapture } from "./delegation/spawn";

export type TManagerResolutionKind =
  | "ordinary" // not recognized as any manager shim
  | "resolved" // recognized AND resolved to a real, absolute, existing binary
  | "unresolved"; // recognized as a manager shim but could not be resolved

export type TManagerResolution = {
  readonly kind: TManagerResolutionKind;
  /** The absolute path a link/probe step should use. For "ordinary" this is
   *  always the input candidate. For "resolved" it is the manager's answer.
   *  For "unresolved" it is `null` — callers must NOT link/execute the
   *  original shim. */
  readonly target: string | null;
  /** Stable identity string folded into the reconcile fingerprint so a
   *  changed manager selection (not merely elapsed TTL) triggers a re-link.
   *  `null` for "ordinary" (nothing manager-specific to fingerprint). */
  readonly identity: string | null;
};

export type TManagerAdapter = {
  readonly name: string;
  /** Cheap, synchronous, subprocess-free check: does this candidate path
   *  look like this manager's shim? Bounded path/file evidence only. */
  readonly recognizes: (candidate: string) => boolean;
  /** Bounded, cancellable resolution to the real target binary. Must reject
   *  cycles, relative paths, and self-reference; return `null` on any
   *  failure (timeout, bad output, missing binary). */
  readonly resolve: (candidate: string) => Promise<string | null>;
};

const adapters: TManagerAdapter[] = [];

/** Test/registration hook. Adapters are appended; there are none by default,
 *  so default behavior is the "ordinary" passthrough below. */
export const registerManagerAdapter = (adapter: TManagerAdapter): void => {
  adapters.push(adapter);
};

/** Test-only reset so adapter registration doesn't leak across test files.
 *  Clears to a TRULY empty registry (no mise default) — used by fixtures
 *  that need the pure zero-adapter passthrough or that register their own
 *  fakes in its place. */
export const resetManagerAdaptersForTests = (): void => {
  adapters.length = 0;
};

/** Test-only: restore the production default registry (mise only) after a
 *  test mutated it with `resetManagerAdaptersForTests` / its own fakes, so
 *  later tests in the same process see the same default a real daemon
 *  boots with. Prefer this over `resetManagerAdaptersForTests` in `afterEach`
 *  unless the test specifically exercises the zero-adapter passthrough. */
export const restoreDefaultManagerAdaptersForTests = (): void => {
  adapters.length = 0;
  adapters.push(miseManagerAdapter);
};

/**
 * Test-only escape hatch for A5 sandbox fixtures: restore the current
 * registry (whatever `resetManagerAdaptersForTests` left it as) after a test
 * mutates it, without re-running the module's default registration.
 */
export const managerAdaptersForTests = (): readonly TManagerAdapter[] =>
  adapters;

/**
 * Resolve `candidate` (an ordinary host-CLI path already chosen by
 * `hostCliCandidates()` precedence) through any registered manager adapters.
 * With zero adapters registered this is a no-op: returns `{ kind: "ordinary",
 * target: candidate, identity: null }` for every input, so existing behavior
 * (link the candidate as-is) is entirely unchanged.
 */
export const resolveManagerCandidate = async (
  candidate: string,
): Promise<TManagerResolution> => {
  for (const adapter of adapters) {
    if (!adapter.recognizes(candidate)) continue;
    const target = await adapter.resolve(candidate);
    if (target === null) {
      return { kind: "unresolved", target: null, identity: adapter.name };
    }
    return {
      kind: "resolved",
      target,
      identity: `${adapter.name}:${target}`,
    };
  }
  return { kind: "ordinary", target: candidate, identity: null };
};

// ---------------------------------------------------------------------------
// mise adapter (A3)
// ---------------------------------------------------------------------------

/** Numeric env override (tests only) — mirrors `cli-install.ts`'s `envMs`. */
const envMsLocal = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
};

/** Bounded deadline for the `mise which <cmd>` explicit-argv query. Resolved
 *  lazily (per-call) so a test can override it without a module reload. */
const miseResolveTimeoutMs = (): number =>
  envMsLocal("OPENLLM_MISE_RESOLVE_TIMEOUT_MS", 2_000);

/** The `mise` launcher to invoke. Overridable so hermetic tests can point at
 *  a fake stub script instead of spawning a real, possibly-absent `mise`. */
const miseBin = (): string => process.env.OPENLLM_MISE_BIN ?? "mise";

/** A mise-managed shim lives at `.../mise/shims/<cmd>` (asdf-compatible
 *  layout mise also honors: `.../<data-dir>/shims/<cmd>` where the parent
 *  segment is literally named `mise`). Path-segment match only — cheap,
 *  synchronous, no filesystem probe beyond the string itself, per the
 *  `TManagerAdapter.recognizes` contract. */
const isMiseShimPath = (candidate: string): boolean => {
  const segments = candidate.split(sep);
  const shimsIdx = segments.lastIndexOf("shims");
  if (shimsIdx <= 0) return false;
  return segments[shimsIdx - 1] === "mise";
};

/**
 * Resolve a recognized mise shim to the real, absolute, existing binary it
 * currently activates, via a bounded `mise which <cmd>` explicit-argv call
 * (no shell, no arbitrary script execution). Rejects:
 *   - non-zero exit / empty output / timeout (→ null, per `runCapture`),
 *   - a relative answer (mise always prints absolute paths; anything else is
 *     untrusted output, not a real resolution),
 *   - self-reference (`mise which` echoing the shim path back — would cause
 *     `linkIsolatedCli` to symlink the shim to itself),
 *   - a cyclic answer that is itself another mise shim path (would leave the
 *     isolated link pointing at a shim, defeating the whole point of
 *     resolution and risking infinite indirection if something re-probes).
 * Any rejection returns `null` — the coordinator then reports "unresolved"
 * and the caller must NOT link or version-probe the original shim.
 */
/**
 * Strip every inherited `MISE_*` env var so the query cannot be steered by a
 * project- or session-scoped selector (`MISE_CONFIG_FILE`,
 * `MISE_OVERRIDE_CONFIG_FILENAMES`, `MISE_ENV`, …) the daemon process happens
 * to have inherited from whatever launched it. `mise` still consults its own
 * user-level global config on this stripped env — the point is to remove
 * ambient overrides, not to sandbox `mise` itself. Passed as an explicit
 * override map (values `undefined` delete the key via `mergeSpawnEnv`), so
 * this composes with `spawnEnv`'s normal "no `env` → fully inherited" default
 * instead of trying to hand-build a full replacement environment.
 */
const globalOnlyMiseEnvOverrides = (): Record<string, string | undefined> => {
  const overrides: Record<string, string | undefined> = {};
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("MISE_")) overrides[key] = undefined;
  }
  return overrides;
};

const resolveMiseShim = async (candidate: string): Promise<string | null> => {
  const cmd = basename(candidate);
  if (cmd.length === 0) return null;
  const result = await runCapture(
    [miseBin(), "which", cmd],
    globalOnlyMiseEnvOverrides(),
    {
      probe: true,
      timeoutMs: miseResolveTimeoutMs(),
      maxBytes: 4_096,
    },
  );
  if (result === null) return null;
  const answer = result.split("\n")[0]?.trim() ?? "";
  if (answer.length === 0) return null;
  if (!isAbsolute(answer)) return null;
  if (answer === candidate) return null; // self-reference
  if (isMiseShimPath(answer)) return null; // cyclic — still a shim
  let real: string;
  try {
    real = realpathSync(answer);
  } catch {
    return null; // dangling — mise pointed at a binary that doesn't exist
  }
  if (!existsSync(real)) return null;
  if (real === candidate || isMiseShimPath(real)) return null;
  return real;
};

export const miseManagerAdapter: TManagerAdapter = {
  name: "mise",
  recognizes: isMiseShimPath,
  resolve: resolveMiseShim,
};

/**
 * Default production registration — additive, per design decision §2.1: the
 * coordinator still runs the SAME `hostCliCandidates()` → `linkIsolatedCli`
 * pipeline; this only teaches it to recognize one more shim shape. A
 * candidate that never looks like a mise shim (`isMiseShimPath` false) never
 * triggers a subprocess, so every non-mise provider/path is unaffected.
 *
 * Tests that need a clean registry call `resetManagerAdaptersForTests()` and
 * register their own fakes; production takes this one adapter by default.
 */
registerManagerAdapter(miseManagerAdapter);
