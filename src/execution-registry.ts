/**
 * The provider execution registry — the ONE capability authority for the
 * named execution variants (`stream-json` / `agent-sdk` / `sdk-facade` /
 * `acp` / `app-server` / `msp`) and their composable capture forms.
 *
 * This is additive, new-vocabulary machinery living alongside (not
 * replacing) `sub-method.ts`'s legacy `bridge` / `bridge-capture` /
 * `handrolled` capability table and selection. `sub-method.ts` still owns
 * the OUTER per-hop branch (native-runtime vs handrolled vs fleet — see
 * `localMethodsForHop`), driven by the same `ACTIVE_SUB_METHOD` env through
 * its own legacy grammar; this module exists so:
 *
 *   - a provider's declared new-vocabulary variants and their capture
 *     eligibility have exactly one home (no parallel hand-maintained
 *     tables per provider), and
 *   - the cloud can look up, for an EXPLICIT new-vocabulary selection,
 *     whether an old daemon (one that never negotiated
 *     `EXECUTION_SELECTION2_CAP`) would behave identically if the
 *     selection were projected into the legacy `active_sub_method(s)`
 *     field — safe for `chatgpt`/`cursor`/`muse` (their shipped `bridge`
 *     already means exactly one thing each: `app-server` / `acp` / `msp`),
 *     never safe for `claude_code` (its `bridge` is request-shape-
 *     dependent: text→`stream-json`, tools→`agent-sdk` today) — see
 *     09-implementation-plan.md §8.2.
 *
 * `resolveExecutionSelection` below is the per-hop resolver for an
 * EXPLICIT new-vocabulary request against this registry, producing a typed
 * refusal rather than silently falling through to a provider default.
 * `native-runtime/serve.ts` calls it (09-implementation-plan.md phase 5,
 * "existing-path migration") whenever the walker samples a non-null
 * `execution_selection(s)` bootstrap field for the hop's provider — an
 * EXPLICIT admin choice through the SAME `ACTIVE_SUB_METHOD` env, decoded
 * into the richer wire grammar by `packages/api/lib/sub-method.ts` and
 * negotiated via `EXECUTION_SELECTION2_CAP`. When the walker has no such
 * explicit selection for a hop (the common case today), `serve.ts` keeps
 * its unchanged legacy `shouldActivateBridgeRequestCapture` dispatch —
 * this registry only ever governs an EXPLICIT selection, never silently
 * overrides the default.
 */

import type {
  TBridgeVariant,
  TExecutionSelection,
  TSubMethod,
  TSubscriptionProviderSlug,
} from "@openllmsh/protocol";
import { bridgeVariantSupportsCaptureForm } from "@openllmsh/protocol";

export type TProviderExecutionRegistration = {
  readonly provider: TSubscriptionProviderSlug;
  /**
   * Ordered, duplicate-free new-vocabulary variants this provider's
   * binding declares; `variants[0]` is the default when one exists. Empty
   * for providers with no new-vocabulary integration yet (kimi_code,
   * grok) — they stay `handrolled`-only in this vocabulary too.
   */
  readonly variants: readonly TBridgeVariant[];
  /**
   * Subset of `variants` this provider's binding declares CAPTURE
   * readiness for — independent of (but never wider than) the protocol-
   * level {@link bridgeVariantSupportsCaptureForm} grammar fact.
   */
  readonly captureVariants: readonly TBridgeVariant[];
  /** Whether `handrolled` is a legitimate selection for this provider. */
  readonly handrolledAvailable: boolean;
};

/**
 * The new-vocabulary registration, grounded in `SUB_METHOD_CAPABILITIES`
 * (`./sub-method.ts`) and the baseline plan's target matrix
 * (09-implementation-plan.md §2). `agent-sdk` (independently selectable) is
 * a reserved public id with NO registration yet — selecting it MUST resolve
 * to `unsupported_execution_variant` until a later phase implements and
 * registers it; the same held true for `sdk-facade` until phase 6
 * (`claude-sdk-facade.ts`/`claude-sdk-facade-capture.ts`,
 * 12-hermes-adoption-plan.md H1-H4) implemented and registered it below.
 * Adding a registration is how a reservation becomes a real, selectable
 * integration; it is never done by widening this file's literal set alone.
 */
export const PROVIDER_EXECUTION_REGISTRY: Readonly<
  Record<TSubscriptionProviderSlug, TProviderExecutionRegistration>
> = {
  claude_code: {
    provider: "claude_code",
    // `stream-json` (direct-CLI text) stays `variants[0]` — the ONE variant
    // `legacySubMethodEquivalentFor` would even consider (it never actually
    // reaches that comparison for claude_code — see that function's doc
    // comment: claude_code's legacy `bridge` is request-shape-dependent and
    // never gets a legacy-field projection for ANY explicit variant).
    // `sdk-facade` (12-hermes-adoption-plan.md, H1-H4) is a SECOND,
    // independently-selectable Claude variant: unlike `stream-json` it
    // supports caller tools (no `requestShapeUnsupportedFor` gate — see
    // that function's doc comment, which is `stream-json`-only) because it
    // replays the full canonical history itself rather than relying on the
    // held Agent SDK. Live-authenticated validation (H6) is still pending;
    // registering it here only makes it a REACHABLE, typed-refusal-free
    // selection for its PROVEN shape, never a claim that H6's gates passed.
    // H1's real-CLI construction proof (`claude-sdk-facade.ts`'s module doc,
    // `tests/transport/claude-sdk-facade-real-cli-construction.e2e.test.ts`)
    // found that "replays the full canonical history itself" is proven true
    // only for a SINGLE first turn against this installed CLI — an
    // assistant-typed replay frame (required by any multi-turn or
    // tool-continuation history) is never acknowledged by the real CLI.
    // This registration does NOT narrow to single-turn-only at the registry
    // level (the correct fix is a protocol-shape qualification, not a
    // registry-level capability change) because the multi-turn shape is
    // instead BLOCKED one layer down, structurally, before any spawn: both
    // `runClaudeSdkFacade` and `runClaudeSdkFacadeCapture`
    // (`claude-sdk-facade.ts`/`claude-sdk-facade-capture.ts`) call the SAME
    // shared `sdkFacadeRequiresUnsupportedAssistantReplay` guard immediately
    // after planning the turn and refuse pre-dispatch — no spawn, no
    // capture resource, no send — rather than reaching the CLI and
    // exhausting the replay deadline. That guard runs unconditionally
    // inside those two functions themselves, so it holds even for a caller
    // that reaches them without going through this registry's
    // `resolveExecutionSelection` first. Treat multi-turn `sdk-facade` as an
    // evidenced, actively BLOCKED gap — not merely "pending" and not a
    // runtime timeout — until the underlying protocol-shape investigation
    // resolves it.
    variants: ["stream-json", "sdk-facade"],
    captureVariants: ["stream-json", "sdk-facade"],
    handrolledAvailable: true,
  },
  chatgpt: {
    provider: "chatgpt",
    variants: ["app-server"],
    captureVariants: ["app-server"],
    handrolledAvailable: true,
  },
  cursor: {
    provider: "cursor",
    variants: ["acp"],
    captureVariants: ["acp"],
    handrolledAvailable: false,
  },
  muse: {
    provider: "muse",
    variants: ["msp"],
    captureVariants: ["msp"],
    handrolledAvailable: false,
  },
  kimi_code: {
    provider: "kimi_code",
    variants: [],
    captureVariants: [],
    handrolledAvailable: true,
  },
  grok: {
    provider: "grok",
    variants: [],
    captureVariants: [],
    handrolledAvailable: true,
  },
};

export const registeredVariantsFor = (
  provider: string,
): readonly TBridgeVariant[] =>
  PROVIDER_EXECUTION_REGISTRY[provider as TSubscriptionProviderSlug]
    ?.variants ?? [];

export const providerSupportsVariant = (
  provider: string,
  variant: TBridgeVariant,
): boolean => registeredVariantsFor(provider).includes(variant);

/**
 * Whether `provider` declares CAPTURE readiness for `variant` — the
 * provider-level fact AND the protocol-level naming-grammar fact must both
 * hold (defense in depth: a provider table can never widen what the
 * public vocabulary allows).
 */
export const providerSupportsCaptureFor = (
  provider: string,
  variant: TBridgeVariant,
): boolean => {
  if (!bridgeVariantSupportsCaptureForm(variant)) return false;
  const registration =
    PROVIDER_EXECUTION_REGISTRY[provider as TSubscriptionProviderSlug];
  return registration?.captureVariants.includes(variant) ?? false;
};

export const providerHandrolledAvailable = (provider: string): boolean =>
  PROVIDER_EXECUTION_REGISTRY[provider as TSubscriptionProviderSlug]
    ?.handrolledAvailable ?? false;

/**
 * The legacy `SubMethod` an old daemon (one that never negotiated
 * `EXECUTION_SELECTION2_CAP`) would already behave identically to, for an
 * EXPLICIT concrete `selection` on `provider` — or `null` when no such
 * equivalence exists and the selection must instead be logged as
 * unsupported for that daemon rather than silently projected.
 *
 * `handrolled` is always its own trivial equivalent (both vocabularies
 * agree on its meaning). For a `bridge` selection, only the providers
 * whose ALREADY-SHIPPED legacy `bridge` unconditionally means the SAME
 * variant get a projection (`chatgpt`→`app-server`, `cursor`→`acp`,
 * `muse`→`msp`); `claude_code` never does, because its legacy `bridge`
 * is request-shape-dependent (text→`stream-json`, tools→`agent-sdk`) and
 * an explicit `stream-json`-only (or `sdk-facade`) selection would behave
 * DIFFERENTLY under that ambiguity than the admin explicitly chose. Any
 * variant with no shipped legacy meaning at all (e.g. `sdk-facade`,
 * `agent-sdk`, on any provider) never projects either — there is no old
 * behavior to be equivalent to.
 */
export const legacySubMethodEquivalentFor = (
  provider: string,
  selection: TExecutionSelection,
): TSubMethod | null => {
  if (selection.kind === "handrolled") {
    return providerHandrolledAvailable(provider) ? "handrolled" : null;
  }
  if (provider === "claude_code") return null;
  const registration =
    PROVIDER_EXECUTION_REGISTRY[provider as TSubscriptionProviderSlug];
  if (registration === undefined) return null;
  // Only the provider's OWN single already-shipped variant has a legacy
  // meaning to be equivalent to (not merely any registered variant).
  if (registration.variants[0] !== selection.variant) return null;
  if (!selection.capture) return "bridge";
  return providerSupportsCaptureFor(provider, selection.variant)
    ? "bridge-capture"
    : null;
};

/**
 * Provider/variant combinations whose request-shape support is not yet
 * proven — checked independently of capture. Per
 * 09-implementation-plan.md §2 ("Claude CLI tool scope"): Claude's explicit
 * `stream-json` (direct CLI) integration is proven for TEXT only; caller
 * tools on an explicit `stream-json`/`stream-json-capture` selection must
 * refuse pre-dispatch rather than silently falling back to the held Agent
 * SDK (`agent-sdk`) — that would defeat the whole point of an explicit
 * selection. This is UNRELATED to the legacy `bridge`/`bridge-capture`
 * selector, which keeps its existing text→CLI / tools→SDK dispatch
 * unconditionally (see `legacySubMethodEquivalentFor`'s claude_code note) —
 * this check only ever runs for an EXPLICIT new-vocabulary selection.
 */
const requestShapeUnsupportedFor = (
  provider: string,
  variant: TBridgeVariant,
  requestShape: { readonly hasClientTools: boolean } | undefined,
): string | null => {
  if (
    provider === "claude_code" &&
    variant === "stream-json" &&
    requestShape?.hasClientTools === true
  ) {
    return "claude_code stream-json has no proven caller-tool integration yet — refusing rather than silently invoking the official Agent SDK";
  }
  return null;
};

/** Typed refusal for an explicit new-vocabulary selection this registry
 *  cannot honor. */
export type TExecutionSelectionRefusal =
  | {
      readonly kind: "unsupported_execution_variant";
      readonly provider: string;
      readonly variant: TBridgeVariant;
    }
  | {
      readonly kind: "capture_not_supported";
      readonly provider: string;
      readonly variant: TBridgeVariant;
    }
  | {
      /** The variant/provider pair is registered, but THIS request's shape
       *  (e.g. caller tools) is not yet a proven combination — see
       *  {@link requestShapeUnsupportedFor}. Distinct from
       *  `unsupported_execution_variant` (the pair itself is fine) and from
       *  `capture_not_supported` (a capture-eligibility fact, not a
       *  request-shape one). */
      readonly kind: "unsupported_execution_shape";
      readonly provider: string;
      readonly variant: TBridgeVariant;
      readonly reason: string;
    };

export type TExecutionSelectionResolution =
  | { readonly ok: true; readonly selection: TExecutionSelection }
  | { readonly ok: false; readonly refusal: TExecutionSelectionRefusal };

/**
 * Resolve one hop's EXPLICIT new-vocabulary selection against this
 * registry. `requested === null` means no explicit new-vocabulary
 * selection was configured for this hop — callers keep using the
 * unchanged legacy `sub-method.ts` resolution in that case; this function
 * is only for a hop that DID configure one.
 *
 * The genuine-Claude-Code-originator override mirrors
 * `sub-method.ts#selectSubMethod`'s ToS-alignment rule exactly: a request
 * that is itself the real Claude Code client always resolves to
 * `handrolled`, beating any configured preference, because forwarding the
 * genuine client's own request on its own credential IS the official-
 * client flow.
 *
 * `requestShape` folds in the ONE request-shape gate this baseline defines
 * (Claude `stream-json` + caller tools — see
 * {@link requestShapeUnsupportedFor}); a caller with no request-shape
 * concerns (or resolving a non-Claude/non-stream-json selection) may omit
 * it safely.
 */
export const resolveExecutionSelection = (
  provider: string,
  requested: TExecutionSelection | null,
  originator?: { readonly isClaudeCode: boolean },
  requestShape?: { readonly hasClientTools: boolean },
): TExecutionSelectionResolution | null => {
  if (requested === null) return null;
  if (provider === "claude_code" && originator?.isClaudeCode === true) {
    return { ok: true, selection: { kind: "handrolled" } };
  }
  if (requested.kind === "handrolled") {
    return { ok: true, selection: requested };
  }
  if (!providerSupportsVariant(provider, requested.variant)) {
    return {
      ok: false,
      refusal: {
        kind: "unsupported_execution_variant",
        provider,
        variant: requested.variant,
      },
    };
  }
  const shapeReason = requestShapeUnsupportedFor(
    provider,
    requested.variant,
    requestShape,
  );
  if (shapeReason !== null) {
    return {
      ok: false,
      refusal: {
        kind: "unsupported_execution_shape",
        provider,
        variant: requested.variant,
        reason: shapeReason,
      },
    };
  }
  if (
    requested.capture &&
    !providerSupportsCaptureFor(provider, requested.variant)
  ) {
    return {
      ok: false,
      refusal: {
        kind: "capture_not_supported",
        provider,
        variant: requested.variant,
      },
    };
  }
  return { ok: true, selection: requested };
};

/** Human-readable diagnostic for a typed refusal — used by native-runtime
 *  serve sites as the pre-dispatch decline reason (never a fallback to
 *  another variant; see 09-implementation-plan.md §4.1). */
export const describeExecutionSelectionRefusal = (
  refusal: TExecutionSelectionRefusal,
): string => {
  if (refusal.kind === "unsupported_execution_variant") {
    return `${refusal.provider} has no registered ${refusal.variant} execution variant`;
  }
  if (refusal.kind === "capture_not_supported") {
    return `${refusal.provider} does not support capture for ${refusal.variant}`;
  }
  return refusal.reason;
};
