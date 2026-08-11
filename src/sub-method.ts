/**
 * Sub-method capability table + per-hop selection — the ONE home for
 * "which execution methods does each subscription provider support, and
 * which one does this hop use?".
 *
 * `bridge` = the native vendor-runtime path (`native-runtime/`);
 * `handrolled` = the walker's manual upstream-HTTP transport. The cloud
 * publishes a preference in the bootstrap snapshot
 * (`config.ts#activeSubMethod` + per-provider
 * `config.ts#activeSubMethodOverrides`, both from the cloud env
 * `ACTIVE_SUB_METHOD`); the walker passes `overrides[provider] ?? global`
 * as `requested`, and selection resolves it against the provider's
 * declared methods:
 *
 *   selected = requested !== null && methods.includes(requested)
 *     ? requested
 *     : methods[0];               // provider default (array-index-0)
 *
 * The walker samples the selection ONCE per hop, before local execution:
 * `handrolled` never probes or spawns the bridge; `bridge` keeps the
 * pre-commit decline → manual fallback on the same hop. See
 * `docs/proposals/active-sub-method.md` +
 * `docs/proposals/sub-method-simplified-execution.md`.
 */

import type {
  TSubMethod,
  TSubscriptionProviderSlug,
} from "@openllmsh/protocol";

export type TSubMethodCapability = {
  /** Ordered, non-empty, duplicate-free; `methods[0]` is the default. */
  readonly methods: readonly TSubMethod[];
};

/**
 * The initial capability matrix (active-sub-method.md §initial capability
 * matrix). `bridge` is declared exactly for the native-runtime providers
 * (`isNativeRuntimeProvider`); kimi_code + grok are handrolled-only; cursor is
 * the one BRIDGE-ONLY provider (ACP has no manual HTTP transport to fall back
 * to). The table ⇔ native-runtime lockstep is machine-checked in
 * `tests/transport/sub-method.test.ts`.
 */
export const SUB_METHOD_CAPABILITIES: Readonly<
  Record<TSubscriptionProviderSlug, TSubMethodCapability>
> = {
  claude_code: { methods: ["bridge", "handrolled"] },
  chatgpt: { methods: ["bridge", "handrolled"] },
  kimi_code: { methods: ["handrolled"] },
  grok: { methods: ["handrolled"] },
  // Cursor's ONLY inference transport is the ACP bridge (`cursor-agent acp`,
  // native-runtime/cursor-acp.ts) — there is no manual HTTP path (no
  // UPSTREAM_WIRE entry), so it is the one BRIDGE-ONLY provider: a bridge
  // decline advances the plan instead of falling to a manual transport.
  cursor: { methods: ["bridge"] },
  // OpenCode Go is a static-key forward over the openai wire — handrolled only,
  // no native runtime bridge.
  opencode_go: { methods: ["handrolled"] },
};

/**
 * Is the inbound request from a REAL first-party Claude client? Claude
 * Code stamps `user-agent: claude-cli/<semver> …`, Claude Cowork (and
 * sibling official Claude apps) stamp their own `claude*` identity, and
 * the gateway/daemon forward the header verbatim
 * (`originatorHeadersFrom`) — so the `claude` prefix is the family
 * signature. A spoof (or an unrelated third-party lib that happens to
 * name itself `claude-*`) gains nothing: it merely selects the MORE
 * ToS-aligned transport, which serves every request shape anyway.
 */
export const isClaudeCodeOriginator = (headers: Headers): boolean =>
  headers.get("user-agent")?.toLowerCase().startsWith("claude") === true;

/**
 * Resolve the effective method for one subscription hop. Deterministic:
 * a null/unsupported preference selects the provider default
 * (`methods[0]`). Unknown providers (not in the closed subscription set)
 * resolve to `handrolled` — the walker's `canWalkPlan`/`UPSTREAM_WIRE`
 * already decide whether such a hop is servable at all.
 *
 * ToS-alignment override (beats `ACTIVE_SUB_METHOD`): a `claude_code`
 * hop whose inbound request comes from the REAL Claude Code client
 * (`originator.isClaudeCode`) is ALWAYS handrolled. The handrolled
 * transport forwards the genuine client's own request — verbatim
 * Anthropic wire, its own identity headers — on the CLI's own
 * credential, which IS the official-client flow the subscription terms
 * describe. Spawning the bridge there would nest a SECOND Claude Code
 * runtime around a request the real one already produced: slower
 * (process spawn + stream-json re-encode), lossier, and no more
 * compliant.
 */
export const selectSubMethod = (
  provider: string,
  requested: TSubMethod | null,
  originator?: { readonly isClaudeCode: boolean },
): TSubMethod => {
  if (provider === "claude_code" && originator?.isClaudeCode === true) {
    return "handrolled";
  }
  const capability =
    SUB_METHOD_CAPABILITIES[provider as TSubscriptionProviderSlug];
  if (capability === undefined) return "handrolled";
  return requested !== null && capability.methods.includes(requested)
    ? requested
    : capability.methods[0];
};

/**
 * Ordered local transports this box may attempt for one subscription hop.
 * Provider-agnostic: capability table + preference + the two ToS policies
 * already owned by {@link selectSubMethod} / the non-CC claude_code rule.
 *
 * Walker uses this instead of hard-coding per-slug branches:
 *   - `["bridge"]`            — bridge-only (cursor), or non-CC claude_code
 *                               (handrolled would spoof Claude Code identity)
 *   - `["handrolled"]`        — handrolled preference, or CC originator
 *                               (selectSubMethod forces handrolled)
 *   - `["bridge","handrolled"]` — bridge preference with handrolled fallback
 *
 * Empty only for an unknown provider with no declared methods (walker then
 * treats local serve as exhausted and tries the fleet tunnel).
 */
export const localMethodsForHop = (
  provider: string,
  requested: TSubMethod | null,
  originator?: { readonly isClaudeCode: boolean },
): readonly TSubMethod[] => {
  // Non-CC claude_code: never attempt handrolled on this box (would require
  // spoofing a "You are Claude Code" identity the client never sent). Bridge
  // only; fleet covers a peer that can serve under its own policy.
  if (provider === "claude_code" && originator?.isClaudeCode !== true) {
    return ["bridge"];
  }

  const capability =
    SUB_METHOD_CAPABILITIES[provider as TSubscriptionProviderSlug];
  // Unknown provider: no declared local transports. Walker treats empty as
  // local-exhausted and tries the fleet tunnel (matches the doc comment above).
  if (capability === undefined) return [];

  const selected = selectSubMethod(provider, requested, originator);
  if (selected === "handrolled") return ["handrolled"];
  // Bridge selected (preference or default): try bridge first; fall through
  // to handrolled on the same hop when the capability table declares it.
  if (capability.methods.includes("handrolled")) {
    return ["bridge", "handrolled"];
  }
  return ["bridge"];
};
