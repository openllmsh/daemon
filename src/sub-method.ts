/**
 * Sub-method capability table + per-hop selection — the ONE home for
 * "which execution methods does each subscription provider support, and
 * which one does this hop use?".
 *
 * `bridge` = the native vendor-runtime path (`native-runtime/`);
 * `handrolled` = the walker's manual upstream-HTTP transport. The cloud
 * publishes a preference in the bootstrap snapshot
 * (`config.ts#activeSubMethod`, from the cloud env `ACTIVE_SUB_METHOD`);
 * selection resolves it against the provider's declared methods:
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
 * (`isNativeRuntimeProvider`); kimi_code + grok are handrolled-only. The
 * table ⇔ native-runtime lockstep is machine-checked in
 * `tests/transport/sub-method.test.ts`.
 */
export const SUB_METHOD_CAPABILITIES: Readonly<
  Record<TSubscriptionProviderSlug, TSubMethodCapability>
> = {
  claude_code: { methods: ["bridge", "handrolled"] },
  chatgpt: { methods: ["bridge", "handrolled"] },
  kimi_code: { methods: ["handrolled"] },
  grok: { methods: ["handrolled"] },
};

/**
 * Resolve the effective method for one subscription hop. Deterministic:
 * a null/unsupported preference selects the provider default
 * (`methods[0]`). Unknown providers (not in the closed subscription set)
 * resolve to `handrolled` — the walker's `canWalkPlan`/`UPSTREAM_WIRE`
 * already decide whether such a hop is servable at all.
 */
export const selectSubMethod = (
  provider: string,
  requested: TSubMethod | null,
): TSubMethod => {
  const capability =
    SUB_METHOD_CAPABILITIES[provider as TSubscriptionProviderSlug];
  if (capability === undefined) return "handrolled";
  return requested !== null && capability.methods.includes(requested)
    ? requested
    : capability.methods[0];
};
