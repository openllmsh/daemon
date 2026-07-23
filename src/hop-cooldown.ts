import type { TCooldownReason } from "@openllmsh/protocol";
import { cooldownPolicyFor } from "@openllmsh/protocol";

/**
 * The daemon's LOCAL, synchronous hop cooldown table.
 *
 * The cloud already cools a failed model (daemon-record → `publishCooldownMark`)
 * and the daemon drops its signed-plan cache so the next request re-resolves.
 * That loop is best-effort and cross-process: the Runtime Cache mark is
 * regional, published off the response path, and the re-resolve may land on a
 * different function instance — so an exhausted subscription kept being
 * re-dialled request after request ("Grok Build usage balance exhausted" ×84
 * within one session, an Anthropic 429 storm right behind it).
 *
 * This table is the backstop on the box that actually places the call: once a
 * hop fails with a reason the shared policy says cools, the SAME daemon refuses
 * to dial it again until the policy TTL expires. The policy is the protocol's
 * (`cooldownPolicyFor`) so daemon and cloud can't disagree about what cools.
 *
 * Deliberately NOT applied to the final hop — never-drop-all: the caller gets a
 * real upstream error rather than a synthetic one the gateway invented.
 */
const marks = new Map<string, number>();

const key = (provider: string, modelId: string): string =>
  `${provider}|${modelId}`;

/**
 * Record a hop failure. A non-cooling reason (`network`, `context_overflow`,
 * `content_filter`) is ignored; an existing later expiry is never shortened, so
 * a long quota cooldown survives a subsequent short-TTL failure.
 */
export const markHopCooldown = (
  provider: string,
  modelId: string,
  reason: TCooldownReason,
  now: number = Date.now(),
): void => {
  const policy = cooldownPolicyFor(reason);
  if (!policy.cools || policy.ttlMs <= 0) return;
  const k = key(provider, modelId);
  const until = now + policy.ttlMs;
  const existing = marks.get(k);
  if (existing !== undefined && existing > until) return;
  marks.set(k, until);
};

/** Is this (provider, model) still cooling on THIS box? Expired marks are
 *  dropped on read — the table only ever holds live entries. */
export const isHopCoolingDown = (
  provider: string,
  modelId: string,
  now: number = Date.now(),
): boolean => {
  const k = key(provider, modelId);
  const until = marks.get(k);
  if (until === undefined) return false;
  if (until <= now) {
    marks.delete(k);
    return false;
  }
  return true;
};

/** Drop every mark (tests; a credential reconnect that may restore quota). */
export const clearHopCooldowns = (): void => {
  marks.clear();
};
