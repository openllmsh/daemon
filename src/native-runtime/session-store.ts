/**
 * Native session store — bridges OpenLLM's STATELESS gateway (the client
 * resends the full conversation every request) to the vendor runtimes'
 * STATEFUL sessions (a live `claude -p` resume file / a persistent
 * `codex app-server` thread that only accept the NEW turn). This is T3's
 * approach: correlate a conversation to a provider session and feed only the
 * delta turn.
 *
 * Correlation is content-derived (the gateway has no session id): the
 * conversation is identified by a hash of its "consumed prefix" — the system
 * prompt plus every turn up to and including the last ASSISTANT turn. The
 * DELTA (the new user turn after that) is what gets fed to the resumed
 * session. After the runtime answers, the store re-keys the session under
 * `hash(prefix + delta + assistantResponse)` so the NEXT request — which
 * carries exactly those messages plus its own new user turn — matches and
 * resumes the same session.
 *
 * If nothing matches (first turn, or the client edited/compacted history) the
 * caller starts a FRESH session; for a first turn that's clean, and for an
 * unmatched mid-conversation join the caller seeds the fresh session with the
 * rendered prior turns (lossy but functional — see `renderSeed`).
 *
 * State lives in the daemon (the resume files / threads are daemon-local
 * disk/process state; the cloud can't hold them). In-memory with LRU + TTL;
 * a per-key lock serialises concurrent advances of the same conversation
 * (vendor resume files don't tolerate concurrent writers).
 */

import { createHash } from "node:crypto";
import type { TNativeTurn } from "./types";

/** Max distinct conversations tracked per provider before LRU eviction. */
const MAX_ENTRIES = 500;
/** Idle TTL — a conversation not advanced within this window is evicted. */
const TTL_MS = 60 * 60 * 1000;

const hashConversation = (
  model: string,
  systemText: string | null,
  turns: ReadonlyArray<TNativeTurn>,
): string => {
  const h = createHash("sha256");
  // Length-prefixed JSON so no field concatenation can collide across turns.
  // `model` is in the key so a fallback that switches models mid-conversation
  // gets a DIFFERENT hash → a fresh vendor thread, never a resume of a thread
  // started with another model. Codex's own GPT-5.6 Sol/Terra (V2) and Luna
  // (V1) cannot share a resumed thread; resuming across a model change would
  // feed the wrong-model thread (audit 2026-07-14 §F3).
  h.update(JSON.stringify({ model, systemText, turns }));
  return h.digest("hex");
};

/**
 * Decompose a conversation into the resume decision: the identity of the
 * consumed prefix, the delta turn to feed, and whether there IS a prior
 * (assistant) turn (→ attempt resume) or not (→ fresh session). `model` is
 * folded into the prefix identity so a model switch never resumes another
 * model's thread.
 */
export const deriveConversation = (
  model: string,
  systemText: string | null,
  turns: ReadonlyArray<TNativeTurn>,
): {
  readonly prefixHash: string;
  readonly deltaText: string;
  readonly hasPrior: boolean;
} => {
  let lastAssistant = -1;
  for (let i = 0; i < turns.length; i++) {
    if (turns[i]?.role === "assistant") lastAssistant = i;
  }
  const prefixTurns = turns.slice(0, lastAssistant + 1);
  const deltaTurns = turns.slice(lastAssistant + 1);
  const deltaText = deltaTurns
    .filter((t) => t.role === "user")
    .map((t) => t.text)
    .join("\n\n");
  return {
    prefixHash: hashConversation(model, systemText, prefixTurns),
    deltaText,
    hasPrior: lastAssistant >= 0,
  };
};

/**
 * The key the session lands under AFTER this turn: the full inbound turns plus
 * the assistant's response. The next request carries exactly these messages
 * before its new user turn, so its `deriveConversation().prefixHash` equals
 * this — and resumes the same session.
 */
export const nextPrefixHash = (
  model: string,
  systemText: string | null,
  turns: ReadonlyArray<TNativeTurn>,
  assistantResponse: string,
): string =>
  hashConversation(model, systemText, [
    ...turns,
    { role: "assistant", text: assistantResponse },
  ]);

/**
 * Render prior turns into a single seed prompt for the UNMATCHED-with-history
 * fallback (daemon restarted / history edited). Lossy — the native session
 * memory is gone — but carries the transcript forward as context so the
 * answer is still grounded. The common case (client starts the conversation
 * with us) never hits this: turn 1 has no prior turns.
 */
export const renderSeed = (
  turns: ReadonlyArray<TNativeTurn>,
  deltaText: string,
): string => {
  const prior = turns.slice(0, -1); // everything but the final (delta) user turn
  if (prior.length === 0) return deltaText;
  const transcript = prior
    .map((t) => `${t.role === "user" ? "User" : "Assistant"}: ${t.text}`)
    .join("\n\n");
  return `Continue this conversation. Prior transcript:\n\n${transcript}\n\nUser: ${deltaText}`;
};

type TEntry = { sessionId: string; lastUsed: number };

/** One lease over a conversation key — held across the whole turn so a
 *  concurrent request for the same conversation waits. */
export type TSessionLease = {
  /** The resumable session id, or null → start a fresh session. */
  readonly sessionId: string | null;
  /** Record the turn's outcome under the NEXT key and release the lock.
   *  A null `sessionId` (the runtime produced none) drops the entry. */
  readonly commit: (nextKey: string, sessionId: string | null) => void;
  /** Release without recording (pre-commit failure) — the old entry, if any,
   *  is restored so a retry can still resume. */
  readonly abandon: () => void;
};

/** Per-provider store; one instance per native provider. */
export class NativeSessionStore {
  private readonly entries = new Map<string, TEntry>();
  private readonly locks = new Map<string, Promise<void>>();

  /**
   * Acquire the conversation identified by `prefixHash`: serialise behind any
   * in-flight lease for it, then hand back the resumable session id (or null).
   */
  async lease(prefixHash: string): Promise<TSessionLease> {
    // Serialise concurrent advances of the SAME conversation.
    while (this.locks.has(prefixHash)) {
      await this.locks.get(prefixHash);
    }
    let release!: () => void;
    this.locks.set(
      prefixHash,
      new Promise<void>((r) => {
        release = r;
      }),
    );

    const existing = this.entries.get(prefixHash);
    // Consume the entry: this key is being advanced to a new one.
    this.entries.delete(prefixHash);
    let settled = false;
    const unlock = (): void => {
      this.locks.delete(prefixHash);
      release();
    };

    return {
      sessionId: existing?.sessionId ?? null,
      commit: (nextKey, sessionId) => {
        if (settled) return;
        settled = true;
        if (sessionId !== null) {
          this.set(nextKey, { sessionId, lastUsed: nowMs() });
        }
        unlock();
      },
      abandon: () => {
        if (settled) return;
        settled = true;
        // Restore the consumed entry so a retry can still resume it.
        if (existing !== undefined) this.set(prefixHash, existing);
        unlock();
      },
    };
  }

  private set(key: string, entry: TEntry): void {
    this.entries.set(key, entry);
    this.evict();
  }

  /** LRU + TTL trim. Called on every insert (cheap at this scale). */
  private evict(): void {
    const cutoff = nowMs() - TTL_MS;
    for (const [key, entry] of this.entries) {
      if (entry.lastUsed < cutoff) this.entries.delete(key);
    }
    if (this.entries.size <= MAX_ENTRIES) return;
    // Oldest-first (Map preserves insertion order; re-inserts move to the end
    // via set()), so deleting from the front drops the least-recently-set.
    const overflow = this.entries.size - MAX_ENTRIES;
    let dropped = 0;
    for (const key of this.entries.keys()) {
      if (dropped >= overflow) break;
      this.entries.delete(key);
      dropped++;
    }
  }

  /** Test/introspection: current tracked-conversation count. */
  size(): number {
    return this.entries.size;
  }
}

// Monotonic-ish wall clock; `Date.now` is fine here (not a workflow script).
const nowMs = (): number => Date.now();
