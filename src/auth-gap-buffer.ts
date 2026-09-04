/**
 * Bounded buffer for `auth.*` events emitted while the control WebSocket is
 * not ready (closed, reconnecting, or hello not yet sent).
 *
 * Login FSM on the wire: one `started`, ≥0 `prompt`s, exactly one terminal.
 * Across a gap we keep, per `flow_id`: the first `started`, the latest
 * `prompt`, and the first terminal. Non-login events (session.lost /
 * liveness.degraded) keep the latest per slug. Flush restores that sequence
 * once; a live socket never enqueues, so a never-dropped channel re-delivers
 * nothing.
 */
import type { TAuthEvent } from "@openllmsh/protocol";

const MAX_FLOWS = 8;

type TLoginGap = {
  started: TAuthEvent | null;
  prompt: TAuthEvent | null;
  terminal: TAuthEvent | null;
};

type TSlugGap = {
  last: TAuthEvent;
};

const loginGaps = new Map<string, TLoginGap>();
const slugGaps = new Map<string, TSlugGap>();
const loginOrder: string[] = [];
const slugOrder: string[] = [];

const flowIdOf = (event: TAuthEvent): string | null => {
  if (
    event.event === "auth.login.started" ||
    event.event === "auth.login.prompt" ||
    event.event === "auth.login.succeeded" ||
    event.event === "auth.login.failed"
  ) {
    return event.flow_id;
  }
  return null;
};

const evictOldestLogin = (): void => {
  const oldest = loginOrder.shift();
  if (oldest !== undefined) loginGaps.delete(oldest);
};

const evictOldestSlug = (): void => {
  const oldest = slugOrder.shift();
  if (oldest !== undefined) slugGaps.delete(oldest);
};

const touchLogin = (flowId: string): TLoginGap => {
  let gap = loginGaps.get(flowId);
  if (gap === undefined) {
    if (loginGaps.size >= MAX_FLOWS) evictOldestLogin();
    gap = { started: null, prompt: null, terminal: null };
    loginGaps.set(flowId, gap);
    loginOrder.push(flowId);
  }
  return gap;
};

const touchSlug = (key: string, event: TAuthEvent): void => {
  if (!slugGaps.has(key)) {
    if (slugGaps.size >= MAX_FLOWS) evictOldestSlug();
    slugOrder.push(key);
  }
  slugGaps.set(key, { last: event });
};

/** Queue an event that did not leave the socket. Collapses per flow / slug. */
export const enqueueAuthGap = (event: TAuthEvent): void => {
  const flowId = flowIdOf(event);
  if (flowId !== null) {
    const gap = touchLogin(flowId);
    if (event.event === "auth.login.started") {
      if (gap.started === null) gap.started = event;
      return;
    }
    if (event.event === "auth.login.prompt") {
      gap.prompt = event;
      return;
    }
    if (gap.terminal === null) gap.terminal = event;
    return;
  }
  touchSlug(`${event.event}:${event.slug}`, event);
};

/** Snapshot in enqueue order without mutating the buffer. */
export const peekAuthGap = (): TAuthEvent[] => {
  const out: TAuthEvent[] = [];
  for (const flowId of loginOrder) {
    const gap = loginGaps.get(flowId);
    if (gap === undefined) continue;
    if (gap.started !== null) out.push(gap.started);
    if (gap.prompt !== null) out.push(gap.prompt);
    if (gap.terminal !== null) out.push(gap.terminal);
  }
  for (const key of slugOrder) {
    const gap = slugGaps.get(key);
    if (gap !== undefined) out.push(gap.last);
  }
  return out;
};

/**
 * Drop the first `count` peeked events. Call only after those events were
 * eligible to send (`key_id` present and transport ready).
 */
export const commitAuthGap = (count: number): void => {
  if (count <= 0) return;
  if (count >= authGapSize()) {
    clearAuthGap();
    return;
  }
  let left = count;
  const remainingLogin: string[] = [];
  for (const flowId of loginOrder) {
    const gap = loginGaps.get(flowId);
    if (gap === undefined) continue;
    if (left > 0 && gap.started !== null) {
      gap.started = null;
      left -= 1;
    }
    if (left > 0 && gap.prompt !== null) {
      gap.prompt = null;
      left -= 1;
    }
    if (left > 0 && gap.terminal !== null) {
      gap.terminal = null;
      left -= 1;
    }
    if (gap.started !== null || gap.prompt !== null || gap.terminal !== null) {
      remainingLogin.push(flowId);
    } else {
      loginGaps.delete(flowId);
    }
  }
  loginOrder.length = 0;
  loginOrder.push(...remainingLogin);

  const remainingSlug: string[] = [];
  for (const key of slugOrder) {
    if (left > 0) {
      slugGaps.delete(key);
      left -= 1;
      continue;
    }
    remainingSlug.push(key);
  }
  slugOrder.length = 0;
  slugOrder.push(...remainingSlug);
};

/**
 * Attempt to send buffered events. Does not remove anything until `trySend`
 * returns true. Stops (and retains the tail) on the first false — typically
 * a missing key id, a closed socket, or hello not yet sent.
 */
export const flushAuthGap = (
  keyId: string | null,
  trySend: (event: TAuthEvent) => boolean,
): number => {
  if (keyId === null) return 0;
  const pending = peekAuthGap();
  let sent = 0;
  for (const event of pending) {
    if (!trySend(event)) break;
    sent += 1;
  }
  commitAuthGap(sent);
  return sent;
};

/** Drain in enqueue order: per login flow started → prompt → terminal, then slug events. */
export const drainAuthGap = (): TAuthEvent[] => {
  const out = peekAuthGap();
  clearAuthGap();
  return out;
};

export const clearAuthGap = (): void => {
  loginGaps.clear();
  slugGaps.clear();
  loginOrder.length = 0;
  slugOrder.length = 0;
};

export const authGapSize = (): number => {
  let n = 0;
  for (const gap of loginGaps.values()) {
    if (gap.started !== null) n += 1;
    if (gap.prompt !== null) n += 1;
    if (gap.terminal !== null) n += 1;
  }
  n += slugGaps.size;
  return n;
};

export const AUTH_GAP_MAX_FLOWS = MAX_FLOWS;
