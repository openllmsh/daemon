/**
 * Durable session-host registry adapter.
 *
 * Every PTY now belongs to an independent `openllmd __session-host` process.
 * This module preserves the historical import surface for daemon status and boot
 * reconciliation while never creating or retaining a daemon-owned session.
 */

import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { TDeviceSessionCli } from "@openllmsh/protocol";
import { SESSION_ID_PATTERN } from "@openllmsh/protocol";
import { stateDir } from "./env";
import { logInfo } from "./logger";
import { discoverSessionHosts } from "./session-host-proc";

const sessionRoot = (): string => join(stateDir(), "sessions");

/**
 * Adopt live durable session-host directories and reap stale entries. Discovery
 * validates pid + socket and never signals a discovered process.
 */
export const reapOrphanSessionProcs = (): void => {
  const live = new Set(discoverSessionHosts().map((host) => host.id));
  let entries: string[];
  try {
    entries = readdirSync(sessionRoot());
  } catch {
    return;
  }
  for (const id of entries) {
    if (!SESSION_ID_PATTERN.test(id) || live.has(id)) continue;
    try {
      rmSync(join(sessionRoot(), id), { recursive: true, force: true });
      logInfo("session", "reaped stale durable session registry entry", { id });
    } catch {
      // Leave an unreadable entry for a later reconciliation attempt.
    }
  }
};

/** Reconcile without touching live sibling session-host processes. */
export const reconcileSessionHostsAtBoot = (): void => {
  reapOrphanSessionProcs();
};

/** Durable discovery rows for compatibility consumers and picker merges. */
export const sessionStatusReport = (): Array<{
  id: string;
  cli: TDeviceSessionCli;
  started_at_ms: number;
  attached: boolean;
  live: boolean;
  busy: boolean;
  title?: string;
  vendor_session_id?: string | null;
}> =>
  discoverSessionHosts().map((host) => ({
    id: host.id,
    cli: host.cli,
    started_at_ms: host.startedAtMs,
    attached: false,
    live: true,
    busy: false,
    ...(host.title === null ? {} : { title: host.title }),
    ...(host.vendorSessionId === null
      ? {}
      : { vendor_session_id: host.vendorSessionId }),
  }));

export const deviceSessionsForList = (): ReadonlyArray<{
  readonly id: string;
  readonly cli: TDeviceSessionCli;
  readonly live: boolean;
  readonly title: string | null;
  readonly vendor_session_id: string | null;
  readonly cwd: string;
  readonly started_at_ms: number;
}> =>
  discoverSessionHosts().map((host) => ({
    id: host.id,
    cli: host.cli,
    live: true,
    title: host.title,
    vendor_session_id: host.vendorSessionId,
    cwd: host.cwd,
    started_at_ms: host.startedAtMs,
  }));

export { ptySupported } from "./session-core";
