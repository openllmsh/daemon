/**
 * Shared vendor-command recognition — a leaf module (no daemon imports) so
 * both `session-host.ts` (orphan reaping) and `local-sessions/live-run.ts`
 * (run-dir liveness) use ONE list and cannot drift.
 *
 * Conservative by design: a match only gates "is this pid still one of our
 * session CLIs", never anything destructive on its own.
 */

import { basename } from "node:path";

/** Vendor CLI command names we launch or wrap. Includes the openllm wrapper. */
export const VENDOR_CLI_NAMES: readonly string[] = [
  "claude",
  "codex",
  "kimi",
  "grok",
  "cursor-agent",
  "opencode",
  // Preferred launch path: openllm [-d] <client>
  "openllm",
  "openllmc",
];

/** Extract and validate the executable token from `ps -o command=` output. */
export const isVendorSessionCommand = (command: string): boolean => {
  const executable = command.trim().split(/\s+/, 1)[0];
  if (executable === undefined || executable === "") return false;
  const name = basename(executable).toLowerCase();
  return VENDOR_CLI_NAMES.some(
    (vendor) => name === vendor || name.startsWith(`${vendor}-`),
  );
};
