/**
 * Local session index types — the daemon-side view of vendor history +
 * `~/.openllm/run` live processes, normalized to `TLocalCliSession` for the
 * control command `list_local_sessions`.
 */

import type { TDeviceSessionCli, TLocalCliSession } from "@openllmsh/protocol";

/** openllm client id used under `~/.openllm/run/<client>/`. */
export type TOpenllmClientId =
  | "claude"
  | "codex"
  | "grok"
  | "opencode"
  | "hermes";

/** Device CLI slugs that have a local history reader in v1. */
export const LISTABLE_DEVICE_CLIS = [
  "claude_code",
  "chatgpt",
  "grok",
  "opencode",
  "hermes",
] as const satisfies readonly TDeviceSessionCli[];

export type TListableDeviceCli = (typeof LISTABLE_DEVICE_CLIS)[number];

export const isListableDeviceCli = (
  cli: TDeviceSessionCli,
): cli is TListableDeviceCli =>
  (LISTABLE_DEVICE_CLIS as readonly string[]).includes(cli);

/** Map device CLI → openllm client id (and run-dir name). */
export const openllmClientIdOf = (
  cli: TDeviceSessionCli,
): TOpenllmClientId | null => {
  switch (cli) {
    case "claude_code":
      return "claude";
    case "chatgpt":
      return "codex";
    case "grok":
      return "grok";
    case "opencode":
      return "opencode";
    case "hermes":
      return "hermes";
    default:
      return null;
  }
};

export const deviceCliOfClientId = (
  clientId: TOpenllmClientId,
): TListableDeviceCli => {
  switch (clientId) {
    case "claude":
      return "claude_code";
    case "codex":
      return "chatgpt";
    case "grok":
      return "grok";
    case "opencode":
      return "opencode";
    case "hermes":
      return "hermes";
  }
};

/** Intermediate history row before live merge. */
export type THistorySession = {
  readonly id: string;
  readonly title: string;
  readonly cwd: string | null;
  readonly updated_at_ms: number;
  readonly cli: TDeviceSessionCli;
};

/** One live.json entry that passed the liveness check. */
export type TLiveRun = {
  readonly client: TOpenllmClientId;
  readonly pid: number;
  readonly cwd: string;
  readonly started_at_ms: number;
  readonly host: "local" | "device";
  readonly openllm_session_id: string | null;
  readonly vendor_session_id: string | null;
  readonly title: string | null;
};

export type { TLocalCliSession };
