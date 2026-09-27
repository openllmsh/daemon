/**
 * Integrator-owned readiness for bridge request capture.
 *
 * Selection is owned by `ACTIVE_SUB_METHOD` / `sub-method.ts`. There is NO
 * separate capture env flag. Cursor/Muse omit `bridge-capture` from the
 * capability table until a verified serve path exists.
 */

import { providerDeclaresBridgeCapture } from "../sub-method";
import type { TNativeRuntimeProvider } from "./types";

export type TBridgeCaptureReadiness = {
  readonly provider: TNativeRuntimeProvider;
  readonly ready: boolean;
  readonly mode: "text_capture" | "unchanged_bridge";
  readonly reason: string;
};

const CLAUDE_READY: TBridgeCaptureReadiness = {
  provider: "claude_code",
  ready: true,
  mode: "text_capture",
  reason:
    "text-only Claude Messages capture+Anthropic SSE decode proven hermetically; tools stay on existing SDK bridge",
};

const CODEX_READY: TBridgeCaptureReadiness = {
  provider: "chatgpt",
  ready: true,
  mode: "text_capture",
  reason:
    "text-only Codex HTTP/WS capture+existing Responses decode proven hermetically; tools stay on existing app-server bridge",
};

const CURSOR_BLOCKED: TBridgeCaptureReadiness = {
  provider: "cursor",
  ready: false,
  mode: "unchanged_bridge",
  reason:
    "Connect AgentService capture exists, but no verified Connect→OpenAI chunk decoder — keep ACP response path; capability table omits bridge-capture",
};

const MUSE_BLOCKED: TBridgeCaptureReadiness = {
  provider: "muse",
  ready: false,
  mode: "unchanged_bridge",
  reason:
    "no verified serve-compatible plaintext request seam — keep existing MSP muse serve bridge; capability table omits bridge-capture",
};

const READINESS: Record<TNativeRuntimeProvider, TBridgeCaptureReadiness> = {
  claude_code: CLAUDE_READY,
  chatgpt: CODEX_READY,
  cursor: CURSOR_BLOCKED,
  muse: MUSE_BLOCKED,
};

export const bridgeRequestCaptureReadiness = (
  provider: TNativeRuntimeProvider,
): TBridgeCaptureReadiness => READINESS[provider];

export const shouldActivateBridgeRequestCapture = (
  provider: TNativeRuntimeProvider,
  bridgeCaptureSelected: boolean,
): boolean => {
  if (!bridgeCaptureSelected) return false;
  if (!providerDeclaresBridgeCapture(provider)) return false;
  return bridgeRequestCaptureReadiness(provider).ready;
};

export const bridgeRequestCaptureReadinessTable =
  (): ReadonlyArray<TBridgeCaptureReadiness> => [
    CLAUDE_READY,
    CODEX_READY,
    CURSOR_BLOCKED,
    MUSE_BLOCKED,
  ];
