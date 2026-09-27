/**
 * Muse bridge request-capture capability (W5).
 *
 * Offline verification against installed `muse-bin-1.4.0-R4302.1` +
 * `@muse-code/sdk@1.3.0` (MUSE_NO_AUTO_UPDATE=1; no live inference, no real
 * credential inspection):
 *
 *   - Inference HTTP is native Rust (reqwest/hyper/rustls). Patching the SDK's
 *     JS `fetch` cannot observe Meta request bodies/headers.
 *   - `muse serve --base-url` is rejected (`unknown option --base-url`). Serve
 *     help exposes sandbox/session flags only — no provider/base-url/endpoint.
 *   - Enterprise config planes reject `settings.base_url` /
 *     `settings.api_base_url` as `unknown_member`. User settings have no
 *     verified serve-applicable endpoint override for plaintext capture.
 *   - Auth-store `api_base_url` (typed in delegation) is an observation clue,
 *     not a proven serve redirect; mutating credentials for capture is out of
 *     scope and unsafe for this demo.
 *   - Proxy env symbols exist in the native binary, but HTTPS CONNECT sees
 *     ciphertext — proxy-only traffic is not request capture. TLS interception
 *     is forbidden under the plan.
 *   - `muse exec --base-url` accepts a base URL, but switching the builder from
 *     MSP `serve` to `exec` requires unproven input/tool/history parity with the
 *     current bridge. It is not a drop-in capture seam.
 *   - MSP schema exposes `turn/cancel`, `session/resume` (history is a READ
 *     preference / served representation), and `turn/steer` (active-turn input).
 *     There is no client history-injection method comparable to Codex
 *     `thread/inject_items`.
 *
 * Therefore Muse request capture is UNSUPPORTED. The shared demo flag may list
 * `muse`, but this provider-owned helper refuses decoration and keeps today's
 * MSP `muse serve` bridge path unchanged. Do not fake a green capture path.
 */

import { providerDeclaresBridgeCapture } from "../sub-method";
import type { TMuseSpawnTarget } from "./muse-runtime";
import { MUSE_SERVE_SAFETY_ARGS, wrapMuseServeSpawn } from "./muse-runtime";
import type { TCaptureDestinationPolicy } from "./request-capture";

export type TMuseCaptureBlockerCode =
  | "native_reqwest_stack"
  | "serve_rejects_base_url"
  | "settings_no_endpoint_override"
  | "proxy_ciphertext_only"
  | "exec_builder_parity_unproven"
  | "no_msp_history_inject";

export type TMuseCaptureBlocker = {
  readonly code: TMuseCaptureBlockerCode;
  readonly detail: string;
};

/**
 * Capability report for Muse capture. `supported` is currently always false —
 * widen only after a verified plaintext serve-compatible mechanism lands.
 */
export type TMuseRequestCaptureCapability = {
  readonly supported: false;
  readonly provider: "muse";
  /** No verified mechanism id while unsupported. */
  readonly mechanism: null;
  readonly blockers: ReadonlyArray<TMuseCaptureBlocker>;
  readonly inspected: {
    readonly sdk: string;
    readonly native: string;
  };
};

export const MUSE_REQUEST_CAPTURE_BLOCKERS: ReadonlyArray<TMuseCaptureBlocker> =
  [
    {
      code: "native_reqwest_stack",
      detail:
        "muse serve inference uses a native Rust HTTP stack; SDK/JS fetch patches do not see Meta envelopes",
    },
    {
      code: "serve_rejects_base_url",
      detail:
        "muse serve rejects --base-url; root/exec flags cannot prefix the serve subcommand",
    },
    {
      code: "settings_no_endpoint_override",
      detail:
        "enterprise defaults/policy reject base_url/api_base_url; no verified serve settings endpoint seam for plaintext capture",
    },
    {
      code: "proxy_ciphertext_only",
      detail:
        "HTTPS CONNECT / packet redirect sees ciphertext, not headers/body; TLS interception is out of scope",
    },
    {
      code: "exec_builder_parity_unproven",
      detail:
        "muse exec accepts --base-url but is not a proven MSP serve replacement for tools/history/input parity",
    },
    {
      code: "no_msp_history_inject",
      detail:
        "MSP has turn/cancel and resume history read preferences, not a client history-injection API for warm capture",
    },
  ] as const;

/** Snapshot of the offline-inspected Muse artifact tuple (not a package pin). */
export const MUSE_REQUEST_CAPTURE_INSPECTED = {
  sdk: "1.3.0",
  native: "1.4.0-R4302.1",
} as const;

export const MUSE_REQUEST_CAPTURE_CAPABILITY: TMuseRequestCaptureCapability = {
  supported: false,
  provider: "muse",
  mechanism: null,
  blockers: MUSE_REQUEST_CAPTURE_BLOCKERS,
  inspected: MUSE_REQUEST_CAPTURE_INSPECTED,
};

/** Static capability evaluation — no process spawn, no credential access. */
export const evaluateMuseRequestCaptureCapability =
  (): TMuseRequestCaptureCapability => MUSE_REQUEST_CAPTURE_CAPABILITY;

/**
 * Whether Muse serve argv (the daemon's real builder) admits a base-URL
 * override. Encoded from verified help/rejection — always false today.
 */
export const museServeAcceptsBaseUrlFlag = (): boolean => false;

/**
 * Pre-sandbox serve argv the daemon uses for MSP hosts. Pure; mirrors
 * `wrapMuseServeSpawn` inputs so capture work cannot invent a different
 * builder under the same helper.
 */
export const museServeCaptureArgv = (
  museBin: string,
): ReadonlyArray<string> => [museBin, "serve", ...MUSE_SERVE_SAFETY_ARGS];

/**
 * Actual daemon spawn target for Muse MSP hosts (includes sandbox wrap).
 * Capture adapters must reuse this — never invent a `--base-url` serve argv.
 */
export const museDaemonServeSpawnTarget = (museBin: string): TMuseSpawnTarget =>
  wrapMuseServeSpawn(museBin);

/**
 * True when a candidate serve argv would attempt the rejected `--base-url`
 * shape. Used by tests / future adapters to refuse unsafe argv mutation.
 */
export const museServeArgvAttemptsBaseUrl = (
  argv: ReadonlyArray<string>,
): boolean => {
  for (let i = 0; i < argv.length; i += 1) {
    const part = argv[i];
    if (part === "--base-url") return true;
    if (part?.startsWith("--base-url=") === true) return true;
  }
  return false;
};

/**
 * Settings keys that must NOT be written into the Muse overlay for capture.
 * Writing them would either be ignored, rejected, or (for auth) mutate
 * credential material — none of which is a verified plaintext capture seam.
 */
export const MUSE_CAPTURE_FORBIDDEN_SETTINGS_KEYS = [
  "base_url",
  "api_base_url",
  "endpoint",
  "meta_base_url",
] as const;

export type TMuseCaptureForbiddenSettingsKey =
  (typeof MUSE_CAPTURE_FORBIDDEN_SETTINGS_KEYS)[number];

export const museCaptureForbiddenSettingsPresent = (
  settings: Readonly<Record<string, unknown>>,
): ReadonlyArray<TMuseCaptureForbiddenSettingsKey> =>
  MUSE_CAPTURE_FORBIDDEN_SETTINGS_KEYS.filter((key) => key in settings);

export type TMuseRequestCapturePlan = {
  /**
   * Always `unchanged_bridge` while Muse capture is unsupported — even when
   * a caller requests `muse:bridge-capture` (capability table omits it).
   */
  readonly mode: "unchanged_bridge";
  readonly reason: string;
  /** True when a caller asked for Muse capture despite undeclared capability. */
  readonly bridgeCaptureRequested: boolean;
  readonly capability: TMuseRequestCaptureCapability;
};

/**
 * Resolve what Muse should do under a requested `bridge-capture` selection.
 *
 * Unsupported mechanism ⇒ keep today's MSP bridge. Capability normalization
 * already drops undeclared methods; this guard is defense in depth.
 */
export const resolveMuseRequestCapturePlan = (opts?: {
  readonly bridgeCaptureRequested?: boolean;
}): TMuseRequestCapturePlan => {
  const bridgeCaptureRequested = opts?.bridgeCaptureRequested === true;
  const capability = evaluateMuseRequestCaptureCapability();
  const declared = providerDeclaresBridgeCapture("muse");
  if (bridgeCaptureRequested || declared) {
    return {
      mode: "unchanged_bridge",
      reason:
        "muse request capture unsupported; bridge-capture not serve-activated; existing MSP serve bridge retained",
      bridgeCaptureRequested,
      capability,
    };
  }
  return {
    mode: "unchanged_bridge",
    reason: "muse keeps the existing MSP bridge (bridge-capture not selected)",
    bridgeCaptureRequested: false,
    capability,
  };
};

export type TOpenMuseRequestCaptureResult = {
  readonly plan: TMuseRequestCapturePlan;
  /** Always null while unsupported — never a functioning capture decoration. */
  readonly decoration: null;
};

/**
 * Muse-owned entry point for capture decoration.
 *
 * Unlike shared `openCaptureDecoration`, this NEVER returns a live session
 * while Muse capability is unsupported — even if `enabled` is true. Callers
 * must keep the existing `runMuseNative` / MSP path.
 */
export const openMuseRequestCaptureDecoration = (args: {
  readonly bridgeCaptureRequested?: boolean;
  readonly enabled?: boolean;
  readonly destinationPolicy: TCaptureDestinationPolicy;
  readonly signal?: AbortSignal;
  readonly maxBodyBytes?: number;
  readonly captureTimeoutMs?: number;
}): TOpenMuseRequestCaptureResult => {
  // Shared `enabled` / destination knobs are accepted so a future supported
  // path can reuse this entry point — but Muse currently has no verified
  // plaintext capture mechanism, so decoration stays null regardless.
  void args.enabled;
  void args.destinationPolicy;
  void args.signal;
  void args.maxBodyBytes;
  void args.captureTimeoutMs;
  return {
    plan: resolveMuseRequestCapturePlan({
      bridgeCaptureRequested: args.bridgeCaptureRequested === true,
    }),
    decoration: null,
  };
};

/**
 * Guard for integration wiring: Muse capture decoration must stay null.
 * Throws if a future change returns a decoration without flipping capability.
 */
export const assertMuseRequestCaptureUnarmed = (
  result: TOpenMuseRequestCaptureResult,
): void => {
  if (result.decoration !== null) {
    throw new Error(
      "muse request capture decoration must be null while capability.supported is false",
    );
  }
  if (result.plan.mode !== "unchanged_bridge") {
    throw new Error(
      `muse request capture plan must be unchanged_bridge, got ${result.plan.mode}`,
    );
  }
  if (result.plan.capability.supported !== false) {
    throw new Error(
      "muse request capture capability.supported must be false until a verified mechanism exists",
    );
  }
};

/** Narrow helper for serve.ts-adjacent callers: should Muse decorate? Never. */
export const shouldDecorateMuseRequestCapture = (opts?: {
  readonly bridgeCaptureRequested?: boolean;
}): boolean => {
  const plan = resolveMuseRequestCapturePlan(opts);
  return plan.mode !== "unchanged_bridge" && plan.capability.supported;
};
