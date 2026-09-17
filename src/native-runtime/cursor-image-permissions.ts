/**
 * Image-mode ACP server-request handler. Chat {@link handleCursorServerRequest}
 * auto-approves every native tool; image generation must NOT. Only the native
 * Generate Image tool is allowed. Unidentifiable permission asks are rejected
 * (fail closed). `cursor/generate_image` is never treated as a client RPC we
 * implement — if the agent sends it as a server request we refuse it; native
 * generation is the agent's own Generate Image tool_call.
 */

const REJECT_ONCE = "reject-once";

type TPermissionOption = {
  readonly optionId?: unknown;
  readonly kind?: unknown;
};

const rejectOutcome = (
  options: ReadonlyArray<TPermissionOption> | undefined,
): {
  readonly outcome: { readonly outcome: "selected"; readonly optionId: string };
} => {
  const pick = Array.isArray(options)
    ? (options.find((o) => o.kind === "reject_once") ??
      options.find((o) => o.kind === "reject_always"))
    : undefined;
  const optionId =
    typeof pick?.optionId === "string" ? pick.optionId : REJECT_ONCE;
  return { outcome: { outcome: "selected", optionId } };
};

const allowOutcome = (
  options: ReadonlyArray<TPermissionOption> | undefined,
): {
  readonly outcome: { readonly outcome: "selected"; readonly optionId: string };
} => {
  const pick = Array.isArray(options)
    ? (options.find((o) => o.kind === "allow_once") ??
      options.find((o) => o.kind === "allow_always"))
    : undefined;
  const optionId =
    typeof pick?.optionId === "string" ? pick.optionId : "allow-once";
  return { outcome: { outcome: "selected", optionId } };
};

const GENERATE_IMAGE_RE = /generate[\s_-]*image/i;

/** True when an ACP permission / tool payload names the Generate Image tool. */
export const isCursorGenerateImageTool = (value: unknown): boolean => {
  if (typeof value === "string") return GENERATE_IMAGE_RE.test(value);
  if (typeof value !== "object" || value === null) return false;
  const o = value as {
    readonly title?: unknown;
    readonly kind?: unknown;
    readonly toolName?: unknown;
    readonly name?: unknown;
    readonly toolCall?: unknown;
  };
  const fields = [o.title, o.kind, o.toolName, o.name];
  if (fields.some((f) => typeof f === "string" && GENERATE_IMAGE_RE.test(f))) {
    return true;
  }
  if (o.toolCall !== undefined) return isCursorGenerateImageTool(o.toolCall);
  return false;
};

/**
 * SECURITY (concrete, evidenced): native tool-call auto-run posture for
 * Cursor ACP image mode.
 *
 * Evidence — installed `cursor-agent` 2026.07.23-e383d2b:
 *   `cursor-agent acp --help` lists ONLY `-h, --help`. The ACP subcommand
 *   exposes no permission/sandbox/allowed-tools flag of its own. The
 *   top-level `agent` command's `--sandbox <enabled|disabled>`,
 *   `--mode <plan|ask>` and `-f/--force` are documented only for the
 *   interactive/print command; the binary does not reject them when placed
 *   before `acp`, but nothing in `--help` or shipped docs states they take
 *   effect inside an ACP session, and confirming real effect would require
 *   a live authenticated ACP run against Cursor's cloud, which is out of
 *   scope for this daemon to do just to find out.
 *
 * Conclusion: no VERIFIED before-the-fact mechanism exists to stop the
 * agent auto-running a non-image native tool (Shell, Write, …) inside an
 * ACP session at this CLI version. `session/request_permission` denial
 * (`rejectOutcome` above) only covers tools the agent asks permission for —
 * the installed build frequently does not ask before its first native
 * tool_call. Cancelling the session when a foreign `tool_call` is observed
 * (`runCursorNativeImage` in `cursor-acp.ts`) is cleanup AFTER an
 * already-started action, not prevention, and MUST NOT be reported or
 * relied on as a sandbox guarantee. `enforced: false` here is the signal a
 * future capability-negotiation layer should gate the image-generation
 * entry point on; this module does not itself decide whether to expose
 * that entry point.
 */
export const cursorImageToolEnforcement = {
  enforced: false,
  mechanism: "none-verified",
  reason:
    "cursor-agent acp exposes no permission/sandbox flags (verified via --help on 2026.07.23-e383d2b); session/request_permission denial and post-hoc session/cancel on a foreign tool_call are mitigations, not prevention",
} as const;

export type TCursorImageToolEnforcement = typeof cursorImageToolEnforcement;

export const handleCursorImageServerRequest = (
  method: string,
  params: unknown,
): unknown => {
  if (method === "cursor/generate_image") {
    // Agent-to-client generate request — we do not implement client-side
    // generation and never invoke this as a client RPC.
    return null;
  }
  if (method === "session/request_permission") {
    const p = params as {
      readonly options?: ReadonlyArray<TPermissionOption>;
      readonly toolCall?: unknown;
      readonly title?: unknown;
    };
    if (isCursorGenerateImageTool(p) || isCursorGenerateImageTool(p.toolCall)) {
      return allowOutcome(p.options);
    }
    return rejectOutcome(p.options);
  }
  if (method === "cursor/ask_question") {
    return {
      answers: [],
    };
  }
  return null;
};
