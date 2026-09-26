/**
 * Native-runtime bridge contract (trial) — the daemon-local seam that lets a
 * subscription hop execute through the OFFICIAL vendor runtime instead of the
 * walker's manual upstream HTTP serialization:
 *
 *   - claude_code → the isolated Claude Code CLI in headless stream-json mode
 *     (`claude -p --output-format stream-json --include-partial-messages`),
 *   - chatgpt     → the isolated Codex CLI's `codex app-server` JSON-RPC.
 *
 * The bridge changes WHERE the vendor request is produced (the vendor's own
 * runtime, under the daemon's isolated CLI env), never WHO routes: the cloud
 * still resolves + signs the plan, the walker still validates it, and every
 * pre-commit failure falls back to the existing manual transport on the SAME
 * hop. See docs/audit/2026-07-13-t3code-provider-routing-comparison.md §5.
 *
 * Scope (see `nativeRequestOf`): a hop is native-eligible when the request is a
 * plain multi-turn TEXT conversation (served via session resume — only the
 * delta turn is fed), plus tool-bearing `claude_code` requests (the held-open
 * SDK query). Images, structured output, and (for now) chatgpt tools decline
 * up front and the MANUAL transport serves them on the same hop, so the bridge
 * can never regress behavior it does not support.
 */

import type {
  TChatCompletionChunk,
  TChatCompletionRequest,
  TCooldownReason,
} from "@openllmsh/protocol";
import { stateDir } from "../env";
import { childEnvironment } from "../sandbox/child-policy";

/**
 * The subscription providers served by the native runtime FIRST — `claude_code`
 * (Claude Code CLI, `claude -p` stream-json) and `chatgpt` (Codex `app-server`
 * JSON-RPC). Both verified live against the daemon's ISOLATED credential: the
 * official runtime owns auth/refresh/identity and the upstream request. The
 * walker falls back to the MANUAL transport when the native path declines
 * (tools/images/structured-output/native gaps), so no workflow is blocked;
 * auth/refresh flow through the CLI on both paths. (kimi_code + grok are
 * manual-only.)
 *
 * Two non-obvious requirements make `claude -p` work with the isolated home
 * (see `claude-native.ts` + `cleanNativeSpawnEnv`): NO `--bare` flag (it drops
 * the setting sources that carry the subscription credential → "Not logged
 * in"), and a session env that still carries the host-neutral vars the
 * runtime needs (HOME + PATH + temp + locale — macOS keychain reads resolve
 * by HOME path; a bare `env -i` spawn starves them).
 */
export type TNativeRuntimeProvider =
  | "claude_code"
  | "chatgpt"
  | "cursor"
  | "muse";

/** Pre-commit budget shared by BOTH native bridges: how long a runtime may
 *  stay silent (spawn/handshake + thread start + first model output) before
 *  the bridge declines to the manual transport. After commit there is
 *  deliberately no deadline (mirrors the walker's commit-on-first-byte). */
export const PRE_COMMIT_TIMEOUT_MS = 60_000;

const NATIVE_PROVIDERS: ReadonlySet<string> = new Set([
  "claude_code",
  "chatgpt",
  // cursor is BRIDGE-ONLY: `cursor-agent acp` is Cursor's sole inference
  // transport (see native-runtime/cursor-acp.ts) — there is no manual
  // UPSTREAM_WIRE fallback; a bridge decline advances the plan.
  "cursor",
  // muse is BRIDGE-ONLY: official `muse serve` / SDK is the sole inference
  // transport (see native-runtime/muse-runtime.ts).
  "muse",
]);

/** Whether a plan hop's provider is served exclusively by a native runtime. */
export const isNativeRuntimeProvider = (
  provider: string,
): provider is TNativeRuntimeProvider => NATIVE_PROVIDERS.has(provider);

/**
 * The ambient env keys a native vendor child may INHERIT — the host-neutral
 * set a CLI genuinely needs: binary lookup (`PATH`), locale, temp dirs, and
 * the corporate-egress proxy/CA knobs (without them a vendor runtime cannot
 * reach its API at all behind a MITM proxy). Everything else stays OUT:
 *   - daemon keys (`OPENLLM_*`) and the daemon-authority prefixes the
 *     sandbox shim's `childEnvironment` also strips (`PRIVATE_PLANE_*`,
 *     `RELAY_*`, `DEVICE_GRANT_*`),
 *   - vendor auth overrides (`ANTHROPIC_*` / `OPENAI_*` / token keys) that
 *     Bun's auto-loaded `.env*` or the ambient shell can inject and which
 *     would override the runtime's OWN subscription credential resolution,
 *     401-ing as "Not logged in",
 *   - session/agent authority (`SSH_AUTH_SOCK`, `DBUS_*`, GUI display vars),
 *   - loader-injection knobs (`LD_*`, `DYLD_*`, `NODE_OPTIONS`).
 * This is an ALLOWLIST, not a denylist: the leak class is "any key the daemon
 * or the user's shell adds later" — a denylist only covers keys known today.
 * Vendor-specific knobs never come through ambient inheritance; they arrive
 * via the isolated `cliEnv` overlay below (HOME, config dir, TMPDIR, provider
 * env — see `cli-paths.ts` `SPECS`).
 */
const POSIX_AMBIENT_KEYS: ReadonlySet<string> = new Set([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TMPDIR",
  "TEMP",
  "TMP",
  "TERM",
  "COLORTERM",
  "TERM_PROGRAM",
  "LANG",
  "LANGUAGE",
  "TZ",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_EXTRA_CA_CERTS",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
  // Text-encoding hint launchd stamps on every macOS user process.
  "__CF_USER_TEXT_ENCODING",
]);

/**
 * Same contract on Windows, where env names are case-INSENSITIVE: the lookup
 * upper-cases each ambient name before membership-testing, so this list is
 * upper-case. Includes the system vars a Windows child needs to resolve
 * system DLLs, its command interpreter, and exec-able suffixes.
 */
const WINDOWS_AMBIENT_KEYS: ReadonlySet<string> = new Set([
  "PATH",
  "PATHEXT",
  "COMSPEC",
  "SYSTEMROOT",
  "SYSTEMDRIVE",
  "WINDIR",
  "OS",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "PUBLIC",
  "ALLUSERSPROFILE",
  "USERNAME",
  "USERDOMAIN",
  "USERDOMAIN_ROAMINGPROFILE",
  "COMPUTERNAME",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "PROGRAMW6432",
  "COMMONPROGRAMFILES",
  "COMMONPROGRAMFILES(X86)",
  "COMMONPROGRAMW6432",
  "PSMODULEPATH",
  "PROCESSOR_ARCHITECTURE",
  "PROCESSOR_ARCHITEW6432",
  "PROCESSOR_IDENTIFIER",
  "PROCESSOR_LEVEL",
  "PROCESSOR_REVISION",
  "NUMBER_OF_PROCESSORS",
  "LANG",
  "TZ",
  "TERM",
  "COLORTERM",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_EXTRA_CA_CERTS",
]);

/**
 * TEST-ONLY seam: ambient env keys a test has explicitly registered to inherit
 * (on top of the allowlist) — the narrow channel for fake-CLI fixture knobs
 * such as `FAKE_MUSE_LOGIN_MODE` that drive mock vendor binaries in transport
 * login tests. There is deliberately NO environment trigger: the set is
 * populated only by calling this function, and it is consulted only while
 * `NODE_ENV === "test"` (which `bun test` always sets), so nothing about a
 * production daemon's environment can widen the ambient allowlist. The
 * `childEnvironment` authority-prefix strip still runs afterwards, so even a
 * registered `OPENLLM_*` key can never reach the child. Tests must reset with
 * `setAmbientPassthroughKeysForTests(null)` in `afterEach`.
 */
let ambientPassthroughKeysForTests: ReadonlySet<string> | null = null;

/** Only fake-CLI fixture knobs may be passed through; anything else (vendor
 *  secrets such as `META_API_KEY`, loader or authority variables) is refused
 *  even in tests. */
const TEST_PASSTHROUGH_KEY = /^FAKE_[A-Z0-9_]+$/;

export const setAmbientPassthroughKeysForTests = (
  keys: readonly string[] | null,
): void => {
  if (keys !== null) {
    const bad = keys.filter((key) => !TEST_PASSTHROUGH_KEY.test(key));
    if (bad.length > 0)
      throw new Error(
        `test env passthrough accepts only FAKE_* fixture keys, got: ${bad.join(", ")}`,
      );
  }
  ambientPassthroughKeysForTests = keys === null ? null : new Set(keys);
};

/** Consulted only under `NODE_ENV === "test"` — fail-closed in production. */
const testPassthroughAllowed = (key: string): boolean =>
  process.env.NODE_ENV === "test" &&
  ambientPassthroughKeysForTests !== null &&
  ambientPassthroughKeysForTests.has(key);

/** Locale categories (`LC_ALL`, `LC_CTYPE`, …) pass as a family on every
 *  platform; the rest of the ambient contract is the per-platform set. */
const ambientKeyAllowed = (key: string, win: boolean): boolean =>
  key.startsWith("LC_") ||
  (win ? WINDOWS_AMBIENT_KEYS : POSIX_AMBIENT_KEYS).has(key) ||
  testPassthroughAllowed(key);

/**
 * The spawn env for a native vendor runtime: INHERIT ONLY the allowlisted
 * ambient vars, overlay the isolated CLI env (`cliEnv(...)`: HOME, config-dir,
 * TMPDIR, provider knobs) so the runtime uses the daemon's OWN account state,
 * then strip the daemon-authority prefixes (`childEnvironment`:
 * `OPENLLM_*`/`PRIVATE_PLANE_*`/`RELAY_*`/`DEVICE_GRANT_*`) from the MERGED
 * map — an ambient OR overlay-sourced `OPENLLM_API_KEY` must never reach the
 * vendor binary. The `--sandbox-exec` shim re-strips the same prefixes
 * pre-exec, but the SDK `query()` tool path and unwrapped spawns have no
 * shim, so the guarantee has to live here.
 */
export const cleanNativeSpawnEnv = (
  cliEnv: Record<string, string>,
  ambient: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = process.platform,
): Record<string, string> => {
  const win = platform === "win32";
  // Typed as ProcessEnv (Bun's type requires NODE_ENV) so it can be handed to
  // childEnvironment; every value written below is a defined string.
  const merged = {} as NodeJS.ProcessEnv;
  for (const [key, value] of Object.entries(ambient)) {
    if (value === undefined) continue;
    if (!ambientKeyAllowed(win ? key.toUpperCase() : key, win)) continue;
    merged[key] = value;
  }
  for (const [key, value] of Object.entries(cliEnv)) merged[key] = value;
  // childEnvironment's `NodeJS.ProcessEnv` values are all strings here — the
  // delete pass only removes keys.
  const child = childEnvironment(merged) as Record<string, string>;
  // Pin the daemon's REAL state dir so any openllm daemon code the child
  // (or a child's child) runs resolves `~/.openllm` to the real location —
  // NOT `<isolated HOME>/.openllm`. Without this, a child computing
  // `stateDir()` under the isolated HOME recursively creates
  // `<iso home>/.openllm/cli/<provider>/home`. `childEnvironment` strips it
  // with the rest of `OPENLLM_*`; this is the ONE deliberate, non-secret
  // knob. (openllm uses `homedir()` directly and ignores this — the
  // `--strict-mcp-config`/`--setting-sources ""` flags keep the openllm MCP
  // from loading on the inference path.)
  child.OPENLLM_DAEMON_STATE_DIR = stateDir();
  return child;
};

/**
 * The daemon's per-hop token row (what the recorder + cloud consume).
 * `tokens_in` is the canonical prompt-token total and INCLUDES the two cache
 * fields; the cloud prices the split at cache rates. Shared by BOTH the native
 * path (serve + tool bridges) and the walker's manual transport so the two
 * can't drift.
 */
export type TNativeTokens = {
  readonly tokens_in: number;
  readonly tokens_out: number;
  readonly cached_tokens: number;
  readonly cache_creation_tokens: number;
};

/** The all-zero token row (pre-output failures, un-metered fallbacks). */
export const ZERO_TOKENS: TNativeTokens = {
  tokens_in: 0,
  tokens_out: 0,
  cached_tokens: 0,
  cache_creation_tokens: 0,
};

/** Extract the token row from a canonical response's usage — the SINGLE mapper
 *  both the native and manual paths use (identical field folding). */
export const tokensFromResponse = (resp: {
  readonly usage?: {
    readonly prompt_tokens: number;
    readonly completion_tokens: number;
    readonly prompt_tokens_details?: {
      readonly cached_tokens?: number;
      readonly cache_creation_tokens?: number;
    };
  } | null;
}): TNativeTokens => ({
  tokens_in: resp.usage?.prompt_tokens ?? 0,
  tokens_out: resp.usage?.completion_tokens ?? 0,
  cached_tokens: resp.usage?.prompt_tokens_details?.cached_tokens ?? 0,
  cache_creation_tokens:
    resp.usage?.prompt_tokens_details?.cache_creation_tokens ?? 0,
});

/** One text turn of a canonical conversation (Phase 1 = text only). */
export type TNativeTurn = {
  readonly role: "user" | "assistant";
  readonly text: string;
};

/**
 * A native-eligible request decomposed for session-resume execution: the
 * system prompt plus the ordered user/assistant TEXT turns. The session store
 * derives the conversation identity + the delta turn to feed from `turns`.
 */
export type TNativeRequest = {
  readonly systemText: string | null;
  readonly turns: ReadonlyArray<TNativeTurn>;
};

/**
 * Phase-1 capability gate: decompose a canonical request into `{ systemText,
 * turns }` when it's a plain multi-turn TEXT conversation the native runtimes
 * can serve via session resume, or null when it isn't yet supported (tools /
 * tool_choice / response_format / non-text content / `tool`-role messages —
 * those are Phase 2). It accepts prior assistant turns: the session store
 * feeds only the NEW turn to a resumed session.
 */
/**
 * A generation control the native runtimes CANNOT honor, or null when the
 * request is servable natively. The vendor CLIs / app-server accept only model
 * + system + input (plus codex `reasoning_effort`); there is no mapping for the
 * sampling / penalty / decoding / structured-output controls, so a non-default
 * value must DECLINE rather than be silently served at the runtime's own
 * defaults. The walker decides whether a manual transport is available. Applies
 * to BOTH the text path and the tool path.
 *
 * Two deliberate carve-outs keep the PRIMARY native path (Claude Code on the
 * Anthropic wire) alive:
 *   - `max_tokens`/`max_completion_tokens` are NOT decline triggers: max_tokens
 *     is REQUIRED on the Anthropic Messages wire, so every claude_code request
 *     carries it — declining would abandon native for ALL of them. The native
 *     runtime IS Claude Code, capping output at its own equivalent budget, so
 *     the client's cap is a documented best-effort gap, not a manual fallback.
 *   - `temperature`/`top_p` decline only when NON-DEFAULT (≠ 1): Claude Code
 *     sends `temperature: 1` (the wire default the runtime also uses, so
 *     ignoring it changes nothing); `temperature: 0` DOES change sampling and
 *     must decline.
 */
export const unsupportedNativeControl = (
  req: TChatCompletionRequest,
): string | null => {
  const set = (v: unknown): boolean => v !== undefined && v !== null;
  if (set(req.temperature) && req.temperature !== 1) return "temperature";
  if (set(req.top_p) && req.top_p !== 1) return "top_p";
  if (set(req.frequency_penalty) && req.frequency_penalty !== 0) {
    return "frequency_penalty";
  }
  if (set(req.presence_penalty) && req.presence_penalty !== 0) {
    return "presence_penalty";
  }
  if (typeof req.n === "number" && req.n !== 1) return "n";
  if (set(req.stop)) return "stop";
  if (set(req.seed)) return "seed";
  if (set(req.logit_bias)) return "logit_bias";
  if (req.logprobs === true) return "logprobs";
  if (set(req.top_logprobs)) return "top_logprobs";
  if (set(req.response_format)) return "response_format";
  // tool_choice "auto" (or absent) = the native default (the model decides). A
  // forced / "none" / specific choice can't be enforced by the SDK query or the
  // app-server → decline so the manual transport applies it.
  if (set(req.tool_choice) && req.tool_choice !== "auto") return "tool_choice";
  return null;
};

export const nativeRequestOf = (
  canonical: TChatCompletionRequest,
): TNativeRequest | null => {
  if ((canonical.tools?.length ?? 0) > 0) return null;
  if (canonical.tool_choice !== undefined && canonical.tool_choice !== null) {
    return null;
  }
  if (
    canonical.response_format !== undefined &&
    canonical.response_format !== null
  ) {
    return null;
  }
  const systemParts: string[] = [];
  const turns: TNativeTurn[] = [];
  for (const message of canonical.messages) {
    if (message.role === "system") {
      const text = plainTextOf(message.content);
      if (text === null) return null;
      if (text.length > 0) systemParts.push(text);
      continue;
    }
    if (message.role === "user" || message.role === "assistant") {
      const text = plainTextOf(message.content);
      if (text === null) return null; // non-text content (image/file) → Phase 2
      turns.push({ role: message.role, text });
      continue;
    }
    return null; // `tool` role → Phase 2 (tool-passthrough)
  }
  // The final turn must be a user turn (the thing to answer), and there must
  // be at least one.
  const last = turns.at(-1);
  if (last === undefined || last.role !== "user" || last.text.length === 0) {
    return null;
  }
  return {
    systemText: systemParts.length > 0 ? systemParts.join("\n\n") : null,
    turns,
  };
};

/** Plain text of a canonical message content, or null when non-text parts
 *  (images/files) are present — those are out of trial scope. */
const plainTextOf = (
  content: TChatCompletionRequest["messages"][number]["content"],
): string | null => {
  if (typeof content === "string") return content;
  if (content === null || content === undefined) return "";
  if (!Array.isArray(content)) return null;
  const parts: string[] = [];
  for (const part of content) {
    if (
      typeof part !== "object" ||
      part === null ||
      (part as { type?: unknown }).type !== "text" ||
      typeof (part as { text?: unknown }).text !== "string"
    ) {
      return null;
    }
    parts.push((part as { text: string }).text);
  }
  return parts.join("");
};

/**
 * A bridge run either COMMITS (first model output observed — the canonical
 * chunk stream is live and the walker must serve it; mirrors the walker's
 * commit-on-first-byte rule) or DECLINES pre-commit (spawn failure, protocol
 * error, vendor refusal before output) — the walker falls back to the manual
 * transport on the same hop.
 */
export type TNativeRunResult =
  | {
      readonly kind: "committed";
      readonly chunks: ReadableStream<TChatCompletionChunk>;
      /** The provider session id to resume next turn — Claude's stream-json
       *  `session_id`, or Codex's app-server thread id. A GETTER because
       *  Claude's authoritative id may only settle on the terminal `result`
       *  line; the serve adapter reads it AFTER the stream drains. Null when
       *  the runtime produced none (→ the session isn't recorded). */
      readonly sessionId: () => string | null;
    }
  | {
      readonly kind: "declined";
      readonly reason: string;
      readonly cooldownReason?: TCooldownReason;
    };

export type TNativeTerminalResult =
  | { readonly kind: "success" }
  | { readonly kind: "failure"; readonly reason: string };

const terminalRecord = (
  value: unknown,
): Readonly<Record<string, unknown>> | null =>
  typeof value === "object" && value !== null
    ? (value as Readonly<Record<string, unknown>>)
    : null;

const terminalString = (value: unknown): string | null => {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const terminalFailureReason = (
  result: Readonly<Record<string, unknown>>,
): string => {
  const errors = Array.isArray(result.errors)
    ? result.errors
        .map(terminalString)
        .filter((value): value is string => value !== null)
    : [];
  if (errors.length > 0) return errors.join("; ");

  const legacyResult = terminalString(result.result);
  if (legacyResult !== null) return legacyResult;

  const status =
    typeof result.api_error_status === "number" &&
    Number.isFinite(result.api_error_status)
      ? result.api_error_status
      : null;
  const state = terminalString(result.subtype) ?? terminalString(result.status);
  if (status !== null && state !== null) {
    return `native runtime reported terminal failure ${status} (${state})`;
  }
  if (status !== null)
    return `native runtime reported terminal failure ${status}`;
  return state === null
    ? "native runtime reported an unsuccessful terminal result"
    : `native runtime reported an unsuccessful terminal result (${state})`;
};

/**
 * Interpret a native runtime's structured terminal frame without inspecting
 * generated assistant text. Success must be explicit; embedded HTTP failures,
 * error flags, malformed frames, and future terminal states fail closed.
 */
export const normalizeNativeTerminalResult = (
  value: unknown,
): TNativeTerminalResult => {
  const result = terminalRecord(value);
  const apiErrorStatus = result?.api_error_status;
  const hasEmbeddedHttpFailure =
    typeof apiErrorStatus === "number" &&
    Number.isFinite(apiErrorStatus) &&
    apiErrorStatus >= 400;
  const subtype = terminalString(result?.subtype);
  const terminalStatus = terminalString(result?.status);
  const state = subtype ?? terminalStatus;
  const hasInvalidDiagnosticField =
    (result !== null && Object.hasOwn(result, "subtype") && subtype === null) ||
    (result !== null &&
      Object.hasOwn(result, "status") &&
      terminalStatus === null) ||
    // `api_error_status` is null on EVERY successful result (it means "no
    // upstream HTTP error") — a present-but-null value is normal, not invalid.
    // Only a present, non-null, non-finite-number value is malformed.
    (result !== null &&
      Object.hasOwn(result, "api_error_status") &&
      apiErrorStatus !== null &&
      (typeof apiErrorStatus !== "number" || !Number.isFinite(apiErrorStatus)));
  const hasConflictingState =
    subtype !== null && terminalStatus !== null && subtype !== terminalStatus;
  const hasStructuredErrors =
    result?.errors !== undefined &&
    (!Array.isArray(result.errors) || result.errors.length > 0);
  if (
    state === "success" &&
    result?.is_error === false &&
    !hasEmbeddedHttpFailure &&
    !hasInvalidDiagnosticField &&
    !hasConflictingState &&
    !hasStructuredErrors
  ) {
    return { kind: "success" };
  }
  return {
    kind: "failure",
    reason:
      result === null
        ? "native runtime reported an unsuccessful terminal result"
        : terminalFailureReason(result),
  };
};
