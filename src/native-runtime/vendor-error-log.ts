/**
 * Vendor-controlled error prose → a closed classification for LOGS.
 *
 * Vendor CLIs / SDKs echo caller text, file paths and credentials inside their
 * error strings. Those strings must never reach a log line or log metadata:
 * the only vendor-derived data a log may carry is the closed code below plus a
 * byte count. (Decline reasons returned to the caller are a separate channel.)
 */

/** Closed set — the ONLY vendor-error-derived text allowed in a log. */
export type TVendorErrorCode =
  | "auth"
  | "rate_limit"
  | "keychain"
  | "sandbox"
  | "timeout"
  | "protocol"
  | "other"
  | "none";

export type TVendorErrorClass = {
  readonly code: TVendorErrorCode;
  readonly bytes: number;
};

export type TVendorErrorLogFields = {
  readonly errorCode: TVendorErrorCode;
  readonly errorBytes: number;
};

const VENDOR_ERROR_CLASSES: ReadonlyArray<readonly [TVendorErrorCode, RegExp]> =
  [
    ["keychain", /keychain/i],
    ["auth", /\b(401|403|unauthori[sz]ed|forbidden|login|credential|token)\b/i],
    ["rate_limit", /\b(429|rate.?limit|overloaded|quota)\b/i],
    ["sandbox", /\b(sandbox|seatbelt|landlock|operation not permitted)\b/i],
    ["timeout", /\b(timed?[ _-]?out|timeout|deadline|ETIMEDOUT)\b/i],
    [
      "protocol",
      /\b(protocol|malformed|invalid (?:json|request|response|message)|unexpected|parse)\b/i,
    ],
  ];

export const classifyVendorError = (
  text: string | null | undefined,
): TVendorErrorClass => {
  if (text === null || text === undefined || text.length === 0) {
    return { code: "none", bytes: 0 };
  }
  const bytes = Buffer.byteLength(text, "utf8");
  for (const [code, pattern] of VENDOR_ERROR_CLASSES) {
    if (pattern.test(text)) return { code, bytes };
  }
  return { code: "other", bytes };
};

/** Log metadata for a vendor-controlled string: code + byte count, never text. */
export const vendorErrorLogFields = (
  text: string | null | undefined,
): TVendorErrorLogFields => {
  const { code, bytes } = classifyVendorError(text);
  return { errorCode: code, errorBytes: bytes };
};

/** Same, for a caught value (`Error` message or stringified). */
export const vendorErrorLogFieldsOf = (error: unknown): TVendorErrorLogFields =>
  vendorErrorLogFields(error instanceof Error ? error.message : String(error));
