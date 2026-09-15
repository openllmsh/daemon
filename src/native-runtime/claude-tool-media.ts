/**
 * The media boundary of the Claude native TOOL path: canonical message content
 * → the structured user content the Agent SDK accepts.
 *
 * Two rules shape this file:
 *
 *   1. **wire owns the conversion.** MIME sniffing, data-URL parsing and
 *      source-variant selection live in `@openllmsh/wire`'s Anthropic request
 *      transform (`anthropicContentBlocksOf`) and are reused verbatim — the
 *      daemon does not grow a second media hierarchy.
 *   2. **the SDK's own types own admission.** `@anthropic-ai/claude-agent-sdk`
 *      types a user message as Anthropic's `MessageParam`, whose image/document
 *      sources are NARROWER than the gateway's canonical wire block (e.g. an
 *      image base64 source accepts only four media types, and a document has no
 *      Files-API source). Anything outside that is reported as unsupported so
 *      the caller can fail explicitly, never silently flattened to a sentence
 *      that mentions a URL — a plausible text-only answer is worse than an
 *      error, because the user believes the model saw the attachment.
 */

import type { SDKUserMessage } from "@anthropic-ai/claude-agent-sdk";
import type { TAnthropicContentBlock, TChatMessage } from "@openllmsh/protocol";
import { anthropicContentBlocksOf } from "@openllmsh/wire/providers/anthropic";

/** The SDK's own user-message content type (Anthropic `MessageParam`). */
export type TSdkUserContent = SDKUserMessage["message"]["content"];
type TSdkContentBlock = Exclude<TSdkUserContent, string>[number];
type TSdkImageBlock = Extract<TSdkContentBlock, { type: "image" }>;
type TSdkBase64ImageSource = Extract<
  TSdkImageBlock["source"],
  { type: "base64" }
>;

/** The only base64 image media types the SDK's `MessageParam` admits. Typed by
 *  the SDK union, so an SDK widening/narrowing surfaces here at compile time. */
const SDK_IMAGE_MEDIA_TYPES: ReadonlyArray<
  TSdkBase64ImageSource["media_type"]
> = ["image/jpeg", "image/png", "image/gif", "image/webp"];

const asSdkImageMediaType = (
  mediaType: string,
): TSdkBase64ImageSource["media_type"] | null =>
  SDK_IMAGE_MEDIA_TYPES.find((t) => t === mediaType) ?? null;

export type TSdkContentOutcome =
  | { readonly kind: "ok"; readonly content: TSdkUserContent }
  | { readonly kind: "unsupported"; readonly reason: string };

/**
 * Narrow wire's Anthropic blocks to what the SDK boundary accepts. Only the
 * block kinds a USER turn can carry are considered; any other kind (or an
 * unrepresentable source) is an explicit unsupported outcome.
 */
export const sdkUserContentOf = (
  blocks: ReadonlyArray<TAnthropicContentBlock>,
): TSdkContentOutcome => {
  const content: Array<TSdkContentBlock> = [];
  for (const block of blocks) {
    if (block.type === "text") {
      if (block.text.length > 0)
        content.push({ type: "text", text: block.text });
      continue;
    }
    if (block.type === "image") {
      const source = block.source;
      if (source.type === "url") {
        content.push({
          type: "image",
          source: { type: "url", url: source.url },
        });
        continue;
      }
      if (source.type === "base64") {
        const mediaType = asSdkImageMediaType(source.media_type);
        if (mediaType === null) {
          return {
            kind: "unsupported",
            reason: `image media type ${source.media_type} is not accepted on the Claude native tool path`,
          };
        }
        content.push({
          type: "image",
          source: { type: "base64", media_type: mediaType, data: source.data },
        });
        continue;
      }
      return {
        kind: "unsupported",
        reason:
          "image file references are not accepted on the Claude native tool path",
      };
    }
    if (block.type === "document") {
      const source = block.source;
      // The filename rides `title` (wire puts it there). Two same-shaped PDFs
      // are only distinguishable by it, so dropping it would hand the model
      // unnamed attachments it cannot refer to.
      const title =
        typeof block.title === "string" ? { title: block.title } : {};
      if (source.type === "url") {
        content.push({
          type: "document",
          source: { type: "url", url: source.url },
          ...title,
        });
        continue;
      }
      if (source.type === "base64" && source.media_type === "application/pdf") {
        content.push({
          type: "document",
          source: {
            type: "base64",
            media_type: "application/pdf",
            data: source.data,
          },
          ...title,
        });
        continue;
      }
      if (source.type === "text" && source.media_type === "text/plain") {
        content.push({
          type: "document",
          source: { type: "text", media_type: "text/plain", data: source.data },
          ...title,
        });
        continue;
      }
      return {
        kind: "unsupported",
        reason:
          "document source is not accepted on the Claude native tool path",
      };
    }
    return {
      kind: "unsupported",
      reason: `${block.type} blocks are not accepted on the Claude native tool path`,
    };
  }
  return { kind: "ok", content };
};

/** Does this canonical message content carry anything other than text parts? */
export const hasNonTextContent = (
  content: TChatMessage["content"] | null | undefined,
): boolean =>
  Array.isArray(content) && content.some((part) => part.type !== "text");

/**
 * Canonical content → SDK user content, via wire's conversion. `prefixText`
 * (the lossy prior-transcript seed) leads the turn's own ordered blocks, so
 * images and documents keep their position relative to the user's text.
 */
export const sdkUserContentFor = (
  content: TChatMessage["content"] | null | undefined,
  prefixText: string,
): TSdkContentOutcome => {
  const turnBlocks = anthropicContentBlocksOf(content);
  // wire degrades an unusable attachment to a TEXT annotation ("[file content
  // omitted — …]") rather than throwing, which is right for the HTTP transform
  // but wrong here: it would hand the model a sentence about an attachment it
  // never saw. Every non-text PART must have produced a non-text BLOCK (wire
  // emits exactly one block per part); a shortfall means something degraded.
  const nonTextParts = Array.isArray(content)
    ? content.filter((part) => part.type !== "text").length
    : 0;
  const nonTextBlocks = turnBlocks.filter((b) => b.type !== "text").length;
  if (nonTextBlocks !== nonTextParts) {
    return {
      kind: "unsupported",
      reason:
        "attachment could not be represented as Claude content (unsupported media type or malformed payload)",
    };
  }
  const blocks: Array<TAnthropicContentBlock> = [];
  if (prefixText.length > 0) blocks.push({ type: "text", text: prefixText });
  blocks.push(...turnBlocks);
  return sdkUserContentOf(blocks);
};
