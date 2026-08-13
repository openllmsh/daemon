import type {
  TImageGenerationRequest,
  TImageGenerationResponse,
} from "@openllmsh/protocol";
import {
  ImageGenerationRequest,
  ImageGenerationResponse,
} from "@openllmsh/protocol";
import { originatorHeadersFrom } from "@openllmsh/wire/lib/forwarded-headers";
import { Schema } from "effect";
import { errorJson } from "./cors";
import { getDelegate, isSubscriptionSlug } from "./delegation";
import type { TWalkArgs } from "./walker";
import {
  parsePlan,
  planSignatureOk,
  postUpstream,
  report,
  resolveHop,
  statusFor,
} from "./walker";

const parseImageRequest = Schema.decodeUnknownSync(ImageGenerationRequest);
const parseImageResponse = Schema.decodeUnknownSync(ImageGenerationResponse);

type TImageUpstream = {
  readonly headers: Record<string, string>;
  readonly url: string;
  readonly accountHash: string | null;
};

const acquireImageUpstream = async (
  provider: string,
  args: TWalkArgs,
): Promise<TImageUpstream | "retry"> => {
  const delegate = getDelegate(provider);
  if (delegate?.credentialForImage === undefined) return "retry";
  try {
    const cred = await delegate.credentialForImage(args.req.headers);
    return {
      headers: {
        ...originatorHeadersFrom(args.req.headers),
        ...cred.headers,
        authorization: `Bearer ${cred.access_token}`,
      },
      url: cred.url,
      accountHash: cred.account_hash ?? null,
    };
  } catch {
    return "retry";
  }
};

export const sizeToAspect = (size?: string): string => {
  switch (size) {
    case "1792x1024":
      return "16:9";
    case "1024x1792":
      return "9:16";
    default:
      return "1:1";
  }
};

export const buildImageUpstreamBody = (
  provider: string,
  req: TImageGenerationRequest,
  providerModelId: string,
): Record<string, unknown> => {
  if (provider === "chatgpt") {
    // Forward the `gpt-image`-supported options so client settings aren't
    // silently dropped. `style` + `response_format` are DALL·E-era params that
    // gpt-image (what Codex serves) rejects — forwarding them would 400, so
    // they're intentionally omitted (gpt-image always returns b64_json).
    return {
      model: providerModelId,
      prompt: req.prompt,
      ...(req.n !== undefined ? { n: req.n } : {}),
      ...(req.size !== undefined ? { size: req.size } : {}),
      ...(req.quality !== undefined ? { quality: req.quality } : {}),
      ...(req.background !== undefined ? { background: req.background } : {}),
      ...(req.user !== undefined ? { user: req.user } : {}),
    };
  }
  if (provider === "grok") {
    return {
      model: providerModelId,
      prompt: req.prompt,
      n: req.n ?? 1,
      aspect_ratio: sizeToAspect(req.size),
      resolution: "1k",
      response_format: "b64_json",
    };
  }
  throw new Error(`Unsupported subscription image provider: ${provider}`);
};

export const normalizeImageResponse = (
  upstream: unknown,
): TImageGenerationResponse => {
  const data =
    upstream !== null && typeof upstream === "object"
      ? (upstream as { readonly data?: unknown }).data
      : undefined;
  // A "success" upstream body with no `data` array is malformed — surface it
  // as a 502 (the caller converts this throw) rather than fabricating an empty
  // but 200-OK image response the client would read as a successful no-op.
  if (!Array.isArray(data)) {
    throw new Error("upstream image response missing a data array");
  }
  return parseImageResponse({
    created: Math.floor(Date.now() / 1000),
    data,
  });
};

export const runImageWalker = async (args: TWalkArgs): Promise<Response> => {
  if (
    !planSignatureOk(
      args.planParam,
      args.pmidsParam,
      args.originParam,
      args.sigParam,
    )
  ) {
    return errorJson(403, "invalid or missing __plan signature");
  }
  if (args.planParam === null) {
    return errorJson(400, "images require a daemon plan");
  }

  let imageRequest: TImageGenerationRequest;
  try {
    imageRequest = parseImageRequest(args.rawBody);
  } catch (err) {
    return errorJson(
      400,
      err instanceof Error ? err.message : "Invalid image generation request",
    );
  }

  const pmids = args.pmidsParam === null ? [] : args.pmidsParam.split(",");
  const hop = parsePlan(args.planParam)
    .map((modelId, index) => resolveHop(modelId, pmids[index]))
    .find((candidate) => {
      const delegate = getDelegate(candidate.provider);
      return (
        isSubscriptionSlug(candidate.provider) &&
        delegate?.credentialForImage !== undefined
      );
    });
  if (hop === undefined) {
    return errorJson(
      404,
      "No subscription image provider in the daemon plan can serve this request",
    );
  }

  const acquired = await acquireImageUpstream(hop.provider, args);
  if (acquired === "retry") {
    return errorJson(404, `No image credential available for ${hop.provider}`);
  }

  let upstreamBody: Record<string, unknown>;
  try {
    upstreamBody = buildImageUpstreamBody(
      hop.provider,
      imageRequest,
      hop.providerModelId,
    );
  } catch (err) {
    return errorJson(
      400,
      err instanceof Error ? err.message : "Unsupported image provider",
    );
  }

  const resp = await postUpstream(
    acquired.url,
    {
      method: "POST",
      headers: {
        ...acquired.headers,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(upstreamBody),
      signal: args.req.signal,
    },
    true,
    args.req.signal,
  );
  if (resp === null) {
    return args.req.signal.aborted
      ? errorJson(499, "client aborted request")
      : errorJson(502, "upstream image provider is unreachable");
  }

  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    report(
      {
        model: hop.modelId,
        provider: hop.provider,
        status: statusFor(resp.status),
        tokens_in: 0,
        tokens_out: 0,
        latency_ms: Date.now() - args.startedAt,
        endpoint: args.endpoint,
        ...(acquired.accountHash !== null
          ? { account_hash: acquired.accountHash }
          : {}),
      },
      args.originParam,
    );
    return new Response(body.length > 0 ? body : null, {
      status: resp.status,
      headers: { "content-type": "application/json" },
    });
  }

  let upstream: unknown;
  try {
    upstream = await resp.json();
  } catch {
    return errorJson(502, "upstream image provider returned invalid JSON");
  }
  let normalized: TImageGenerationResponse;
  try {
    normalized = normalizeImageResponse(upstream);
  } catch (err) {
    return errorJson(
      502,
      err instanceof Error
        ? `upstream image provider returned invalid data: ${err.message}`
        : "upstream image provider returned invalid data",
    );
  }
  report(
    {
      model: hop.modelId,
      provider: hop.provider,
      status: statusFor(resp.status),
      tokens_in: 0,
      tokens_out: 0,
      latency_ms: Date.now() - args.startedAt,
      endpoint: args.endpoint,
      ...(acquired.accountHash !== null
        ? { account_hash: acquired.accountHash }
        : {}),
    },
    args.originParam,
  );
  return new Response(JSON.stringify(normalized), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
