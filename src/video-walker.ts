import type {
  TVideoDeleted,
  TVideoGenerationRequest,
  TVideoIdPayload,
  TVideoJob,
  TVideoJobStatus,
} from "@openllmsh/protocol";
import {
  decodeVideoId,
  encodeVideoId,
  isSubscriptionProviderSlug,
  normalizeContentType,
  parseVideoGenerationInput,
  redactVideoErrorText,
  VIDEO_INPUT_ERROR,
  VideoGenerationRequest,
  videoInputReceiptFromCounts,
} from "@openllmsh/protocol";
import { originatorHeadersFrom } from "@openllmsh/wire/lib/forwarded-headers";
import { Schema } from "effect";
import { uploadMedia } from "./cloud-client";
import { errorJson } from "./cors";
import { getDelegate } from "./delegation";
import { passthroughToOrigin } from "./forward";
import { logWarn, safeDiagnosticMessage } from "./logger";
import { withMediaAttribution } from "./media-attribution";
import { forwardMediaHopToCloud } from "./media-cloud-forward";
import { mediaHopAdvances, mediaHttpErrorCode } from "./media-retry";
import type { TWalkArgs } from "./walker";
import {
  coolHopAfterStaleRefresh,
  parsePlan,
  passthroughHeaders,
  planSignatureOk,
  postUpstream,
  report,
  resolveHop,
  statusFor,
} from "./walker";

const parseVideoRequest = Schema.decodeUnknownSync(VideoGenerationRequest);

type TVideoUpstream = {
  readonly headers: Record<string, string>;
  readonly url: string;
  readonly accountHash: string | null;
};

type TXaiVideoStatus = {
  readonly status?: unknown;
  readonly progress?: unknown;
  readonly video?: { readonly url?: unknown };
  readonly error?: { readonly message?: unknown } | string;
};

export const acquireVideoUpstream = async (
  provider: string,
  args: TWalkArgs,
  hop: { readonly provider: string; readonly modelId: string },
  walkSessionKey?: string,
): Promise<TVideoUpstream | "retry"> => {
  const delegate = getDelegate(provider);
  if (delegate?.credentialForVideo === undefined) return "retry";
  try {
    const cred = await delegate.credentialForVideo(args.req.headers);
    if (cred.stale_refresh !== undefined) {
      coolHopAfterStaleRefresh(hop, cred.stale_refresh, walkSessionKey);
      return "retry";
    }
    return {
      headers: {
        ...originatorHeadersFrom(args.req.headers),
        ...cred.headers,
        authorization: `Bearer ${cred.access_token}`,
      },
      url: cred.url.replace(/\/+$/, ""),
      accountHash: cred.account_hash ?? null,
    };
  } catch {
    return "retry";
  }
};

const hopForVideoJob = (
  args: TWalkArgs,
  payload: TVideoIdPayload,
): ReturnType<typeof resolveHop> | undefined => {
  const pmids = args.pmidsParam === null ? [] : args.pmidsParam.split(",");
  return parsePlan(args.planParam)
    .map((modelId, index) => resolveHop(modelId, pmids[index]))
    .find(
      (candidate) =>
        candidate.modelId === payload.m && candidate.provider === payload.p,
    );
};

const EMPTY_BODY = new ArrayBuffer(0);

const followVideoJob = async (
  args: TWalkArgs,
  payload: TVideoIdPayload,
): Promise<Response | TVideoUpstream> => {
  if (!isSubscriptionProviderSlug(payload.p)) {
    return passthroughToOrigin(args.req, EMPTY_BODY, { pinModel: payload.m });
  }
  const hop = hopForVideoJob(args, payload);
  if (hop === undefined) {
    return errorJson(403, "Signed plan does not cover this video job");
  }
  const upstream = await acquireVideoUpstream(payload.p, args, hop);
  if (upstream === "retry") {
    return errorJson(404, `No video credential available for ${payload.p}`);
  }
  return upstream;
};

const signedPlanError = (args: TWalkArgs): Response | null => {
  if (
    !planSignatureOk(
      args.planParam,
      args.pmidsParam,
      args.originParam,
      args.contextOverflowStrategy ?? null,
      args.sigParam,
    )
  ) {
    return errorJson(403, "invalid or missing __plan signature");
  }
  if (args.planParam === null)
    return errorJson(400, "videos require a daemon plan");
  return null;
};

const upstreamError = async (resp: Response): Promise<Response> => {
  const body = await resp.text().catch(() => "");
  return new Response(body.length > 0 ? body : null, {
    status: resp.status,
    headers: passthroughHeaders(resp),
  });
};

const responseJson = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const xaiStatus = (body: unknown): TXaiVideoStatus | null =>
  body !== null && typeof body === "object" ? (body as TXaiVideoStatus) : null;

const errorMessageFrom = (status: TXaiVideoStatus): string | undefined => {
  if (typeof status.error === "string") return status.error;
  return typeof status.error?.message === "string"
    ? status.error.message
    : undefined;
};

const upstreamHeaders = (headers: Record<string, string>): Headers =>
  new Headers({ ...headers, accept: "application/json" });

const videoRequestIdFrom = (body: unknown): string | null => {
  if (body === null || typeof body !== "object") return null;
  const requestId = (body as { readonly request_id?: unknown }).request_id;
  return typeof requestId === "string" && requestId.length > 0
    ? requestId
    : null;
};

/**
 * Derive Grok's `aspect_ratio` from a `WIDTHxHEIGHT` size by reducing the
 * ratio. Only an absent size defaults to `1:1`; other explicit values are
 * preserved for native provider validation rather than silently replaced.
 */
export const videoAspectRatio = (size?: string): string => {
  const match = size?.match(/^(\d+)x(\d+)$/i);
  if (!match) return size ?? "1:1";
  const width = Number.parseInt(match[1] ?? "", 10);
  const height = Number.parseInt(match[2] ?? "", 10);
  if (!(width > 0 && height > 0)) return size ?? "1:1";
  const gcd = (a: number, b: number): number => (b === 0 ? a : gcd(b, a % b));
  const divisor = gcd(width, height);
  return `${width / divisor}:${height / divisor}`;
};

/** Map xAI's asynchronous video statuses to OpenLLM's job lifecycle. */
export const mapVideoStatus = (status: unknown): TVideoJobStatus => {
  if (status === "done") return "completed";
  if (status === "failed" || status === "expired") return "failed";
  return status === "queued" ? "queued" : "in_progress";
};

/** Select Grok's required output resolution from a WIDTHxHEIGHT size. */
export const sizeToResolution = (size?: string): string => {
  if (size === undefined) return "480p";
  const match = /^(\d+)x(\d+)$/.exec(size);
  return match ? `${Math.min(Number(match[1]), Number(match[2]))}p` : size;
};

/** Build the provider-native video generation request without performing I/O. */
export const buildVideoUpstreamBody = (
  provider: string,
  req: TVideoGenerationRequest,
  providerModelId: string,
): Record<string, unknown> => {
  parseVideoGenerationInput(req);
  if (provider !== "grok") {
    throw new Error(`Unsupported subscription video provider: ${provider}`);
  }
  const duration =
    req.seconds === undefined
      ? undefined
      : req.seconds.trim() !== "" && Number.isFinite(Number(req.seconds))
        ? Number(req.seconds)
        : req.seconds;
  return {
    model: providerModelId,
    prompt: req.prompt,
    ...(req.input_image !== undefined
      ? { image: { url: req.input_image } }
      : {}),
    ...(req.reference_images !== undefined && req.reference_images.length > 0
      ? { reference_images: req.reference_images.map((url) => ({ url })) }
      : {}),
    ...(req.reference_voices !== undefined && req.reference_voices.length > 0
      ? {
          reference_audios: req.reference_voices.map((voice_id) => ({
            voice_id,
          })),
        }
      : {}),
    ...(duration !== undefined ? { duration } : {}),
    aspect_ratio: videoAspectRatio(req.size),
    resolution: sizeToResolution(req.size),
  };
};

const reportVideo = (
  args: TWalkArgs,
  provider: string,
  model: string,
  httpStatus: number,
  accountHash: string | null,
): void => {
  report(
    {
      model,
      provider,
      status: statusFor(httpStatus),
      tokens_in: 0,
      tokens_out: 0,
      latency_ms: Date.now() - args.startedAt,
      endpoint: args.endpoint,
      ...(accountHash !== null ? { account_hash: accountHash } : {}),
    },
    args.originParam,
  );
};

const decodeJob = (videoId: string | undefined): TVideoIdPayload | Response => {
  if (videoId === undefined) return errorJson(404, "No such video");
  const payload = decodeVideoId(videoId);
  return payload ?? errorJson(404, `No such video: ${videoId}`);
};

// Bound a single xAI status GET so a hung upstream can't stall the poll —
// combined with the client's own abort signal (same pattern as cloud-client).
const VIDEO_STATUS_TIMEOUT_MS = 30_000;

// Bound the presigned MP4 download so a hung transfer can't stall indefinitely
// even if the client stays connected. Generous — a Grok clip is ≤15s of video,
// so a real download finishes well inside this.
const VIDEO_DOWNLOAD_TIMEOUT_MS = 120_000;

const getStatus = async (
  args: TWalkArgs,
  upstream: TVideoUpstream,
  payload: TVideoIdPayload,
): Promise<Response | TXaiVideoStatus> => {
  let resp: Response;
  try {
    resp = await (args.fetchImpl ?? fetch)(
      `${upstream.url}/videos/${encodeURIComponent(payload.u)}`,
      {
        method: "GET",
        headers: upstreamHeaders(upstream.headers),
        signal: AbortSignal.any([
          args.req.signal,
          AbortSignal.timeout(VIDEO_STATUS_TIMEOUT_MS),
        ]),
      },
    );
  } catch {
    return args.req.signal.aborted
      ? errorJson(499, "client aborted request")
      : errorJson(502, "upstream video provider is unreachable");
  }
  if (!resp.ok) return upstreamError(resp);
  try {
    const body = xaiStatus(await resp.json());
    return (
      body ?? errorJson(502, "upstream video provider returned invalid JSON")
    );
  } catch {
    return errorJson(502, "upstream video provider returned invalid JSON");
  }
};

export const runVideoCreate = async (args: TWalkArgs): Promise<Response> => {
  const signatureError = signedPlanError(args);
  if (signatureError !== null) return signatureError;

  let request: TVideoGenerationRequest;
  try {
    request = parseVideoRequest(parseVideoGenerationInput(args.rawBody));
  } catch {
    return errorJson(400, VIDEO_INPUT_ERROR);
  }
  const pmids = args.pmidsParam === null ? [] : args.pmidsParam.split(",");
  const hops = parsePlan(args.planParam).map((modelId, index) =>
    resolveHop(modelId, pmids[index]),
  );
  const attempted: string[] = [];
  const stamp = (resp: Response, resolved?: string): Response =>
    withMediaAttribution(resp, {
      attempted,
      ...(resolved !== undefined ? { resolvedModel: resolved } : {}),
    });
  let lastError: Response | null = null;

  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];
    if (hop === undefined) continue;
    const last = i === hops.length - 1;
    if (!isSubscriptionProviderSlug(hop.provider)) {
      attempted.push(hop.modelId);
      const forwarded = await forwardMediaHopToCloud(args, hop.modelId);
      if (forwarded.ok) return stamp(forwarded, hop.modelId);
      lastError = forwarded;
      if (
        !last &&
        mediaHopAdvances({
          dispatched: true,
          httpStatus: forwarded.status,
          errorCode: mediaHttpErrorCode(forwarded.status),
          accepted: false,
        })
      ) {
        continue;
      }
      return stamp(forwarded);
    }
    const upstream = await acquireVideoUpstream(hop.provider, args, hop);
    if (upstream === "retry") {
      lastError = errorJson(
        404,
        `No video credential available for ${hop.provider}`,
      );
      if (
        !last &&
        mediaHopAdvances({
          dispatched: false,
          errorCode: "missing_credential",
        })
      ) {
        continue;
      }
      return stamp(lastError);
    }
    attempted.push(hop.modelId);
    let body: Record<string, unknown>;
    try {
      body = buildVideoUpstreamBody(hop.provider, request, hop.providerModelId);
    } catch (err) {
      lastError = errorJson(
        400,
        err instanceof Error ? err.message : "Unsupported video provider",
      );
      if (
        !last &&
        mediaHopAdvances({
          dispatched: false,
          errorCode: "model_unavailable",
        })
      ) {
        continue;
      }
      return stamp(lastError);
    }
    const resp = await postUpstream(`${upstream.url}/videos/generations`, {
      method: "POST",
      headers: {
        ...upstream.headers,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(body),
      signal: args.req.signal,
    });
    if (resp === null) {
      return stamp(
        args.req.signal.aborted
          ? errorJson(499, "client aborted request")
          : errorJson(502, "upstream video provider is unreachable"),
      );
    }
    if (!resp.ok) {
      reportVideo(
        args,
        hop.provider,
        hop.modelId,
        resp.status,
        upstream.accountHash,
      );
      const rawError = await upstreamError(resp);
      const errorText = redactVideoErrorText(await rawError.text(), [
        request.input_image ?? "",
        ...(request.reference_images ?? []),
        ...(request.reference_voices ?? []),
        ...Object.entries(upstream.headers).flatMap(([key, value]) =>
          /authorization|cookie|token|key/i.test(key)
            ? [value, value.replace(/^(?:Bearer|Basic)\s+/i, "")]
            : [],
        ),
      ]);
      lastError = new Response(errorText, {
        status: rawError.status,
        headers: rawError.headers,
      });
      if (
        !last &&
        mediaHopAdvances({
          dispatched: true,
          httpStatus: resp.status,
          errorCode: mediaHttpErrorCode(resp.status),
          accepted: false,
        })
      ) {
        continue;
      }
      return stamp(lastError);
    }
    let requestId: string | null;
    try {
      requestId = videoRequestIdFrom(await resp.json());
    } catch {
      requestId = null;
    }
    if (requestId === null) {
      return stamp(
        errorJson(502, "upstream video provider returned no request_id"),
      );
    }
    const createdAt = Math.floor(Date.now() / 1000);
    const job: TVideoJob = {
      id: encodeVideoId({
        p: hop.provider,
        u: requestId,
        m: hop.modelId,
        c: createdAt,
      }),
      object: "video",
      created_at: createdAt,
      status: "queued",
      model: hop.modelId,
      progress: 0,
      // Read forwarding evidence from the accepted outbound body, not user intent.
      input_receipt: videoInputReceiptFromCounts({
        starting_images: body.image === undefined ? 0 : 1,
        subject_images: Array.isArray(body.reference_images)
          ? body.reference_images.length
          : 0,
        voices: Array.isArray(body.reference_audios)
          ? body.reference_audios.length
          : 0,
      }),
      ...(request.seconds !== undefined ? { seconds: request.seconds } : {}),
      ...(request.size !== undefined ? { size: request.size } : {}),
    };
    reportVideo(
      args,
      hop.provider,
      hop.modelId,
      resp.status,
      upstream.accountHash,
    );
    return stamp(responseJson(job), hop.modelId);
  }
  return stamp(
    lastError ??
      errorJson(
        404,
        "No video provider in the daemon plan can serve this request",
      ),
  );
};

export const runVideoPoll = async (
  args: TWalkArgs,
  videoId?: string,
): Promise<Response> => {
  const signatureError = signedPlanError(args);
  if (signatureError !== null) return signatureError;
  const payload = decodeJob(videoId);
  if (payload instanceof Response) return payload;
  const followed = await followVideoJob(args, payload);
  if (followed instanceof Response) return followed;
  const status = await getStatus(args, followed, payload);
  if (status instanceof Response) return status;
  const errorMessage = errorMessageFrom(status);
  const job: TVideoJob = {
    id: videoId ?? "",
    object: "video",
    created_at: payload.c,
    status: mapVideoStatus(status.status),
    model: payload.m,
    ...(typeof status.progress === "number"
      ? { progress: status.progress }
      : {}),
    ...(errorMessage !== undefined ? { error: { message: errorMessage } } : {}),
  };
  return responseJson(job);
};

export const runVideoContent = async (
  args: TWalkArgs,
  videoId?: string,
): Promise<Response> => {
  const signatureError = signedPlanError(args);
  if (signatureError !== null) return signatureError;
  const payload = decodeJob(videoId);
  if (payload instanceof Response) return payload;
  const followed = await followVideoJob(args, payload);
  if (followed instanceof Response) return followed;
  const status = await getStatus(args, followed, payload);
  if (status instanceof Response) return status;
  if (status.status !== "done") {
    return errorJson(
      409,
      `Video is not ready yet (status: ${typeof status.status === "string" ? status.status : "unknown"}). Poll GET /v1/videos/${videoId} until it completes.`,
    );
  }
  const contentUrl = status.video?.url;
  if (typeof contentUrl !== "string" || contentUrl.length === 0) {
    return errorJson(502, "Completed video has no downloadable content URL");
  }
  let content: Response;
  try {
    // NOT tied to `args.req.signal`: the client (e.g. the browser tool) cancels
    // the response body as soon as it has read the durable-url header, which
    // aborts the inbound request. If this download were bound to that signal the
    // teed persist branch would die mid-flight and nothing would ever land in the
    // library. A timeout alone bounds it so persistence completes regardless.
    content = await (args.fetchImpl ?? fetch)(contentUrl, {
      method: "GET",
      signal: AbortSignal.timeout(VIDEO_DOWNLOAD_TIMEOUT_MS),
    });
  } catch {
    return args.req.signal.aborted
      ? errorJson(499, "client aborted request")
      : errorJson(502, "video download is unreachable");
  }
  if (!content.ok) return upstreamError(content);

  const body = content.body;
  if (body === null) {
    return errorJson(502, "upstream video has no content body");
  }

  const id = videoId;
  if (id === undefined) {
    return errorJson(404, "No such video");
  }
  // This is a video content endpoint, so the payload IS a video. Pin a video
  // content-type when the upstream CDN serves a generic one (e.g.
  // application/octet-stream): the library allowlist keys on the exact type,
  // and the ingest rejects an x-media-kind that disagrees with the content-type
  // — a non-video type would fail-close a legitimate video.
  const rawContentType = normalizeContentType(
    content.headers.get("content-type"),
    "video/mp4",
  );
  const contentType = rawContentType.startsWith("video/")
    ? rawContentType
    : "video/mp4";
  const [clientBranch, persistBranch] = body.tee();

  void (async () => {
    const bytes = await new Response(persistBranch).arrayBuffer();
    await uploadMedia(
      bytes,
      {
        contentType,
        kind: "video",
        sourceRef: videoId,
        id,
      },
      args.originParam,
    );
  })().catch((err) => {
    logWarn(
      "video-walker",
      safeDiagnosticMessage`Failed to persist generated video`,
      {
        error: err instanceof Error ? err.message : String(err),
        videoId,
      },
    );
  });

  const durable = args.originParam
    ? `${args.originParam}/api/media/${id}`
    : null;

  const responseHeaders: Record<string, string> = {
    "content-type": contentType,
    "cache-control": "no-store",
    "x-openllm-media-id": id,
  };
  if (durable !== null) {
    responseHeaders["x-openllm-media-url"] = durable;
  }

  return new Response(clientBranch, {
    status: 200,
    headers: responseHeaders,
  });
};

export const runVideoCancel = async (
  args: TWalkArgs,
  videoId?: string,
): Promise<Response> => {
  const signatureError = signedPlanError(args);
  if (signatureError !== null) return signatureError;
  const payload = decodeJob(videoId);
  if (payload instanceof Response) return payload;
  const followed = await followVideoJob(args, payload);
  if (!(followed instanceof Response)) {
    await fetch(`${followed.url}/videos/${encodeURIComponent(payload.u)}`, {
      method: "DELETE",
      headers: upstreamHeaders(followed.headers),
      signal: AbortSignal.any([
        args.req.signal,
        AbortSignal.timeout(VIDEO_STATUS_TIMEOUT_MS),
      ]),
    }).catch(() => {});
  }
  const deleted: TVideoDeleted = {
    id: videoId ?? "",
    object: "video.deleted",
    deleted: true,
  };
  return responseJson(deleted);
};
