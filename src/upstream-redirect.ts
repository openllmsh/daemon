/**
 * The daemon's ONE upstream redirect policy, shared by every outbound call
 * that carries credentials or user content: the `/v1/*` forward/passthrough
 * (`forward.ts`), the cloud control plane (`cloud-client.ts`), and the
 * walker family (`walker.ts` → video/image/audio walkers).
 *
 * fetch must NEVER auto-follow: a cloud- or vendor-controlled 30x could
 * otherwise pull prompts, media, and bearer credentials to an arbitrary
 * origin — the automatic cross-origin `Authorization` strip is a browser
 * affordance, not a secret-safety property (the body alone already leaks
 * everything).
 */
import { logWarn } from "./logger";

/** Bound on upstream redirect hops — a real cloud move is one hop; anything
 *  longer is treated as a loop and the last redirect is surfaced verbatim. */
export const MAX_UPSTREAM_REDIRECTS = 4;

/**
 * May the daemon re-issue a request — body, metadata, and credentials
 * intact — to an upstream `Location`? Only two destinations ever earn that:
 *
 *   - a SAME-ORIGIN move (scheme+host+port identical — the body and
 *     `Authorization` stay with the deployment that issued them), and
 *   - the canonical `https://openllm.sh` → `https://www.openllm.sh` apex
 *     redirect the CLI-side transport already special-cases.
 *
 * Every other redirect is answered verbatim.
 */
export const upstreamRedirectAllowed = (from: URL, to: URL): boolean =>
  to.origin === from.origin ||
  (from.origin === "https://openllm.sh" &&
    to.origin === "https://www.openllm.sh");

/**
 * Drive `fetchOnce` against `target`, re-issuing the request — body,
 * metadata, and credentials intact — only on a redirect that is
 * METHOD-PRESERVING and lands on an allowed origin:
 *
 *   - 307/308 are the only method-preserving redirects — re-issuing a POST
 *     body on a 301/302/303 would silently rewrite the call into a GET, so
 *     those are surfaced verbatim rather than mangled;
 *   - {@link upstreamRedirectAllowed} bounds WHERE a re-issue may go;
 *   - {@link MAX_UPSTREAM_REDIRECTS} bounds how many.
 *
 * Anything else is returned verbatim so the caller sees the redirect the
 * upstream actually sent.
 *
 * `fetchOnce` MUST issue its call with `redirect: "manual"` (an auto-
 * following fetch consumes the 30x before this policy can gate it) and a
 * REPLAYABLE body (string/Blob — a one-shot stream cannot be re-issued).
 * `logScope` labels refusal warnings with the caller's log scope.
 */
export const fetchWithBoundedRedirects = async (
  target: string,
  fetchOnce: (target: string) => Promise<Response>,
  logScope: string,
): Promise<Response> => {
  let current = target;
  for (let hop = 0; hop <= MAX_UPSTREAM_REDIRECTS; hop++) {
    const resp = await fetchOnce(current);
    const location = resp.headers.get("location");
    if ((resp.status !== 307 && resp.status !== 308) || location === null) {
      return resp;
    }
    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      return resp;
    }
    if (!upstreamRedirectAllowed(new URL(current), next)) {
      logWarn(
        logScope,
        `refusing upstream ${resp.status} to ${next.origin} (allowed: same-origin or the canonical cloud move)`,
      );
      return resp;
    }
    if (hop === MAX_UPSTREAM_REDIRECTS) {
      logWarn(
        logScope,
        `refusing upstream redirect chain longer than ${MAX_UPSTREAM_REDIRECTS} hops`,
      );
      return resp;
    }
    // Drain the redirect body so the connection is reusable before re-issue.
    await resp.arrayBuffer().catch(() => undefined);
    current = next.toString();
  }
  // Unreachable — the loop returns on the last hop — but keeps the control
  // flow explicit if the bound above ever changes.
  return fetchOnce(current);
};
