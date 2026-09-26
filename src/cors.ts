/**
 * Shared CORS for the daemon's localhost surfaces.
 *
 * Both the control surface (`/status`, `/connect`, …) and the `/v1/*`
 * inference surface are called by the dashboard browser (an HTTPS page
 * fetching `http://127.0.0.1`), so both need to answer the CORS preflight
 * + reflect an allowed origin. Request-side access control is layered:
 * the localhost bind, this origin lock (enforced — see
 * `requestOriginAllowed`), a loopback request-target check, and the
 * per-boot local caller token (`env.localCallerToken`).
 */
import {
  MEDIA_ERROR_RESPONSE_HEADER,
  MEDIA_PERSISTENCE_RESPONSE_HEADER,
  NO_DAEMON_HEADER,
  TOOL_SESSION_HEADER,
} from "@openllmsh/protocol";
import {
  daemonEnv,
  isDaemonApiKeyCredential,
  isDevMode,
  isLocalCallerCredential,
} from "./env";

/**
 * Swap localhost <-> 127.0.0.1 in an origin. `localhost` and `127.0.0.1`
 * are DISTINCT origins to the browser, so a fixed allow-origin pinned to
 * one breaks the other (a dashboard on `localhost:3000` calling a daemon
 * configured for `127.0.0.1:3000` would be CORS-blocked).
 */
const loopbackSibling = (origin: string): string | null => {
  if (origin.includes("127.0.0.1")) {
    return origin.replace("127.0.0.1", "localhost");
  }
  if (origin.includes("localhost")) {
    return origin.replace("localhost", "127.0.0.1");
  }
  return null;
};

/**
 * The OpenLLM product's own deployment origins. ONE daemon serves EVERY
 * deployment (prod + previews), not just the one it was paired with — the
 * whole point of the deployment-agnostic design
 * (`docs/proposals/daemon-presence-without-heartbeat.md`). So the control
 * surface reflects any of these, regardless of the daemon's configured origin.
 */
const PROD_ORIGINS: ReadonlySet<string> = new Set([
  "https://openllm.sh",
  "https://www.openllm.sh",
]);

/**
 * OpenLLM's own Vercel preview deployments:
 *   `openllm-<hash>-quantide.vercel.app`
 *   `openllm-git-<branch>-quantide.vercel.app`
 * Anchored to the `openllm` project + `quantide` team so a stranger's
 * `*.vercel.app` can't reach the daemon's localhost control surface.
 */
const PREVIEW_ORIGIN = /^https:\/\/openllm-[a-z0-9-]+-quantide\.vercel\.app$/;

/** A real `http(s)` loopback origin (`localhost` / `127.0.0.1` / `[::1]`, any
 *  port) — parsed, not substring-matched, so `https://localhost.attacker.com`
 *  / `https://evil-localhost.io` can't slip past an `includes("localhost")`.
 *  Trusted only by the dev paths (`isTrustedDeploymentOrigin` under
 *  `NODE_ENV=development`, and the dev-mode branches below). */
const isLoopbackWebOrigin = (origin: string): boolean => {
  try {
    const u = new URL(origin);
    return (
      (u.protocol === "http:" || u.protocol === "https:") &&
      (u.hostname === "localhost" ||
        u.hostname === "127.0.0.1" ||
        u.hostname === "[::1]")
    );
  } catch {
    return false;
  }
};

export const isTrustedDeploymentOrigin = (origin: string): boolean =>
  PROD_ORIGINS.has(origin) ||
  PREVIEW_ORIGIN.test(origin) ||
  (process.env.NODE_ENV === "development" && isLoopbackWebOrigin(origin));

/**
 * May this request's `Origin` header call the local surfaces at all? A
 * browser ALWAYS sends `Origin` on a cross-site POST — including the
 * `text/plain` / `no-cors` "simple request" a hostile page uses to reach
 * `127.0.0.1` without a preflight. Rejecting an origin CORS would not
 * reflect closes the blind-POST vector (the response was already
 * unreadable; now the request never runs). Absent `Origin` = a non-browser
 * client (vendor CLIs, curl, the mux dispatch) — allowed.
 */
export const requestOriginAllowed = (req: Request): boolean => {
  const origin = req.headers.get("origin");
  if (origin === null) return true;
  const configured = daemonEnv().dashboardOrigin;
  if (origin === configured || loopbackSibling(configured) === origin) {
    return true;
  }
  if (isTrustedDeploymentOrigin(origin)) return true;
  // Dev mode adds ONLY a real loopback origin — a local dev server on an
  // arbitrary port — never "every origin". A dev daemon can hold the shared
  // production API key, so a hostile page must never reach `/v1/*`.
  return isDevMode() && isLoopbackWebOrigin(origin);
};

/**
 * The daemon binds `127.0.0.1`, so every legitimate request-target is a
 * loopback URL. Checking `req.url`'s host (what Bun built from the request
 * line / Host header) refuses DNS-rebinding shapes that arrive without a
 * usable `Origin` — a page rebound to 127.0.0.1 still names its own host.
 */
export const isLoopbackRequestTarget = (req: Request): boolean => {
  try {
    const { hostname } = new URL(req.url);
    return (
      hostname === "127.0.0.1" ||
      hostname === "localhost" ||
      hostname === "[::1]" ||
      hostname === "::1"
    );
  } catch {
    return false;
  }
};

/** Header carrying the per-boot local caller token (`env.localCallerToken`). */
export const LOCAL_CALLER_TOKEN_HEADER = "x-openllm-local-token";

/**
 * The local caller token presented either as a dedicated header or as the
 * request's bearer credential (a vendor CLI knows it as "the API key" from
 * its launch env). Presented via {@link LOCAL_CALLER_TOKEN_HEADER}, or
 * `Authorization: Bearer <token>`, or `x-api-key: <token>`.
 */
export const isLocalCallerAuthorized = (req: Request): boolean => {
  const dedicated = req.headers.get(LOCAL_CALLER_TOKEN_HEADER);
  if (dedicated !== null && isLocalCallerCredential(dedicated.trim())) {
    return true;
  }
  const apiKeyHeader = req.headers.get("x-api-key");
  if (apiKeyHeader !== null) {
    const apiKey = apiKeyHeader.trim();
    if (isLocalCallerCredential(apiKey) || isDaemonApiKeyCredential(apiKey)) {
      return true;
    }
  }
  const authorization = req.headers.get("authorization");
  if (authorization?.startsWith("Bearer ") === true) {
    const bearer = authorization.slice("Bearer ".length).trim();
    return isLocalCallerCredential(bearer) || isDaemonApiKeyCredential(bearer);
  }
  return false;
};

/**
 * The `access-control-allow-origin` to return for THIS request: the request's
 * `Origin` when it's the configured dashboard origin / its loopback sibling, a
 * trusted OpenLLM deployment (prod or a project preview), or — in dev — ANY
 * origin; else the configured origin.
 */
const allowOrigin = (req: Request): string => {
  const configured = daemonEnv().dashboardOrigin;
  const origin = req.headers.get("origin");
  if (origin === null) return configured;
  if (origin === configured || loopbackSibling(configured) === origin) {
    return origin;
  }
  // Any OpenLLM deployment's dashboard may drive this daemon — reflect the
  // prod origins + the project's own previews even when the daemon was
  // installed against a different one (e.g. a prod daemon used from a preview).
  if (isTrustedDeploymentOrigin(origin)) return origin;
  // Dev mode keeps an EXACT allowlist — it only adds a real loopback origin
  // (a local dev server on an arbitrary port). A dev daemon can hold the
  // shared production API key, so an arbitrary hostile origin is never
  // reflected.
  if (isDevMode() && isLoopbackWebOrigin(origin)) return origin;
  return configured;
};

/**
 * CORS response headers. `allow-headers` includes:
 *  - `authorization` — the `/v1/*` surface takes `Authorization: Bearer sk-llm-…`;
 *  - `x-openllm-daemon` / `x-openllm-no-daemon` — when the gateway 307s a
 *    subscription request to `127.0.0.1`, the browser REPLAYS the original
 *    request (incl. these presence headers) to the daemon as a fresh
 *    cross-origin call; the preflight must allow them even though the daemon
 *    ignores them (the plan rides in the `?__plan=` query, not a header).
 * (The control surface only needs `content-type`, but a superset is harmless.)
 *
 * `expose-headers` covers the DIRECT cross-origin path only (the browser
 * replaying a gateway 307 to `127.0.0.1`); the mux carries its own closed
 * `res_head` struct instead. An unexposed response header is unreadable to
 * the page and therefore indistinguishable from one the daemon never sent —
 * so every media header the browser BRANCHES on must be listed, or an
 * omission degrades silently into the WRONG diagnosis rather than an error.
 */
export const corsHeaders = (req: Request): Record<string, string> => ({
  "access-control-allow-origin": allowOrigin(req),
  // DELETE — the browser video-cancel surface (`DELETE /v1/media/<id>` via the
  // relay-mux / direct replay); without it the cancel preflight is blocked.
  "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
  "access-control-allow-headers": `content-type, authorization, x-api-key, ${LOCAL_CALLER_TOKEN_HEADER}, ${TOOL_SESSION_HEADER}, ${NO_DAEMON_HEADER}`,
  "access-control-expose-headers": `x-openllm-media-id, x-openllm-media-url, x-openllm-resolved-model, x-openllm-chain, ${MEDIA_ERROR_RESPONSE_HEADER}, ${MEDIA_PERSISTENCE_RESPONSE_HEADER}, ${TOOL_SESSION_HEADER}`,
  "access-control-allow-private-network": "true",
  vary: "origin",
});

/** True for a CORS/PNA preflight (handle with a 204 + cors headers). */
export const isPreflight = (req: Request): boolean => req.method === "OPTIONS";

export const preflightResponse = (req: Request): Response =>
  new Response(null, { status: 204, headers: corsHeaders(req) });

/** A JSON error envelope (`{ error: { message, type? } }`) — the daemon's
 *  standard error shape, shared by the listener + the walker. CORS is
 *  layered on by the caller's `withCors`. */
export const errorJson = (
  status: number,
  message: string,
  type?: string,
  code?: string,
): Response =>
  new Response(
    JSON.stringify({
      error: {
        message,
        ...(type !== undefined ? { type } : {}),
        ...(code !== undefined ? { code } : {}),
      },
    }),
    {
      status,
      headers: { "content-type": "application/json" },
    },
  );
