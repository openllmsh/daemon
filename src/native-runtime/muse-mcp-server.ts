/**
 * Ephemeral loopback MCP server for Muse caller-tool handoff.
 *
 * Muse reads MCP servers from `$XDG_CONFIG_HOME/muse/settings.json` (Streamable
 * HTTP with Authorization). Per request we bind Bun.serve on 127.0.0.1:0 with a
 * unique bearer and implement the minimal MCP subset (initialize /
 * notifications/initialized / tools/list / tools/call).
 *
 * On the first authorized `tools/call`, `onToolCall` fires so the runtime can
 * emit canonical OpenAI `tool_calls` and cancel the native turn. The MCP
 * response is an ERROR result — never a fabricated success — so the cancelled
 * Muse host does not treat the tool as completed. Late/duplicate callbacks
 * after handoff or `stop()` cannot re-emit or continue the native turn.
 */

import { randomUUID } from "node:crypto";
import type { TMuseCallerTool } from "./muse-request";

export type TMuseMcpServer = {
  readonly name: string;
  readonly url: string;
  readonly headers: ReadonlyArray<{
    readonly name: string;
    readonly value: string;
  }>;
  readonly stop: () => void;
};

const MAX_BODY_BYTES = 256 * 1024;

const rpcResult = (id: number | string | null, result: unknown): Response =>
  Response.json({ jsonrpc: "2.0", id, result });

const rpcError = (
  id: number | string | null,
  code: number,
  message: string,
): Response => Response.json({ jsonrpc: "2.0", id, error: { code, message } });

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const rpcIdOf = (value: unknown): number | string | null =>
  typeof value === "number" || typeof value === "string" ? value : null;

/** Read at most `limit` bytes from the request body. Rejects oversize. */
const readBodyBytes = async (
  req: Request,
  limit: number,
): Promise<
  { readonly ok: true; readonly text: string } | { readonly ok: false }
> => {
  const lengthHeader = req.headers.get("content-length");
  if (lengthHeader !== null) {
    const length = Number(lengthHeader);
    if (!Number.isFinite(length) || length < 0 || length > limit) {
      return { ok: false };
    }
  }
  const reader = req.body?.getReader();
  if (reader === undefined) {
    return { ok: true, text: "" };
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > limit) {
      try {
        await reader.cancel();
      } catch {
        // ignore
      }
      return { ok: false };
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged) };
};

type TParsedRpc =
  | {
      readonly ok: true;
      readonly id: number | string | null;
      readonly method: string;
      readonly params: Record<string, unknown> | undefined;
      readonly isNotification: boolean;
    }
  | {
      readonly ok: false;
      readonly id: number | string | null;
      readonly reason: string;
    };

const parseRpc = (text: string): TParsedRpc => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, id: null, reason: "parse error" };
  }
  // JSON.parse("null") / arrays / primitives must not reach property access.
  if (!isPlainObject(parsed)) {
    return { ok: false, id: null, reason: "invalid request" };
  }
  const id = rpcIdOf(parsed.id);
  if (parsed.jsonrpc !== "2.0") {
    return { ok: false, id, reason: "invalid jsonrpc" };
  }
  if (typeof parsed.method !== "string" || parsed.method.length === 0) {
    return { ok: false, id, reason: "invalid method" };
  }
  if (parsed.params !== undefined && !isPlainObject(parsed.params)) {
    return { ok: false, id, reason: "invalid params" };
  }
  return {
    ok: true,
    id,
    method: parsed.method,
    params: parsed.params,
    isNotification:
      !("id" in parsed) || parsed.id === null || parsed.id === undefined,
  };
};

/**
 * Start the per-request loopback MCP server advertising exactly `tools`.
 * `onToolCall` fires at most once for the first valid `tools/call`.
 */
export const startMuseMcpServer = (params: {
  readonly tools: ReadonlyArray<TMuseCallerTool>;
  readonly onToolCall: (name: string, args: Record<string, unknown>) => void;
}): TMuseMcpServer => {
  const token = randomUUID();
  const allowed = new Map(params.tools.map((tool) => [tool.name, tool]));
  let stopped = false;
  let handedOff = false;

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    maxRequestBodySize: MAX_BODY_BYTES,
    fetch: async (req: Request): Promise<Response> => {
      if (stopped) {
        return new Response("gone", { status: 410 });
      }
      if (req.headers.get("authorization") !== `Bearer ${token}`) {
        return new Response("unauthorized", { status: 401 });
      }
      if (req.method !== "POST") {
        return new Response(null, { status: 405 });
      }

      const body = await readBodyBytes(req, MAX_BODY_BYTES);
      if (!body.ok) {
        return rpcError(null, -32600, "request too large");
      }

      const rpc = parseRpc(body.text);
      if (!rpc.ok) {
        const code = rpc.reason === "parse error" ? -32700 : -32600;
        return rpcError(rpc.id, code, rpc.reason);
      }
      const { id, method, params: rpcParams } = rpc;

      switch (method) {
        case "initialize":
          return rpcResult(id, {
            protocolVersion: "2025-03-26",
            capabilities: { tools: {} },
            serverInfo: { name: "openllm-muse-client-tools", version: "1" },
          });
        case "notifications/initialized":
          return new Response(null, { status: 202 });
        case "tools/list":
          return rpcResult(id, {
            tools: params.tools.map((tool) => ({
              name: tool.name,
              ...(tool.description !== null
                ? { description: tool.description }
                : {}),
              inputSchema: tool.parameters,
            })),
          });
        case "tools/call": {
          if (rpcParams === undefined) {
            return rpcError(id, -32602, "tools/call requires params");
          }
          const name = rpcParams.name;
          if (typeof name !== "string" || name.length === 0) {
            return rpcError(id, -32602, "tools/call requires a name");
          }
          const rawArgs = rpcParams.arguments;
          if (rawArgs !== undefined && !isPlainObject(rawArgs)) {
            return rpcError(
              id,
              -32602,
              "tools/call arguments must be an object",
            );
          }
          const args: Record<string, unknown> = rawArgs ?? {};
          if (!allowed.has(name)) {
            return rpcResult(id, {
              content: [
                {
                  type: "text",
                  text: `Tool "${name}" is not in the caller's allowed set.`,
                },
              ],
              isError: true,
            });
          }
          // Claim the handoff BEFORE invoking the callback so a concurrent
          // duplicate cannot also emit or continue the native turn.
          const first = !handedOff && !stopped;
          if (first) {
            handedOff = true;
            try {
              params.onToolCall(name, args);
            } catch {
              // Truthful error to the native agent; handoff already claimed so
              // duplicates still cannot re-fire. Runtime cancel is best-effort.
              return rpcResult(id, {
                content: [
                  {
                    type: "text",
                    text: "Tool handoff failed inside the gateway; this native turn ends without a fabricated result.",
                  },
                ],
                isError: true,
              });
            }
          }
          return rpcResult(id, {
            content: [
              {
                type: "text",
                text: first
                  ? "Tool execution is delegated to the API client; this native turn ends without a fabricated result."
                  : "Duplicate tools/call ignored; the native turn already handed off.",
              },
            ],
            isError: true,
          });
        }
        default:
          return typeof method === "string" && rpc.isNotification
            ? new Response(null, { status: 202 })
            : rpcError(id, -32601, "method not found");
      }
    },
  });

  return {
    name: "openllm-muse-client-tools",
    url: `http://127.0.0.1:${server.port}/mcp`,
    headers: [{ name: "Authorization", value: `Bearer ${token}` }],
    stop: () => {
      stopped = true;
      server.stop(true);
    },
  };
};
