/** No daemon backend currently qualifies cache-only hosted web search. */
export const requiresRestrictedWebSearch = (body: unknown): boolean => {
  if (body === null || typeof body !== "object") return false;
  const record = body as Record<string, unknown>;
  const restricted = (tools: unknown): boolean =>
    Array.isArray(tools) &&
    tools.some((tool) => {
      if (tool === null || typeof tool !== "object") return false;
      return (
        ((tool.type === "web_search" || tool.type === "web_search_preview") &&
          tool.external_web_access === false) ||
        (tool.type === "namespace" && restricted(tool.tools))
      );
    });
  return restricted(record.tools) || restricted(record.responses_tools);
};
