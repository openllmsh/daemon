/** Shared title truncation for local session readers. */

export const TITLE_MAX = 80;

export const truncate = (s: string): string => {
  const t = s.replace(/\s+/g, " ").trim();
  if (t.length === 0) return "Untitled";
  return t.length <= TITLE_MAX ? t : `${t.slice(0, TITLE_MAX - 1)}...`;
};
