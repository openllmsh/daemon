/**
 * Screen serializer for the per-consumer terminal virtual-screen.
 *
 * Turns an `@xterm/headless` emulator's CURRENT active buffer into a
 * self-contained repaint byte stream (clear + home, cell-by-cell text with
 * minimal SGR transitions, then a cursor restore). This is what a freshly
 * attaching / differently-sized consumer receives as its initial paint, and
 * what a passive (non-primary) viewer receives on every reflow.
 *
 * The emulator passed in is already sized to the target viewport:
 *  - normal screen: the per-consumer `view` was `resize()`d, so xterm has
 *    reflowed the wrapped content — we serialize its visible rows verbatim.
 *  - alt screen: the app draws absolute-positioned cells; xterm clips them to
 *    the view's size, so serializing the view's own rows/cols yields the
 *    top-left canonical region (a "letterbox" — no reflow is attempted, which
 *    matches tmux's alt-screen behavior).
 *
 * SGR coverage is intentionally the minimal v1 set: palette fg (30-37/90-97),
 * palette bg (40-47/100-107), 256-colour + truecolour via SGR 38/48, and the
 * bold / dim / italic / underline / inverse / strikethrough flags, each reset
 * with SGR 0. Cell attribute reads use the documented `IBufferCell` API
 * (`getFgColor`/`getFgColorMode`/`isBold`/… — see
 * node_modules/@xterm/headless/typings/xterm-headless.d.ts).
 */

import type { IBufferCell, Terminal } from "@xterm/headless";

/** Snapshot of the SGR-relevant attributes of a single cell. */
type TCellAttrs = {
  readonly fgMode: number;
  readonly fg: number;
  readonly bgMode: number;
  readonly bg: number;
  readonly bold: boolean;
  readonly dim: boolean;
  readonly italic: boolean;
  readonly underline: boolean;
  readonly inverse: boolean;
  readonly strike: boolean;
};

/** Colour-mode discriminants (xterm returns these from get*ColorMode()). */
const COLOR_MODE_PALETTE = 1;
const COLOR_MODE_RGB = 2;

const DEFAULT_ATTRS: TCellAttrs = {
  fgMode: 0,
  fg: 0,
  bgMode: 0,
  bg: 0,
  bold: false,
  dim: false,
  italic: false,
  underline: false,
  inverse: false,
  strike: false,
};

const readAttrs = (cell: IBufferCell): TCellAttrs => ({
  fgMode: cell.getFgColorMode(),
  fg: cell.getFgColor(),
  bgMode: cell.getBgColorMode(),
  bg: cell.getBgColor(),
  bold: cell.isBold() !== 0,
  dim: cell.isDim() !== 0,
  italic: cell.isItalic() !== 0,
  underline: cell.isUnderline() !== 0,
  inverse: cell.isInverse() !== 0,
  strike: cell.isStrikethrough() !== 0,
});

const attrsEqual = (a: TCellAttrs, b: TCellAttrs): boolean =>
  a.fgMode === b.fgMode &&
  a.fg === b.fg &&
  a.bgMode === b.bgMode &&
  a.bg === b.bg &&
  a.bold === b.bold &&
  a.dim === b.dim &&
  a.italic === b.italic &&
  a.underline === b.underline &&
  a.inverse === b.inverse &&
  a.strike === b.strike;

/** Foreground SGR params for a cell's colour mode. */
const fgParams = (mode: number, color: number): string[] => {
  if (mode === COLOR_MODE_PALETTE) {
    if (color < 8) return [String(30 + color)];
    if (color < 16) return [String(90 + (color - 8))];
    return ["38", "5", String(color & 0xff)];
  }
  if (mode === COLOR_MODE_RGB) {
    return [
      "38",
      "2",
      String((color >> 16) & 0xff),
      String((color >> 8) & 0xff),
      String(color & 0xff),
    ];
  }
  return [];
};

/** Background SGR params for a cell's colour mode. */
const bgParams = (mode: number, color: number): string[] => {
  if (mode === COLOR_MODE_PALETTE) {
    if (color < 8) return [String(40 + color)];
    if (color < 16) return [String(100 + (color - 8))];
    return ["48", "5", String(color & 0xff)];
  }
  if (mode === COLOR_MODE_RGB) {
    return [
      "48",
      "2",
      String((color >> 16) & 0xff),
      String((color >> 8) & 0xff),
      String(color & 0xff),
    ];
  }
  return [];
};

/** Build the SGR sequence that moves the pen from `prev` to `next`.
 *  Any turned-off flag or colour reset forces a full `0;` reset then re-apply,
 *  which keeps the emitter simple and correct at the cost of a few extra bytes. */
const sgrTransition = (prev: TCellAttrs, next: TCellAttrs): string => {
  if (attrsEqual(prev, next)) return "";
  if (attrsEqual(next, DEFAULT_ATTRS)) return "\x1b[0m";
  const params: string[] = ["0"];
  if (next.bold) params.push("1");
  if (next.dim) params.push("2");
  if (next.italic) params.push("3");
  if (next.underline) params.push("4");
  if (next.inverse) params.push("7");
  if (next.strike) params.push("9");
  params.push(...fgParams(next.fgMode, next.fg));
  params.push(...bgParams(next.bgMode, next.bg));
  return `\x1b[${params.join(";")}m`;
};

/**
 * Serialize the emulator's current active screen into a repaint string.
 *
 * TRADEOFF (v1, documented for review): this is a FULL-SCREEN serialize of the
 * active buffer, not a true dirty-row diff. Callers must NOT invoke it
 * synchronously per output chunk in a hot loop — the per-consumer fan-out
 * coalesces writes onto a microtask before serializing (see session-core.ts).
 * A future optimization can track dirty rows and emit only changed lines.
 */
export const serializeScreen = (term: Terminal): string => {
  const buffer = term.buffer.active;
  const rows = term.rows;
  const cols = term.cols;
  let out = "\x1b[2J\x1b[H";
  let pen = DEFAULT_ATTRS;
  const scratch = buffer.getNullCell();
  // `getLine` takes an ABSOLUTE buffer index; the buffer includes scrollback, so
  // the visible viewport starts at `baseY`. Iterating from 0 would serialize the
  // TOP OF HISTORY, not the live screen (only correct when nothing has scrolled).
  // The alt buffer has no scrollback, so baseY is 0 there. cursorX/cursorY are
  // already viewport-relative (documented), so they need no offset.
  const top = buffer.baseY;
  for (let y = 0; y < rows; y += 1) {
    if (y > 0) out += "\r\n";
    const line = buffer.getLine(top + y);
    if (line === undefined) continue;
    for (let x = 0; x < cols; x += 1) {
      const cell = line.getCell(x, scratch);
      if (cell === undefined) break;
      const width = cell.getWidth();
      // Width-0 cells are the trailing half of a wide glyph already emitted.
      if (width === 0) continue;
      const next = readAttrs(cell);
      const transition = sgrTransition(pen, next);
      if (transition.length > 0) {
        out += transition;
        pen = next;
      }
      const chars = cell.getChars();
      out += chars.length === 0 ? " " : chars;
    }
  }
  // Reset attributes, then restore cursor position + visibility so the next
  // live PTY output lands where the app expects it.
  if (!attrsEqual(pen, DEFAULT_ATTRS)) out += "\x1b[0m";
  out += `\x1b[${buffer.cursorY + 1};${buffer.cursorX + 1}H`;
  return out;
};

/** Convenience: serialize + UTF-8 encode for direct stream writes. */
export const serializeScreenBytes = (term: Terminal): Uint8Array =>
  new TextEncoder().encode(serializeScreen(term));
