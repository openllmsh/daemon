/**
 * Screen serializer for the per-consumer terminal virtual-screen.
 *
 * Turns an `@xterm/headless` emulator's CURRENT active buffer into a
 * self-contained repaint byte stream (clear + home, then the visible viewport
 * with SGR attributes and a cursor restore). This is what a freshly attaching /
 * differently-sized consumer receives as its initial paint, and what a passive
 * (non-primary) viewer receives on every reflow.
 *
 * Implementation: the official `@xterm/addon-serialize` (`SerializeAddon`) — the
 * same serializer VS Code and the wider xterm.js ecosystem use for the
 * "headless + serialize for reconnect" pattern. It is loaded once per emulator
 * (cached in a WeakMap) and reads the terminal's active buffer via the addon's
 * documented API, so SGR colours (palette / 256 / truecolour) and text
 * attributes (bold / dim / italic / underline / inverse / strike) all round-trip
 * correctly — unlike a hand-rolled SGR emitter, which is easy to desync from
 * xterm's internal colour-mode encoding.
 *
 * REFLOW: `serialize()` emits LOGICAL lines (wrapped rows are joined, with the
 * wrap flag preserved), so the output is width-agnostic — writing it into a
 * terminal of any width lets xterm re-wrap the content to that width. That is
 * exactly the per-consumer reflow the session fan-out relies on: seed a
 * consumer-sized view with the shared emulator's serialization and it reflows
 * to the consumer's columns. The alternate screen has no scrollback and is
 * absolute-positioned, so it is clipped (a "letterbox") rather than reflowed —
 * matching tmux's alt-screen behaviour.
 *
 * We serialize with `scrollback: 0` (the visible viewport only) and prepend an
 * explicit `\x1b[2J\x1b[H` so the payload is a complete repaint that overwrites
 * whatever the consumer currently shows, independent of its prior state.
 */

import { SerializeAddon } from "@xterm/addon-serialize";
import type { Terminal } from "@xterm/headless";

/** One SerializeAddon per emulator, loaded lazily and reused across calls.
 *  Keyed weakly so a disposed Terminal's addon is collectable. */
const addons = new WeakMap<Terminal, SerializeAddon>();

const addonFor = (term: Terminal): SerializeAddon => {
  const existing = addons.get(term);
  if (existing !== undefined) return existing;
  const addon = new SerializeAddon();
  // `@xterm/addon-serialize` typings are declared against `@xterm/xterm`'s
  // Terminal, but the addon only touches the shared core buffer API that the
  // headless build also exposes (this is how VS Code drives it headless).
  addon.activate(term as unknown as Parameters<SerializeAddon["activate"]>[0]);
  addons.set(term, addon);
  return addon;
};

/**
 * Serialize the emulator's current active screen into a repaint string: a
 * clear + home, then the visible viewport (SGR + cursor) as produced by
 * `SerializeAddon`. `scrollback: 0` restricts the dump to the visible rows.
 */
export const serializeScreen = (term: Terminal): string =>
  `\x1b[2J\x1b[H${addonFor(term).serialize({ scrollback: 0 })}`;

/** Convenience: serialize + UTF-8 encode for direct stream writes. */
export const serializeScreenBytes = (term: Terminal): Uint8Array =>
  new TextEncoder().encode(serializeScreen(term));
