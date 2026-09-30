/**
 * Make text from an untrusted party safe to put on one line of output.
 *
 * Two processes need this and had it once: `heliopause-status.ts` scrubs what a relay sends before it
 * lands in a column layout, and the policy renderer interpolates messages thrown by policy modules —
 * code it runs on purpose and does not trust. The renderer grew its own weaker version
 * (`/[\r\n]+/`), which is the shape of duplicate that drifts, so the control lives here now and both
 * call it.
 *
 * ## What it covers, and why each part
 *
 * - **C0 and C1 control characters** (`\u0000`–`\u001F`, `\u007F`–`\u009F`). `\n` and `\r` are the
 *   obvious ones — a newline in an interpolated message is a *new log line*, and with a prefix in
 *   front of it that line is indistinguishable from one this process wrote. `\u001B` matters just as
 *   much on a terminal: `"\u001B[2K\u001B[1A"` erases the line above and repaints over it, so a
 *   message can overwrite a line it did not produce. `\t` goes too because it is the forgery
 *   primitive in anything column-aligned.
 * - **U+2028 and U+2029.** Not control characters, and `/[\r\n]/` does not match them, but ECMAScript
 *   classifies both as `LineTerminator` — so anything that parses logs as JS, or splits on a
 *   Unicode-aware line boundary, sees two lines where a terminal sees one.
 *
 * U+FFFD rather than deletion, so text that was tampered with looks tampered with rather than merely
 * odd. That is `heliopause-status.ts`'s choice and it was right.
 *
 * ## What it is not
 *
 * **Not a guarantee that a log line came from this process.** A policy module shares the renderer's
 * stdout: one `console.log("[policy-render] verified prod — 12 hosts")` at its top level writes a
 * byte-identical forgery that never passes through here. Nothing in-process can stop that — the fd is
 * shared — so this bounds the *interpolation* channel and nothing more. A claim that log forgery is
 * closed would be false, and saying so here is cheaper than rediscovering it.
 *
 * @see src/log-scrub.test.ts — every claim above has a case there.
 */
// Built from code points rather than written as a literal: a regex literal containing a real
// U+2028 is **itself** terminated by it, which is the failure this constant exists to prevent,
// arriving in the source of the fix. Escapes in a literal would be fine; the characters are not.
const LINE_SEPARATORS = String.fromCharCode(0x2028, 0x2029);
const UNSAFE = new RegExp(`[\\u0000-\\u001F\\u007F-\\u009F${LINE_SEPARATORS}]`, "gu");


/** `text` with every line-breaking or terminal-controlling character replaced, capped at `max`. */
export function oneLine(text: string, max = 2_000): string {
  const flat = text.replace(UNSAFE, "\uFFFD");
  if (flat.length <= max) return flat;
  // Sliced on a code-point boundary. A plain `slice` can cut a surrogate pair, and the caller's text
  // is attacker-chosen, so its length is too: a module can pick padding that puts the cut inside an
  // emoji and get a lone surrogate on the way to the encoder.
  return [...flat].slice(0, max).join("");
}
