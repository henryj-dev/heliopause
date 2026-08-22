// The icons this console draws, by their name in the icon library.
//
// ## Why a library and not the glyphs the design document draws
//
// 시안 is written in dingbats — `✓ ✕ ! ? → ◇ △ ▲ ■ □ ⧉ ＋`. They read correctly in a design
// canvas and badly in a firewall console, for three reasons this repository has already met:
//
//   1. **They are font-dependent.** `⧉` and `◇` are outside every core system font on Linux, which
//      is where the operator reading this page during an incident is. A missing glyph renders as a
//      box, and a box in the `state` column of a fleet table is indistinguishable from a state this
//      console does not know about.
//   2. **They carry no accessible name.** A screen reader says "white diamond" for `◇`, which is
//      the shape, not "maintenance", which is the fact.
//   3. **They cannot be checked.** A typo in a dingbat is another dingbat.
//
// stardust met the same wall on 2026-08-17 and moved to Lucide; this file is the same decision made
// the same way. The names here are Lucide 1.x names, and `scripts/build-icons.ts --check` fails if
// one of them stops existing in the installed library — a name Lucide does not have renders as
// **nothing at all**, which is exactly the silent blank this console must never draw.
//
// ⚠️ Lucide renamed three of these between 0.544 (the version the design canvas was drawn against)
//    and 1.x: `help-circle` → `circle-question-mark`, `filter` → `funnel`, `x-octagon` →
//    `octagon-x`. Only the first is used here; if a design document names an old one, this is why.
//
// The union exists so a typo is a **compile error** rather than a blank cell. `src/icon-paths.ts` is
// generated as `Record<IconName, string>`, so removing a name here and forgetting to rebuild fails
// `npm run typecheck` instead of shipping.
export const ICON_NAMES = [
  "arrow-left",
  "arrow-right",
  "ban",
  "check",
  "circle-dot",
  "circle-question-mark",
  "copy",
  "diamond",
  "loader-circle",
  "minus",
  "octagon-alert",
  "plus",
  "refresh-cw",
  "search",
  "shield-alert",
  "shield-check",
  "shield-x",
  "triangle-alert",
  "upload",
  "x",
] as const;

export type IconName = (typeof ICON_NAMES)[number];
