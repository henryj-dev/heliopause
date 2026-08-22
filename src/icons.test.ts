// 아이콘 층 — **그려 보고** 검사한다.
//
// ## 이 파일이 막는 실패는 침묵이다
//
// 아이콘이 잘못되는 방식은 예외가 아니다. `<use href="#i-checkk">` 는 오류를 내지 않고 **빈 칸**을
// 그린다. `state` 칸의 빈 칸은 「이 콘솔이 모르는 상태」와 구분되지 않고, 그 칸은 시안이
// 「모양이 뜻이다」라고 못 박은 바로 그 칸이다.
//
// 그래서 여기 있는 검사는 전부 **알려진 양성**을 함께 든다 — 없는 이름을 넣어 보고, 딩뱃을 섞어
// 보고, 스프라이트에서 심볼을 빼 본다. 그러지 않으면 「아이콘이 하나도 없는 페이지」가 이 파일을
// 통째로 통과한다.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ICON_NAMES, type IconName } from "./icon-names.ts";
import { ICON_PATHS } from "./icon-paths.ts";
import { GLYPH, icon, iconSprite } from "./icons.ts";
import { innerMarkup } from "../scripts/build-icons.ts";
import { policyPage } from "./policy-ui.ts";
import type { PolicyRow } from "./policy-view.ts";

const row = (over: Partial<PolicyRow> = {}): PolicyRow => ({
  id: "DEV-SSH", name: "ssh from mgmt", action: "allow", denyMode: "drop",
  proto: "tcp", ports: "22", priority: 100, enabled: true, notes: null,
  hosts: ["gw-01.dev"], skippedOn: [], egressHosts: [], srcCidrs: ["10.254.0.0/16"],
  placementKnown: true, risks: [], ...over,
});

const meta = { site: "policy/dev.ts", generation: "abc1234", hosts: ["gw-01.dev"] };

/**
 * The document this project serves that carries the sprite, with something in every icon-bearing cell.
 *
 * It was two. The classic console was the other, and it is gone — the product screen is the Svelte
 * console under `/app`, which draws its own icons and never used this sprite. Keeping a dead page in
 * this list would have meant these checks stayed green against markup nobody serves.
 */
const pages = (): Array<[string, string]> => [
  ["policy", policyPage(
    [row({ risks: ["renders-nowhere"] }), row({ id: "W", risks: ["any-source"] }),
     row({ id: "D", risks: ["disabled"] }), row({ id: "X", action: "deny" })],
    { ...meta, section: "policies", freshness: { state: "unknown", why: "the repository did not answer" } },
  )],
];

describe("the generated icon table", () => {
  it("has a non-empty drawing for every declared name", () => {
    for (const n of ICON_NAMES) {
      assert.ok(ICON_PATHS[n], `${n} has no markup — src/icon-paths.ts is stale, run npm run icons`);
      assert.match(ICON_PATHS[n], /<(path|circle|rect|line|polyline|polygon|ellipse)\b/,
        `${n} carries no drawable element`);
    }
  });

  it("declares exactly the names it draws, in both directions", () => {
    // `Record<IconName, string>` catches a missing key at compile time and says nothing about an
    // extra one. An orphan symbol is dead weight in every response this console sends.
    assert.deepEqual(Object.keys(ICON_PATHS).sort(), [...ICON_NAMES].sort());
  });

  it("keeps the library's own viewBox by stripping only the wrapper", () => {
    // The known positive for the extractor. A version of `innerMarkup` that returned its input
    // unchanged would still satisfy every other assertion in this file.
    const svg = '<!-- @license x -->\n<svg width="24" viewBox="0 0 24 24">\n  <path d="M0 0" />\n</svg>';
    assert.equal(innerMarkup(svg), '<path d="M0 0" />');
    assert.equal(innerMarkup(svg).includes("<svg"), false);
    assert.equal(innerMarkup(svg).includes("@license"), false);
    assert.throws(() => innerMarkup("<path d=\"M0 0\" />"), /감싸여/);
  });
});

describe("the meaning-to-icon map", () => {
  it("names only icons that exist", () => {
    for (const [meaning, name] of Object.entries(GLYPH)) {
      assert.ok(ICON_NAMES.includes(name as IconName), `${meaning} names ${name}, which is not drawn`);
    }
  });

  it("gives the four verdicts a reader must tell apart four different shapes", () => {
    // 시안 A9 — 「모양이 뜻이다」. These four sit in the same column on the fleet screen and are the
    // set that decides whether somebody is woken up: confirmed, broken, a contradiction the manager
    // is sure of, and one it is not. Sharing a shape between any two of them makes the column say
    // less than the data does.
    const four = [GLYPH.confirmed, GLYPH.broken, GLYPH.certain, GLYPH.unexplained];
    assert.equal(new Set(four).size, 4, `two verdicts share a shape: ${four.join(", ")}`);
  });

  it("keeps the one action that changes the fleet apart from the one that warns", () => {
    // 시안 draws both as triangles — `△` for stale, `▲` for publish. That collision is exactly why
    // publish became `upload` here: a warning and 「함대를 바꾼다」 must not be the same outline.
    assert.notEqual(GLYPH.publish, GLYPH.warn);
  });
});

describe("what the pages actually emit", () => {
  it("resolves every icon reference against a symbol in the same document", () => {
    // The failure this file exists for. A reference to a symbol that is not there renders **nothing**
    // — no error, no fallback, an empty cell where a verdict should be.
    //
    // Both halves are counted. The policy screen writes its `<use>` elements out; the console builds
    // its tables in the browser, so its references exist only as the names in `G` — and a name in `G`
    // with no symbol behind it is the same dangling reference, discovered ten seconds later in front
    // of an operator instead of here.
    for (const [name, html] of pages()) {
      const written = [...html.matchAll(/href="#i-([a-z0-9-]+)"/g)].map((m) => m[1]!);
      const runtime = Object.values(
        JSON.parse(/\nconst G = (\{[\s\S]*?\});\n/.exec(html)?.[1] ?? "{}") as Record<string, string>,
      );
      const used = new Set([...written, ...runtime]);
      const defined = new Set([...html.matchAll(/<symbol id="i-([a-z0-9-]+)"/g)].map((m) => m[1]!));
      assert.ok(used.size > 0, `${name} draws no icons at all`);
      for (const u of used) assert.ok(defined.has(u), `${name} points at #i-${u}, which nothing defines`);
    }
  });

  // ## The glyph-map test went with the page it tested
  //
  // It read the classic console's inline `const G = {…}` back out of the HTML and compared it with
  // the server's `GLYPH`, guarding against two hand-kept copies of one mapping. That script does not
  // exist any more: the Svelte console draws its own icons and carries no such map, so there is no
  // second copy for them to drift apart into. The concern is retired, not unhandled.

  it("carries the sprite before anything that uses it", () => {
    for (const [name, html] of pages()) {
      const sprite = html.indexOf("<symbol id=");
      const firstUse = html.indexOf('><use href="#i-');
      assert.ok(sprite !== -1, `${name} carries no sprite`);
      if (firstUse !== -1) assert.ok(sprite < firstUse, `${name} references a symbol before defining it`);
    }
  });

  it("marks icons as decoration, because the word beside them carries the meaning", () => {
    // 시안 J1: 「뱃지는 **기호 + 낱말**」. The word is what a screen reader should say; an icon that
    // announced "triangle" beside it would say the shape twice and the fact never.
    assert.equal(icon("check"), '<svg class="i" aria-hidden="true" focusable="false"><use href="#i-check"></use></svg>');
    for (const [name, html] of pages()) {
      // `.sprite` is the definitions block and is already `aria-hidden`; `.i` are the drawn ones.
      const svgs = html.match(/<svg class="i(?![a-z])[^"]*"[^>]*>/g) ?? [];
      for (const s of svgs) assert.match(s, /aria-hidden="true"/, `${name}: ${s}`);
    }
    assert.match(iconSprite(), /^<svg class="sprite" aria-hidden="true"/);
  });

  // The client/server parity test went with `CLIENT_ICON_JS`. `icon()` existed twice because the
  // classic console built its tables in an inline script; there is one copy now, so there is nothing
  // for the two to disagree about.

  it("defines a symbol for every declared name, not only the ones a fixture happened to draw", () => {
    // The reason changed when the client script went, and the check did not. It used to be that the
    // browser picked from `G` at render time, so the page could not know in advance which it needed.
    // Now it is simpler and still worth asserting: `ICON_NAMES` is the declared set, a `<use>` for a
    // name with no `<symbol>` renders as **nothing**, and a fixture that draws four rows exercises
    // four icons. A sprite missing the fifth is a blank cell nobody sees until that row appears.
    const sprite = iconSprite();
    for (const n of ICON_NAMES) assert.ok(sprite.includes(`<symbol id="i-${n}"`), `${n} is not in the sprite`);
  });
});

describe("the dingbats are gone", () => {
  // 시안 is drawn in `✓ ✕ ! ? → ◇ △ ▲ ■ □ ⧉ ＋`. They read correctly on a design canvas and badly in
  // a console served to a Linux operator mid-incident, where the ones outside the core fonts render
  // as an empty box — in the `state` column, indistinguishable from a state this console cannot name.
  //
  // Checked against the **rendered pages**, not the sources: a source scan would trip over this very
  // comment, and would say nothing about what reaches a browser.
  const DINGBATS = /[✓✔✕✖✗✘■□▲△▼▽◆◇●○⚠➕＋⧉✅❌⛔\u{1F534}\u{1F7E0}\u{1F7E1}\u{1F7E2}]/u;

  it("finds them when they are there", () => {
    // The known positive. Without it this suite is satisfied by a regular expression that matches
    // nothing, which is the shape a grep-based check fails in.
    for (const d of ["✓ confirmed", "✕ drifted", "△ stale", "▲ publish", "■ deny", "□ allow", "◇ disabled", "⧉ 개입", "＋ 추가"]) {
      assert.match(d, DINGBATS, `the scanner does not see ${d}`);
    }
  });

  it("finds none in what either page sends", () => {
    for (const [name, html] of pages()) {
      const hit = DINGBATS.exec(html);
      assert.equal(hit, null, `${name} still ships ${hit?.[0]} near: ${html.slice(Math.max(0, (hit?.index ?? 0) - 90), (hit?.index ?? 0) + 90)}`);
    }
  });
});

describe("self-contained, which is the reason the icons are inlined at all", () => {
  it("fetches nothing at load time", () => {
    // 「No CDN, no external font, no remote anything」 — `manager-ui.ts` says why: this is the page
    // that has to work when the network is the thing that is broken. An icon library loaded from a
    // CDN would have made a third party an author of what an operator believes about their network.
    for (const [name, html] of pages()) {
      const remote = /(?:src|href)\s*=\s*"https?:\/\//i.exec(html);
      assert.equal(remote, null, `${name} loads ${remote?.[0]} from off-host`);
      assert.equal(/@import\s+url\(/i.test(html), false, `${name} imports a remote stylesheet`);
    }
  });
});
