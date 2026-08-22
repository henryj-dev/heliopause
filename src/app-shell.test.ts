// 껍데기 — 두 문서가 **같은** 상단·사이드를 쓰는지.
//
// ## 이 파일이 잡는 실패
//
// 이 변경을 만드는 동안 실제로 두 번 났다:
//
//   1. 정책 화면이 `SHELL_CSS` 없이 껍데기 마크업만 냈다. 예외는 없고 200 이 나가고, 상단 바가
//      그냥 **본문 흐름의 글자 몇 줄**로 렌더됐다. 스타일이 없는 클래스는 오류가 아니다.
//   2. 콘솔의 `main { max-width }` 가 껍데기의 `<main class="app-main">` 에 걸려, 크롬은 화면
//      전체를 쓰고 내용만 가운데로 좁아졌다. 셀렉터는 유효했고 대상이 바뀐 것이다.
//
// 둘 다 「아래 계층이 전부 옳아 보인다」는 이 저장소의 반복 형태이고, 렌더 결과를 읽는 검사만이
// 본다. 그래서 여기 있는 검사는 전부 **두 페이지가 실제로 낸 HTML** 을 읽는다.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { CONSOLE_ROUTES, appShell, consoleAppPath, consoleNav, policyAppPath, sideNav, workstationAppPath } from "./app-shell.ts";
import { policyPage } from "./policy-ui.ts";
import type { PolicyRow } from "./policy-view.ts";
import { t } from "./i18n.ts";

const row = (over: Partial<PolicyRow> = {}): PolicyRow => ({
  id: "DEV-SSH", name: "ssh from mgmt", action: "allow", denyMode: "drop",
  proto: "tcp", ports: "22", priority: 100, enabled: true, notes: null,
  hosts: ["gw-01.dev"], skippedOn: [], egressHosts: [], srcCidrs: ["10.254.0.0/16"],
  placementKnown: true, risks: [], ...over,
});

/**
 * The document that still renders this shell server-side.
 *
 * The classic console was the other and has been removed; `/app` is the product screen and builds
 * its shell in Svelte, with `packages/web/src/lib/shell/parity.test.ts` asserting that it paints the
 * same token and CSS system this file exports.
 */
const pages = (): Array<[string, string]> => [
  ["policy", policyPage([row()], {
    site: "policy/dev.ts", generation: "abc1234", hosts: ["gw-01.dev"],
    nav: consoleNav("en", "policy"),
  })],
];

const styleOf = (html: string) => /<style>([\s\S]*?)<\/style>/.exec(html)?.[1] ?? "";

describe("both documents carry the same shell", () => {
  it("draws the bar, the side and the content region on each", () => {
    for (const [name, html] of pages()) {
      for (const bit of ['<div class="app-edge"', '<div class="app"', '<header class="topbar">',
                         '<nav class="sidenav"', '<main class="main">', '<div class="content">',
                         '<div class="page">']) {
        assert.ok(html.includes(bit), `${name} has no ${bit}`);
      }
      // One shell, not two. A page that wrapped itself twice would satisfy every `includes` above.
      assert.equal((html.match(/<header class="topbar">/g) ?? []).length, 1, `${name} has two bars`);
    }
  });

  it("styles every class the shell emits", () => {
    // **The defect this test was written for.** The policy page shipped the shell's markup with none
    // of its rules for one commit: the bar rendered as three lines of body text, nothing threw, and
    // the page returned 200. An unstyled class is not an error in CSS — it is silence.
    const classes = ["app-edge", "app", "topbar", "brand", "sep", "crumb", "spacer", "status",
                     "sidenav", "group", "main", "content", "page", "foot", "langs"];
    for (const [name, html] of pages()) {
      const css = styleOf(html);
      assert.ok(css.length > 0, `${name} carries no stylesheet`);
      for (const c of classes) {
        assert.match(css, new RegExp(`\\.${c}\\b`), `${name} emits .${c} and styles nothing by that name`);
      }
    }
  });

  it("fills the viewport instead of floating in it, and bounds the content instead of the frame", () => {
    // ## The two defects this pins, both of which shipped once
    //
    // 1. The frame was a **bordered, rounded box inside `body` padding**. That is the artboard's
    //    edge from `Tiny Universe Screens.dc.html`, where seven screens share one canvas page and
    //    need a line between them. It is not chrome. stardust — the running implementation of the
    //    same mockup — has neither, and sizes the frame to the viewport.
    // 2. `max-width` was on the **frame**, so the chrome used the whole window and the table was a
    //    narrow column inside it. stardust caps `.page`, which is the content.
    //
    // Neither threw, neither failed a test, and both look deliberate in a screenshot.
    for (const [name, html] of pages()) {
      const css = styleOf(html);
      const app = /\.app\s*\{([^}]*)\}/.exec(css)?.[1] ?? "";
      assert.ok(app, `${name} has no .app rule`);
      assert.match(app, /height:\s*calc\(100vh - 2px\)/, `${name}: the frame is not the viewport`);
      assert.match(app, /overflow:\s*hidden/, `${name}: the frame does not own its scrolling`);
      assert.equal(/border(?!-)/.test(app), false, `${name}: the frame still has the artboard's edge`);
      assert.equal(/max-width/.test(app), false, `${name}: the frame is capped, not the content`);
      assert.match(css, /\.page\s*\{[^}]*max-width/, `${name}: the content is not capped`);
      // The page itself must not scroll — that is what takes the bar and the nav off screen.
      assert.equal(/\bbody\s*\{[^}]*padding:\s*[1-9]/.test(css), false,
        `${name}: body padding puts the shell on a mat`);
      assert.match(css, /\.content\s*\{[^}]*overflow:\s*auto/, `${name}: nothing scrolls`);
    }
  });

  it("keeps the ink edge outside the frame, which is where the 2px comes from", () => {
    // `height: calc(100vh - 2px)` is only correct if the rule is a sibling. Inside, the two together
    // are 2px taller than the window and the page grows a scrollbar that scrolls nothing.
    for (const [name, html] of pages()) {
      const edge = html.indexOf('<div class="app-edge"');
      const frame = html.indexOf('<div class="app"');
      assert.ok(edge !== -1 && frame !== -1, `${name} is missing the edge or the frame`);
      assert.ok(edge < frame, `${name} draws the edge inside the frame`);
      assert.match(styleOf(html), /\.app-edge\s*\{[^}]*height:\s*2px/, name);
    }
  });

  it("spans the bar across both columns, so one line says where you are", () => {
    // The bar sits above the side, not beside it. With the brand in the sidebar head and the path in
    // the bar, two places split one fact — which is the arrangement stardust moved away from.
    for (const [name, html] of pages()) {
      assert.match(styleOf(html), /\.app\s*>\s*\.topbar\s*\{[^}]*grid-column:\s*1\s*\/\s*-1/, name);
    }
  });

  it("takes its bar from appShell rather than building one of its own", () => {
    // `NAV_CSS` was written because a menu that differs between screens tells the operator they have
    // left the product. Sharing a constant did not make the *markup* the same; sharing `appShell`
    // does, and this is the assertion that says so.
    //
    // It used to compare the two served documents against each other. One of them — the classic
    // console — is gone, so the comparison is now against `appShell`'s own output: a policy page
    // that stopped calling it, or an `appShell` that changed shape underneath it, still fails here.
    const bar = (h: string) => /<header class="topbar">[\s\S]*?<\/header>/.exec(h)?.[0] ?? "";
    const shape = (h: string) =>
      [...bar(h).replace(/^<header[^>]*>/, "").matchAll(/class="([a-z-]+)"/g)].map((m) => m[1]!);
    const [, policyHtml] = pages()[0]!;
    const direct = appShell({ crumbs: ["policy"], groups: [], main: "" });
    assert.deepEqual(shape(direct).slice(0, 4), ["brand", "sep", "crumb", "spacer"]);
    assert.deepEqual(shape(policyHtml).slice(0, 4), shape(direct).slice(0, 4));
  });
});

describe("the side nav", () => {
  it("groups the console's screens and marks the one you are on", () => {
    const groups = consoleNav("en", "changes");
    assert.deepEqual(groups.map((g) => g.label), ["fleet", "evidence", "policy"]);
    const on = groups.flatMap((g) => g.items).filter((i) => i.on);
    assert.equal(on.length, 1);
    assert.equal(on[0]!.href, "/changes");
  });

  it("carries every route, so a screen cannot fall out of the menu by being forgotten", () => {
    const hrefs = consoleNav("en", "fleet").flatMap((g) => g.items).map((i) => i.href);
    assert.deepEqual(hrefs.sort(), CONSOLE_ROUTES.map((r) => r.path).sort());
  });

  it("maps the old ?s= query onto /app/policy and refuses a free-form path", () => {
    assert.equal(policyAppPath(null), "/app/policy");
    assert.equal(policyAppPath("files"), "/app/policy/files");
    assert.equal(policyAppPath("all"), "/app/policy/all");
    assert.equal(policyAppPath("../secret"), "/app/policy");
    assert.equal(policyAppPath("/fleet"), "/app/policy");
  });

  it("sends the workstation home to every policy section, not to the fleet", () => {
    assert.equal(workstationAppPath("/", null), "/app/policy/all");
    assert.equal(workstationAppPath("/", "files"), "/app/policy/files");
    assert.equal(workstationAppPath("/policy", null), "/app/policy");
    assert.equal(workstationAppPath("/policy", "zones"), "/app/policy/zones");
    assert.equal(workstationAppPath("/fleet", null), "/app/fleet");
    assert.equal(workstationAppPath("/enrollment/tokens", null), null);
  });

  it("maps each SPA screen onto /app and leaves data paths alone", () => {
    assert.equal(consoleAppPath("/fleet"), "/app/fleet");
    assert.equal(consoleAppPath("/changes"), "/app/changes");
    assert.equal(consoleAppPath("/enrollment"), "/app/enrollment");
    assert.equal(consoleAppPath("/lookup"), "/app/lookup");
    assert.equal(consoleAppPath("/traffic"), "/app/traffic");
    assert.equal(consoleAppPath("/routing"), "/app/routing");
    // `/policy` has its own mapper — `?s=` is a slug, not a screen key.
    assert.equal(consoleAppPath("/policy"), null);
    assert.equal(consoleAppPath("/enrollment/tokens"), null);
    assert.equal(consoleAppPath("/workload-traffic"), null);
    assert.equal(consoleAppPath("/api/fleet"), null);
    assert.equal(consoleAppPath("/"), null);
  });

  it("routes the console's own screens client-side and the policy screen not at all", () => {
    // The product is `/app/policy`. Classic `consoleNav` still lists `/policy` with `spa: false`
    // so that router does not swap the fallback view empty.
    const items = consoleNav("en", "fleet").flatMap((g) => g.items);
    assert.equal(items.find((i) => i.href === "/fleet")?.spa, "fleet");
    assert.equal(items.find((i) => i.href === "/policy")?.spa, undefined);
  });

  it("drops a group with nothing in it, rather than drawing an empty heading", () => {
    // 시안: 「관리 항목이 목록에 없다(비활성이 아니라 부재)」 — the permission rule, in markup. An
    // empty heading is exactly the disabled-looking remnant that rule exists to prevent, and it is
    // what a workstation render of the policy page would show for the console's routes.
    const html = sideNav([
      { label: "kept", items: [{ href: "/a", label: "a" }] },
      { label: "empty", items: [] },
    ]);
    assert.match(html, /kept/);
    assert.equal(html.includes("empty"), false, html);
  });

  it("draws a count only when it was given one", () => {
    // A `0` is a claim — counted, none. An absent count is a different fact and must not become one.
    const html = sideNav([{ label: "g", items: [
      { href: "/a", label: "counted", count: 0 },
      { href: "/b", label: "uncounted" },
    ] }]);
    assert.match(html, /counted<span class="n">0<\/span>/);
    assert.match(html, /uncounted<\/a>/);
  });

  it("escapes what it is handed", () => {
    const html = sideNav([{ label: '<img src=x>', items: [{ href: '"><img src=x>', label: "x" }] }]);
    assert.equal(html.includes("<img"), false, html);
  });
});

describe("the breadcrumb", () => {
  it("says where you are, with only the last step solid", () => {
    const html = appShell({ crumbs: ["policy", "zones"], groups: [], main: "" });
    assert.match(html, /<span class="crumb">policy \/ <b>zones<\/b><\/span>/);
  });

  it("names the screen it was asked for, not the one it defaults to", () => {
    // A bar that keeps saying `fleet` while the reader is on `changes` is a stale table in the one
    // element whose job is saying where you are.
    //
    // Asserted against `appShell` itself rather than through a page that calls it. It used to go
    // through the classic console, so removing that page would have taken the check with it — and
    // the property belongs to this function, not to any one of its callers.
    for (const key of ["changes", "lookup", "routing"]) {
      const route = CONSOLE_ROUTES.find((r) => r.key === key)!;
      const label = t("en", route.label as Parameters<typeof t>[1]);
      const html = appShell({ crumbs: [label], groups: [], main: "" });
      const bar = /<header class="topbar">[\s\S]*?<\/header>/.exec(html)?.[0] ?? "";
      assert.match(bar, new RegExp(`<b>${label}</b>`), key);
    }
  });
});
