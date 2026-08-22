// 상단 바 + 왼쪽 사이드 — 두 문서가 함께 쓰는 껍데기.
//
// 시안 `Tiny Universe Screens.dc.html` 의 일곱 화면이 전부 같은 틀을 쓴다: 2px 잉크 선, 42px
// 상단 바(상호 · 구분선 · 빵부스러기 · 여백 · 상태 · 신원), 그리고 184px 사이드. 화면마다
// 달라지는 것은 **사이드에 무엇이 들어가는가**와 본문뿐이다.
//
// ## 왜 상수 두 개가 아니라 함수 하나인가
//
// 이 저장소는 이미 한 번 그 답을 적어 뒀다 — `NAV_CSS` 의 주석이 「메뉴가 두 화면 사이에서
// 갈라지면 운영자에게 제품을 떠났다고 말한다」이다. 그건 **CSS** 를 공유해서 지킬 수 있는
// 성질이 아니다. 콘솔과 정책 화면은 서로 다른 프로세스가 그리는 별개의 문서이고, 같은 클래스
// 이름 위에 서로 다른 마크업을 얹으면 규칙만 같고 모양은 다른 상태가 된다. 그래서 여기서는
// **마크업까지** 한 함수가 낸다.
//
// ## 사이드에 들어가는 것이 화면마다 다른 것은 의도다
//
//   · 콘솔  → 화면 일곱 개, 묶음 셋 (`consoleNav`)
//   · 정책  → 섹션 열일곱 개와 각각의 건수 (시안 G1). 정책 화면에서 첫 질문은
//             「무엇이 비어 있지 않은가」이고, 그 답은 건수가 붙은 목록이지 화면 이름이 아니다.
//
// 둘 다 같은 `<nav class="sidenav">` 를 쓰므로 폭·여백·활성 표시는 갈라질 수 없다.
//
// ## 권한 — 없는 항목은 **사라진다**
//
// 시안이 이 화면들에서 못 박은 규칙이고(「viewer 권한에서는 위험 버튼이 비활성이 아니라
// 사라진다 … 관리 항목이 목록에 없다(비활성이 아니라 부재)」), 이 콘솔이 이미 지키던 규칙이기도
// 하다. 그래서 사이드는 넘겨받은 항목만 그린다 — 비활성 항목이라는 상태가 없다.
import { LANGS, LANG_NAME, t, type Lang } from "./i18n.ts";

/**
 * The screens, in the order the menu shows them, and the group each sits in.
 *
 * **Named for what the operator does there, not for the resource behind it.** `/changes` reads the
 * `/plans` API and could have been called `/plans` to match, except that `/plans` is already that
 * API — the CLI calls it — so a screen of the same name would have to be told apart from the data by
 * `Accept`, and this console has one Accept-shaped decision already (authentication) that is quite
 * enough.
 *
 * `/policy` is the exception for the classic HTML menu only. The product screen is `/app/policy`.
 * `spa: false` keeps `consoleNav` from client-routing the fallback `/policy` href — that swap
 * would empty the page. The manager GET 302s through `policyAppPath`. `policyPage` is what
 * `heliopause-ui` draws when `packages/web/build` is missing.
 *
 * It is also the one screen whose name matches its API.
 *
 * ## The groups
 *
 * 시안 uses two (`RUN` · `INFRA`) and the labels are the load-bearing part: they say what question
 * the screens under them answer, so an operator who arrives with a question can find the row without
 * reading seven names. Ours are the three questions this console exists for — what is the fleet
 * doing, what does the evidence say, and what do the rules say — which is also the order an incident
 * moves through them.
 */
export const CONSOLE_ROUTES = [
  { path: "/fleet", key: "fleet", label: "nav.fleet", group: "g.fleet", spa: true },
  { path: "/changes", key: "changes", label: "nav.changes", group: "g.fleet", spa: true },
  { path: "/enrollment", key: "enrollment", label: "nav.enrollment", group: "g.fleet", spa: true },
  { path: "/lookup", key: "lookup", label: "nav.lookup", group: "g.evidence", spa: true },
  { path: "/traffic", key: "traffic", label: "nav.traffic", group: "g.evidence", spa: true },
  { path: "/routing", key: "routing", label: "nav.routing", group: "g.evidence", spa: true },
  { path: "/policy", key: "policy", label: "nav.policy", group: "g.policy", spa: false },
] as const;

/** The classic HTML fleet. `/fleet` keeps this meaning; `/` no longer points here. */
export const CONSOLE_HOME = "/fleet";

/**
 * Where `/` (and the retired `/ui` alias) send a browser.
 *
 * The Svelte console is the product. Classic HTML paths 302 here so a bookmark
 * still names the screen; `/policy` has its own mapper because of `?s=`.
 */
export const CONSOLE_ENTRY = "/app";

/**
 * Where a classic HTML screen GET sends a browser. Exact SPA paths only —
 * `/enrollment/tokens` is the token list, not this screen.
 */
export function consoleAppPath(pathname: string): string | null {
  const route = CONSOLE_ROUTES.find((r) => r.spa && r.path === pathname);
  return route ? `${CONSOLE_ENTRY}${route.path}` : null;
}

/**
 * Where GET `/policy` sends a browser. `?s=files` becomes `/app/policy/files`.
 *
 * Only a slug. `s` used to be a query the HTML page read; a free-form value here
 * would be an open redirect into `/app/policy/…`.
 */
export function policyAppPath(section: string | null): string {
  if (section === "all") return "/app/policy/all";
  if (section && /^[a-z0-9-]+$/.test(section)) return `/app/policy/${section}`;
  return "/app/policy";
}

/**
 * Where a workstation browser goes when the Svelte console is present.
 *
 * `/` used to render every policy section. That is `/app/policy/all`, not
 * `/app` (fleet) and not `/app/policy` (first section). Data stems stay put.
 */
export function workstationAppPath(pathname: string, section: string | null): string | null {
  if (pathname === "/" || pathname === "/policy") {
    return pathname === "/" && !section ? policyAppPath("all") : policyAppPath(section);
  }
  return consoleAppPath(pathname);
}

/** One row in the side nav. `count` is drawn right-aligned; `undefined` draws nothing at all. */
export interface NavItem {
  href: string;
  label: string;
  /** Right-aligned figure. Omit rather than passing 0 — a 0 says "counted, none", which is a claim. */
  count?: number | string;
  on?: boolean;
  /** `data-spa` value, for the routes the console's own router handles without a page load. */
  spa?: string;
}

/** A labelled block of rows. The label is uppercase mono, per 시안. */
export interface NavGroup {
  label: string;
  items: readonly NavItem[];
}

const esc = (s: unknown): string =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/**
 * The shell's stylesheet.
 *
 * Every value here is a token. The two that are not obviously so — the 42px bar and the 184px column
 * — are 시안's own figures and are deliberately *not* density-driven: the chrome must not move when
 * the table under it gets denser, or the whole page appears to resize when only the rows did.
 */
export const SHELL_CSS = `/* ── the shell ─────────────────────────────────────────────────────────────────
   **stardust 가 도는 모양 그대로다** (\`dashboard/src/app.css\`). 시안 캔버스가 아니라 앱을
   베낀 것이고, 그 둘은 한 곳에서 크게 갈린다.

   시안 파일에서 각 화면은 \`width:1280px; border:1px solid var(--bd-2)\` 로 그려져 있다. 그건
   **아트보드의 가장자리**다 — 한 캔버스 위에 화면 일곱 개가 나란히 있으니 서로를 구분할 선이
   필요했던 것이지, 제품의 크롬이 아니다. 이 파일의 첫 판이 그 선과 라운드를 그대로 앱에 옮겼고,
   \`body\` 패딩과 합쳐져 **문서 위에 떠 있는 카드**가 됐다. 앱은 카드가 아니다.

   그래서 프레임은 뷰포트를 채운다: \`height: calc(100vh - 2px)\` · \`overflow: hidden\` · 테두리
   없음 · 라운드 없음. 2px 잉크선은 \`.app\` **바깥**의 형제이고, \`100vh\` 에서 빼는 2px 이 그것이다.

   ## 스크롤하는 것은 본문뿐이다
   이게 값을 치르는 자리다. 페이지 전체가 스크롤되면 \`/fleet\` 에서 표가 길어질 때 「읽음 3초 전 ·
   실패 0회」와 화면 목록이 위로 사라진다 — 그 바가 존재하는 이유의 정반대다. \`.app\` 이
   \`overflow:hidden\` 이고 \`.content\` 만 \`overflow:auto\` 이므로 바와 사이드는 제자리에 있는다. */
.app-edge { height: 2px; background: var(--n-11); }
.app {
  display: grid;
  grid-template-columns: var(--sb-expanded) minmax(0, 1fr);
  grid-template-rows: var(--topbar-h) minmax(0, 1fr);
  height: calc(100vh - 2px);
  overflow: hidden;
  background: var(--surface-base);
}
/* 탑바는 사이드바 **위로** 전체 폭을 지난다. 브랜드가 사이드 머리에 있고 경로가 바에 있으면
   같은 「지금 어디」를 두 군데가 나눠 말하게 된다 — stardust 가 옮긴 이유가 그것이다. */
.app > .topbar { grid-column: 1 / -1; }

.topbar { display: flex; align-items: center; gap: 12px; padding: 0 14px; min-width: 0;
          background: var(--surface-card); border-bottom: 1px solid var(--bd-1);
          font-family: var(--font-mono); font-size: 12px; }
.topbar .brand { font-size: 13px; font-weight: 600; letter-spacing: -.01em; color: var(--text-1); flex: none; }
.topbar .sep { width: 1px; height: 16px; background: var(--bd-1); flex: none; }
/* 한 줄로 고정된 띠라 넘치는 것은 줄바꿈이 아니라 말줄임이어야 한다 — 42px 안에서 줄바꿈하면
   두 번째 줄이 잘린다. 경로와 상태만 줄어들고 상호·언어는 안 줄어든다. */
.topbar .crumb { color: var(--text-3); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.topbar .crumb b { color: var(--text-1); font-weight: 600; }
.topbar .spacer { flex: 1 1 auto; }
.topbar .status { display: inline-flex; align-items: center; gap: 8px; min-width: 0;
                  overflow: hidden; white-space: nowrap; font-size: 11.5px; color: var(--text-2); }
.topbar .who { font-size: 11.5px; color: var(--text-2); white-space: nowrap; flex: none; }
/* One segmented control, so the two languages read as one choice rather than two destinations. */
.topbar .langs { display: flex; align-items: stretch; flex: none; border: 1px solid var(--bd-2);
                 border-radius: var(--r-md); overflow: hidden; }
.topbar .langs span, .topbar .langs a { font-size: 11px; padding: 3px 8px; color: var(--text-3);
                                        text-decoration: none; }
.topbar .langs a { border-left: 1px solid var(--bd-1); }
.topbar .langs a:first-child { border-left: 0; }
.topbar .langs span.on { background: var(--n-2); color: var(--text-1); }

/* 사이드는 카드 표면이다 — 본문보다 한 단 위. 같은 base 면 경계가 선 하나뿐이 된다. */
.sidenav { display: flex; flex-direction: column; overflow: auto; padding: 12px 0;
           background: var(--surface-card); border-right: 1px solid var(--bd-1); }
.sidenav .group { font-family: var(--font-mono); font-size: 10px; letter-spacing: .16em;
                  text-transform: uppercase; color: var(--text-off); padding: 14px 14px 6px; }
.sidenav .group:first-child { padding-top: 0; }
/* 항목은 모서리를 안 깎는다 — 목록의 행이지 카드가 아니다. 좌측 2px 은 활성 행에서만 잉크가
   되고 나머지는 투명이라, 표시가 나타났다 사라져도 글자가 밀리지 않는다.
   **잉크(\`--n-11\`)이지 액센트가 아니다.** 액센트는 「지금 바뀐 것·고를 수 있는 것」의 색이고
   「여기 있다」는 그 부류가 아니다. */
.sidenav a { display: flex; align-items: baseline; gap: 8px; font-size: 12.5px; padding: 4px 14px;
             color: var(--text-2); text-decoration: none; border-left: 2px solid transparent; }
.sidenav a:hover { color: var(--text-1); background: var(--surface-sunken); }
.sidenav a.on { color: var(--text-1); border-left-color: var(--n-11);
                background: var(--surface-sunken); font-weight: 500; }
.sidenav .n { margin-left: auto; font-family: var(--font-mono); font-variant-numeric: tabular-nums;
              font-size: 11px; color: var(--text-3); }
.sidenav a.on .n { color: var(--text-2); }
.sidenav .foot { margin: 14px 14px 0; padding-top: 10px; border-top: 1px solid var(--bd-1);
                 font-size: 11.5px; color: var(--text-off); line-height: 1.6; }

/* \`.main\` 은 격자 칸이고 \`.content\` 가 스크롤러다. 둘로 나뉜 이유는 \`min-height:0\` 없이는
   격자 칸이 내용만큼 커져 버려 안쪽 스크롤이 생기지 않기 때문이다. */
.main { display: grid; min-width: 0; min-height: 0; overflow: hidden; }
.content { overflow: auto; background: var(--surface-base); min-width: 0; }
/* 폭을 제한하는 것은 **본문**이지 프레임이 아니다. 첫 판이 반대로 했고, 그러면 크롬은 화면
   전체를 쓰는데 표만 가운데로 좁아진다. */
.page { max-width: 1400px; margin: 0 auto; padding: 24px 28px 60px; }

/* ## 좁은 폭 — stardust 와 갈리는 유일한 곳, 그리고 그 이유
   stardust 는 900px 아래에서 사이드를 탑바 아래 고정 드로어로 바꾸고 햄버거로 연다. 여기서는
   못 한다: **정책 화면은 스크립트를 한 줄도 싣지 않는다**(\`policy-ui.test.ts\` 의 「carries no
   script at all」이 그걸 고정한다 — 그게 그 페이지가 nonce 없이 안전한 이유다). 드로어에는 토글이
   필요하고 토글에는 스크립트가 필요하다.
   그래서 CSS 만으로 되는 쪽을 쓴다: 사이드가 본문 **위 한 줄**이 된다. 감추지 않는 편을 고른
   것이기도 하다 — 사고 중에 읽는 페이지에서 화면 목록을 제스처 뒤에 두지 않는다. */
@media (max-width: 900px) {
  .app { grid-template-columns: minmax(0, 1fr);
         grid-template-rows: var(--topbar-h) auto minmax(0, 1fr); }
  .sidenav { flex-direction: row; align-items: center; gap: 2px; padding: 8px 10px;
             overflow-x: auto; border-right: 0; border-bottom: 1px solid var(--bd-1); }
  .sidenav .group { padding: 0 6px; white-space: nowrap; }
  .sidenav a { border-left: 0; border-bottom: 2px solid transparent; padding: 3px 8px; white-space: nowrap; }
  .sidenav a.on { border-left-color: transparent; border-bottom-color: var(--n-11); }
  .sidenav .n { margin-left: 5px; }
  .sidenav .foot { display: none; }
  .page { padding: 12px; }
}`;

/** One side-nav row. */
function navLink(i: NavItem): string {
  return `<a href="${esc(i.href)}"${i.on ? ' class="on" aria-current="page"' : ""}` +
    `${i.spa ? ` data-spa="${esc(i.spa)}"` : ""}>${esc(i.label)}` +
    `${i.count === undefined ? "" : `<span class="n">${esc(i.count)}</span>`}</a>`;
}

/**
 * The side.
 *
 * A group whose items are all absent is not drawn at all. That is the permission rule stated in
 * markup: 시안 says 「관리 항목이 목록에 없다(비활성이 아니라 부재)」, and an empty group heading
 * would be exactly the disabled-looking remnant that rule exists to prevent.
 */
export function sideNav(groups: readonly NavGroup[], foot?: string): string {
  const body = groups
    .filter((g) => g.items.length > 0)
    .map((g) => `<div class="group">${esc(g.label)}</div>${g.items.map(navLink).join("")}`)
    .join("");
  return `<nav class="sidenav" aria-label="sections">${body}` +
    `${foot ? `<div class="foot">${foot}</div>` : ""}</nav>`;
}

/** The console's seven screens, grouped, with the current one marked. */
export function consoleNav(lang: Lang, active: string): readonly NavGroup[] {
  const groups: NavGroup[] = [];
  for (const r of CONSOLE_ROUTES) {
    const label = t(lang, r.group as Parameters<typeof t>[1]);
    let g = groups.find((x) => x.label === label);
    if (!g) groups.push((g = { label, items: [] }));
    (g.items as NavItem[]).push({
      href: r.path,
      label: t(lang, r.label as Parameters<typeof t>[1]),
      on: r.key === active,
      ...(r.spa ? { spa: r.key } : {}),
    });
  }
  return groups;
}

/** The language switch, carrying the screen you are on so switching does not also send you home. */
export function langSwitch(lang: Lang, href: (l: Lang) => string): string {
  return `<span class="langs">` + LANGS.map((l) => (l === lang
    ? `<span class="on" aria-current="true">${esc(LANG_NAME[l])}</span>`
    : `<a href="${esc(href(l))}" rel="nofollow">${esc(LANG_NAME[l])}</a>`)).join("") + `</span>`;
}

export interface ShellOptions {
  /** Steps from the product root. The last is where you are and is drawn as the only solid one. */
  crumbs: readonly string[];
  /** Groups for the side. Pass `[]` for a screen with no side — the grid collapses to one column. */
  groups: readonly NavGroup[];
  /** The sentence under the side nav. Already-escaped markup, because it carries counts and links. */
  navFoot?: string;
  /** Right-hand end of the top bar, before the identity. Already-escaped markup. */
  status?: string;
  /** `id` for the status slot, so the console's poll can refill it without re-rendering the bar. */
  statusId?: string;
  /** Who you are and what that lets you do. Already-escaped markup. */
  who?: string;
  whoId?: string;
  langs?: string;
  /** The page. Already-escaped markup. */
  main: string;
}

/**
 * The whole frame.
 *
 * Everything but `crumbs` is optional, and every optional part is **absent** rather than empty when
 * it is not passed — an empty status slot in the bar reads as "nothing to report", which on this
 * console is a different claim from "not measured".
 */
export function appShell(o: ShellOptions): string {
  const crumbs = o.crumbs.map((c, i) =>
    i === o.crumbs.length - 1 ? `<b>${esc(c)}</b>` : esc(c)).join(" / ");
  const side = o.groups.length > 0 || o.navFoot ? sideNav(o.groups, o.navFoot) : "";
  // The 2px ink rule is a **sibling** of the frame, not a child of it: it is the edge of the tool,
  // drawn before the tool starts, and `.app` subtracts exactly those 2px from the viewport height.
  // The first version had it inside, which is what an artboard does — see SHELL_CSS.
  return `<div class="app-edge" aria-hidden="true"></div>
<div class="app"${side ? "" : ' style="grid-template-columns:minmax(0,1fr)"'}>
<header class="topbar">
  <span class="brand">heliopause</span>
  <span class="sep"></span>
  <span class="crumb">${crumbs}</span>
  <span class="spacer"></span>
  <span class="status"${o.statusId ? ` id="${esc(o.statusId)}"` : ""}>${o.status ?? ""}</span>
  ${o.who !== undefined || o.whoId ? `<span class="who"${o.whoId ? ` id="${esc(o.whoId)}"` : ""}>${o.who ?? ""}</span>` : ""}
  ${o.langs ?? ""}
</header>
${side}
<main class="main"><div class="content"><div class="page">
${o.main}
</div></div></main>
</div>`;
}

/**
 * Chrome that is **not** the shell — what only the server-rendered policy page draws.
 *
 * ## Why it lives here now
 *
 * It was in `manager-ui.ts`, beside the classic console, and both documents imported it: a menu that
 * drifted apart between the two would tell the operator they had left the product. That console has
 * been removed — `/app` is the product screen and draws its own chrome — so the constant outlived
 * the pairing it was written for, and this file is where the shell already lives.
 *
 * `policy-ui.ts` is the one caller. The rules below are the parts that file draws and the shell does
 * not: the plan hash and its copy button, and the diff a second operator reads before approving.
 */
export const NAV_CSS = `/* Chrome that is not the shell. The bar and the side live in
   \`app-shell.ts\`; what is left here is what only these two documents draw.

   The hash and its copy button on one line. The hash stays full width and wraps if it must — an
   approver compares it character by character, so truncating it to fit the button would defeat it. */
.hashrow { display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
.hashrow .mono { word-break: break-all; }
.caveat { margin: .5rem 0 1rem; max-width: 52rem; line-height: 1.6; color: var(--text-2); }
.changes { margin: .4rem 0; }
.changes pre.ruleset { max-height: 22rem; }
/* A patch. Red for what leaves, blue for what arrives — not red/green, because green already means
   "this host is fine" on the fleet screen and a colour that means two things means neither.
   The line background says which side; the mark says which characters. */
pre.patch { line-height: 1.45; }
pre.patch span { display: block; }
pre.patch .hunk { color: var(--text-3); margin-top: .4rem; }
pre.patch .ctx { color: var(--text-2); }
pre.patch .del { background: color-mix(in srgb, var(--danger-fg) 14%, transparent); color: var(--text-1); }
pre.patch .add { background: color-mix(in srgb, var(--accent) 16%, transparent); color: var(--text-1); }
pre.patch mark { background: transparent; color: inherit; font-weight: 700;
                 box-shadow: inset 0 -0.62em 0 color-mix(in srgb, currentColor 22%, transparent); }
pre.patch .del mark { box-shadow: inset 0 -0.62em 0 color-mix(in srgb, var(--danger-fg) 38%, transparent); }
pre.patch .add mark { box-shadow: inset 0 -0.62em 0 color-mix(in srgb, var(--accent) 42%, transparent); }`;
