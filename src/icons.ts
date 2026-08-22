// 아이콘 — 시안의 딩뱃을 아이콘 라이브러리로 옮긴 자리.
//
// ## 왜 스프라이트인가
//
// 이 콘솔의 표는 **브라우저 안에서** 그려진다(`manager-ui.ts` 의 인라인 스크립트). 그러니
// 아이콘 마크업은 클라이언트에도 있어야 하는데, 20 종의 path 를 스크립트에 또 실으면 같은
// 바이트를 두 번 보내는 것이고 두 벌이 갈라질 자리가 생긴다.
//
// 그래서 `<symbol>` 스프라이트를 페이지에 **한 번** 넣고, 서버와 클라이언트가 똑같이
// `<svg class="i"><use href="#i-check"></svg>` 를 쓴다. 같은 정의를 가리키므로 갈라질 수 없다.
//
// `<use>` 는 **같은 문서 안의** 참조다 — 외부 파일을 가져오지 않으므로 「No CDN, no remote
// anything」 규약이 유지되고, CSP 에도 아무것도 추가하지 않는다.
//
// ## 접근성 — 아이콘은 장식이다
//
// 시안의 규칙이 「뱃지는 **기호 + 낱말**」이다(J1). 낱말이 옆에 항상 있으므로 아이콘은
// `aria-hidden` 이다. 아이콘이 혼자 뜻을 지는 자리는 이 콘솔에 없고, 있으면 안 된다 — 색과
// 모양만으로 말하는 칸은 이 저장소가 이미 대가를 치른 형태다.
import { ICON_PATHS } from "./icon-paths.ts";
import { ICON_NAMES, type IconName } from "./icon-names.ts";

export type { IconName };
export { ICON_NAMES };

/**
 * 뜻 → 아이콘 이름. **시안의 딩뱃이 어느 아이콘이 되었는지가 여기 한 곳에 적혀 있다.**
 *
 * 이 사상(寫像)을 상수로 두는 이유는 뜻이 두 화면에서 쓰이기 때문이다 — `state` 칸의 「어긋남」과
 * policy 표의 「renders-nowhere」는 같은 `✕` 를 쓰고, 한쪽만 바꾸면 콘솔이 두 개의 어휘를 갖게
 * 된다. 시안이 A9 에서 「모양이 뜻이다」라고 못 박은 것이 정확히 이것이다.
 *
 * 딩뱃 → 아이콘, 그리고 그 아이콘을 고른 이유:
 *
 * | 시안 | 아이콘 | 왜 |
 * |---|---|---|
 * | `✓` | `check` | 그대로다 |
 * | `✕` | `x` | 그대로다 |
 * | `!` | `octagon-alert` | 삼각형은 `△`(경고)가 이미 쓴다. 팔각형은 「멈춰라」의 모양이고, certain 모순은 사람을 깨우는 값이다 |
 * | `?` | `circle-question-mark` | Lucide 0.544 의 `help-circle` 이 1.x 에서 개명된 이름 |
 * | `→` | `arrow-right` | 그대로다 |
 * | `◇` | `diamond` | 그대로다 |
 * | `⧉` | `shield-alert` | `⧉` 는 어느 폰트에도 없다. 「외부 개입」은 방패에 붙은 경고가 더 정확하기도 하다 |
 * | `△` | `triangle-alert` | 그대로다 |
 * | `▲` | `upload` | `△` 와 같은 삼각형이면 「낡음」과 「함대를 바꾼다」가 같은 모양이 된다. publish 는 세대를 함대로 **올리는** 동작이다 |
 * | `■` | `shield-x` | deny |
 * | `□` | `shield-check` | allow. `■`/`□` 는 채움만 다른 같은 도형이라 색 없이 구분되지 않는다 — 시안 자신의 기준(A9)에 걸린다 |
 * | `●` | `circle-dot` | 저장 안 된 변경 |
 * | `＋` | `plus` | 그대로다 |
 */
export const GLYPH = {
  /** 확인됨 · pass · fresh · ok */
  confirmed: "check",
  /** 어긋남 · fail · renders-nowhere · gone · 못 읽음 */
  broken: "x",
  /** certain 모순 · 단독 승인 — 사람을 깨우는 값 */
  certain: "octagon-alert",
  /** unexplained 모순 · unknown verdict · freshness unknown — 물어볼 수 없었다 */
  unexplained: "circle-question-mark",
  /** 낡음 · any-source · all-ports · 넓지만 틀리진 않은 것 */
  warn: "triangle-alert",
  /** 대기 중 · holding · moved — 멈춘 게 아니라 기다린다 */
  waiting: "arrow-right",
  /** 사람이 선언한 상태 — 점검 중 · disabled · unchecked */
  declared: "diamond",
  /** 외부 개입 — 우리 에이전트가 하지 않은 변경 */
  intrusion: "shield-alert",
  /** allow */
  allow: "shield-check",
  /** deny */
  deny: "shield-x",
  /** 함대를 바꾸는 단 하나의 동작 */
  publish: "upload",
  /** 저장 안 된 변경 */
  unsaved: "circle-dot",
  /** 추가 */
  add: "plus",
  /** 복사 */
  copy: "copy",
  /** 다시 읽기 */
  reread: "refresh-cw",
  /** 질의 */
  query: "search",
  /** 되돌아가기 */
  back: "arrow-left",
  /** 요청이 나가 있다 */
  pending: "loader-circle",
} as const satisfies Record<string, IconName>;

/** SVG 속성이므로 `"` 만 막으면 된다. 이름은 전부 `ICON_NAMES` 에서 오지만, 값이 상수라는 것과 이스케이프가 있다는 것은 다른 사실이다. */
const attr = (s: string): string => s.replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

/**
 * 한 아이콘.
 *
 * 크기는 `1em` 이므로 옆 글자를 따라 커진다 — 뱃지의 11px 과 제목의 20px 에서 같은 규칙이
 * 그린다. 고정 px 로 두면 밀도(`--row-py`)를 바꿀 때마다 아이콘만 안 따라온다.
 */
export function icon(name: IconName, cls = ""): string {
  return `<svg class="i${cls ? " " + attr(cls) : ""}" aria-hidden="true" focusable="false"><use href="#i-${attr(name)}"></use></svg>`;
}

/**
 * 페이지에 한 번 들어가는 정의. `<body>` 의 첫 요소로 두어야 뒤따르는 `<use>` 가 전부 닿는다.
 *
 * `<symbol>` 에 그린 stroke 속성은 자식 `<path>` 들이 상속한다 — 그래서 20 개 path 마다
 * 반복하지 않는다.
 */
export function iconSprite(): string {
  const symbols = ICON_NAMES.map((n) =>
    `<symbol id="i-${n}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICON_PATHS[n]}</symbol>`,
  ).join("");
  return `<svg class="sprite" aria-hidden="true" focusable="false"><defs>${symbols}</defs></svg>`;
}

/**
 * 아이콘의 CSS.
 *
 * `vertical-align:-.14em` 은 눈으로 맞춘 값이다 — `middle` 은 대문자 없는 한글 옆에서 뜬다.
 * `.sprite` 는 `display:none` 이 **아니다**: 그렇게 하면 일부 브라우저가 `<use>` 참조를
 * 못 찾는다. 화면에서 사라지되 문서에는 남는 방식으로 숨긴다.
 */
export const ICON_CSS = `.i { width: 1em; height: 1em; flex: none; vertical-align: -.14em; }
.sprite { position: absolute; width: 0; height: 0; overflow: hidden; }`;

// ## `CLIENT_ICON_JS` was removed with the page that ran it
//
// It was the browser-side twin of `icon()`, needed because the classic console built its tables in
// an inline script. That console is gone and the Svelte console draws its own icons, so there is no
// second copy for the two to drift apart into — which was the entire reason the constant and its
// parity test existed. The concern is retired, not dropped.

