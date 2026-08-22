// 디자인 토큰 — 옮겨 온 것이 맞는지, 그리고 **세 테마 상태가 다 칠해지는지**.
//
// ## 왜 CSS 를 테스트하는가
//
// 여기서 틀리는 방식은 예외가 아니라 「안 보이는 글자」다. 토큰 하나가 어느 상태에서만 정의되면
// 그 상태 밖에서는 `var(--x)` 가 빈 값이 되고, 색은 상속된 것이나 브라우저 기본값이 된다 —
// 검은 배경 위의 검은 글자가 되는 경로가 정확히 이것이고, 그때도 페이지는 200 을 낸다.
//
// 시안의 규약(`tokens.css` 머리)이 상태를 셋으로 못 박은 이유가 그것이다: `[data-theme="dark"]`
// · `[data-theme="light"]` · **속성 없음(= OS 를 따른다)**. 세 번째가 기본값이므로, 라이트
// 팔레트 전부가 맨 `:root` 에 있어야 한다.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BASE_CSS, TOKENS_CSS } from "./design-tokens.ts";
import { policyPage } from "./policy-ui.ts";

/** The one served document that still carries a server-rendered stylesheet. */
const servedPage = (): string =>
  policyPage(
    [{
      id: "P1", name: "n", src: "cidr 10.0.0.0/8", dst: "host h", proto: "tcp", ports: "22",
      action: "allow" as const, denyMode: "drop" as const, enabled: true, notes: "",
      hosts: ["gw-01.dev"], skippedOn: [], egressHosts: [], srcCidrs: ["10.254.0.0/16"],
      placementKnown: true, risks: [],
    } as unknown as Parameters<typeof policyPage>[0][number]],
    { site: "policy/dev.ts", generation: "abc1234", hosts: ["gw-01.dev"] },
  );

/** `:root{ … }` 한 블록에서 정의된 커스텀 속성 이름들. */
function declared(block: string): Set<string> {
  return new Set([...block.matchAll(/(--[a-z0-9-]+)\s*:/g)].map((m) => m[1]!));
}

/** 셀렉터로 블록 하나를 꺼낸다. 중첩(`@media`)은 안 다룬다 — 부르는 쪽이 잘라서 준다. */
function block(css: string, selector: string): string {
  const at = css.indexOf(selector + "{");
  assert.notEqual(at, -1, `${selector} 블록이 없다`);
  const open = at + selector.length;
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}" && --depth === 0) return css.slice(open + 1, i);
  }
  throw new Error(`${selector} 블록이 안 닫힌다`);
}

describe("the three theme states", () => {
  const base = block(TOKENS_CSS, ":root");
  const explicitDark = block(TOKENS_CSS, ':root[data-theme="dark"]');
  const systemDark = block(TOKENS_CSS, ':root:not([data-theme="light"])');

  it("paints the no-attribute state, which is the default one", () => {
    // 속성이 없는 상태가 기본이다. 라이트 팔레트가 미디어 쿼리 안에만 있으면 OS 가 라이트일 때는
    // 우연히 맞고 그 밖에서는 아무 값도 없다.
    for (const t of ["--surface-base", "--text-1", "--bd-1", "--accent", "--ok-fg", "--warn-fg", "--danger-fg", "--info-fg", "--hatch"]) {
      assert.ok(declared(base).has(t), `${t} 가 맨 :root 에 없다 — 기본 상태가 안 칠해진다`);
    }
  });

  it("redefines the same set in both dark states, so a toggle cannot half-apply", () => {
    // 두 블록이 갈라지면 「시스템 다크」와 「명시 다크」가 다른 화면이 된다. 시안이 다크를 두 번
    // 쓴 것은 중복이 아니라 **전환이 양쪽에서 이기게** 하려는 것이고, 그 대가가 이 검사다.
    assert.deepEqual([...declared(explicitDark)].sort(), [...declared(systemDark)].sort());
    assert.ok(declared(explicitDark).size > 20, "다크 팔레트가 너무 작다 — 옮기다 만 것 아닌가");
  });

  it("never leaves a token defined only in the dark half", () => {
    // 알려진 양성: `--only-dark` 를 다크에만 두면 이 검사가 운다.
    const missing = [...declared(explicitDark)].filter((t) => !declared(base).has(t));
    assert.deepEqual(missing, [], "다크에만 있는 토큰은 라이트에서 빈 값이 된다");

    const injected = declared(explicitDark + "\n--only-dark:red;");
    assert.deepEqual([...injected].filter((t) => !declared(base).has(t)), ["--only-dark"]);
  });
});

describe("density moves padding and nothing else", () => {
  // 시안의 하드 제약이다: 「밀도는 **패딩 토큰만** 움직인다 — 고정 행 높이는 절대」. 한국어와
  // 영어가 같은 표에서 다른 줄 수를 갖기 때문이고(J1), 고정 높이는 그 순간 글자를 자른다.
  for (const d of ["compact", "comfortable"]) {
    it(`redefines only padding-shaped tokens for ${d}`, () => {
      const b = block(TOKENS_CSS, `:root[data-density="${d}"]`);
      const allowed = new Set(["--row-py", "--cell-px", "--stack", "--ctl-h", "--fs-cell", "--lh-cell", "--sec-gap"]);
      for (const t of declared(b)) assert.ok(allowed.has(t), `${d} 가 ${t} 를 건드린다`);
    });
  }

  it("gives the table its height from padding, never from a fixed row", () => {
    const td = /td\{([^}]*)\}/.exec(BASE_CSS)?.[1] ?? "";
    assert.match(td, /padding:var\(--row-py\) var\(--cell-px\)/);
    // `line-height` 는 높이가 아니다 — 앞에 문자가 붙지 않은 `height` 만 본다.
    const fixedHeight = /(?:^|[;{])\s*(?:min-|max-)?height\s*:/;
    assert.equal(fixedHeight.test(td), false, `td 에 고정 높이가 있다: ${td}`);
    // 알려진 양성. 위 검사는 아무것도 안 잡는 정규식으로도 통과한다.
    assert.equal(fixedHeight.test("padding:2px;height:28px"), true);
    assert.equal(fixedHeight.test("line-height:1.45"), false);
  });
});

describe("the tokens the two pages actually name", () => {
  it("defines every custom property the served page's own rules reference", () => {
    // 이 콘솔이 겪은 실패 형태 그대로다 — 아래 계층이 전부 옳고 마지막 한 칸에서 값이 사라진다.
    // `var(--line)` 처럼 옛 이름이 한 줄 남으면 그 규칙만 조용히 무효가 된다.
    //
    // 대상이 고전 콘솔에서 정책 화면으로 옮겨졌다. 고전 콘솔은 이제 서빙되지 않으므로 그것을
    // 검사하는 것은 아무도 보지 않는 마크업을 검사하는 것이었다. 살아 있는 SvelteKit 콘솔의
    // 같은 성질은 `packages/web/src/lib/shell/parity.test.ts` 가 지킨다.
    const page = servedPage();
    const css = /<style>([\s\S]*?)<\/style>/.exec(page)?.[1] ?? "";
    assert.ok(css.length > 0, "the served page carries no stylesheet");

    const defined = new Set([...css.matchAll(/(--[a-z0-9-]+)\s*:/g)].map((m) => m[1]!));
    const used = new Set([...css.matchAll(/var\((--[a-z0-9-]+)/g)].map((m) => m[1]!));
    const orphans = [...used].filter((t) => !defined.has(t));
    assert.deepEqual(orphans, [], "the stylesheet names tokens nothing defines");

    // 알려진 양성. 위 비교는 「아무것도 안 쓰는 스타일시트」로도 만족되므로, 실제로 잡는지 본다.
    const withTypo = new Set([...used, "--lin"]);
    assert.deepEqual([...withTypo].filter((t) => !defined.has(t)), ["--lin"]);
  });
});
