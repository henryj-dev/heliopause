// tiny-universe BLUEPRINT 디자인 시스템 — 이 콘솔이 쓰는 부분.
//
// 시안(`tokens.css` rev 001 · 2026-08)에서 옮겨 왔다. **두 곳이 의도적으로 다르다:**
//
//  1. **웹폰트를 안 건다.** 시안은 `fonts.googleapis.com` 에서 IBM Plex 를 받아 온다. 이 콘솔은
//     받아 올 수 없다 — `manager-ui.ts` 의 규약이 「No CDN, no external font, no remote
//     anything」이고, 그 이유는 이 페이지가 **네트워크가 고장난 날에 열리는 페이지**라는 것이다.
//     그래서 스택의 첫 이름만 IBM Plex 로 두고(설치돼 있으면 시안과 같은 모양이 된다) 나머지는
//     시스템 폰트로 떨어진다. 밀도·행 높이는 폰트가 무엇이든 토큰이 정하므로 표는 안 무너진다.
//
//  2. **Tailwind `@theme` · `@utility` 블록을 안 옮긴다.** 이 저장소에 Tailwind 가 없다. 그
//     블록들은 커스텀 속성을 Tailwind 클래스로 노출하는 사상이고, 여기서는 CSS 를 직접 쓴다.
//     원본 토큰 값은 한 글자도 안 바꿨으므로 나중에 Tailwind 를 들이면 그 블록만 붙이면 된다.
//
// ## 테마는 셋, 밀도는 셋
//
// `[data-theme="dark"]` · `[data-theme="light"]` · **없음(= OS 를 따른다)**. 라이트 팔레트 전부가
// 맨 `:root` 에 있어서 속성이 없는 상태가 항상 칠해지고, 다크는 두 번 정의된다 — 한 번은
// `prefers-color-scheme` 안(시스템 상태), 한 번은 명시 속성 위(전환이 양쪽에서 이긴다).
//
// 밀도는 **패딩만** 움직인다. 고정 행 높이는 없다 — 한국어와 영어가 같은 표에서 다른 줄 수를
// 갖기 때문이고, 고정 높이는 그 순간 글자를 자른다(시안 J1).
export const TOKENS_CSS = `:root{
  --font-mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --font-sans:'IBM Plex Sans KR','IBM Plex Sans',system-ui,-apple-system,'Apple SD Gothic Neo','Noto Sans KR',sans-serif;

  --n-0:oklch(0.995 0.002 240); --n-1:oklch(0.978 0.003 240); --n-2:oklch(0.955 0.004 240);
  --n-3:oklch(0.920 0.006 240); --n-4:oklch(0.868 0.008 240); --n-5:oklch(0.775 0.010 240);
  --n-6:oklch(0.660 0.012 240); --n-7:oklch(0.548 0.014 240); --n-8:oklch(0.442 0.016 240);
  --n-9:oklch(0.330 0.016 240); --n-10:oklch(0.232 0.014 240); --n-11:oklch(0.152 0.012 240);

  --surface-base:var(--n-1); --surface-card:var(--n-0); --surface-elevated:var(--n-0);
  --surface-input:var(--n-0); --surface-sunken:var(--n-2); --surface-overlay:var(--n-0);
  --surface-scrim:oklch(0.30 0.02 240 / 0.34); --scrim-blur:2px;
  --text-1:var(--n-11); --text-2:var(--n-8); --text-3:var(--n-6); --text-off:var(--n-5);
  --bd-1:var(--n-3); --bd-2:var(--n-5); --bd-strong:var(--n-7);

  --accent:oklch(0.505 0.088 208); --accent-hover:oklch(0.435 0.090 208);
  --accent-on:oklch(0.99 0.005 208); --accent-bg:oklch(0.955 0.026 208); --accent-bd:oklch(0.800 0.055 208);
  --focus:oklch(0.505 0.110 208);
  --ok-fg:oklch(0.470 0.085 155); --ok-bg:oklch(0.960 0.024 155); --ok-bd:oklch(0.810 0.050 155);
  --warn-fg:oklch(0.545 0.115 72); --warn-bg:oklch(0.965 0.038 78); --warn-bd:oklch(0.820 0.080 75);
  --danger-fg:oklch(0.505 0.165 26); --danger-bg:oklch(0.962 0.028 26); --danger-bd:oklch(0.810 0.075 26);
  --info-fg:oklch(0.485 0.110 258); --info-bg:oklch(0.960 0.028 258); --info-bd:oklch(0.805 0.060 258);
  --mute-fg:var(--n-7); --mute-bg:var(--n-2); --mute-bd:var(--n-4);
  --live-decay:oklch(0.505 0.088 208 / 0.14);
  --hatch:oklch(0.548 0.014 240 / 0.30);

  --r-sm:2px; --r-md:3px; --r-lg:4px; --r-full:999px;
  --bw-1:1px; --bw-2:2px;
  --sh-0:none; --sh-1:0 1px 2px oklch(0.30 0.02 240 / 0.07);
  --sh-overlay:0 12px 32px oklch(0.25 0.02 240 / 0.16), 0 1px 0 var(--bd-1);
  --sp-1:4px; --sp-2:8px; --sp-3:12px; --sp-4:16px; --sp-5:24px; --sp-6:32px; --sp-7:48px;
  --dur-1:80ms; --dur-2:140ms; --dur-3:240ms; --dur-decay:1400ms;
  --ease:cubic-bezier(.2,.6,.3,1);
  --z-dropdown:100; --z-popover:200; --z-drawer:300; --z-modal:400; --z-palette:500; --z-toast:600; --z-tooltip:700;

  --row-py:6px; --cell-px:10px; --stack:8px; --ctl-h:28px; --fs-cell:13px; --lh-cell:1.45; --sec-gap:20px;

  /* 껍데기의 치수. stardust 의 \`app.css\` 와 같은 이름·같은 값이다. 밀도 토큰과 **함께 두지
     않는다** — 밀도는 행의 패딩만 움직이고, 크롬은 표가 촘촘해진다고 같이 움직이면 안 된다.
     표만 바뀌어야 할 때 페이지 전체가 크기를 바꾼 것처럼 보인다.

     stardust 는 \`--sb-w\` 를 한 겹 더 두고 \`--sb-collapsed: 60px\` 로 갈아끼워 사이드를 접는다.
     그 두 이름은 **여기 없다.** 접기에는 토글이 필요하고 토글에는 스크립트가 필요한데 정책
     화면은 스크립트를 안 싣는다 — 부르는 데가 없는 이름을 미리 두는 것은 이 저장소가 일곱 번
     당한 모양이고, \`design-tokens.test.ts\` 가 실제로 그걸 잡았다. 접기를 넣는 날 함께 넣는다. */
  --topbar-h:42px; --sb-expanded:184px;
}
:root[data-density="compact"]{ --row-py:3px; --cell-px:8px; --stack:6px; --ctl-h:24px; --fs-cell:12px; --lh-cell:1.35; --sec-gap:14px; }
:root[data-density="comfortable"]{ --row-py:10px; --cell-px:14px; --stack:12px; --ctl-h:32px; --fs-cell:13.5px; --lh-cell:1.55; --sec-gap:28px; }

@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]){
  --n-0:oklch(0.158 0.010 240); --n-1:oklch(0.188 0.011 240); --n-2:oklch(0.222 0.012 240);
  --n-3:oklch(0.272 0.013 240); --n-4:oklch(0.330 0.014 240); --n-5:oklch(0.410 0.014 240);
  --n-6:oklch(0.520 0.014 240); --n-7:oklch(0.628 0.013 240); --n-8:oklch(0.726 0.011 240);
  --n-9:oklch(0.812 0.008 240); --n-10:oklch(0.892 0.006 240); --n-11:oklch(0.958 0.004 240);
  --surface-base:var(--n-0); --surface-card:var(--n-1); --surface-elevated:var(--n-2);
  --surface-input:oklch(0.132 0.010 240); --surface-sunken:oklch(0.132 0.010 240); --surface-overlay:var(--n-2);
  --surface-scrim:oklch(0.10 0.01 240 / 0.62);
  --bd-1:var(--n-3); --bd-2:var(--n-4); --bd-strong:var(--n-6);
  --accent:oklch(0.760 0.098 206); --accent-hover:oklch(0.830 0.100 206);
  --accent-on:oklch(0.150 0.020 206); --accent-bg:oklch(0.278 0.048 206); --accent-bd:oklch(0.400 0.062 206);
  --focus:oklch(0.780 0.110 206);
  --ok-fg:oklch(0.755 0.095 155); --ok-bg:oklch(0.262 0.042 155); --ok-bd:oklch(0.375 0.055 155);
  --warn-fg:oklch(0.810 0.125 80); --warn-bg:oklch(0.288 0.055 72); --warn-bd:oklch(0.412 0.072 74);
  --danger-fg:oklch(0.712 0.150 26); --danger-bg:oklch(0.282 0.070 26); --danger-bd:oklch(0.408 0.098 26);
  --info-fg:oklch(0.742 0.105 258); --info-bg:oklch(0.278 0.050 258); --info-bd:oklch(0.398 0.068 258);
  --live-decay:oklch(0.760 0.098 206 / 0.16);
  --hatch:oklch(0.628 0.013 240 / 0.34);
  --sh-overlay:0 16px 40px oklch(0.05 0.01 240 / 0.55), 0 0 0 1px var(--bd-2);
}}
:root[data-theme="dark"]{
  --n-0:oklch(0.158 0.010 240); --n-1:oklch(0.188 0.011 240); --n-2:oklch(0.222 0.012 240);
  --n-3:oklch(0.272 0.013 240); --n-4:oklch(0.330 0.014 240); --n-5:oklch(0.410 0.014 240);
  --n-6:oklch(0.520 0.014 240); --n-7:oklch(0.628 0.013 240); --n-8:oklch(0.726 0.011 240);
  --n-9:oklch(0.812 0.008 240); --n-10:oklch(0.892 0.006 240); --n-11:oklch(0.958 0.004 240);
  --surface-base:var(--n-0); --surface-card:var(--n-1); --surface-elevated:var(--n-2);
  --surface-input:oklch(0.132 0.010 240); --surface-sunken:oklch(0.132 0.010 240); --surface-overlay:var(--n-2);
  --surface-scrim:oklch(0.10 0.01 240 / 0.62);
  --bd-1:var(--n-3); --bd-2:var(--n-4); --bd-strong:var(--n-6);
  --accent:oklch(0.760 0.098 206); --accent-hover:oklch(0.830 0.100 206);
  --accent-on:oklch(0.150 0.020 206); --accent-bg:oklch(0.278 0.048 206); --accent-bd:oklch(0.400 0.062 206);
  --focus:oklch(0.780 0.110 206);
  --ok-fg:oklch(0.755 0.095 155); --ok-bg:oklch(0.262 0.042 155); --ok-bd:oklch(0.375 0.055 155);
  --warn-fg:oklch(0.810 0.125 80); --warn-bg:oklch(0.288 0.055 72); --warn-bd:oklch(0.412 0.072 74);
  --danger-fg:oklch(0.712 0.150 26); --danger-bg:oklch(0.282 0.070 26); --danger-bd:oklch(0.408 0.098 26);
  --info-fg:oklch(0.742 0.105 258); --info-bg:oklch(0.278 0.050 258); --info-bd:oklch(0.398 0.068 258);
  --live-decay:oklch(0.760 0.098 206 / 0.16);
  --hatch:oklch(0.628 0.013 240 / 0.34);
  --sh-overlay:0 16px 40px oklch(0.05 0.01 240 / 0.55), 0 0 0 1px var(--bd-2);
}
@keyframes tu-pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.42;transform:scale(.82)}}
@keyframes tu-spin{to{transform:rotate(360deg)}}
@keyframes tu-decay{from{background:var(--live-decay)}to{background:transparent}}
@media (prefers-reduced-motion: reduce){*{animation-duration:.001ms !important;animation-iteration-count:1 !important;transition-duration:.001ms !important}}`;

/**
 * 두 문서가 함께 쓰는 컴포넌트 CSS.
 *
 * 콘솔(`manager-ui.ts`)과 정책 화면(`policy-ui.ts`)은 서로 다른 프로세스가 그리는 별개의
 * 페이지다. 상수 하나로 두는 이유는 `NAV_CSS` 가 이미 적어 둔 것과 같다 — **두 화면 사이에서
 * 벌어지는 표는 운영자에게 제품을 떠났다고 말한다.**
 *
 * ## 시안이 새로 만든 것은 둘뿐이다
 *
 * 시안 자신의 설명대로(Fleet 문서 머리) 새 프리미티브는 **결함 칩**과 **해치**뿐이고, 둘 다 기존
 * semantic 3색조와 `--hatch` 로 만들었다. 여기도 같다.
 *
 * ## 해치가 뜻하는 것 — 색이 아니라 관측의 부재
 *
 * `.hatch` 는 「아무도 안 봤다」다. `null`(안 봤다) · `[]`(봤고 없었다) · `unavailable`(못
 * 읽었다) 셋은 **절대 같은 빈 칸이 되지 않는다**는 것이 이 콘솔의 규약이고, 해치는 그 셋 중
 * 첫째를 색 없이 구분하는 장치다. 색맹인 운영자에게도 사선은 사선이다.
 */
export const BASE_CSS = `*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--surface-base);color:var(--text-1);font-family:var(--font-sans);font-size:var(--fs-cell);line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-underline-offset:3px}
a:hover{color:var(--accent-hover)}
:focus-visible{outline:2px solid var(--focus);outline-offset:1px;border-radius:1px}

/* 관측이 없는 칸. 사선은 색이 아니므로 색 없이도 읽힌다. */
.hatch{background-image:repeating-linear-gradient(135deg,var(--hatch) 0 1px,transparent 1px 5px)}

/* 표. 고정 행 높이가 없다 — 패딩만 있고, 그 패딩은 밀도 토큰이 정한다. */
.scroll{overflow-x:auto;background:var(--surface-card);border:1px solid var(--bd-1);border-radius:var(--r-md)}
table{width:100%;border-collapse:collapse}
th{font-family:var(--font-mono);font-size:11px;font-weight:500;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3);text-align:left;padding:6px var(--cell-px);border-bottom:1px solid var(--bd-2);white-space:nowrap}
td{font-size:var(--fs-cell);line-height:var(--lh-cell);padding:var(--row-py) var(--cell-px);border-bottom:1px solid var(--bd-1);vertical-align:top}
tbody tr:last-child td{border-bottom:0}

/* 결함 칩 — 기호 + 낱말. 한국어가 짧고 영어가 길어도 줄바꿈만 늘어난다. */
.chip{display:inline-flex;align-items:center;gap:5px;font-family:var(--font-mono);font-size:11px;
  padding:1px 7px;border-radius:var(--r-full);border:1px solid var(--bd-2);color:var(--text-2);white-space:nowrap}
.chip.ok{background:var(--ok-bg);color:var(--ok-fg);border-color:var(--ok-bd)}
.chip.warn{background:var(--warn-bg);color:var(--warn-fg);border-color:var(--warn-bd)}
.chip.bad{background:var(--danger-bg);color:var(--danger-fg);border-color:var(--danger-fg);font-weight:600}
.chip.info{background:var(--info-bg);color:var(--info-fg);border-color:var(--info-bd)}
.chip.mute{background:var(--mute-bg);color:var(--mute-fg);border-color:var(--mute-bd)}
/* 안 봤다. 점선 + 해치이고 배경색이 없다 — 「값이 나쁘다」가 아니라 「값이 없다」이기 때문이다. */
.chip.none{background:transparent;border-style:dashed;border-color:var(--bd-strong);color:var(--text-2)}
.chips{display:flex;flex-wrap:wrap;gap:4px}

/* 배너 — 사라지지 않는다. 토스트는 이 콘솔에 없다. */
.banner{padding:9px 12px;border:1px solid var(--bd-2);border-radius:var(--r-md);
  display:flex;flex-wrap:wrap;align-items:center;gap:10px;line-height:1.6}
.banner.ok{background:var(--ok-bg);border-color:var(--ok-bd)}
.banner.warn{background:var(--warn-bg);border-color:var(--warn-bd)}
.banner.bad{background:var(--danger-bg);border-color:var(--danger-bd)}
.banner.info{background:var(--info-bg);border-color:var(--info-bd)}
.banner .lead{display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono);font-weight:600}
.banner.ok .lead{color:var(--ok-fg)} .banner.warn .lead{color:var(--warn-fg)}
.banner.bad .lead{color:var(--danger-fg)} .banner.info .lead{color:var(--info-fg)}

.card{background:var(--surface-card);border:1px solid var(--bd-1);border-radius:var(--r-md);padding:11px 13px}

/* semantic 3색조 — 옛 클래스 이름을 토큰 위에 다시 얹는다.
   이름을 안 바꾼 것은 의도다: 이 세 글자는 두 파일의 렌더러 수십 곳에 있고, 한꺼번에 바꾸는
   변경은 「시안 적용」이 아니라 「전면 개작」이 된다. 값은 전부 토큰에서 온다. */
.ok{color:var(--ok-fg)} .warn{color:var(--warn-fg)} .bad{color:var(--danger-fg)}
.dim{color:var(--text-2)} .off{color:var(--text-off)}
/* 해시·주소는 어디서 끊겨도 읽히므로 넘치기 전에 끊는다. 이름은 아니다 — \`k8s-a1.prod\` 가
   \`k8s-a1.p / rod\` 로 끊기면 그건 다른 호스트로 읽힌다. 그래서 이름 칸은 .name 을 쓴다. */
.mono{font-family:var(--font-mono);word-break:break-all}
.name{font-family:var(--font-mono);font-weight:600;white-space:nowrap}
.num{font-family:var(--font-mono);font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 7px;border:1px solid var(--bd-2);border-radius:var(--r-full);
  font-family:var(--font-mono);font-size:11px}

/* 컨트롤. 시안의 위험도 규칙: 채워진 위험색 + 표식을 갖는 것은 publish 하나뿐이다. */
button,.btn{display:inline-flex;align-items:center;gap:6px;height:var(--ctl-h);padding:0 11px;
  font-family:var(--font-mono);font-size:12px;background:transparent;color:var(--text-1);
  border:1px solid var(--bd-strong);border-radius:var(--r-md);cursor:pointer}
button:hover{border-color:var(--accent)}
button:disabled{color:var(--text-off);border-style:dashed;border-color:var(--bd-2);cursor:not-allowed}
button[data-act="publish"]{background:var(--danger-fg);color:var(--n-0);border-color:var(--danger-fg);font-weight:600}
button[data-act="publish"]:disabled{background:transparent;color:var(--text-off);border-color:var(--bd-2)}
input,select,textarea{height:var(--ctl-h);padding:0 8px;font-family:var(--font-mono);font-size:12px;
  background:var(--surface-input);color:var(--text-1);border:1px solid var(--bd-2);border-radius:var(--r-md)}
textarea{height:auto;padding:8px}

/* 요청이 나가 있는 동안. 시안은 회전하는 테두리를 쓰는데, 여기서는 같은 회전을 아이콘에 건다. */
.spin{animation:tu-spin .9s linear infinite}
/* 폴링이 살아 있다는 표시. 값이 아니라 맥박이므로 숫자 옆에 둔다. */
.live{width:6px;height:6px;border-radius:var(--r-full);background:var(--ok-fg);animation:tu-pulse 1.6s var(--ease) infinite;display:inline-block}`;
