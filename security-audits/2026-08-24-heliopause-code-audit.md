# heliopause 코드 감사 보고서

- 감사일: 2026-08-24
- **개정: 2026-08-25** — 검증 재실행, 발견 2건 정정, 3건 추가 (→ [개정 이력](#개정-이력--2026-08-25))
- 감사 기준 커밋: `3de1d05` (재실행 당시 워크트리)
- 현재 후속 검토 커밋: `f293884` — M-01/L-02/I-02 수정과 감사 문서·기대값 갱신을 포함
- 대상: 저장소의 실행 코드 및 테스트 코드 (아래 커버리지 표의 미검토 영역 제외)
- 제외: README, 설계 문서
  - ⚠️ 초판은 「주석의 보안 주장 자체」도 제외했다. **개정에서 철회한다** — 이 저장소에서는
    그것이 가장 큰 사각이다. [방법론](#방법론--이-저장소에서-제외하면-안-되는-것) 참조.
- 방식: 코드 호출 경로 추적, 입력 경계·권한 경계·외부 프로세스 확인, 테스트 및 타입 검사 실행

## 개정 이력 — 2026-08-25

초판의 판정 두 개가 근거 위에 서 있지 않았다. 검사를 전부 다시 돌리고 두 발견을 코드에 대고
재확인했다.

| | 초판 | 개정 |
|---|---|---|
| 검증 실행 | `npm test` 중단 · `test_enroll` 2건 실패 · Ed25519 12건 skip | **전 게이트 통과** — 실패는 전부 초판 환경의 소켓 제한이었다. 다만 그 사실은 초판이 확인한 것이 아니다 |
| 안 돌린 게이트 | 명시 없음 | `build:web` · **누출 스캔** · 훅 7종이 목록에 없었다 |
| M-01 | 유효 · Medium | **유효 · Medium 유지.** 영향 서술의 방향 하나가 빠져 있었고, 행위자 모델이 없었다 |
| L-01 | Low · 수정 제안 4건 | **Info 로 낮춤.** 넷 중 셋은 이미 되어 있다. 남는 것은 부분 인증서 폴백 하나 |
| L-02 (`revokeExisting`) | — | **추가.** M-01 과 같은 결함 유형의 두 번째 자리이며, 기존 토큰 폐기로 운영 영향이 있어 Low로 분류 |
| O-01 | — | **추가.** 저장소 밖에서 확인해야 하는 항목 (IdP 등록 여부) |
| 미검토 영역 | 없음 | **추가.** 「문제 없음」과 「안 봄」이 구별되지 않았다 |

## 요약

코드에서 확인된 우선 수정 사항은 1건이다.

| 심각도 | 개수 |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 1 |
| Info | 1 |

그 밖에 **저장소 밖에 확인이 필요한 항목이 1건**(O-01) 있다. 코드는 완비돼 있지만 실제 IdP
등록 여부는 저장소 코드만으로 확인할 수 없다.

주요 발견은 정책의 `enabled` 필드가 불리언인지 검증하지 않고 JavaScript의 truthy 규칙으로
변환한다는 점이다. `"false"`와 `"0"`이 활성화된 정책으로 처리된다.

### 후속 조치 상태 — 2026-08-25

- **M-01 해결됨** — `normalizePolicy`가 비불리언 `enabled`를 거부하고, 정책·문서·부분 갱신
  경로의 회귀 테스트를 추가했다.
- **L-02 해결됨** — HTTP와 저장소 함수 양쪽에서 `revokeExisting`의 비불리언 입력을 거부한다.
- **I-02 해결됨** — 스캐폴드 TLS 해석을 순수 함수로 분리하고, 인증서·키 부분 설정 시 즉시
  실패하도록 했다. 양쪽 미설정 시 개발용 자체서명 경로는 유지된다.
- **O-01 미검증** — KeyStone 외부 설정은 저장소 밖 작업이며, 배포 체크리스트에 이미 기재된
  `post_logout_redirect_uri`와 달리 Back-channel Logout URI 하나의 실제 등록 여부 확인이 남아 있다.

⚠️ **「0 Critical / 0 High」는 검토한 범위에 한정된 판정이다.** 아래 「아직 아무 주장도 하지 않은
영역」은 전수 검토하지 않았으므로, 저장소 전체에 High 이상이 없다고 주장하지 않는다. 초판은
테스트가 돌지 않은 상태에서 이 판정을 내렸고, 검사가 안 돌면 「High 없음」이 아니라 「판정 불가」다.

## 발견 사항

### M-01. 비불리언 `enabled` 값이 조용히 활성화됨

- 심각도: Medium
- 위치: `src/policy.ts:450`, `normalizePolicy`
- 확신도: 확인됨 (재현 완료)
- 후속 상태: **해결됨** (`normalizePolicy`의 원시 입력 타입 검증 및 회귀 테스트 추가)

현재 구현:

```ts
enabled: o.enabled === undefined ? true : Boolean(o.enabled)
```

#### 재현 (2026-08-25, `3de1d05`, `normalizePolicy` 직접 호출)

```
"false" -> true      "no"  -> true      []    -> true      "true" -> true
"0"     -> true      "off" -> true      {}    -> true
0       -> false     null  -> false     ""    -> false
```

초판의 표(`"false"`·`"0"`·`0`·`null`)에 YAML 관용 표기 `"no"`·`"off"` 와 빈 배열·빈 객체를
더했다. 정책 문서는 JSON 이므로(`policy-store.ts` 의 `JSON.parse`) YAML 파서가 접어 주는
경로는 없다 — `"no"` 는 끝까지 문자열로 도착하고, 문자열은 truthy 다.

#### 이 함수의 규칙에서 이 한 필드만 빠져 있다

「강제 변환이 나쁘다」가 아니다. 같은 함수의 다른 필드도 전부 강제 변환을 쓰지만 **변환 뒤에
검증이 온다.**

| 필드 | 변환 | 검증 |
|---|---|---|
| `name` | `String(o.name ?? "")` | 빈 문자열 거부 · 120자 상한 |
| `proto` | `String(...).toLowerCase()` | `PROTOS.has(proto)` |
| `action` | `String(...).toLowerCase()` | `allow`/`deny` 외 거부 |
| `denyMode` | `String(o.denyMode ?? "drop")` | `drop`/`reject` 외 거부 |
| `priority` | `Number(o.priority ?? 100)` | `Number.isInteger` · 1..100000 |
| `ports` | `normalizePorts` | 문법 검사 |
| `src`/`dst` | `normalizeEndpoint` | kind 화이트리스트 + kind별 값 검사 |
| **`enabled`** | **`Boolean(o.enabled)`** | **없음** |

#### 저장소가 이미 이 규칙을 다른 쪽에서 지키고 있다

콘솔 리더는 엄격하다 — `typeof … !== "boolean"` 가드 8곳, `=== true` 로 불리언을 받는 자리
15곳(`packages/web/src`):

```
packages/web/src/lib/domains/policy/screen.ts:235   typeof value.enabled !== "boolean" → null
packages/web/src/lib/domains/lookup/lookup.ts:244   같은 검사
```

**그리고 그 엄격 검사는 이 결함을 잡을 수 없다** — 서버가 이미 `Boolean()` 으로 접은 뒤에
직렬화하기 때문이다. 리더가 보는 것은 언제나 진짜 불리언이다. 수정이 필요한 이유가 취향이
아니라 이 저장소의 규칙이라는 점, 그리고 하류의 방어가 구조적으로 무력하다는 점이 함께 있다.

#### 영향 — 두 방향이 있고, 한쪽만 조용하다

초판은 활성화되는 방향만 다뤘다. 반대 방향(`null`·`""`·`0` → 비활성)도 있다. 그런데:

| 방향 | 렌더 결과 | 보고 경로 |
|---|---|---|
| `null`·`""`·`0` → **비활성** | 규칙이 렌더에서 빠진다 | **있다** — `nft.ts:783,829` 가 `skipped.push({ reason: "policy is disabled" })` |
| `"false"`·`"0"`·`"no"`·`[]` → **활성** | 규칙이 렌더된다 | **없다** |

즉 **비활성화되는 방향에는 보고 경로가 있고, 활성화되는 방향에는 없다.** 문자열이 `true` 로
접히면 그 규칙은 의도적으로 켠 규칙과 렌더 결과가 구별되지 않는다. 이것이 Medium 의 근거다.

- 비활성화하려던 allow 정책이 활성화되면 의도하지 않은 허용이 렌더된다.
- 비활성화하려던 deny 정책이 활성화되면 의도하지 않은 차단이 렌더된다.
- 어느 쪽이든 **오류가 나지 않는다** — 잘못된 타입이 입력 오류로 보고되는 지점이 없다.

#### 행위자와 완화 — 인가 우회가 아니라 무결성 결함이다

운영 코드에서 `normalizePolicy`를 직접 호출하는 지점은 둘이다.

```
src/policy-store.ts:43    parseDocument — git 저장소의 정책 JSON 로드
src/policy-store.ts:100   putPolicy    — 쓰기 API
```

둘 다 이미 writer 인증서 또는 저장소 커밋 권한을 전제한다. 익명 입력이 닿는 경계가 아니다.
테스트 코드와 `mergePolicy`의 간접 경로는 별도이며, 회귀 테스트에서 함께 다뤄야 한다.

완화도 있다: `enabled` 는 `policyFingerprint`(`policy.ts:497` — `p.enabled ? "1" : "0"`)에
들어가므로 잘못 켜진 규칙은 **2인 승인 diff 에 나타난다.** 다만 승인자가 `/ruleset` 을 실제로
읽어야 하고, CLI 승인자가 그것을 볼 수 있게 된 것이 `4f7d14d`(2026-08-24, `heliopause-approve
--show`)다. 그 전에는 CLI 승인이 해시 대조였다.

그래서 정확한 분류는 **인가 우회가 아니라 무결성 결함**이고, Medium 인 이유는 심각한 권한
상승이어서가 아니라 **틀린 값이 보고 없이 집행으로 흘러가는 유일한 필드**이기 때문이다.

#### 수정 제안

```ts
const enabled = o.enabled === undefined
  ? true
  : typeof o.enabled === "boolean"
    ? o.enabled
    : (() => { throw bad("enabled must be a boolean"); })();
```

또는 별도의 타입 검증 함수로 분리한다. 이 함수의 나머지 필드와 같은 모양(변환 → 검증)이
되도록 하는 편이 낫다.

회귀 테스트:

- `enabled: true` / `enabled: false` / 필드 부재(기본 `true`) — 셋 다 현행 동작 유지
- 거부: `"false"` · `"true"` · `"0"` · `"no"` · `"off"` · `0` · `null` · `""` · `[]` · `{}`
- **`mergePolicy`(`policy.ts:462`) 경유 경로도 같이** — 부분 갱신이라 `enabled` 만 문자열로
  오는 것이 실제로 가장 그럴듯한 형태다
- 결함 주입 확인: 검사를 되돌리면 위 10건이 실패할 것

### L-02. `revokeExisting` — 같은 결함 유형의 두 번째 자리

- 심각도: Low
- 위치: `src/manager-server.ts:1721`, `src/enrollment-store.ts:287`
- 확신도: 확인됨
- 후속 상태: **해결됨** (HTTP 경계와 `createNodeToken` 양쪽에서 비불리언 입력 거부)

```ts
// manager-server.ts:1721
revokeExisting: body.revokeExisting !== false,
// enrollment-store.ts:287
if (input.revokeExisting !== false) for (const token of document.tokens) …
```

`body.revokeExisting = "false"` 는 `!== false` 이므로 취소가 실행된다. M-01 과 같은 유형이다.

인가 우회는 아니지만 영향이 완전히 안전한 방향은 아니다. 「취소하지 말라」는 요청이 취소로
해석되어 기존 호스트 토큰이 폐기될 수 있고, 해당 호스트의 후속 등록·갱신이 실패하여 토큰
재발급이 필요해질 수 있다. 따라서 보안 권한 상승이 아닌 운영 가용성·무결성 영향의 Low로
분류한다.

적는 이유는 하나다: M-01을 「`policy.ts:450` 한 줄」로 보고하면 이 자리가 목록에 들어오지
않는다. 고쳐야 할 것은 줄이 아니라 **불리언을 강제 변환으로 받는 패턴**이고,
저장소에는 이미 반대 사례(콘솔 리더 15+8곳)가 있다.

### I-02. 스캐폴드의 부분 인증서 설정이 조용히 자체서명으로 넘어간다

- 심각도: Info (초판 L-01 을 정정 · 격하)
- 위치: `packages/manager/src/listen.ts:36-41`
- 확신도: 확인됨
- 후속 상태: **해결됨** (`resolveTls` 분리 및 부분 설정 회귀 테스트 추가)

```ts
const tls = process.env.HELIOPAUSE_CERT_FILE && process.env.HELIOPAUSE_KEY_FILE
  ? { cert: readFileSync(…), key: readFileSync(…) }
  : ephemeralTls();
```

둘 중 하나만 설정되면 오류 없이 `ephemeralTls()` — 하루짜리 자체서명 인증서로 뜬다. 설정을
했다고 믿는 운영자와 실제 동작이 갈리는 유일한 지점이다.

**수정**: 한쪽만 설정된 경우 즉시 종료. 종료 메시지에 어느 변수가 비었는지 적을 것.

#### 초판 L-01 의 나머지 세 제안은 이미 되어 있다 (정정)

초판은 「운영자가 이 명령을 실제 매니저로 오인」할 위험을 들어 Low 로 매기고 수정 4건을
제안했다. 코드에 대고 확인하니 셋은 이미 구현돼 있다.

| 초판 제안 | 실제 |
|---|---|
| 개발용 스캐폴드와 운영용 실행 명령 분리 | `packages/manager/package.json` 에 `"private": true`. `packaging/` · `.github/` · `scripts/`에는 `8445`·`manager-scaffold` 참조가 없지만, 루트 `package.json`의 `start:manager-scaffold` 스크립트로 개발자가 명시적으로 도달할 수 있다 — 배포·패키징 경로는 아니다 |
| 실행 시 개발용임을 명확히 표시 | 로그 접두사 `[manager-scaffold]`(`listen.ts:51-52`) · 포트 8445(운영 8444) · `package.json` description · 파일 헤더 주석 — 넷 다 있다 |
| 패키지 경계 유지 | `app.ts` 는 `/healthz` 하나뿐. `console.ts` 는 `src/web-console.ts` 재수출 4줄 |
| 부분 인증서 설정 시 종료 | **없다** → I-02 |

이 경로에 도달하려면 소스 체크아웃에서 `npm start -w @heliopause/manager` 또는 루트의
`npm run start:manager-scaffold`를 명시적으로 실행해야 한다. 배포 경로는 아니므로 Info 판정은
유지한다.

또한 초판이 언급하지 않은 사실: `listen.ts:50` 부근에서 인증 없이 프로세스를 죽일 수 있던
`decodeURIComponent` 결함은 `95487ea`(2026-08-24)에서 근본 위치인 `src/web-console.ts` 를
고쳐 세 호출자가 함께 닫혔다. 이 스캐폴드는 그 수정을 재수출로 상속한다.

## 저장소 밖에서 확인할 항목

### O-01. IdP Back-channel Logout URI 등록 여부 미확인

- 상태: **코드 완비 · 외부 IdP 설정 미검증**
- 코드 위치: `src/manager-server.ts:2980`(백채널 라우트) · `:3188`(시작 로그) ·
  `packaging/manager.env.example:81,113`
- 근거: `security-audits/2026-08-24-todo.md` §4.5 — 30항목 중 유일하게 안 닫힌 것

저장소 코드만으로는 KeyStone 클라이언트에 실제로 등록됐는지 확인할 수 없다. 저장소 밖의
운영 확인 기록(`2026-08-24-todo.md` §4.5)은 Back-channel Logout URI 하나를 남은 작업으로
기록한다. 배포 체크리스트(`docs/oidc-배포-체크리스트.md`)에는 `post_logout_redirect_uri`가
이미 등록 목록에 있다. 따라서 코드로 확인된 취약점이 아니라 외부 배포 설정의 미검증 항목으로
기록한다.

```
Back-channel Logout URI:  https://heliopause.tinyuniver.se/auth/backchannel-logout
backchannel_logout_session_required: off
post_logout_redirect_uri: https://heliopause.tinyuniver.se/
```

여기서 실제로 남은 등록 작업은 Back-channel Logout URI 하나이며,
`backchannel_logout_session_required: off`는 비어 있는 URI가 아니라 이 구현이 요구하는
설정값이다. Post-logout Redirect URI는 배포 체크리스트에 이미 기재되어 있다.

**미등록 시의 실패 방식은 조용하다.**

| | 미등록이면 |
|---|---|
| Back-channel Logout URI | **조용하다** — 강제 로그아웃이 아무에게도 안 닿고 **IdP 는 성공을 보고한다** |

코드 감사가 「코드는 정상」으로 넘길 수 있는 항목이지만, 넘기면 조용한 쪽의 사실이 어느 문서에도
남지 않는다. 그것이 여기 적는 이유다.

확인 방법:

```
IdP 에서 강제 로그아웃 → 매니저 저널에
[manager] backchannel-logout for sub <id>: N session(s) ended
```

줄이 아예 없으면 아직 미등록. 거부 줄이 나오면 등록은 됐고 토큰이 거부된 것이며, 그 줄이 이유를
말한다.

## 검토 결과 문제가 확인되지 않은 영역

다음 영역은 코드 호출 경로와 관련 테스트를 확인한 **검토 범위 안에서** 현재 구현상 취약점이나
기능 결함을 확인하지 못했다. 미검토 영역에는 이 결론을 확장하지 않는다.

- nft JSON allowlist 및 타 테이블 조작 방지
- `flush ruleset`, NAT, prerouting, postrouting 차단
- Ed25519 서명 검증 및 서명 대상 해시 결속
- 릴레이 인증서 CN과 heartbeat host 결속
- 롤백 commitment의 절대 deadline 처리
- workload UID/resourceVersion 기반 삭제·복구
- 릴레이 publish 권한 및 bundle 무결성 검사
- revocation snapshot 단조성 검사
- 세션 쿠키·Origin·CSRF 토큰 방어
- OIDC issuer·audience·nonce·PKCE 검증
- feed HTTPS·redirect 차단·응답 크기·wall-clock timeout
- nft 문자열 주입 및 호스트명 검증
- 정책 렌더러의 credential 보유 방지 검사
- subprocess 및 응답 body 크기 제한
  - 개정에서 추가 확인: 운영 코드에서 확인한 외부 프로세스 호출은 `execFileSync`(셸 없음)다 —
    `policy-screen.ts:157`(git) · `enrollment-store.ts:93`(openssl) ·
    `bin/heliopause-pki.ts:85,196` · `bin/heliopause-publish.ts:129,191,328` ·
    `bin/heliopause-ui.ts:38` · `packages/manager/src/listen.ts:28`. `exec(` 또는 `execSync` 로
    셸을 경유하는 운영 코드 자리는 없다. 테스트 코드의 `spawn` 호출은 이 확인에서 제외했다.

## 아직 아무 주장도 하지 않은 영역

⚠️ **초판에는 이 절이 없었다.** 위의 「문제 없음」 목록만 있으면 독자에게는 「확인함」과 「안 봄」이
구별되지 않고, 다음 감사가 그 위에 쌓을 수 없다.

이 감사가 읽지 않은 곳 (`2026-08-24-todo.md` 의 같은 목록과 일치):

`src/protocol.ts`(757) · `src/publish.ts`(417) · `src/geofeed.ts`(402) ·
`src/i18n.ts` 와 `packages/i18n`(1,561) · `src/coverage*.ts` · `src/zones.ts` ·
`src/device-*.ts` · `src/cf-devices.ts` · `src/site-*.ts` · `src/history-view.ts` ·
`src/where-used.ts` · `src/workload-traffic.ts` · `src/policy-lookup.ts` ·
`src/policy-screen.ts` · `src/policy-store.ts` · `src/policy-view.ts` · `src/routes.ts` ·
`src/ruleset-diff.ts` · `src/membership-record.ts` · `src/env-spec.ts` · `src/objects.ts` ·
`src/icons*.ts` · `src/design-tokens.ts` ·
`agent/heliopause-pull.py` 의 workload 롤백과 복구 경로(약 800줄) · `agent/heliopause-enroll.py` ·
대부분의 `bin/*` · `scripts/claude-hooks/*.py` · Svelte 컴포넌트 본문

3차 감사를 돌린다면 여기부터.

## 방법론 — 이 저장소에서 제외하면 안 되는 것

초판은 범위에서 「주석의 보안 주장 자체」를 명시적으로 뺐다. 다른 저장소에서는 합리적인 선택이다.
**여기서는 아니다.**

`2026-08-23-full-code-review.md` 가 찾은 결함의 상당수가 정확히 그 유형이었다.

| | 주석이 약속한 것 | 코드가 한 것 |
|---|---|---|
| §3.2 `fetchPolicySource` | 응답 크기 경계 | `await res.text()` — 전부 버퍼한 뒤 검사 |
| §3.3 `feeds.ts` | "A ceiling this tight is a guard in its own right" | 실제 상한 32MB, 피드별 256KB 는 다 받은 뒤 검사 |
| §2.7 `rollout.ts:353` | "Below never-seen for the opposite reason" | **지금 코드와 반대 순서**를 설명하는 죽은 분기 |
| §2.5 `NODE_TOKEN_PREFIX` | 「제대로 생긴 토큰」 관문 | 소스에 있는 공개 상수 7글자 — 완화 효과 사실상 0 |

이 저장소는 주석에 설계 판단을 싣는 스타일이다. 그래서 **주석–코드 불일치가 곧 결함**이고,
그것을 범위에서 빼면 이 저장소가 실제로 결함을 생산하는 방식을 통째로 안 보게 된다.
`AGENTS.md` 가 자기 문서에 대해 같은 일을 해 놓았다 — 「`policy/` 없으면 npm test 가 깨진다」고
오래 적혀 있었고 실측하면 아니었다.

## 검증 실행 결과

### 개정 재실행 — 2026-08-25

환경: 워크트리 `audit-b1-relay-buffering`, HEAD `3de1d05`, `policy/` · `node_modules` 심링크 연결,
macOS. `AGENTS.md` 「검사」 절의 명령 전부.

| 게이트 | 결과 |
|---|---|
| `npm test` | **1,770 + 8 + 194 · fail 0** |
| `python3 agent/test_validate.py` | `Ran 241 · OK (skipped=12)` → 실행 229 |
| `python3 agent/test_enroll.py` | `Ran 16 · OK` |
| `npm run typecheck` | 통과 (루트 + `@heliopause/manager`) |
| `npm run check:web` | `339 FILES 0 ERRORS 0 WARNINGS` |
| `npm run build:web` | 통과 |
| `npm run icons:check` | 아이콘 20종 전부 실재 |
| `node scripts/scan-public-history.mjs --worktree` | `site-data scan passed (worktree)` |
| 훅 스위트 7종 | 실패 0 |

`policy/` 심링크가 연결된 트리에서 돌렸다. 안 걸면 87개가 말없이 사라진다(`AGENTS.md`).

### 초판 실행 결과와 그 정정

초판이 보고한 것:

- `npm run typecheck` · `check:web` · `icons:check`: 통과
- `python3 agent/test_validate.py`: **241개 통과**
- `python3 agent/test_enroll.py`: 2개 테스트가 샌드박스의 loopback 소켓 생성 제한으로 실패
- 전체 `npm test`: 소켓 생성 제한으로 중단
- Ed25519 관련 12개 테스트: macOS LibreSSL의 `openssl -rawin` 미지원으로 skip

정정 셋:

1. **`test_validate.py` 는 241개가 통과한 것이 아니다.** `Ran 241 · OK (skipped=12)` — 실행은
   229다. 그리고 그 12건이 바로 아래 「Ed25519 12개 skip」과 같은 것이라 한 번 더 세어졌다.
2. **`test_enroll.py` 의 실패 2건은 코드 결함이 아니었다** — 같은 명령이 이 트리에서
   `Ran 16 · OK`. 초판의 「환경 제한으로 분류」는 결과적으로 맞았지만, 그것은 확인이 아니라
   추정이었다.
3. **`npm test` 는 중단된 것이 아니라 돌지 않은 것이다.** 그 상태에서 나온 「Medium 1 · Low 1」은
   실행된 검사의 결론이 아니다.

### 초판이 목록에 넣지 않은 게이트 셋

`AGENTS.md` 「검사」 절이 정본인데 초판 목록에서 빠져 있었다.

- `npm run build:web` — 타입 통과와 빌드 성공은 다른 것이다
- **`node scripts/scan-public-history.mjs`** — 이 저장소에서 「모든 게이트 통과」 보고 뒤에
  CI 를 3커밋 동안 빨갛게 세운 바로 그 잡이다(`2026-08-24-todo.md` 2차 검수 4건)
- 훅 스위트 7종

게이트 목록이 CI 잡 목록과 다르면 초록은 **목록의 초록**이지 CI 의 초록이 아니다.

## 미구현·더미 코드 점검

코드상 명확히 스캐폴드인 것은 `packages/manager`의 Hono 기반 서버다(`"private": true`, 어디에도
배포되지 않음). 실제 운영 매니저 기능은 `src/manager-server.ts`와 `bin/heliopause-manager.ts`에
있다.

그 밖의 mock·fixture는 테스트 코드에 한정되어 있었고, 운영 코드에서 인증·정책 적용을 우회하는
dummy branch나 빈 구현은 확인하지 못했다.

## 권장 우선순위

1. **M-01** — 완료. `enabled` 타입 검증과 회귀 테스트를 추가했다.
2. **L-02** — 완료. `revokeExisting` 두 경계의 입력 검증을 추가했다.
3. **I-02** — 완료. 스캐폴드 TLS 부분 설정을 실패 처리한다.
4. **O-01** — KeyStone 클라이언트의 Back-channel Logout URI 등록 여부를 운영 환경에서 확인한다.
   저장소 밖 작업이고, 백채널 쪽은 미등록이 조용하다.
5. 3차 감사를 돌린다면 「아직 아무 주장도 하지 않은 영역」 절부터, 그리고 **주석–코드 대조를
   범위에 넣고**.
