---
name: heliopause-security-audit
description: Generates the heliopause-specific security audit request prompt (trust boundaries, known risky patterns, doc-vs-code verification rule) for handing off to another security-specialized agent. Use when the user wants a full security audit of this repo done by another agent (internal subagent or external CLI agent), not just a review of the pending diff.
---

# heliopause Security Audit Brief

heliopause 전체 코드베이스를 다른 보안 전문 에이전트(내부 `security-reviewer` 서브에이전트든
외부 CLI 에이전트든)에게 감사시킬 때 쓰는, 이 리포에 특화된 감사 요청 프롬프트다. 범용 버전은
`security-audit-brief`(글로벌 스킬)를 참고 — 이 스킬은 그 원칙(문서는 증거가 아니라 검증 대상)에
heliopause의 실제 신뢰 경계와 알려진 의심 지점을 채워 넣은 완성본이다.

`/security-review`(pending diff 리뷰)와는 다르다. 이건 diff가 아니라 리포 전체, 특히
`agent/heliopause-pull.py` 와 `src/relay.ts` 의 신뢰 경계를 겨냥한다.

> ⚠️ **2026-08-23 갱신.** 이 브리프의 이전 판은 존재하지 않는 파일(`src/agent.ts`,
> `agent/heliopause-agent.py`)과 은퇴한 아키텍처(에이전트가 HTTP 서버를 열고 Bearer 토큰으로
> 인증하며 nft **텍스트**를 정규식으로 검사하는 push 모델)를 겨냥하고 있었다. 지금은 pull 모델이다:
> 에이전트는 **아무것도 listen 하지 않고**, mTLS 로 나가서 하트비트하며, 아티팩트는 **nft JSON**
> 이고 매니저의 Ed25519 서명을 커널에 손대기 전에 검증한다.

## 사용법

1. 사용자가 "보안 감사시켜줘" 류 요청을 하면 아래 프롬프트를 그대로(또는 사용자가 지정한
   범위로 좁혀서) 보여주거나, Agent 툴로 `oh-my-claudecode:security-reviewer`에 바로 전달한다.
2. 마지막 커밋 이후 `agent/heliopause-pull.py`, `src/relay.ts`, `src/artifact-signature.ts`,
   `src/manager-server.ts`, `src/nft.ts`, `src/policy.ts` 가 크게 바뀌었으면, "중점 영역"의
   파일:라인 참조가 여전히 유효한지 먼저 확인하고 프롬프트를 보내기 전에 갱신한다. **줄 번호는
   빠르게 썩는다 — 함수 이름으로 다시 찾을 것.**
3. 외부 에이전트에 보낼 때는 이 세션의 컨텍스트가 없으므로, 프롬프트 앞의 "먼저 이 파일들을
   읽어라" 목록을 유지한다 (템플릿에 이미 포함되어 있음 — 지우지 말 것).

## 프롬프트

```
heliopause는 nftables를 관리하는 host firewall 제어 시스템이다. 코드 수정은 하지 말고
읽기 전용으로 감사해줘. 먼저 다음 파일을 읽어라:

- agent/heliopause-pull.py: 각 호스트에서 root로 도는 Python stdlib-only 프로세스.
  아무 포트도 listen 하지 않는다. mTLS 로 relay 에 하트비트하고, 응답에 실린 아티팩트를
  서명·구조 검증한 뒤 `nft -j -f` 로 적용하고 롤백 타이머를 무장한다.
- src/relay.ts: VPC 당 하나. 아티팩트를 서빙하고 하트비트를 수집한다. 정책을 렌더하지
  않으며 룰셋을 만들어낼 수 없다. `peerCN()` 이 신원 결속의 전부다.
- src/artifact-signature.ts: 매니저 Ed25519 인가 봉투 — relay 는 신뢰 없는 배달부다.
- src/manager-server.ts: 사이트 매니저 HTTP 표면 (plan → approve → publish, 등록, 콘솔).
- src/nft.ts, src/policy.ts, src/objects.ts: 정책 모델 → nft 룰셋/JSON 렌더러
- src/revocation-writer.ts, src/revocation-snapshot.ts: 권한 분리된 폐기목록 writer

## 신뢰 경계
- 에이전트는 relay 를 신뢰하지 않는다. relay 는 **배달부**이고, 실제 권위는 매니저의
  Ed25519 서명이다. 침해된 relay 가 룰셋과 그 해시를 함께 바꿔치기해도 서명은 못 만든다.
- 에이전트는 자기 소유 테이블(`inet heliopause`, 기본값) 외에는 절대 건드리면 안 된다.
- 공격자 관점 1: relay 를 장악한 자 (또는 relay ↔ 에이전트 경로에 있는 자).
- 공격자 관점 2: 유효한 **에이전트** 인증서 하나를 가진 침해된 저가치 호스트. 이 자가
  canary 로 보고할 수 있으면 단계적 롤아웃은 장식이 된다.
- 공격자 관점 3: 매니저 콘솔에 세션을 가진 브라우저 — 또는 그 브라우저가 열어 둔 다른 탭
  (CSRF). 인증서와 달리 쿠키는 교차 출처로 실려 간다.
- 에이전트는 root로 돈다 (`nft`가 root를 요구하므로). 여기서의 우회는 곧 호스트 방화벽
  전체에 대한 임의 제어로 이어진다.

## 문서 vs 코드 원칙 (반드시 지킬 것)
이 리포의 docstring/주석은 강한 보안 주장을 아주 많이 한다 — 그리고 그 주장들은 종종
"과거에 실측된 실패"를 근거로 든다. 그것들을 사실로 받아들이지 말고, 각 주장이 지금 코드로
성립하는지 직접 추적해서 검증해라. 특히:

- "The agent applies only what its manager published" — `verify_artifact_envelope()` 와
  `_validate_signed_entry()` 가 정말로 모든 경로에서 불리는지, 서명 검증을 건너뛰고
  적용에 도달하는 분기가 없는지 확인해라.
- "Anything outside our table is refused" (`validate_artifact()`) — nft **JSON** 의 모든
  요소가 family/table 을 자기 안에 이름 붙이는가, 아니면 이름을 생략할 수 있어 검사에서
  빠지는 요소 종류가 있는가.
- "flush ruleset is refused, always" — JSON 표현에서 그 동작이 어떤 키로 나타나는지,
  allowlist 가 정말 닫혀 있는지(모르는 키를 거부하는지, 무시하는지) 확인해라.
- "Rollback is armed before the apply is trusted" / "commitment survives the agent's own
  death" — `_persist_commitment()` → 커널 → `confirm()` 순서와 `recover_commitment()` 의
  재기동 경로. 상대 시간이 아니라 **절대 기한**인지, `prepared` 와 `pending` 이 다른
  의미를 갖는지, fsync + atomic rename 이 실제로 되는지.
- "A host cannot report as another host" (`peerCN()`) — 클레임된 host 필드와 인증서 CN 을
  비교하는 지점이 하나뿐인지, 우회 가능한 두 번째 경로(예: 캐시, 재사용된 연결)가 없는지.
- "Revocation state is fail-closed and monotonic" — writer 가 기존 row 의 생략/재작성을
  정말 거부하는지, relay 가 파일을 직접 못 쓰는 것이 코드가 아니라 배포(systemd)에만
  의존하는 부분은 어디까지인지.
- "The relay cannot invent policy" — `POST /publish` 가 받은 번들을 자기 매니페스트의
  다이제스트와 대조하는 것 외에 relay 가 내용을 만들어낼 수 있는 경로가 없는지.

각 주장에 대해 "확인됨" 또는 "주장됨(미검증)"으로 표시하고, 주장과 실제 구현이 다르면
그 자체를 finding으로 보고해라. **주석이 실측을 인용한다고 해서 그 실측이 지금도 유효한
것은 아니다.**

## 중점 영역
1. `validate_artifact()` (agent/heliopause-pull.py, `def validate_artifact`) — nft JSON
   구조 allowlist. 텍스트 파싱을 버리고 JSON 으로 옮긴 이유가 "모든 요소가 family/table 을
   스스로 이름 붙이므로 필드 비교가 된다"인데, 그 전제가 모든 요소 종류에 대해 참인지.
   `_is_ours()`, `_without_nft_runtime()`, `snapshot()` 전후 diff 백스톱도 함께.
2. 서명 검증 체인 — `verify_artifact_envelope()`, `_validate_signed_entry()`,
   `_validate_signed_routes()`, `_verify_ed25519()`, `load_artifact_trust()`.
   `_verify_ed25519()` 는 openssl 을 **임시 파일**로 호출한다 (파이프로는 실패하는 것을
   실측했다는 주석이 있다). 그 임시 파일 경로/권한/정리, 그리고 검증 실패와 "검증을
   실행하지 못함"이 구분되는지. `_strict_json`, `_exact_keys`, `_b64url` 의 상한.
3. 롤백 상태기계 — `_persist_commitment()`, `recover_commitment()`, `rollback()`,
   `apply_artifact()`, `confirm()`, `rollback_generation()`. 타이머 발화와 명시적
   confirm/rollback 사이의 레이스, 크래시 루프가 기한을 무한 연장할 수 있는지,
   `prepared` 상태에서 재기동했을 때 side effect 유무가 불명확한 구간.
4. 워크로드(Cilium) 절반 — `validate_workload()`, `_owned_object_error()`,
   `_verify_workload_identity()`, `_delete_workload_object()`, `rollback_workload()`.
   identity-bound 롤백이 "우리가 만들지 않은 객체는 절대 덮어쓰지 않는다"를 실제로
   보장하는지, UID/resourceVersion precondition 이 빠지는 경로가 있는지.
5. relay 신원 결속과 게이트 — `src/relay.ts` 의 `peerCN()`/하트비트 처리,
   `src/rollout.ts` 의 `computeGate()`. canary 게이트를 여는 입력이 전부 인증서에
   결속된 신원에서만 오는지.
6. 매니저 쓰기 표면 — `src/manager-server.ts` 의 `/plan` → `/approve` → `/publish`,
   `src/approval.ts`(제안자 ≠ 승인자, 내용 주소화), `src/session.ts`(쿠키 CSRF 다층 방어),
   `src/oidc.ts`, `src/otp.ts`, `src/set.ts`(역할 취소의 즉시성). 세션 경로가 인증서
   경로와 같은 권한을 갖는데, 쿠키는 교차 출처로 실린다는 점을 중심으로.
7. 폐기목록 권한 분리 — `src/revocation-writer.ts`, `src/revocation-snapshot.ts`,
   `bin/heliopause-revocation-writer.ts`. 단조성/상한 검사가 소켓 너머에서 다시 되는지,
   relay 가 파일을 직접 조작할 수 없다는 보장이 코드/배포 중 어디에 있는지.
8. 렌더러 주입면 — `src/nft.ts`, `src/policy.ts`, `src/objects.ts`, `src/geofeed.ts`,
   `src/device-policy.ts`. inventory/resolver/geofeed 가 준 값(호스트명, 주소, 서비스
   이름, CSV 한 줄)이 이스케이프 없이 문자열 결합되어 nft 문법을 깨거나 의도치 않은
   규칙을 만들 수 있는지. **특히 "넓어지는 방향"의 실패** — 매치 조건이 조용히
   사라져 규칙이 전부에 걸리는 경우.
9. 정책 렌더러 격리 — `src/policy-render-guard.ts`, `bin/heliopause-policy-render.ts`.
   자격증명 없는 프로세스라는 주장이 실제로 기동 전에 검사되는지, 검사가 우회 가능한지.
10. DoS 표면: 요청/번들/스냅샷 크기 상한(`MAX_*_BYTES`), `nft`/`kubectl` subprocess
    타임아웃, relay 의 하트비트 처리 비용, 정규식 백트래킹(`src/policy.ts` 의
    `USER_EMAIL` 은 이미 한 번 이 이유로 좁혀졌다 — 남은 정규식들도 볼 것).

## 범위 밖
- CI/CD 파이프라인(`.github/workflows`)은 별도 감사 대상. 단, 워크플로가 **주장하는**
  보안 속성(예: `trusted-leaks.yml` 이 후보 코드를 실행하지 않는다)이 이 리포의 문서에
  적혀 있다면 그 주장의 사실 여부는 범위 안이다.
- 워크트리 가드(`scripts/claude-hooks`, `scripts/git-hooks`)는 개발 위생이지 제품
  보안 경계가 아니다 — 명시적으로 fail-open 이라고 문서화되어 있다.

## 결과 형식
각 발견 사항마다:
- 심각도: Critical / High / Medium / Low
- 위치: 파일:라인 (+ 함수 이름 — 줄 번호는 썩는다)
- 공격 시나리오: 구체적 입력값(가능하면 실제 nft JSON / 봉투 / HTTP 요청 예시) →
  실제로 벌어지는 일
- 확신도: 확인됨(코드로 추적 완료) / 의심됨(추가 확인 필요) / 문서-구현 불일치
- 수정 제안

발견 사항이 없는 영역도 "검토했으나 문제 없음"으로 짧게 언급해줘 (침묵하지 말 것).

## 출력 언어 및 저장
- 결과는 한국어로 작성해줘.
- 감사가 끝나면 위 내용을 마크다운 리포트로 정리해서
  `security-audits/<YYYY-MM-DD>-heliopause-security-audit.md`(리포지토리 루트 기준)에
  저장해줘. 대상 파일 목록, 신뢰 경계 요약, "문서 vs 코드" 검증 결과표(주장 / 확인됨·주장됨·
  불일치), 발견 사항 표를 포함해줘. 저장 후 채팅에는 파일 경로와 심각도별 개수 요약만
  짧게 남겨줘 (본문 전체를 다시 출력하지 마).
```
