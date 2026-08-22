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
`src/agent.ts`와 `agent/heliopause-agent.py`의 신뢰 경계를 겨냥한다.

## 사용법

1. 사용자가 "보안 감사시켜줘" 류 요청을 하면 아래 프롬프트를 그대로(또는 사용자가 지정한
   범위로 좁혀서) 보여주거나, Agent 툴로 `oh-my-Codex:security-reviewer`에 바로 전달한다.
2. 마지막 커밋 이후 `src/agent.ts`, `agent/heliopause-agent.py`, `src/policy.ts`,
   `src/objects.ts`, `src/nft.ts`가 크게 바뀌었으면, "중점 영역"의 파일:라인 참조가 여전히
   유효한지 먼저 확인하고 프롬프트를 보내기 전에 갱신한다.
3. 외부 에이전트에 보낼 때는 이 세션의 컨텍스트가 없으므로, 프롬프트 앞에 "먼저
   src/agent.ts, agent/heliopause-agent.py, src/policy.ts, src/nft.ts를 읽어라"를 유지한다
   (템플릿에 이미 포함되어 있음 — 지우지 말 것).

## 프롬프트

```
heliopause는 nftables를 관리하는 host firewall 제어 시스템이다. 코드 수정은 하지 말고
읽기 전용으로 감사해줘. 먼저 다음 파일을 읽어라:
- src/agent.ts (TS): 제어 플레인 — apply → verify → confirm 시퀀스로 룰셋을 호스트에 밀어넣음
- agent/heliopause-agent.py: 각 호스트에서 root로 도는 Python stdlib-only HTTP 서비스.
  Bearer 토큰 인증, 받은 룰셋을 검증한 뒤 `nft -f -`로 적용하고 rollback 타이머를 건다.
- src/policy.ts, src/objects.ts, src/nft.ts: 정책 모델 → nft 룰셋 렌더러

## 신뢰 경계
- 에이전트(agent/heliopause-agent.py)는 제어 플레인을 신뢰하지 않는다 — 코드 주석에도
  "The control plane is not trusted"라고 명시되어 있다.
- 에이전트는 자기 소유 테이블(`inet heliopause`, 기본값) 외에는 절대 건드리면 안 된다.
- 공격자 관점 1: 네트워크상에서 에이전트 HTTP 포트(기본 8099)에 접근 가능하지만 토큰이 없는 자.
- 공격자 관점 2: 유효한 토큰은 있지만 악의적이거나 버그가 있는 제어 플레인
  (validate_ruleset 우회를 시도하는 입장).
- 에이전트는 root로 돈다 (`nft`가 root를 요구하므로). 여기서의 우회는 곧 호스트 방화벽
  전체에 대한 임의 제어로 이어진다.

## 문서 vs 코드 원칙 (반드시 지킬 것)
이 리포의 docstring/주석은 강한 보안 주장을 여러 개 하고 있다. 그것들을 사실로 받아들이지
말고, 각 주장이 실제 코드로 성립하는지 직접 추적해서 검증해라. 특히:
- "Constant-time comparison so the token cannot be recovered by timing"
  (agent/heliopause-agent.py의 `_authed()` 근처) — 길이가 다를 때 조기 반환하는 경로가
  실제로 상수시간을 깨지 않는지 확인해라.
- "The control plane is not trusted" / "Anything that reaches beyond our own table is
  refused here" (`validate_ruleset()`) — 이 함수가 정말로 모든 우회 경로를 막는지, 아니면
  일부 nft 문법 패턴은 검사망을 피해가는지 확인해라.
- "flush ruleset is refused, always", "include is not allowed" — 정규식(`_FLUSH_RULESET`,
  `_INCLUDE`)이 대소문자/공백/줄바꿈/주석 삽입 변형에도 여전히 걸리는지 확인해라.
- "Only input and output hooks" — `_HOOK` 정규식이 모든 hook 선언 형태(다른 표현식,
  중첩 블록 등)를 잡아내는지 확인해라.
- "rollback does not require the control plane to be alive" (src/agent.ts 상단 주석) —
  실제로 rollback이 에이전트 로컬 타이머에만 의존하는지, 제어 플레인 쪽 코드 경로에
  이 보장을 깨는 지점이 없는지 확인해라.
각 주장에 대해 "확인됨" 또는 "주장됨(미검증)"으로 표시하고, 주장과 실제 구현이 다르면
그 자체를 finding으로 보고해라.

## 중점 영역
1. `validate_ruleset()` (agent/heliopause-agent.py:117) — 정규식 기반 파서다.
   `table` 선언문만 검사하는데, 기존에 존재하는 다른 테이블(`ip filter` 등)을 대상으로
   `add rule <family> <table> <chain> ...`처럼 테이블 선언 없이 규칙/체인을 주입하면
   family/name 검사를 우회할 수 있는지 확인해줘. 이게 성립하면 "다른 테이블은 절대 안
   건드린다"는 핵심 안전 보장이 깨지는 것이니 최우선으로 봐줘.
2. 인증 (`_authed`, agent/heliopause-agent.py:228) — 타이밍 사이드채널, 토큰 로테이션
   부재, 레이트리밋 부재로 인한 브루트포스 가능성.
3. 동시성 — `_lock`(agent/heliopause-agent.py:64)이 타이머 fire와 명시적
   confirm/rollback 요청 사이의 레이스를 실제로 다 막는지 (apply_ruleset,
   _do_rollback, _arm_timer 사이 상호작용, agent/heliopause-agent.py:140-209).
4. subprocess 사용 (`nft()` 함수, agent/heliopause-agent.py:85) — 인자 배열 방식이라
   셸 인젝션은 아니지만, stdin으로 넘기는 룰셋 텍스트에 대한 검증이 우회됐을 때
   `nft -f -`가 실제로 무엇까지 할 수 있는지.
5. src/agent.ts — 토큰이 로그/에러 메시지·예외 스택에 노출될 가능성, fetch 타임아웃/
   재시도 로직이 apply→verify→confirm 시퀀스의 안전성(특히 verify 실패 시 confirm을
   보내지 않는다는 보장)을 깨뜨릴 수 있는 경로.
6. DoS 표면: MAX_BODY(512KB), confirm_timeout_sec 범위(5-600) 외에 반복 apply/409 응답을
   유발하는 요청으로 인한 서비스 거부, ThreadingMixIn 하에서의 락 경합.
7. `src/policy.ts`, `src/objects.ts` — 정책 모델에서 렌더링된 nft 텍스트로 가는 경로에
   사용자/inventory 제공 값(호스트명, 주소, 서비스 이름 등)이 이스케이프 없이 문자열
   결합되어 nft 문법을 깨거나 의도치 않은 규칙을 주입할 수 있는지.

## 범위 밖
- 패키징/배포 (systemd unit 파일, 설치 스크립트)는 아직 초기 단계이므로 이번 감사에서 제외.
- CI/CD 파이프라인은 별도.

## 결과 형식
각 발견 사항마다:
- 심각도: Critical / High / Medium / Low
- 위치: 파일:라인
- 공격 시나리오: 구체적 입력값(가능하면 실제 nft 룰셋 텍스트 예시) → 실제로 벌어지는 일
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
