# heliopause 코드 전수 감사 보고서

- 감사일: 2026-08-24
- 대상: 저장소의 실행 코드 및 테스트 코드
- 제외: README, 설계 문서, 주석의 보안 주장 자체
- 방식: 코드 호출 경로 추적, 입력 경계·권한 경계·외부 프로세스 확인, 테스트 및 타입 검사 실행

## 요약

코드에서 확인된 우선 수정 사항은 1건이다.

| 심각도 | 개수 |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 1 |

주요 발견은 정책의 `enabled` 필드가 불리언인지 검증하지 않고 JavaScript의 truthy 규칙으로 변환한다는 점이다. `"false"`와 `"0"`이 활성화된 정책으로 처리된다.

## 발견 사항

### M-01. 비불리언 `enabled` 값이 조용히 활성화됨

- 심각도: Medium
- 위치: `src/policy.ts:450`, `normalizePolicy`
- 확신도: 확인됨

현재 구현:

```ts
enabled: o.enabled === undefined ? true : Boolean(o.enabled)
```

다음 입력이 모두 거부되지 않는다.

```json
{ "enabled": "false" }
{ "enabled": "0" }
```

JavaScript에서 두 문자열은 truthy이므로 결과적으로 정책이 활성화된다.

재현 결과:

| 입력 | 결과 |
|---|---|
| `"false"` | `true` |
| `"0"` | `true` |
| `0` | `false` |
| `null` | `false` |

영향:

- API나 정책 파일에 타입이 잘못된 값이 들어가도 입력 오류가 발생하지 않는다.
- 비활성화하려던 allow/deny 정책이 활성화될 수 있다.
- deny 정책이라면 의도하지 않은 트래픽 차단으로 이어질 수 있다.
- 정책 화면은 문자열을 다시 불리언으로 만들어 보내지만, 직접 API 호출·파일 편집·구형 클라이언트는 이 검사를 우회한다.

수정 제안:

```ts
const enabled = o.enabled === undefined
  ? true
  : typeof o.enabled === "boolean"
    ? o.enabled
    : (() => { throw bad("enabled must be a boolean"); })();
```

또는 별도의 타입 검증 함수로 분리하고 다음 회귀 테스트를 추가한다.

- `enabled: false`는 비활성화됨
- `enabled: true`는 활성화됨
- `enabled: "false"`, `enabled: "0"`, `enabled: 0`, `enabled: null`은 거부됨

### L-01. 운영 매니저와 별개인 인증 없는 스캐폴드 표면

- 심각도: Low
- 위치: `packages/manager/src/listen.ts:36-50`
- 확신도: 확인됨

이 실행 경로는 실제 `src/manager-server.ts`가 아니라 다음만 제공한다.

- `127.0.0.1:8445` 바인딩
- `/healthz`
- 정적 `/app`
- `requestCert: false`
- 인증·OIDC·쓰기 API 없음

인증서 환경 변수가 없으면 임시 자체서명 인증서를 생성한다. 현재 loopback 전용이므로 직접적인 원격 취약점은 확인되지 않았다. 다만 운영자가 이 명령을 실제 매니저로 오인하거나 향후 바인드 주소를 변경하면 인증 없는 콘솔 표면이 될 수 있다.

추가로 인증서 파일 중 하나만 설정된 경우에도 오류를 내지 않고 임시 인증서 경로로 넘어간다.

수정 제안:

- 개발용 스캐폴드와 운영용 실행 명령을 명확히 분리한다.
- 인증서 파일이 하나만 설정된 경우 즉시 종료한다.
- 실행 시 개발용·운영용임을 명확히 표시한다.
- 운영 매니저의 인증·권한 경로를 스캐폴드에 기대지 않도록 패키지 경계를 유지한다.

## 검토 결과 문제가 확인되지 않은 영역

다음 영역은 코드 호출 경로와 관련 테스트를 확인했으나 현재 구현상 취약점이나 기능 결함을 확인하지 못했다.

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
- 주요 subprocess 및 응답 body 크기 제한

## 미구현·더미 코드 점검

코드상 명확히 스캐폴드인 것은 `packages/manager`의 Hono 기반 서버다. 실제 운영 매니저 기능은 `src/manager-server.ts`와 `bin/heliopause-manager.ts`에 있다.

그 밖의 mock·fixture는 테스트 코드에 한정되어 있었고, 운영 코드에서 인증·정책 적용을 우회하는 dummy branch나 빈 구현은 확인하지 못했다.

## 검증 실행 결과

- `npm run typecheck`: 통과
- `npm run check:web`: 통과
- `npm run icons:check`: 통과
- `python3 agent/test_validate.py`: 241개 통과
- `python3 agent/test_enroll.py`: 2개 테스트가 샌드박스의 loopback 소켓 생성 제한으로 실패
- 전체 `npm test`: 소켓 생성 제한으로 네트워크·Unix socket 테스트가 진행되지 않아 중단
- Ed25519 관련 12개 테스트: macOS LibreSSL의 `openssl -rawin` 미지원으로 skip

테스트 실행 실패 중 소켓 생성 오류는 코드 assertion 실패가 아니라 감사 환경의 네트워크·Unix socket 권한 제한으로 분류했다.

## 권장 우선순위

1. `normalizePolicy`에서 `enabled`의 타입을 엄격히 검증하고 회귀 테스트를 추가한다.
2. Linux/OpenSSL 환경에서 전체 테스트를 다시 실행해 Ed25519 및 socket 테스트를 검증한다.
3. `packages/manager` 스캐폴드의 실행 계약과 운영 매니저의 실행 계약을 분리하고, 부분 인증서 설정을 실패 처리한다.
