# 새 워크트리 준비

`EnterWorktree` 는 `.claude/settings.json` 의 `worktree.symlinkDirectories` 를 걸어 준다.
**하지만 실측에서 안 걸린 적이 있다** — 새 워크트리에서 아래 일곱 개가 있는지 눈으로 보고,
없으면 이 명령을 돌린다.

```bash
# 메인 트리는 git 에게 묻는다 — 경로를 적어 두면 다른 클론에서 그 줄이 거짓말을 한다.
MAIN="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
for d in node_modules policy docs pki pki-prod pki-util pki-signing; do
  [ -e "$d" ] || ln -s "$MAIN/$d" "$d"
done
ls -ld node_modules policy docs pki pki-prod pki-util pki-signing
```

이 일곱은 **이 저장소가 배포되는 사이트에만 있는 것**이다. 공개 클론에는 애초에 없고, 없어도
`npm test` · `npm run typecheck` · `npm run check:web` 는 `node_modules` 만 있으면 전부 돈다.
아래는 그 사이트에서 작업할 때의 이야기다.

## 왜 심링크인가 — 이 일곱은 **git 이 안 옮겨 준다**

전부 이 저장소에서 추적되지 않는다(이유는 `.gitignore` 의 주석에 적혀 있다). 워크트리
체크아웃은 추적된 파일만 가져오므로 **새 워크트리는 이것들이 통째로 없는 상태로 시작한다.**

| 디렉토리 | 없을 때 |
|---|---|
| `node_modules` | `npm test` · `npm run typecheck` 이 아예 안 돈다 |
| `policy` | 정책 스위트가 **말없이 빠진다** — 깨지지 않는다. `AGENTS.md` 의 「새 워크트리에는 없는 것」 참조. 자체 git 저장소다 |
| `docs` | 배포 설계 기록을 못 읽는다 (코드는 참조하지 않는다) |
| `pki-prod` · `pki-signing` | `heliopause-publish` · `heliopause-approve` 흐름을 워크트리에서 못 돌린다 |
| `pki` · `pki-util` | 함대를 못 읽는다. 매니저는 클라이언트 인증서를 **해당 VPC 의** CA 로 검증하므로, 조회에 쓰는 운영자 인증서와 CA 가 같은 VPC 의 것이어야 한다 |

⚠️ **CA 는 VPC 마다 하나인데 이름이 전부 같다.** 그래서 엉뚱한 것을 들이대도 「이름이 맞으니
되겠지」로 읽힌다 — 다른 VPC 의 운영자 인증서로 매니저를 부르면 `no client certificate and no
session` 이 돌아온다. 거절이 아니라 **핸드셰이크에서 아예 안 실린 것**이고, 증상은 「인증서를
안 보냈다」라 클라이언트가 고장 난 것처럼 보인다. 가르는 방법은 이름이 아니라 지문이다 —
손에 든 CA 와 매니저가 실제로 읽는 CA 의 SHA-256 지문을 각각 뽑아 비교할 것:

```bash
openssl x509 -in <손에 든 ca.pem> -noout -fingerprint -sha256
```

## 심링크가 격리를 뚫는 지점 — 알고 쓸 것

**`policy/` 는 자체 저장소이고 심링크다.** 워크트리에서 `policy/` 를 고치면 그 변경은 메인
트리와 **같은 실체**에 들어간다 — 이 저장소의 워크트리 격리는 `policy/` 에 걸리지 않는다.
정책 편집의 인터페이스는 그 저장소의 git 이지 이쪽 워크트리가 아니다.

같은 이유로 `pki/` · `pki-prod/` · `pki-util/` · `pki-signing/` 의 키와 발행물도 워크트리
사이에 공유된다. 두 워크트리에서 동시에 발행·승인 흐름을 돌리지 말 것.

### ⚠️ `node_modules` 심링크는 `check:web` 이 **메인 트리의 소스**를 읽게 만든다

`node_modules/@heliopause/i18n` 는 워크스페이스 링크라 `../../packages/i18n` 를 가리킨다. 그
상대 경로의 기준은 **링크가 놓인 `node_modules` 의 실제 위치** — 즉 메인 트리다. 그래서
`node_modules` 를 심링크로 걸어 둔 워크트리에서 `npm run check:web` 을 돌리면 svelte-check 은
`packages/i18n` 를 **메인 트리에서** 읽는다. `packages/core` · `packages/manager` 등 워크스페이스
패키지 전부가 같다.

실측 2026-08-24: 워크트리에서 `packages/i18n` 에 메시지 키를 하나 추가하고 그것을 Svelte 에서
쓰자, 그 파일이 워크트리에 실재하는데도 `check:web` 이 `is not assignable to parameter of type
MessageKey` 로 떨어졌다. **CI 는 통과한다** — 깨끗한 체크아웃에서 `npm ci` 를 돌리므로 링크가
자기 `packages/` 를 가리킨다. 즉 이 방향의 거짓 실패는 시끄럽고 안전하다.

**반대 방향이 위험하다.** 같은 날 같은 방법으로 확인했다 — 워크트리의 `packages/i18n` 에서
Svelte 가 실제로 쓰는 키(`m.withTraffic`)를 **지웠는데 그 삭제에 대한 오류가 한 줄도 안 나왔다.**
그 실행이 실패한 것은 위의 추가 때문이고, 추가가 없었다면 그냥 통과했을 것이다. 지역 링크를 걸고
같은 상태로 다시 돌리면 삭제가 즉시 잡힌다. 워크스페이스 패키지의 export 를 지우거나 이름을
바꿀 때, 링크 없는 초록불은 **워크트리의 코드에 대한 것이 아니다.**

워크트리 안에서 실제로 검사하려면 그 패키지만 지역 링크로 가려라(`node_modules` 는 어디서나
gitignore 되어 있어 커밋에 안 들어간다):

```bash
mkdir -p packages/web/node_modules/@heliopause
ln -sfn ../../../i18n packages/web/node_modules/@heliopause/i18n
npm run check:web
```

Node 와 TS 는 import 하는 파일에서 위로 올라가며 찾으므로 `packages/web/node_modules` 가 루트
것을 가린다. 워크스페이스 패키지를 건드렸다면 이걸 걸고 한 번 돌릴 것 — 안 걸었을 때의 초록은
**메인 트리의 초록**이다.
