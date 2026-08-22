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
