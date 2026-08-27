# AGENTS.md

에이전트(Claude · codex · 그 밖)가 이 저장소에서 지켜야 하는 규칙. `CLAUDE.md` 는 이 파일을
가리키는 심링크다 — **정본은 하나**다. 둘로 두면 갈라진다.

## 에이전트는 워크트리, 사람은 메인에서 작업

에이전트의 `Edit`/`Write`/트리 변경 git 명령은 메인에서 **항상 거부**된다. 사람은 메인에서
수정·커밋·push 할 수 있다. 에이전트 작업 흐름: 하네스 전용 worktree 도구 또는
`python3 scripts/claude-hooks/enter-worktree.py <이름>` → 생성된 경로에서 작업·커밋 →

```bash
git fetch origin && git rebase origin/main
git push -u origin <워크트리 브랜치>            # HEAD:main 이 아니다 — 아래
gh pr create --base main --fill                  # 본문에 무엇·왜·돌린 검사와 수
gh pr checks <n> --watch                         # 필수 검사 3개 + 나머지, 전부 초록까지
gh pr merge <n> --squash                         # 이것이 「메인 브랜치로 머지」다
```

**대화(작업 사이클)가 끝났다고 선언하려면 이 머지까지 끝나 있어야 한다.** 워크트리에 커밋만
남기거나 PR 만 열어 두고 미루면 그 사이클은 아직 메인에 반영되지 않은 것이다.

`main` 은 저장소 규칙으로 **PR 전용**이다(2026-08-26 실측: `git push origin HEAD:main` 이
`GH013 … Changes must be made through a pull request · 3 of 3 required status checks are expected`
로 거부된다). `gh pr merge --auto` 도 이 저장소에서는 꺼져 있어(`Auto merge is not allowed`)
검사가 끝난 뒤 사람 또는 에이전트가 머지 명령을 직접 친다. 가장 오래 걸리는 필수 검사는
`auto-rollback against a real kernel` 로 수 분이다. 여기에는 오래 「`push origin HEAD:main`
이 곧 머지」라고 적혀 있었고, 규칙이 바뀐 뒤(PR #10~#13 즈음)에도 그대로여서 첫 push 가
거부되고서야 알았다. `scripts/claude-hooks/main-tree-guard.py` 가 거부 메세지에 인쇄하는
`git push origin HEAD:<branch>` 힌트는 stardust 정본의 일반형이라 이 저장소에서는 **그대로
따르면 막힌다** — 그 훅은 사본이라 여기서 고치지 않는다.

메인은 세션 시작·종료에 깨끗할 때만 자동 fast-forward 된다. 사람이 메인에 미커밋을
쌓으면 그 최신화는 더러워서 건너뛴다 — 그것이 이 허용의 대가다. 사용자는 기다리지
않고 언제든 메인 트리에서 직접 `git pull`(ff-only) 을 받아도 된다.

에이전트에게 메인에서 통과하는 것: `Read`·`Grep`·`git status|log|diff|pull|fetch`.
에이전트가 정말 메인에서 해야 하면 `touch .git/claude-main-tree-rescue` (30분 TTL,
**사용자 승인 후에만**).

### 왜

여러 에이전트 세션이 같은 작업 트리를 공유하면 인덱스가 섞여 **남의 미완성 변경이
내 커밋에 딸려 들어간다.** 워크트리는 자기 인덱스와 자기 작업 트리를 가지므로 그
사고가 구조적으로 일어나지 않는다. 두 번째 값은 **메인을 에이전트가 안 더럽히면
항상 pull 할 수 있다**는 것 — 누가 작업 중인지 따질 필요가 없어져 세션 시작·종료의
최신화가 조건 없이 돈다. 사람이 메인에 미커밋을 쌓으면 그 최신화는 건너뛴다.

### 이 장치가 못 하는 것 — 「경계」로 읽지 말 것

1. **fail-open.** 세 층(Claude · codex · git) 다 내부 오류가 나면 통과시킨다. 훅 버그로 전
   세션이 서는 것이 동시 편집보다 나쁘다는 판단이다.
2. **`git commit --no-verify` 로 우회된다.** git 설계상 막을 수 없다.
3. **`core.hooksPath` 를 설정 안 한 클론에서는 git 층이 아예 안 돈다** — `bash scripts/git-hooks/install.sh`
   를 **머신마다 한 번** 돌려야 한다.
4. **편집을 막는 것은 에이전트 PreToolUse 층뿐이다.** git 층은 커밋 시점에만, 그리고
   **에이전트 하네스 환경이 있을 때만** 막는다. 사람은 메인에 커밋할 수 있다. 목록에
   없는 하네스는 사람으로 본다.
5. **codex 층은 `~/.codex/config.toml` 의 `[hooks.state]` 승인 없이는 안 돈다.** 파일이 있는
   것과 훅이 도는 것은 다르다.
6. **구제 파일이 살아 있는 동안은 가드가 통째로 열린다.** 검사가 DENY 케이스를 한꺼번에
   놓치면 먼저 `ls -l .git/claude-main-tree-rescue` 를 보라. 그 검사는 끝에 그 파일을
   지우므로, 남이 쓰던 구제 창을 내가 검사 돌리면서 닫는다.

## 새 워크트리에는 없는 것

`node_modules` · `policy` · `docs` · `pki-prod` · `pki-signing` 는 이 저장소에서 추적되지 않아
워크트리 체크아웃에 딸려오지 않는다. 거는 방법과 그 심링크가 격리를 뚫는 지점은
[`.claude/worktree-bootstrap.md`](.claude/worktree-bootstrap.md) 에 있다.

**`policy/` 가 없으면 `npm test` 는 깨지지 않는다 — 조용히 좁아진다.** 여기에는 오래
「깨진다」라고 적혀 있었다. 실측하면 아니다: `node --test` 는 아무것도 맞지 않는 글롭을 그냥
넘긴다. node 22(CI 가 고정한 버전)에서 `policy/` 없는 깨끗한 체크아웃이 통과했고, node 26 에서도
같다. 달라지는 것은 **수**다 — 이 트리에서 1,609, `policy/` 없이 1,522(2026-08-23 실측, 루트
`node --test` 기준). 87개가 말없이 사라진다.

그래서 위험은 반대 방향이다. 심링크를 안 건 워크트리에서 초록불을 보고 「정책까지 통과했다」고
읽게 된다. 정책을 건드렸다면 그 87개가 실제로 돌았는지 수를 보고 확인할 것.

`node_modules` 는 심링크로 걸어도 그 안에서 `npm install` 을 돌리면 npm 이 링크를 지우고 실제
디렉토리로 바꾼다. 그 편이 격리에는 낫지만 **메인 트리의 `node_modules` 와 갈라진다** — 워크트리
쪽에서 devDependency 를 추가했다면 메인에서도 한 번 `npm install` 을 돌려야 `npm run icons:check`
가 돈다.

## 검사

```bash
npm test                                                  # node --test (src + examples + policy)
                                                          #   + @heliopause/manager + @heliopause/web
python3 agent/test_validate.py                            # 에이전트 검증기·롤백 상태기계
python3 agent/test_enroll.py                              # 호스트 생성 키 · 지속 CSR 등록
npm run typecheck                                         # 루트(src + bin + examples) + @heliopause/manager
npm run check:web                                         # Svelte 진단 (루트 tsconfig 밖)
npm run build:web                                         # 타입 통과와 빌드 성공은 다른 것이다
npm run icons:check                                       # 아이콘 20종이 lucide-static 에 실재하는가
node scripts/scan-public-history.mjs --worktree           # 공개 레포에 사이트 데이터가 섞였는가
python3 scripts/claude-hooks/test-main-tree-guard.py      # 실패 0
python3 scripts/claude-hooks/test-enter-worktree.py       # 실패 0 (도구 중립 생성·소유권)
python3 scripts/claude-hooks/test-ignored-paths.py        # 실패 0 (이 레포 — 무시 경로 예외)
python3 scripts/claude-hooks/test-session-start-pull.py   # 실패 0
python3 scripts/claude-hooks/test-session-end-cleanup.py  # 실패 0
python3 scripts/claude-hooks/test-codex-hooks.py          # 실패 0
python3 scripts/git-hooks/test-pre-commit.py              # 실패 0 (사람 통과 · 에이전트 거부)
```

⚠️ **누출 스캔이 이 목록에 없어서 CI 가 세 커밋 동안 빨갛게 서 있었다.** 위 검사를 전부 돌리고
「모든 게이트 통과」라고 보고한 뒤, `defense-in-depth leak scan` 잡만 계속 실패하고 있었다. 로컬
게이트 목록이 CI 잡 목록과 다르면 초록불은 **목록의 초록**이지 CI 의 초록이 아니다. 걸린 것은
실제 사이트 데이터가 아니라 **결함을 설명하는 주석에 적은 예시 주소**였다 — 스캐너는 그 둘을
구별할 수 없고, 구별하려 들면 안 된다.

이 목록은 이제 CI(`.github/workflows/ci.yml` 의 `check` · `agent worktree guards`)에서도 돈다.
손으로 돌리는 것을 대신하지는 않는다 — 워크트리에서 훅을 고친 뒤 CI 가 알려주기를 기다리면
그 사이 세션이 이미 깨진 가드를 쓴다. CI 는 **아무도 안 돌린 날**을 위한 것이다.

⚠️ **수를 보라.** 「OK」는 무엇이 돌았는지 말하지 않는다. `agent/test_validate.py` 의
`if __name__ == "__main__"` 이 파일 중간에 있어서 그 아래 다섯 클래스(라우트 안전 검사
39개)가 정의조차 되지 않은 채 몇 달을 지났고, 초록불은 그동안 한 번도 흔들리지 않았다
— 수가 줄어든 게 아니라 센 적이 없어 비교할 기준선이 없었다. 현재 기대값(정책 심링크 연결):
`npm test` 1,803 + 8 (`@heliopause/manager`) + 206 (`@heliopause/web`) ·
`test_validate.py` 244 (실행 232 · skip 12) · `test_enroll.py` 16.

⚠️ 훅 검사 7종은 `refs/remotes/origin/HEAD` 를 필요로 한다. `git clone` 은 그것을 쓰지만
`actions/checkout` 은 안 쓴다 — 그래서 CI 쪽 job 이 먼저 `git symbolic-ref` 로 세운다.
없으면 `fatal: invalid reference: origin/HEAD` 로 첫 픽스처에서 통째로 죽는다.
