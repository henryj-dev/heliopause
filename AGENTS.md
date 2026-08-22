# AGENTS.md

에이전트(Claude · codex · 그 밖)가 이 저장소에서 지켜야 하는 규칙. `CLAUDE.md` 는 이 파일을
가리키는 심링크다 — **정본은 하나**다. 둘로 두면 갈라진다.

## 에이전트는 워크트리, 사람은 메인에서 작업

에이전트의 `Edit`/`Write`/트리 변경 git 명령은 메인에서 **항상 거부**된다. 사람은 메인에서
수정·커밋·push 할 수 있다. 에이전트 작업 흐름: 하네스 전용 worktree 도구 또는
`python3 scripts/claude-hooks/enter-worktree.py <이름>` → 생성된 경로에서 작업·커밋 →
`git fetch origin && git rebase origin/main && git push origin HEAD:main`

**대화(작업 사이클)가 끝났다고 선언하려면 이 push 까지 끝나 있어야 한다 — 그것이 곧
「메인 브랜치로 머지」다.** 별도의 병합 절차는 없다. 워크트리에 커밋만 남기고 push 를
미루면 그 사이클은 아직 메인에 반영되지 않은 것이다.

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
같다. 달라지는 것은 **수**다 — 이 트리에서 1,583, `policy/` 없이 1,496. 87개가 말없이 사라진다.

그래서 위험은 반대 방향이다. 심링크를 안 건 워크트리에서 초록불을 보고 「정책까지 통과했다」고
읽게 된다. 정책을 건드렸다면 그 87개가 실제로 돌았는지 수를 보고 확인할 것.

`node_modules` 는 심링크로 걸어도 그 안에서 `npm install` 을 돌리면 npm 이 링크를 지우고 실제
디렉토리로 바꾼다. 그 편이 격리에는 낫지만 **메인 트리의 `node_modules` 와 갈라진다** — 워크트리
쪽에서 devDependency 를 추가했다면 메인에서도 한 번 `npm install` 을 돌려야 `npm run icons:check`
가 돈다.

## 검사

```bash
npm test                                                  # node --test (src + policy)
npm run typecheck
npm run icons:check                                       # 아이콘 20종이 lucide-static 에 실재하는가
python3 scripts/claude-hooks/test-main-tree-guard.py      # 실패 0
python3 scripts/claude-hooks/test-enter-worktree.py       # 실패 0 (도구 중립 생성·소유권)
python3 scripts/claude-hooks/test-ignored-paths.py        # 실패 0 (이 레포 — 무시 경로 예외)
python3 scripts/claude-hooks/test-session-start-pull.py   # 실패 0
python3 scripts/claude-hooks/test-session-end-cleanup.py  # 실패 0
python3 scripts/claude-hooks/test-codex-hooks.py          # 실패 0
python3 scripts/git-hooks/test-pre-commit.py              # 실패 0 (사람 통과 · 에이전트 거부)
```
