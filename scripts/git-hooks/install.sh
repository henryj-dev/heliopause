#!/usr/bin/env bash
# 도구 중립 git 훅을 이 클론에 연결한다. **머신마다 한 번** 실행해야 한다.
#
# `.git/hooks/` 는 커밋되지 않으므로 훅을 거기 두면 클론마다 사라진다. 그래서 훅은
# 추적되는 `scripts/git-hooks/` 에 두고 `core.hooksPath` 로 가리킨다.
#
# ⚠️ `core.hooksPath` 는 `.git/config`(공용)에 들어가므로 **워크트리에도 함께 적용**된다.
#    훅 자신이 「메인 트리인가」를 보고 워크트리는 통과시키므로 그래도 된다.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
COMMON="$(git rev-parse --path-format=absolute --git-common-dir)"
MAIN="$(dirname "$COMMON")"

git -C "$MAIN" config core.hooksPath scripts/git-hooks
chmod +x "$MAIN/scripts/git-hooks/pre-commit"

echo "core.hooksPath = $(git -C "$MAIN" config core.hooksPath)"
echo "설치됨: $MAIN/scripts/git-hooks/pre-commit"
echo
echo "확인:  사람 셸에서 git commit --allow-empty -m probe   → 통과돼야 정상"
echo "       에이전트 세션에서 같은 명령                      → 거부돼야 정상"
echo "⚠️  --no-verify 로는 우회됩니다. 이건 경계가 아니라 위생 장치입니다."
