#!/usr/bin/env python3
"""`main-tree-guard.py` 의 「무시되는 경로는 통과」 규칙을 알려진 양성·음성으로 고정한다.

훅은 **막는 쪽만 검사하면 오탐이 안 잡힌다** — 그 경고가 훅 본문에 이미 적혀 있어서,
이 검사는 통과해야 하는 것과 막혀야 하는 것을 **같은 목록에서** 돌린다.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "main-tree-guard.py")
MAIN = subprocess.run(["git", "-C", HERE, "rev-parse", "--path-format=absolute",
                       "--git-common-dir"], capture_output=True, text=True).stdout.strip()
MAIN = os.path.dirname(MAIN)

CASES = [
    # (설명, 통과해야 하나, payload)
    ("Edit  docs/… (무시·미추적)", True,
     {"tool_name": "Edit", "tool_input": {"file_path": MAIN + "/docs/조직별-구현-경계.md",
                                          "new_string": "x"}}),
    ("Write observe.log (무시·미추적·우리 저장소)", True,
     {"tool_name": "Write", "tool_input": {"file_path": MAIN + "/observe.log",
                                           "content": "x"}}),
    # ⚠️ 아래는 **다른 규칙**을 잰다. `policy/` 는 별도 저장소 심링크라 이 훅이 애초에
    #    관여하지 않는다(「우리 저장소의 메인 트리만 지킨다」). 처음엔 이것을 「무시되는
    #    경로는 통과」의 양성으로 넣었는데, 결함 주입에서 **호출을 빼도 통과**했다 —
    #    다른 이유로 통과하고 있었다. 지우지 않고 이름을 바꿔 남긴다: 두 규칙이 같은
    #    결과를 내는 자리라, 하나가 사라져도 다른 하나가 가려 준다는 것을 적어 둔다.
    ("Write policy/dev.ts — 별도 저장소라 관여 안 함(이 규칙이 아님)", True,
     {"tool_name": "Write", "tool_input": {"file_path": MAIN + "/policy/dev.ts",
                                           "content": "x"}}),
    ("Edit  src/index.ts (추적됨)", False,
     {"tool_name": "Edit", "tool_input": {"file_path": MAIN + "/src/index.ts",
                                          "new_string": "x"}}),
    ("Edit  섞임 — docs + src", False,
     {"tool_name": "Edit", "tool_input": {"file_path": MAIN + "/docs/README.md",
                                          "path": MAIN + "/src/index.ts",
                                          "new_string": "x"}}),
    ("Edit  없는 경로 (판정 불가)", False,
     {"tool_name": "Edit", "tool_input": {"file_path": MAIN + "/nope/none.txt",
                                          "new_string": "x"}}),
    ("Bash  git commit", False,
     {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}}),
    ("Bash  git add .", False,
     {"tool_name": "Bash", "tool_input": {"command": "git add ."}}),
    ("Bash  git status (읽기)", True,
     {"tool_name": "Bash", "tool_input": {"command": "git status"}}),
]

bad = 0
for label, want_allow, payload in CASES:
    payload["cwd"] = MAIN
    payload["session_id"] = "test"
    r = subprocess.run([sys.executable, GUARD], input=json.dumps(payload),
                       capture_output=True, text=True)
    allowed = not r.stdout.strip()
    ok = allowed == want_allow
    bad += 0 if ok else 1
    print(f"  {'ok  ' if ok else 'FAIL'}  {'통과' if allowed else '거부'}  "
          f"(기대 {'통과' if want_allow else '거부'})  {label}")


# ── 이 검사가 공허하지 않은가 ────────────────────────────────────────────────
#
# 🔴 **이 파일에는 변이 검사가 없었다.** 그리고 이 파일은 자기가 왜 그것을 필요로 하는지를
#    이미 위에 적어 두고 있었다 — `policy/dev.ts` 케이스는 「무시되는 경로는 통과」의 양성으로
#    넣었는데 결함을 주입해도 통과했고, 다른 규칙이 가려 주고 있었다. 그 자각이 있는 채로
#    나머지 8건이 같은 상태인지 아무도 모르는 상태로 남아 있었다.
#
#    `ignored_only` 호출을 지운 사본을 만들어, 「통과해야 하는 것」이 실제로 **그 규칙 때문에**
#    통과하는지 묻는다. 변이본에서도 통과하는 케이스는 다른 이유로 통과하고 있는 것이다.
MUT = GUARD.replace(".py", "_mut_ignored.py")
src = open(GUARD, encoding="utf-8").read()
mut = src.replace("    if ignored_only(tool, tool_input, tcwd):\n"
                  "        return                          # 인덱스에 들어갈 수 없는 경로 — 막을 근거가 없다\n",
                  "    if False:\n        return\n")
try:
    assert mut != src, "변이가 안 심겼다 — 이 검사는 무의미하다"
    open(MUT, "w", encoding="utf-8").write(mut)

    still_allowed = []
    for label, want_allow, payload in CASES:
        if not want_allow:
            continue                     # 거부 케이스는 변이해도 거부다 — 물을 것이 없다
        payload = dict(payload, cwd=MAIN, session_id="test")
        r = subprocess.run([sys.executable, MUT], input=json.dumps(payload),
                           capture_output=True, text=True)
        if not r.stdout.strip():
            still_allowed.append(label)

    # 다른 규칙이 가려 주는 자리는 **이름으로** 적어 둔다. 「몇 건 예외」로 세면 새로 생긴
    # 가림이 옛 가림과 구별되지 않는다.
    #
    #   · `policy/dev.ts` — 별도 저장소 심링크라 `ignored_only` 이전에 「우리 메인이 아니다」로
    #     빠진다. 위 CASES 주석이 설명하는 그 자리다.
    #   · `git status` — 읽기 명령 허용 규칙이 먼저 통과시킨다. 무시-경로 규칙과 무관하고,
    #     그래서 이 목록의 양성으로는 애초에 약하다. 남겨 두는 이유는 CASES 주석과 같다:
    #     **막는 쪽만 재면 「전부 막는 훅」도 통과하므로** 읽기가 계속 통과하는 것 자체를
    #     따로 고정할 값어치가 있다.
    EXPECTED_COVERED_ELSEWHERE = [
        "Write policy/dev.ts — 별도 저장소라 관여 안 함(이 규칙이 아님)",
        "Bash  git status (읽기)",
    ]
    leaked = [l for l in still_allowed if l not in EXPECTED_COVERED_ELSEWHERE]
    if leaked:
        bad += len(leaked)
        for l in leaked:
            print(f"  FAIL  변이본에서도 통과 — 이 케이스는 무시-경로 규칙을 재지 않는다: {l}")
    else:
        print(f"  ok    변이본(무시-경로 규칙 제거)에서 양성 {len(CASES) - len(still_allowed)}건이 "
              f"거부로 뒤집힌다 — 검사가 공허하지 않다")
finally:
    try:
        os.remove(MUT)
    except OSError:
        pass

print(f"\n{'모두 통과' if bad == 0 else str(bad) + '건 실패'}")
sys.exit(1 if bad else 0)
