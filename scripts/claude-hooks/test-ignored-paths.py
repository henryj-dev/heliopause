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

print(f"\n{'모두 통과' if bad == 0 else str(bad) + '건 실패'}")
sys.exit(1 if bad else 0)
