#!/usr/bin/env python3
"""`.codex/hooks.json` 검사 — 등록이 살아 있고, 런처가 스크립트를 찾아 판정하는가.

**왜 따로 있나.** codex 는 Claude 와 같은 훅 이벤트·같은 입력 스키마를 쓰므로 스크립트를
공유한다. 그런데 **연결 부위가 다르다** — 등록 파일이 `.codex/hooks.json` 이고, 명령이
`$CLAUDE_PROJECT_DIR` 를 못 쓰므로 런처 셸 한 줄이 경로를 스스로 찾는다. 그 한 줄이
깨지면 **훅이 있는데 아무것도 안 도는** 상태가 되고, 그건 조용하다.

⚠️ **이 검사가 재는 것과 못 재는 것을 구분할 것.**
  - 잰다: JSON 유효성 · 셋(PreToolUse·SessionStart·SessionEnd) 등록 여부 · 런처가 경로를
    찾는가 · 메인/워크트리 판정 · 저장소 밖에서 조용히 통과하는가 · codex 모양(배열
    command·apply_patch) 처리.
  - 못 잰다: **codex 가 실제로 이 훅을 부르는지.** 프로젝트 훅은 `~/.codex/config.toml`
    의 `[hooks.state]` 에 `trusted_hash` 가 있어야 발화한다(사용자 승인). 승인 전에는
    이 검사가 전부 통과해도 **라이브에서는 아무 일도 안 일어난다.**
  - 못 잰다: **툴 이름과 입력 모양이 실제로 이것인지.** 아래 모양은 codex 바이너리에서
    읽은 것이고 라이브 발화로 확인하지 못했다. 다르면 여기부터 고칠 것.

⚠️ 런처는 `git rev-parse --show-toplevel` 로 스크립트를 찾는다. 즉 **워크트리에서 부르면
   워크트리의 사본**을, 메인에서 부르면 **메인의 사본**을 쓴다. 훅을 고쳐도 메인이 pull
   하기 전까지 메인 세션에는 안 먹는다(§2-1 의 그 지연이 여기에도 있다).
"""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def sh(*a, **kw):
    return subprocess.run(a, capture_output=True, text=True, **kw)


TOP = sh("git", "-C", HERE, "rev-parse", "--show-toplevel").stdout.strip()
COMMON = sh("git", "-C", HERE, "rev-parse", "--path-format=absolute",
            "--git-common-dir").stdout.strip()
MAIN = os.path.dirname(COMMON)
CONF = os.path.join(TOP, ".codex", "hooks.json")
fail = 0


def check(label, ok):
    global fail
    fail += not ok
    print(f"{'✓' if ok else '✗'} {label}")


def run(cmd, payload, cwd):
    p = subprocess.run(["sh", "-c", cmd], input=json.dumps(payload),
                       capture_output=True, text=True, cwd=cwd)
    return p.returncode, p.stdout.strip()


try:
    d = json.load(open(CONF, encoding="utf-8"))
    check("`.codex/hooks.json` 이 유효한 JSON 이다", True)
except Exception as e:
    print(f"✗ `.codex/hooks.json` 파싱 실패: {e}")
    sys.exit(1)

cmds, others = {}, 0
for ev, groups in (d.get("hooks") or {}).items():
    for g in groups:
        for h in g.get("hooks", []):
            c = h.get("command", "")
            if "main-tree-guard" in c:
                cmds["PreToolUse"] = c
            elif "session-start-pull" in c:
                cmds["SessionStart"] = c
            elif "session-end-cleanup" in c:
                cmds["SessionEnd"] = c
            else:
                others += 1

check("세 훅이 전부 등록돼 있다", set(cmds) == {"PreToolUse", "SessionStart", "SessionEnd"})
# 기존 규칙(ssh 허용 등)을 덮어쓰지 않았는가 — 남의 규칙을 조용히 지우면 그쪽이 조용히 깨진다.
# ⚠️ **이것은 개수일 뿐 검사가 아니다.** 원래 몇 개였는지 모르므로 「지워졌다」를 잴 수 없다.
#    실패로 세면 규칙이 원래 없던 레포에서 정상을 고장으로 오판한다(이식하며 실측).
#    병합했는지는 설치할 때 사람이 봐야 한다.
print(f"ℹ️ 우리 것 외 등록 {others} 건 — 원래 있던 규칙은 그대로여야 합니다(개수로는 못 잽니다)")

if "PreToolUse" not in cmds:
    print("\n실패", fail + 1, "건")
    sys.exit(1)

G = cmds["PreToolUse"]
WT = TOP if os.path.realpath(TOP) != os.path.realpath(MAIN) else None

rc, out = run(G, {"tool_name": "Edit", "tool_input": {"file_path": f"{MAIN}/PLAN.md"},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("메인에서 편집 → deny", "deny" in out)

if WT:
    rc, out = run(G, {"tool_name": "Edit", "tool_input": {"file_path": f"{WT}/PLAN.md"},
                      "cwd": WT, "session_id": "T"}, WT)
    check("워크트리에서 편집 → 통과", "deny" not in out)

# codex 모양 — 배열 command 와 apply_patch
rc, out = run(G, {"tool_name": "shell",
                  "tool_input": {"command": ["/bin/zsh", "-lc", "git commit -m x"]},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("배열 command 로 메인 커밋 → deny", "deny" in out)

rc, out = run(G, {"tool_name": "shell",
                  "tool_input": {"command": ["/bin/zsh", "-lc", "git status --short"]},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("배열 command 의 읽기 → 통과", "deny" not in out)

# 🔴 실측 형식 — `apply_patch` 는 패치를 **`command`** 로 보낸다(2026-08-15 codex 실측).
#    `input` 으로 가정했던 첫 판이 이 자리를 통과시켜 메인 트리에 파일이 생겼다.
rc, out = run(G, {"tool_name": "apply_patch",
                  "tool_input": {"command": f"*** Begin Patch\n*** Add File: {MAIN}/_probe.txt\n+x\n*** End Patch"},
                  "cwd": MAIN, "session_id": "T"}, MAIN)
check("apply_patch(command 키) 메인 편집 → deny", "deny" in out)

rc, out = run(G, {"tool_name": "apply_patch",
                  "tool_input": {"command": f"*** Begin Patch\n*** Update File: {WT or MAIN}/PLAN.md\n+x\n*** End Patch"},
                  "cwd": WT or MAIN, "session_id": "T"}, WT or MAIN)
check("apply_patch(command 키) 워크트리 → 통과", ("deny" not in out) if WT else True)

# fail-open — 저장소 밖에서 불려도 조용히 통과해야 한다(훅이 남의 작업을 막으면 안 된다)
rc, out = run(G, {"tool_name": "Edit", "tool_input": {"file_path": "/tmp/x.md"},
                  "cwd": "/tmp", "session_id": "T"}, "/tmp")
check("저장소 밖에서는 조용히 통과(rc=0)", rc == 0 and "deny" not in out)

print("\n실패", fail, "건")
sys.exit(1 if fail else 0)
