#!/usr/bin/env bash
# Runs every test suite, then reports. **All of them, then the verdict** — not `a && b && c`.
#
# ## Why this file exists rather than one line in package.json
#
# `npm test` was:
#
#     node --test "src/*.test.ts" "examples/*.test.ts" "policy/*.test.ts" \
#       && npm test -w @heliopause/manager --if-present \
#       && npm test -w @heliopause/web --if-present
#
# `&&` means the first failure ends the run, and the shape of this repository makes that a trap
# rather than a convenience. `policy/` is an untracked symlink into a **different clone**, and its
# suite tests that clone's `src/`, not this one (AGENTS.md). So the common local failure is two
# tests that have nothing to do with the change in hand — and when they fail, `@heliopause/manager`
# and `@heliopause/web` never run at all. Measured 2026-09-04, before this file: `npm test` printed
#
#     tests 1893 · fail 2
#
# and 214 tests in the two workspaces had not been attempted. The output reads as "2 of 1893
# failed", so the honest response — "those two are the known fork drift, carry on" — silently
# carries on without the console suite. **And CI cannot see this**, because `policy/` does not exist
# in a clean checkout, so there the first command passes and everything runs. Green in CI, a hole on
# the machine where the code is actually being written.
#
# Running everything and summing the failures costs a few seconds and removes the trap.
set -uo pipefail

cd "$(dirname "$0")/.."

failed=()

run() {
  local label="$1"; shift
  printf '\n\033[1m── %s ─────────────────────────────────────────\033[0m\n' "$label"
  if "$@"; then
    return 0
  fi
  failed+=("$label")
}

# The root suite. The policy glob matches nothing in a clean checkout and `node --test` passes an
# unmatched glob over in silence — that is deliberate upstream behaviour, and the reason AGENTS.md
# tells you to read the test *count* rather than the colour.
#
# ## `HELIOPAUSE_POLICY_DIR` — which checkout of the policy repository to run
#
# Unset, this is `policy`, which is what every checkout has had: a symlink into whichever clone
# holds that repository. Setting it points the glob somewhere else without touching this file.
#
# 🔴 **The directory's parent must hold the canonical `src/`.** This is a constraint of the policy
# repository, not of this variable: its files import `../src/*.ts`, and Node resolves that from
# where the file physically is. Measured 2026-10-06 against main, with the local `policy` symlink
# pointing into a retired clone: `node --test "policy/*.test.ts"` printed 107 collected, 91 passing,
# **16 failing** — 15 of them because that clone's `MAX_WATCH_SELECTORS` is 32 where this repository
# has 64, and one because it has no `BASELINE_NEVER_NAMESPACE` export. Pointing this variable at a
# clone in the wrong place reproduces that exactly.
#
# The renderer's **configured layout** satisfies the constraint and is the shape to copy: its
# manifest clones the policy repository into `/opt/heliopause/policy`, next to the image's own
# `src/`, so `../src` there is the canonical one. Read from the manifest and the Dockerfile — which
# image is running, at which commit, is a separate question this does not answer.
# @see stardust-deploy's `policy-render.yaml`
#
# ⚠️ Pointing it at a directory is not a promise that the tests there pass — it decides **which**
# tests run. Read the count, as the paragraph above says.
run "src + examples + policy" \
  node --test "src/*.test.ts" "examples/*.test.ts" "${HELIOPAUSE_POLICY_DIR:-policy}/*.test.ts"

# `--if-present` is kept: a workspace may legitimately have no suite. It is also why the workspace
# list is spelled out here — see `scripts/check-workspace-suites.sh`, which fails when a workspace
# grows a `test` script that nothing calls.
run "@heliopause/manager" npm test -w @heliopause/manager --if-present
run "@heliopause/web" npm test -w @heliopause/web --if-present

# The agent is Python, and its floors live with it — see the script. Running it from here is
# what makes `npm test` mean "everything", and what stops `packages/agent`'s `test` script from
# being a suite nobody calls (`check-workspace-suites.sh` enforces that).
run "@heliopause/agent" npm test -w @heliopause/agent --if-present

printf '\n'
if [ ${#failed[@]} -eq 0 ]; then
  echo "all suites passed"
  exit 0
fi
printf '\033[31m%d suite(s) failed:\033[0m\n' "${#failed[@]}"
for f in "${failed[@]}"; do echo "  · $f"; done
echo
echo "If only 'src + examples + policy' failed, check whether the failures are under policy/ —"
echo "that is a symlink into another clone and its tests do not read this repository's src/."
exit 1
