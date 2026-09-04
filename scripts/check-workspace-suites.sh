#!/usr/bin/env bash
# Every workspace that has a `test` script must be named by `scripts/run-tests.sh`.
#
# ## The failure this exists for
#
# The root runner names its workspaces one by one, because `npm test --workspaces` has no way to
# say "and fail if one of these has no suite". A named list is right, and a named list rots: add a
# workspace with tests, forget this line, and the suite is written, committed, reviewed, and never
# run. Nothing goes red. The count in AGENTS.md stops matching and nobody is looking at it either.
#
# Measured 2026-09-04: `packages/agent` already carried
#
#     "test": "python3 ../../agent/test_validate.py && python3 ../../agent/test_enroll.py"
#
# and **nothing called it**. `grep -rn "heliopause/agent" package.json .github/workflows/` returned
# nothing; CI invokes the two Python files directly instead. That one happened to be harmless — the
# same tests run by another route — but it is the shape, and the shape does not announce which case
# it is. The rule below closes it: a `test` script is a promise that something runs it.
set -euo pipefail

cd "$(dirname "$0")/.."

runner="scripts/run-tests.sh"
missing=()

# `npm query` reads the workspaces array from the root manifest, so a workspace that exists on disk
# but is not declared is invisible here — that is a different failure, and `check-workspaces.sh`
# would be the place for it. This asks only: of the workspaces npm knows about, which have a suite?
while IFS= read -r name; do
  [ -n "$name" ] || continue
  if ! grep -q -- "$name" "$runner"; then
    missing+=("$name")
  fi
done < <(npm query '.workspace' 2>/dev/null |
  node -e '
    const ws = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
    for (const w of ws) if (w.scripts?.test) console.log(w.name);
  ')

if [ ${#missing[@]} -eq 0 ]; then
  echo "every workspace with a test script is run by $runner"
  exit 0
fi

echo "::error::these workspaces declare a \`test\` script that $runner never calls:"
for m in "${missing[@]}"; do echo "  · $m"; done
echo
echo "Either add it to $runner, or delete the script — a suite nobody runs is worse than no suite,"
echo "because it looks like coverage."
exit 1
