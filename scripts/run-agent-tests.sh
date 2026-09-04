#!/usr/bin/env bash
# The agent's Python suites, and the floors that make "OK" mean something.
#
# ## `OK` does not say what ran
#
# `test_validate.py` once had its `if __name__ == "__main__"` block in the middle of the file, so
# `unittest.main()` ran and `sys.exit()`ed before five classes below it were defined — 39
# route-safety tests, green the whole time. Nothing could have noticed: the count did not drop, it
# had never been counted.
#
# ## Two floors, because `Ran N` counts the ones that were skipped
#
# `TestEd25519Verification` and `TestSignedRoutesReachTheApplier` — 12 tests — are gated on the
# agent's own openssl having `-rawin`, which LibreSSL does not. That gate is right: it is the same
# binary `heliopause-pull.py` shells out to, so on a developer's macOS they skip and on a Linux
# runner they run. Measured in `ubuntu:24.04`: OpenSSL 3.0.13, `Ran 263` with no skips.
#
# But `Ran 263` is printed whether those 12 ran or were skipped, so a floor on `Ran` alone cannot
# tell the difference. If a runner image ever ships an openssl without `-rawin`, the only tests that
# check artifact signature verification would switch off in silence and the floor would still pass.
# That is the exact defect those tests exist to catch — a tool failing before the cryptography, and
# the fleet then rejecting every correct artifact while the error blames the manager.
#
# So: on Linux, no skips are tolerated. Elsewhere they are reported and allowed, because refusing
# would mean the suite cannot be run at all on the machine where the code is written.
#
# ## And `test_enroll.py` had no floor at all
#
# CI counted `test_validate.py` and not this one, so the whole enrolment suite could stop being
# discovered — the same accident as above — with nothing to notice. 16 is what it holds today.
set -euo pipefail

cd "$(dirname "$0")/.."

# Floors, not expectations: they catch a suite vanishing, not a test being added. Raise them when
# the real count moves comfortably past — a floor that equals the count fails on the next commit.
VALIDATE_FLOOR=250
ENROLL_FLOOR=14

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

count() { sed -n 's/^Ran \([0-9]*\) tests.*/\1/p' "$1" | tail -1; }
skips() { sed -n 's/^OK (skipped=\([0-9]*\)).*/\1/p' "$1" | tail -1; }

check_suite() {
  local name="$1" floor="$2"
  local ran skipped
  ran="$(count "$log")"
  skipped="$(skips "$log")"
  : "${ran:=0}" "${skipped:=0}"
  echo "$name: ran $ran, skipped $skipped"

  if [ "$ran" -lt "$floor" ]; then
    echo "::error::$name ran $ran tests, expected at least $floor — did a suite stop being discovered?"
    return 1
  fi

  # Linux is what the hosts and the runners are. Anywhere else, a skip is a missing local tool.
  if [ "$skipped" -gt 0 ]; then
    if [ "$(uname -s)" = "Linux" ]; then
      echo "::error::$name skipped $skipped test(s) on Linux — the openssl gate should never fire here."
      echo "         Those are the signature-verification tests; skipping them silently is the"
      echo "         failure they exist to catch. Check \`openssl pkeyutl -help\` for -rawin."
      return 1
    fi
    echo "  note: $skipped skipped — this is not Linux, so the openssl gate is expected to fire."
    echo "        Those tests run in CI. To run them here: HELIOPAUSE_OPENSSL_BIN=\$(brew --prefix openssl@3)/bin/openssl"
  fi
  return 0
}

rc=0
python3 agent/test_validate.py 2>&1 | tee "$log"
check_suite "test_validate.py" "$VALIDATE_FLOOR" || rc=1

python3 agent/test_enroll.py 2>&1 | tee "$log"
check_suite "test_enroll.py" "$ENROLL_FLOOR" || rc=1

exit "$rc"
