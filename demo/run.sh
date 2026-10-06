#!/usr/bin/env bash
# Reproduce an A-grade attribution without installing a debloat tool.
#
# Grade A means "the culprit's own record named it". Normally that requires a
# machine where Winhance actually ran and changed a setting. This demo swaps in
# a fixture so the whole chain is reproducible anywhere:
#
#   WHODUNIT_REGISTRY_FIXTURE  - a JSON snapshot of the registry to read
#   WHODUNIT_CHANGELOG_ROOT    - where %ProgramData%\Winhance\Logs\... resolves
#
# The tool still does the real work: it detects the symptom from the fixture
# registry, then reads the tool's own ChangeHistory.txt and quotes the line that
# names the exact setting. That is what earns grade A.
#
# Usage:  ./demo/run.sh            (zh by default)
#         LANG_CODE=en ./demo/run.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
lang="${LANG_CODE:-zh}"
bin="$root/dist/whodunit-windows-amd64.exe"
[ -x "$bin" ] || bin="$root/dist/whodunit-linux-amd64"

if [ ! -x "$bin" ]; then
  echo "build first: go build -o dist/whodunit-windows-amd64.exe ./cmd/whodunit" >&2
  exit 2
fi

export WHODUNIT_REGISTRY_FIXTURE="$here/registry.json"
export WHODUNIT_CHANGELOG_ROOT="$here"

# `why` exits 1 when a rule matched — that is the design (see the README), so it
# must not abort the demo under `set -e`. A 2 (usage/runtime error) still should.
run_why() {
  set +e
  "$bin" why "$@" -lang "$lang"
  code=$?
  set -e
  if [ "$code" -gt 1 ]; then
    echo "whodunit failed with exit $code" >&2
    exit "$code"
  fi
}

echo "=== scenario: Winhance blocked Windows Update, months ago ==="
echo "    observed: DisableWindowsUpdateAccess = 1"
echo "    question: who wrote it?"
echo
echo "--- step 1: whodunit rules (does any rule cover this symptom?) ---"
"$bin" rules -lang "$lang" | sed -n '1,40p'
echo
echo "--- step 2: whodunit why \"26H2\" ---"
run_why "26h2"
echo
echo "--- step 3: same, as JSON (grade A is machine-readable too) ---"
# No truncation here: CI greps this for "grade": "A", so the whole document
# must survive the pipe.
set +e
"$bin" why "26h2" -lang "$lang" -json
code=$?
set -e
[ "$code" -le 1 ] || exit "$code"