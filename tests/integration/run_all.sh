#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FAIL=0

for test in "$SCRIPT_DIR"/test_*.sh; do
    echo ""
    echo "========================================"
    echo "  Running: $(basename "$test")"
    echo "========================================"
    if bash "$test"; then
        echo "  -> PASSED"
    else
        echo "  -> FAILED"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "All test suites passed."
else
    echo "$FAIL test suite(s) failed."
    exit 1
fi
