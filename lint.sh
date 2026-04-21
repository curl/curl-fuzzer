#!/usr/bin/env bash
# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# SPDX-License-Identifier: curl
#
# Top-level lint. Runs every lint we have:
#   - C++:    clang-format (proto_fuzzer/) + Doxygen doc-coverage (proto_fuzzer/)
#   - Python: ruff check, ruff format --check, mypy (src/)
#
# Each block runs regardless of earlier failures; the script exits non-zero
# if any block failed, with a summary at the end. Missing tools are reported
# as skipped, not as failures — CI environments without clang-format or
# doxygen still get useful output for what they do have.
#
# Usage: ./lint.sh [-f]
#   -f   also auto-apply fixes where safe (clang-format -i, ruff format).

set -u

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "${REPO_ROOT}"

FIX_MODE=0

usage() {
    echo "Usage: $0 [-f]"
    echo "  -f   auto-apply fixes where safe (clang-format -i, ruff format)"
    exit 2
}

while getopts "fh" opt; do
    case "${opt}" in
        f) FIX_MODE=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

FAILED=()
SKIPPED=()
PASSED=()

run_check() {
    local name="$1"
    shift
    echo "--- [${name}] ---"
    if "$@"; then
        PASSED+=("${name}")
    else
        FAILED+=("${name}")
    fi
    echo
}

# --- C++ via CMake ---
if [[ -f build/CMakeCache.txt ]]; then
    if [[ ${FIX_MODE} -eq 1 ]]; then
        run_check "clang-format-fix" cmake --build build --target clang-format-fix
    fi
    run_check "cmake lint" cmake --build build --target lint
else
    echo "--- [cmake lint] SKIPPED: build/ not configured (run ./mainline.sh first) ---"
    echo
    SKIPPED+=("cmake lint")
fi

# --- Python ---
if command -v uv >/dev/null 2>&1; then
    if [[ ${FIX_MODE} -eq 1 ]]; then
        run_check "ruff format" uv run ruff format .
        run_check "ruff check --fix" uv run ruff check --fix .
    else
        run_check "ruff check" uv run ruff check .
        run_check "ruff format --check" uv run ruff format --check .
    fi
    run_check "mypy" uv run mypy src/
else
    echo "--- [ruff/mypy] SKIPPED: uv not installed ---"
    echo
    SKIPPED+=("ruff" "mypy")
fi

# --- Summary ---
echo "==================== lint summary ===================="
for name in "${PASSED[@]}";  do echo "  PASS    ${name}"; done
for name in "${SKIPPED[@]}"; do echo "  SKIP    ${name}"; done
for name in "${FAILED[@]}";  do echo "  FAIL    ${name}"; done
echo "======================================================"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
exit 0
