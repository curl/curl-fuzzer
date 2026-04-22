#!/usr/bin/env bash
#
# Replay corpora through instrumented fuzzer binaries, merge the resulting
# .profraw files, and emit a summary + HTML report restricted to curl's own
# lib/ and src/ trees. Invoked by codecoverage.sh after compile_target.sh
# has built the fuzz target with -fprofile-instr-generate -fcoverage-mapping.

set -eu

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export BUILD_ROOT; BUILD_ROOT=$(readlink -f "${SCRIPTDIR}/..")
# BUILD_DIR is set by codecoverage.sh; fall back to the plain build/ for
# direct invocation (e.g. if someone builds with coverage flags manually).
BUILD_DIR="${BUILD_DIR:-${BUILD_ROOT}/build}"
COVERAGE_DIR="${BUILD_DIR}/coverage"
PROFRAW_DIR="${COVERAGE_DIR}/profraw"

# Allow overriding the llvm tool names (some distros only ship versioned
# binaries, e.g. llvm-cov-18).
LLVM_PROFDATA="${LLVM_PROFDATA:-llvm-profdata}"
LLVM_COV="${LLVM_COV:-llvm-cov}"

# Source the canonical target list, then tack on curl_fuzzer_fnmatch which is
# built but intentionally not in fuzz_targets (unit-test fuzzer, not shipped
# to OSS-Fuzz). Callers can override the list via the TARGETS env var, e.g.
#   TARGETS=curl_fuzzer_proto ./scripts/run_coverage.sh
# to iterate on a single binary without replaying everything else.
# shellcheck disable=SC1091
. "${SCRIPTDIR}/fuzz_targets"
TARGETS="${TARGETS:-${FUZZ_TARGETS} curl_fuzzer_fnmatch}"

mkdir -p "${PROFRAW_DIR}"
# Wipe any stale profraw from a previous run so the merge reflects *this* run.
rm -f "${PROFRAW_DIR}"/*.profraw

# Locate curl's source tree. With CURL_SOURCE_DIR set, the coverage mapping
# records inside the binaries point at that tree; otherwise curl was fetched
# by ExternalProject into the default location below.
if [[ -n "${CURL_SOURCE_DIR:-}" ]]; then
  CURL_SRC="${CURL_SOURCE_DIR}"
else
  # Match the PREFIX set by the ExternalProject_Add(curl_external ...) block
  # in CMakeLists.txt when CURL_SOURCE_DIR is unset.
  CURL_SRC="${BUILD_DIR}/curl/src/curl_external"
fi
if [[ ! -d "${CURL_SRC}" ]]; then
  echo "warning: curl source tree not found at ${CURL_SRC}" >&2
  echo "         the coverage report filter may not match any files" >&2
fi

# %m-%p: per-module signature + PID. %p alone would collide if two targets
# happened to reuse a PID across sequential runs; %m keeps them apart.
export LLVM_PROFILE_FILE="${PROFRAW_DIR}/%m-%p.profraw"

for TARGET in ${TARGETS}; do
  CORPUS_DIR="${BUILD_ROOT}/corpora/${TARGET}"
  PUBLIC_CORPUS_DIR="${BUILD_ROOT}/ossfuzz_corpus/${TARGET}"
  BIN="${BUILD_DIR}/${TARGET}"
  if [[ ! -x "${BIN}" ]]; then
    echo "Skipping ${TARGET}: binary not found at ${BIN}"
    continue
  fi

  CORPUS_ARGS=()
  if [[ -d "${CORPUS_DIR}" ]]; then
    CORPUS_ARGS+=("${CORPUS_DIR}")
  fi
  # Public OSS-Fuzz corpus (if downloaded by scripts/download_public_corpus.sh)
  # contributes additional coverage without being checked in.
  if [[ -d "${PUBLIC_CORPUS_DIR}" ]]; then
    CORPUS_ARGS+=("${PUBLIC_CORPUS_DIR}")
  fi
  if [[ ${#CORPUS_ARGS[@]} -eq 0 ]]; then
    echo "Skipping ${TARGET}: no corpus dirs"
    continue
  fi

  INPUT_COUNT=0
  for DIR in "${CORPUS_ARGS[@]}"; do
    INPUT_COUNT=$(( INPUT_COUNT + $(find "${DIR}" -type f | wc -l) ))
  done
  echo "==> ${TARGET}: replaying ${INPUT_COUNT} inputs from ${#CORPUS_ARGS[@]} dir(s)"
  # The standalone runner walks each directory itself, so we get a single
  # process per target - one .profraw, no xargs batching. || true because a single
  # crashing input must not abort the whole coverage run.
  "${BIN}" "${CORPUS_ARGS[@]}" >/dev/null 2>&1 || true
done

PROFDATA="${COVERAGE_DIR}/coverage.profdata"
echo "==> Merging profraw -> ${PROFDATA}"
# shellcheck disable=SC2046
"${LLVM_PROFDATA}" merge -sparse \
  -o "${PROFDATA}" \
  "${PROFRAW_DIR}"/*.profraw

# Assemble the object list llvm-cov needs: the first binary is positional,
# the rest are -object=.
OBJECTS=()
FIRST_BIN=""
for TARGET in ${TARGETS}; do
  BIN="${BUILD_DIR}/${TARGET}"
  [[ -x "${BIN}" ]] || continue
  if [[ -z "${FIRST_BIN}" ]]; then
    FIRST_BIN="${BIN}"
  else
    OBJECTS+=("-object=${BIN}")
  fi
done

if [[ -z "${FIRST_BIN}" ]]; then
  echo "error: no fuzzer binaries found under ${BUILD_DIR}" >&2
  exit 1
fi

SUMMARY="${COVERAGE_DIR}/summary.txt"
HTML_DIR="${COVERAGE_DIR}/html"

echo "==> llvm-cov report (curl lib/ + src/)"
"${LLVM_COV}" report \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  "${CURL_SRC}/lib" "${CURL_SRC}/src" | tee "${SUMMARY}"

echo "==> llvm-cov show -> ${HTML_DIR}"
rm -rf "${HTML_DIR}"
"${LLVM_COV}" show \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  -format=html -output-dir="${HTML_DIR}" \
  -show-line-counts-or-regions \
  "${CURL_SRC}/lib" "${CURL_SRC}/src"

echo
echo "Coverage summary: ${SUMMARY}"
echo "HTML report:      ${HTML_DIR}/index.html"
# One-liner for the "how much did we cover" number.
awk '/^TOTAL/ {print "TOTAL line coverage: " $10}' "${SUMMARY}" || true
