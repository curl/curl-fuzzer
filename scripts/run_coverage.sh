#!/usr/bin/env bash
#
# Replay corpora through instrumented fuzzer binaries, merge the resulting
# .profraw files, and emit separate reports for libcurl and the checked-in
# fuzzer harness. Invoked by codecoverage.sh after compile_target.sh
# has built the fuzz target with -fprofile-instr-generate, -fcoverage-mapping,
# and -fprofile-update=atomic.

set -euo pipefail

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export BUILD_ROOT; BUILD_ROOT=$(readlink -f "${SCRIPTDIR}/..")
# BUILD_DIR is set by codecoverage.sh; fall back to the plain build/ for
# direct invocation (e.g. if someone builds with coverage flags manually).
BUILD_DIR="${BUILD_DIR:-${BUILD_ROOT}/build}"
COVERAGE_DIR="${BUILD_DIR}/coverage"
PROFRAW_DIR="${COVERAGE_DIR}/profraw"
REPLAY_STATUS="${COVERAGE_DIR}/replay-status.json"
REPLAY_LOG_DIR="${COVERAGE_DIR}/replay-logs"
REPLAY_COUNTER_DIR="${COVERAGE_DIR}/replay-counters"

# Allow overriding the llvm tool names (some distros only ship versioned
# binaries, e.g. llvm-cov-18).
LLVM_PROFDATA="${LLVM_PROFDATA:-llvm-profdata}"
LLVM_COV="${LLVM_COV:-llvm-cov}"

# Source the canonical target list. Callers can override the list via the
# TARGETS env var, e.g.
#   TARGETS=curl_fuzzer_proto ./scripts/run_coverage.sh
# to iterate on a single binary without replaying everything else.
# shellcheck disable=SC1091
. "${SCRIPTDIR}/fuzz_targets"
. "${SCRIPTDIR}/fuzz_corpus_helpers.sh"
TARGETS="${TARGETS:-${FUZZ_TARGETS}}"

# Remove old derived reports before replay so failed runs cannot upload them.
mkdir -p "${PROFRAW_DIR}"
rm -f "${COVERAGE_DIR}"/{coverage.profdata,coverage.profdata.tmp,summary.txt,harness-summary.txt,curl-coverage.json,harness-coverage.json,report.md,gaps.json}
rm -rf "${COVERAGE_DIR}/html" "${COVERAGE_DIR}/harness-html" \
  "${REPLAY_LOG_DIR}" "${REPLAY_COUNTER_DIR}"
mkdir -p "${REPLAY_LOG_DIR}" "${REPLAY_COUNTER_DIR}"
rm -f "${PROFRAW_DIR}"/*.profraw
# shellcheck disable=SC2086
python3 "${SCRIPTDIR}/replay_status.py" init --status "${REPLAY_STATUS}" -- ${TARGETS}

# Persist the current target's replay evidence in REPLAY_STATUS. Arguments are
# the outcome (executed or a skip reason) and exit code (null for skipped
# targets). Per-target globals supply counts, sidecars, logs, and the fresh
# profile pattern; the Python helper derives completeness for the selection.
record_replay() {
  python3 "${SCRIPTDIR}/replay_status.py" record \
    --status "${REPLAY_STATUS}" --target "${TARGET}" --outcome "$1" \
    --exit-code "$2" --expected-inputs "${INPUT_COUNT}" \
    --count-errors "${COUNT_ERRORS}" --counters "${COUNTER_FILE}" \
    --log "${LOG_FILE}" --profiles "${PROFRAW_DIR}/${TARGET}-*.profraw"
}

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

for TARGET in ${TARGETS}; do
  INPUT_COUNT=0
  COUNT_ERRORS=0
  LOG_FILE="${REPLAY_LOG_DIR}/${TARGET}.log"
  COUNTER_FILE="${REPLAY_COUNTER_DIR}/${TARGET}.json"
  : > "${LOG_FILE}"
  rm -f "${COUNTER_FILE}" "${PROFRAW_DIR}/${TARGET}-"*.profraw
  CORPUS_DIR=$(fuzz_local_corpus_dir "${TARGET}" "${BUILD_ROOT}" "${BUILD_DIR}")
  BIN="${BUILD_DIR}/${TARGET}"
  if [[ ! -x "${BIN}" ]]; then
    echo "Skipping ${TARGET}: binary not found at ${BIN}"
    record_replay missing_binary null
    continue
  fi

  CORPUS_ARGS=()
  if [[ -d "${CORPUS_DIR}" ]]; then
    CORPUS_ARGS+=("${CORPUS_DIR}")
  fi
  # Public OSS-Fuzz corpus (if downloaded by scripts/download_public_corpus.sh)
  # contributes additional coverage without being checked in. Fixed proto
  # lanes also replay the compatibility target's historical mixed corpus; all
  # inputs share the Scenario wire format and lane postprocessors normalize
  # scheme/timing fields before execution.
  while IFS= read -r PUBLIC_CORPUS_NAME; do
    PUBLIC_CORPUS_DIR="${BUILD_ROOT}/ossfuzz_corpus/${PUBLIC_CORPUS_NAME}"
    if [[ -d "${PUBLIC_CORPUS_DIR}" ]]; then
      CORPUS_ARGS+=("${PUBLIC_CORPUS_DIR}")
    fi
  done < <(fuzz_public_corpus_names "${TARGET}")
  if [[ ${#CORPUS_ARGS[@]} -eq 0 ]]; then
    echo "Skipping ${TARGET}: no corpus dirs"
    record_replay no_corpus null
    continue
  fi

  for DIR in "${CORPUS_ARGS[@]}"; do
    # Match the runner: follow a linked corpus root and links to regular files,
    # but do not descend into linked directories within the corpus. Broken
    # links are diagnosed during replay.
    if COUNT=$(find -H "${DIR}" -xtype f -printf '.\n' 2>>"${LOG_FILE}" | wc -l); then
      INPUT_COUNT=$(( INPUT_COUNT + COUNT ))
    else
      COUNT_ERRORS=$(( COUNT_ERRORS + 1 ))
    fi
  done
  if [[ ${INPUT_COUNT} -eq 0 && ${COUNT_ERRORS} -eq 0 ]]; then
    echo "Skipping ${TARGET}: empty corpus"
    record_replay empty_corpus null
    continue
  fi
  echo "==> ${TARGET}: replaying ${INPUT_COUNT} inputs from ${#CORPUS_ARGS[@]} dir(s)"
  # The standalone runner walks each directory itself, so we get a single
  # process per target. Capture failures while continuing other targets.
  # The target prefix attributes fresh profiles to their replay status.
  export LLVM_PROFILE_FILE="${PROFRAW_DIR}/${TARGET}-%m-%p.profraw"
  export FUZZ_REPLAY_STATUS_FILE="${COUNTER_FILE}"
  if "${BIN}" "${CORPUS_ARGS[@]}" >>"${LOG_FILE}" 2>&1; then
    EXIT_CODE=0
  else
    EXIT_CODE=$?
  fi
  record_replay executed "${EXIT_CODE}"
done

PROFDATA="${COVERAGE_DIR}/coverage.profdata"
echo "==> Merging profraw -> ${PROFDATA}"
# shellcheck disable=SC2046
"${LLVM_PROFDATA}" merge -sparse \
  -o "${PROFDATA}.tmp" \
  "${PROFRAW_DIR}"/*.profraw
mv -f "${PROFDATA}.tmp" "${PROFDATA}"

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
HARNESS_SUMMARY="${COVERAGE_DIR}/harness-summary.txt"
HARNESS_HTML_DIR="${COVERAGE_DIR}/harness-html"
CURL_JSON="${COVERAGE_DIR}/curl-coverage.json"
HARNESS_JSON="${COVERAGE_DIR}/harness-coverage.json"

# Public curl headers have instrumented inline functions and macros too. Keep
# src/ in the filter for compatibility; ordinary libcurl archives do not link
# the command-line tool, so unmapped files add nothing to the denominator.
CURL_SOURCES=("${CURL_SRC}/lib" "${CURL_SRC}/include/curl" "${CURL_SRC}/src")

# Select source files directly, rather than the repository directory: curl and
# its cached dependencies normally live below it in build-coverage/. Headers
# contain inline helpers and macros whose regions belong in the harness report.
# Tests, generated protobuf code, and the local replay engine are outside this
# source list, so they cannot inflate the harness denominator.
HARNESS_SOURCES=()
for SOURCE in \
  "${BUILD_ROOT}"/*.cc "${BUILD_ROOT}"/*.h \
  "${BUILD_ROOT}"/fuzzer_entrypoints/*.cc \
  "${BUILD_ROOT}"/proto_fuzzer/*.cc "${BUILD_ROOT}"/proto_fuzzer/*.h \
  "${BUILD_ROOT}"/full_coverage/*.cc "${BUILD_ROOT}"/full_coverage/*.h; do
  [[ -f "${SOURCE}" ]] || continue
  [[ "${SOURCE}" != "${BUILD_ROOT}/standalone_fuzz_target_runner.cc" ]] || continue
  HARNESS_SOURCES+=("${SOURCE}")
done
if [[ ${#HARNESS_SOURCES[@]} -eq 0 ]]; then
  echo "error: no harness source files found under ${BUILD_ROOT}" >&2
  exit 1
fi

echo "==> llvm-cov report (curl lib/ + public headers + src/)"
"${LLVM_COV}" report \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  "${CURL_SOURCES[@]}" | tee "${SUMMARY}"

echo "==> llvm-cov show -> ${HTML_DIR}"
rm -rf "${HTML_DIR}"
"${LLVM_COV}" show \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  -format=html -output-dir="${HTML_DIR}" \
  -show-line-counts-or-regions -show-branches=count \
  "${CURL_SOURCES[@]}"

echo "==> llvm-cov export (curl lib/ + public headers + src/) -> ${CURL_JSON}"
"${LLVM_COV}" export \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  "${CURL_SOURCES[@]}" > "${CURL_JSON}"

echo "==> llvm-cov report (curl-fuzzer harness)"
"${LLVM_COV}" report \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  "${HARNESS_SOURCES[@]}" | tee "${HARNESS_SUMMARY}"

echo "==> llvm-cov show -> ${HARNESS_HTML_DIR}"
rm -rf "${HARNESS_HTML_DIR}"
"${LLVM_COV}" show \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  -format=html -output-dir="${HARNESS_HTML_DIR}" \
  -show-line-counts-or-regions -show-branches=count \
  "${HARNESS_SOURCES[@]}"

echo "==> llvm-cov export (curl-fuzzer harness) -> ${HARNESS_JSON}"
"${LLVM_COV}" export \
  "${FIRST_BIN}" "${OBJECTS[@]}" \
  -instr-profile="${PROFDATA}" \
  "${HARNESS_SOURCES[@]}" > "${HARNESS_JSON}"

python3 "${SCRIPTDIR}/summarize_coverage.py" \
  --libcurl "${CURL_JSON}" --harness "${HARNESS_JSON}" \
  --output "${COVERAGE_DIR}/report.md" \
  --json-output "${COVERAGE_DIR}/gaps.json" \
  --replay-status "${REPLAY_STATUS}" --limit 20

echo
echo "Coverage report:         ${COVERAGE_DIR}/report.md"
echo "Libcurl summary:         ${SUMMARY}"
echo "Libcurl HTML report:     ${HTML_DIR}/index.html"
echo "Harness summary:         ${HARNESS_SUMMARY}"
echo "Harness HTML report:     ${HARNESS_HTML_DIR}/index.html"
echo "Coverage exports:        ${CURL_JSON}, ${HARNESS_JSON}"
