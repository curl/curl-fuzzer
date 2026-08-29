#!/usr/bin/env bash

set -ex

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_ROOT=$(readlink -f "${SCRIPTDIR}/..")
ACTIVE_BUILD_DIR=${BUILD_DIR:-${BUILD_ROOT}/build}

. "${SCRIPTDIR}"/fuzz_targets
. "${SCRIPTDIR}"/fuzz_corpus_helpers.sh

for TARGET in ${FUZZ_TARGETS}
do
  CORPUS_NAME=$(fuzz_local_corpus_name "${TARGET}")
  SEED_MANIFEST="${ACTIVE_BUILD_DIR}/corpus_manifests/${CORPUS_NAME}.seed_manifest"
  CORPUS_DIR=$(fuzz_local_corpus_dir "${TARGET}" "${BUILD_ROOT}" "${ACTIVE_BUILD_DIR}")
  rm -f "${BUILD_ROOT}/${TARGET}_seed_corpus.zip"
  pushd "${CORPUS_DIR}"
  if [[ -f "${SEED_MANIFEST}" ]]; then
    mapfile -t CORPUS_FILES < "${SEED_MANIFEST}"

    # A seed larger than libFuzzer's configured max_len is truncated while
    # loading, which can turn a valid protobuf into an unparseable no-op. Keep
    # the check beside packaging so new structured scenarios cannot silently
    # ship in that state again.
    OPTIONS_FILE="${BUILD_ROOT}/ossconfig/${TARGET}.options"
    if [[ -f "${OPTIONS_FILE}" ]]; then
      MAX_LEN=$(awk -F= \
        '$1 ~ /^[[:space:]]*max_len[[:space:]]*$/ { \
           gsub(/[[:space:]]/, "", $2); print $2; exit \
         }' "${OPTIONS_FILE}")
      if [[ "${MAX_LEN}" =~ ^[0-9]+$ ]]; then
        for CORPUS_FILE in "${CORPUS_FILES[@]}"; do
          FILE_SIZE=$(wc -c < "${CORPUS_FILE}")
          if (( FILE_SIZE > MAX_LEN )); then
            echo "error: ${TARGET} seed ${CORPUS_FILE} is ${FILE_SIZE} bytes, above max_len=${MAX_LEN}" >&2
            exit 1
          fi
        done
      fi
    fi
    zip "${BUILD_ROOT}/${TARGET}_seed_corpus.zip" "${CORPUS_FILES[@]}"
  else
    zip "${BUILD_ROOT}/${TARGET}_seed_corpus.zip" ./*
  fi
  popd
done
