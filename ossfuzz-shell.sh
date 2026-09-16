#!/usr/bin/env bash

set -eu

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OSS_FUZZ_ROOT=${OSS_FUZZ_ROOT:-${ROOT}/.oss-fuzz}
HELPER=${OSS_FUZZ_ROOT}/infra/helper.py

if [[ ! -e "${OSS_FUZZ_ROOT}" ]]; then
  git clone --depth 1 https://github.com/google/oss-fuzz.git "${OSS_FUZZ_ROOT}"
fi

if [[ ! -f "${HELPER}" ]]; then
  echo "OSS-Fuzz helper not found at ${HELPER}" >&2
  exit 1
fi

# /work is mounted from .oss-fuzz/build/work/curl by helper.py, so this keeps
# the CMake tree outside the source checkout and preserves it across shells.
CONTAINER_BUILD_DIR=${OSS_FUZZ_BUILD_DIR:-/work/build}

exec python3 "${HELPER}" shell \
  --architecture "${ARCHITECTURE:-x86_64}" \
  --engine "${FUZZING_ENGINE:-libfuzzer}" \
  --sanitizer "${SANITIZER:-address}" \
  -e "BUILD_DIR=${CONTAINER_BUILD_DIR}" \
  curl "${ROOT}"
