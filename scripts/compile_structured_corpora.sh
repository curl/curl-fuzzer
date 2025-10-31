#!/usr/bin/env bash
set -euo pipefail

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT=$(readlink -f "${SCRIPTDIR}/..")

SCENARIOS_DIR="${ROOT}/scenarios"
CORPORA_DIR="${ROOT}/corpora"
SCHEMAS_DIR="${ROOT}/schemas"
PROTO_FILE="curl_fuzzer.proto"
MESSAGE_TYPE="curl.fuzzer.proto.Scenario"
PROTOC_BIN="${PROTOC:-protoc}"

if ! command -v "${PROTOC_BIN}" >/dev/null 2>&1; then
  echo "error: protoc compiler not found. Set PROTOC to override." >&2
  exit 1
fi

if [[ ! -d "${SCENARIOS_DIR}" ]]; then
  echo "error: scenarios directory '${SCENARIOS_DIR}' not found" >&2
  exit 1
fi

if [[ ! -d "${SCHEMAS_DIR}" ]]; then
  echo "error: schemas directory '${SCHEMAS_DIR}' not found" >&2
  exit 1
fi

mkdir -p "${CORPORA_DIR}"

# Prune stale structured corpus entries to keep parity with the scenarios tree.
find "${CORPORA_DIR}" -type f -name '*.scenario' -delete 2>/dev/null || true

count=0
while IFS= read -r -d '' textproto ; do
  rel_path="${textproto#${SCENARIOS_DIR}/}"
  output_path="${CORPORA_DIR}/${rel_path%.textproto}.scenario"
  mkdir -p "$(dirname -- "${output_path}")"
  if ! "${PROTOC_BIN}" \
    --proto_path="${SCHEMAS_DIR}" \
    --encode="${MESSAGE_TYPE}" \
    "${SCHEMAS_DIR}/${PROTO_FILE}" \
    < "${textproto}" \
    > "${output_path}" ; then
    echo "error: failed to compile '${textproto}'" >&2
    exit 1
  fi
  printf 'compiled %s -> %s\n' "${rel_path}" "${output_path#${CORPORA_DIR}/}"
  count=$((count + 1))
done < <(find "${SCENARIOS_DIR}" -type f -name '*.textproto' -print0)

echo "Generated ${count} structured corpus entrie(s) under ${CORPORA_DIR}."
