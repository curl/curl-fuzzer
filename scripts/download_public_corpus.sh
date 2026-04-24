#!/usr/bin/env bash
#
# Download the public OSS-Fuzz corpora for each fuzz target into
# ossfuzz_corpus/<target>/. Intended to be replayed alongside the
# checked-in corpora (scripts/run_coverage.sh already picks this up) so
# local coverage numbers reflect everything the fleet has discovered.
#
# Usage:
#   scripts/download_public_corpus.sh [-f]
#     -f   Force re-download even if ossfuzz_corpus/<target>/ already
#          exists. Without -f, a non-empty target dir is left alone.
#
# The public zips live at:
#   https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/<oss-fuzz-name>/public.zip
#
# OSS-Fuzz prefixes binaries with the project name when the target doesn't
# already start with "curl_" — so fuzz_url is published as curl_fuzz_url,
# while curl_fuzzer_dict stays as-is.
#
# New targets take a while to land after first upload; a non-200 response
# is logged and skipped rather than failing the whole run.

set -eu

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_ROOT=$(readlink -f "${SCRIPTDIR}/..")

FORCE=0
while getopts "f" opt; do
  case "$opt" in
    f) FORCE=1 ;;
    *) echo "Usage: $0 [-f]" >&2; exit 2 ;;
  esac
done

# shellcheck disable=SC1091
. "${SCRIPTDIR}/fuzz_targets"

BASE_URL="https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer"
CORPUS_ROOT="${BUILD_ROOT}/ossfuzz_corpus"
mkdir -p "${CORPUS_ROOT}"

command -v unzip >/dev/null 2>&1 || {
  echo "error: unzip is required" >&2
  exit 1
}

TMPDIR_ROOT=$(mktemp -d)
trap 'rm -rf "${TMPDIR_ROOT}"' EXIT

for TARGET in ${FUZZ_TARGETS}; do
  # OSS-Fuzz adds the project prefix to any target that doesn't already
  # start with "curl_": fuzz_url → curl_fuzz_url, curl_fuzzer_dict unchanged.
  if [[ "${TARGET}" == curl_* ]]; then
    OSS_NAMES=("${TARGET}")
  else
    OSS_NAMES=("curl_${TARGET}")
  fi

  # fuzz_bufq was renamed from curl_fuzzer_bufq. Until OSS-Fuzz rebuilds
  # and starts populating curl_fuzz_bufq, fall back to the legacy name so
  # we don't lose the accumulated corpus.
  if [[ "${TARGET}" == "fuzz_bufq" ]]; then
    OSS_NAMES+=("curl_fuzzer_bufq")
  fi

  DEST="${CORPUS_ROOT}/${TARGET}"
  if [[ ${FORCE} -eq 0 && -d "${DEST}" ]] && \
     [[ -n "$(find "${DEST}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    echo "== ${TARGET}: already present in ${DEST} (use -f to refresh)"
    continue
  fi

  ZIP="${TMPDIR_ROOT}/${TARGET}.zip"
  HTTP_STATUS=000
  for OSS_NAME in "${OSS_NAMES[@]}"; do
    URL="${BASE_URL}/${OSS_NAME}/public.zip"
    echo "== ${TARGET}: downloading ${URL}"
    # -S shows errors even under -s; success is HTTP 200.
    HTTP_STATUS=$(curl -sS -o "${ZIP}" -w '%{http_code}' "${URL}" || echo "000")
    if [[ "${HTTP_STATUS}" == "200" ]]; then
      break
    fi
    echo "   miss: HTTP ${HTTP_STATUS}"
    rm -f "${ZIP}"
  done
  if [[ "${HTTP_STATUS}" != "200" ]]; then
    echo "   skip: no corpus available"
    continue
  fi

  rm -rf "${DEST}"
  mkdir -p "${DEST}"
  if ! unzip -q -o "${ZIP}" -d "${DEST}"; then
    echo "   skip: unzip failed (corpus not extracted)"
    rm -rf "${DEST}"
    continue
  fi

  COUNT=$(find "${DEST}" -type f | wc -l)
  echo "   extracted ${COUNT} files to ${DEST}"
done

echo
echo "Public corpus root: ${CORPUS_ROOT}"
