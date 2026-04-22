#!/usr/bin/env bash
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

set -eu

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

. "${SCRIPTDIR}"/fuzz_targets

echo "BUILD_ROOT: $BUILD_ROOT"
echo "FUZZ_TARGETS: $FUZZ_TARGETS"

# Set the CURL_SOURCE_DIR for the build.
export CURL_SOURCE_DIR=/src/curl

# Under CIFuzz the build runs in an ephemeral container, but $GITHUB_WORKSPACE
# is bind-mounted into the container path-for-path and $OUT lives directly
# beneath it. Redirect the CMake build tree into that mount so it survives
# container teardown and GitHub Actions can cache it between runs.
if [[ "${CIFUZZ:-}" == "True" && -n "${OUT:-}" ]]; then
  CACHE_ROOT=$(dirname "${OUT}")/.ossfuzz-build-cache-${SANITIZER:-address}-${ARCHITECTURE:-x86_64}
  export BUILD_DIR=${CACHE_ROOT}/build
  mkdir -p "${BUILD_DIR}"
  echo "CIFuzz detected: redirecting BUILD_DIR to ${BUILD_DIR}"

  # Curl is cloned fresh (--depth 1) on every container start, but its CMake
  # ExternalProject stamp would skip rebuilding if we kept it. Drop the stamps
  # and the built library so curl (and the fuzzer binaries that link it) get
  # rebuilt against the current tip. Mirrors the REPLAY_ENABLED handling in
  # oss-fuzz/projects/curl/build.sh.
  rm -f "${BUILD_DIR}/curl-install/lib/libcurl.a"
  rm -f "${BUILD_DIR}"/curl_external-prefix/src/curl_external-stamp/curl_external-{configure,build,install,done}
fi
BUILD_DIR=${BUILD_DIR:-${BUILD_ROOT}/build}

# Compile the fuzzers.
"${SCRIPTDIR}"/compile_target.sh fuzz

# Zip up the seed corpus.
scripts/create_zip.sh

# Copy the fuzzers over.
for TARGET in $FUZZ_TARGETS
do
  cp -v "${BUILD_DIR}/${TARGET}" "${TARGET}_seed_corpus.zip" "$OUT"/
done

# Copy dictionary and options file to $OUT.
cp -v ossconfig/*.dict ossconfig/*.options "$OUT"/
