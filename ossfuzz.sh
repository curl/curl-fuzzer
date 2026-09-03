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

# Keep Fuzz Introspector focused on the libcurl and harness code that these
# binaries can actually reach. The setting must be exported before compiling:
# Introspector's compiler wrappers consume it while producing their metadata.
export FUZZ_INTROSPECTOR_CONFIG=${BUILD_ROOT}/fuzz_introspector_exclusion.config

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
fi
export BUILD_DIR=${BUILD_DIR:-${BUILD_ROOT}/build}

# Curl is cloned fresh (--depth 1) on every CIFuzz container start. Replay
# builds likewise update that checkout before invoking this script. Invalidate
# both client variants so a restored ExternalProject stamp cannot retain an
# archive from the previous curl revision.
if [[ "${CIFUZZ:-}" == "True" || -n "${REPLAY_ENABLED:-}" ]]; then
  rm -f "${BUILD_DIR}/curl-install/lib/libcurl.a"
  rm -f "${BUILD_DIR}/curl-gnutls-install/lib/libcurl.a"
  for CURL_VARIANT in curl_external curl_gnutls_external; do
    rm -f "${BUILD_DIR}/${CURL_VARIANT}-prefix/src/${CURL_VARIANT}-stamp/${CURL_VARIANT}-"{configure,build,install,done}
  done
fi

# Compile the fuzzers.
"${SCRIPTDIR}"/compile_target.sh fuzz

# Build GDB separately if requested (it's a tool, not a fuzzer dependency).
if [[ -n ${GDBMODE:-} ]]; then
  "${SCRIPTDIR}"/compile_target.sh gdb_external
fi

# Zip up the seed corpus.
scripts/create_zip.sh

# Copy the fuzzers over.
for TARGET in $FUZZ_TARGETS
do
  cp -v "${BUILD_DIR}/${TARGET}" "${TARGET}_seed_corpus.zip" "$OUT"/
done

# Copy dictionary and options file to $OUT.
cp -v ossconfig/*.dict ossconfig/*.options "$OUT"/

# Copy the built GDB installation to $OUT if requested. The GDB build
# directory is named after its version (e.g. gdb-13.2-install), so resolve
# it with a glob, but always install to a stable $OUT/gdb-install so the
# repro image's PATH (/out/gdb-install/bin) keeps working.
GDB_INSTALL=$(echo "${BUILD_DIR}"/gdb-*-install)
if [[ -n ${GDBINSTALL:-} ]] && [[ -d "${GDB_INSTALL}" ]]; then
  cp -rv "${GDB_INSTALL}" "$OUT"/gdb-install
fi
