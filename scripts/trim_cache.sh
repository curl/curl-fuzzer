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
#
# Trim a CMake build tree so that only the installed outputs needed by
# CMakeLists.txt's if(NOT EXISTS ...) conditionals are cached.
#
# CMakeLists.txt skips ExternalProject_Add entirely when the install
# outputs already exist, so we only need to keep:
#   - *-install/ directories (static libs, headers, binaries)
#   - LPM's bundled protobuf install (protoc, headers, libs) which lives
#     outside any *-install/ directory
#
# Usage: trim_cache.sh <build-dir>

set -eu

BD=${1:?Usage: trim_cache.sh <build-dir>}

if [ ! -d "${BD}" ]; then
  echo "trim_cache.sh: ${BD} does not exist, nothing to trim."
  exit 0
fi

echo "=== trim_cache.sh: before ==="
du -sh "${BD}" 2>/dev/null || true

# Stash LPM's bundled-protobuf install outputs - they live outside any
# *-install/ directory but are needed by the proto fuzzer build (protoc
# binary, protobuf headers, static libs).
LPM_PB=${BD}/lpm/src/libprotobuf_mutator_external-build/external.protobuf
STASH=$(mktemp -d)
if [ -d "${LPM_PB}/bin" ]; then
  mkdir -p "${STASH}/lpm_pb"
  for sub in bin lib include; do
    [ -d "${LPM_PB}/${sub}" ] && cp -a "${LPM_PB}/${sub}" "${STASH}/lpm_pb/"
  done
fi

# Delete everything except *-install/ directories.
find "${BD}" -maxdepth 1 -mindepth 1 ! -name '*-install' -exec rm -rf {} +

# Restore stashed LPM protobuf outputs.
if [ -d "${STASH}/lpm_pb" ]; then
  mkdir -p "${LPM_PB}"
  mv "${STASH}/lpm_pb"/* "${LPM_PB}/"
fi
rm -rf "${STASH}"

echo "=== trim_cache.sh: after ==="
du -sh "${BD}" 2>/dev/null || true
