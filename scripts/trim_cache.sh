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
#   - current *-install/ directories (static libs and headers)
#   - the generated list identifying those current install directories
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

INSTALL_MANIFEST=${BD}/curl-fuzzer-cache-installs.txt
if [ ! -f "${INSTALL_MANIFEST}" ]; then
  echo "trim_cache.sh: missing ${INSTALL_MANIFEST}; refusing to trim." >&2
  exit 1
fi
mapfile -t CURRENT_INSTALLS < "${INSTALL_MANIFEST}"
if [ "${#CURRENT_INSTALLS[@]}" -eq 0 ]; then
  echo "trim_cache.sh: ${INSTALL_MANIFEST} is empty; refusing to trim." >&2
  exit 1
fi

is_current_install() {
  local candidate=$1
  local current
  for current in "${CURRENT_INSTALLS[@]}"; do
    [ "${candidate}" = "${current}" ] && return 0
  done
  return 1
}

# Stash LPM's bundled-protobuf install outputs - they live outside any
# *-install/ directory but are needed by the proto fuzzer build (protoc
# binary, protobuf headers, static libs). Resolve the current LPM build from
# the manifest so a restored older version cannot make the path ambiguous.
LPM_PB=
for current in "${CURRENT_INSTALLS[@]}"; do
  case "${current}" in
    lpm-*-host-protoc-install)
      ;;
    lpm-*-install)
      LPM_PB=${BD}/${current%-install}/src/libprotobuf_mutator_external-build/external.protobuf
      ;;
  esac
done
STASH=$(mktemp -d)
if [ -n "${LPM_PB}" ] && [ -d "${LPM_PB}/bin" ]; then
  mkdir -p "${STASH}/lpm_pb"
  for sub in bin lib include; do
    [ -d "${LPM_PB}/${sub}" ] && cp -a "${LPM_PB}/${sub}" "${STASH}/lpm_pb/"
  done
fi

# Delete build intermediates, then discard install prefixes not named in the
# current configuration's manifest. Direct dependency prefixes also carry the
# recipe marker written by CMakeLists.txt; curl, LPM and optional GDB have their
# own purpose-specific install layouts.
find "${BD}" -maxdepth 1 -mindepth 1 \
  ! -name '*-install' \
  ! -name 'curl-fuzzer-cache-installs.txt' \
  -exec rm -rf {} +
for install_dir in "${BD}"/*-install; do
  [ -d "${install_dir}" ] || continue
  install_name=${install_dir##*/}
  if ! is_current_install "${install_name}"; then
    rm -rf "${install_dir}"
    continue
  fi
  case "${install_name}" in
    curl-install|curl-gnutls-install|curl-mbedtls-install|curl-http3-install|lpm-*-install|gdb-*-install)
      continue
      ;;
  esac
  if ! compgen -G "${install_dir}/.curl-fuzzer-minimal-install-*" >/dev/null; then
    rm -rf "${install_dir}"
  fi
done

# Restore stashed LPM protobuf outputs.
if [ -d "${STASH}/lpm_pb" ]; then
  mkdir -p "${LPM_PB}"
  mv "${STASH}/lpm_pb"/* "${LPM_PB}/"
fi
rm -rf "${STASH}"

echo "=== trim_cache.sh: after ==="
du -sh "${BD}" 2>/dev/null || true
