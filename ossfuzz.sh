#!/bin/bash -eu
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2018-2021, Max Dymond, <cmeister2@gmail.com>, et al.
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

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

. "${SCRIPTDIR}"/fuzz_targets

echo "BUILD_ROOT: $BUILD_ROOT"
echo "FUZZ_TARGETS: $FUZZ_TARGETS"

# Set the CURL_SOURCE_DIR for the build.
export CURL_SOURCE_DIR=/src/curl

# Compile the fuzzers.
"${SCRIPTDIR}"/compile_target.sh fuzz

# Zip up the seed corpus.
scripts/create_zip.sh

# Copy the fuzzers over.
for TARGET in $FUZZ_TARGETS
do
  cp -v build/"${TARGET}" "${TARGET}"_seed_corpus.zip "$OUT"/
done

# Copy dictionary and options file to $OUT.
cp -v ossconfig/*.dict ossconfig/*.options "$OUT"/
