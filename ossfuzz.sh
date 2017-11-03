#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

. fuzz_targets

echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"
echo "FUZZ_TARGETS: $FUZZ_TARGETS"

export MAKEFLAGS+="-j$(nproc)"

# Make an install directory
export INSTALLDIR=/src/curl_install

# Install openssl
export OPENSSLFLAGS="-fno-sanitize=alignment"
OPENSSLDIR=/src/openssl
./handle_openssl.sh ${OPENSSLDIR} ${INSTALLDIR} || exit 1

# Compile curl
./install_curl.sh /src/curl ${INSTALLDIR}

# Build the fuzzers.
./compile_fuzzer.sh ${INSTALLDIR}
make zip

# Copy the fuzzers over.
for TARGET in $FUZZ_TARGETS
do
  cp -v ${TARGET} ${TARGET}_seed_corpus.zip $OUT/
done

# Copy dictionary and options file to $OUT.
cp -v *.dict *.options $OUT/
