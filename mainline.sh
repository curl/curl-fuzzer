#!/bin/bash

set -ex

CURLDIR=$1
if [[ -z ${CURLDIR} ]]
then
  CURLDIR=/tmp/curl
fi

# Use clang to test the code as it allows use of libsanitizer.
export CC=clang
export CXX=clang++
FUZZ_FLAG="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CFLAGS="-fsanitize=address"
export CXXFLAGS="-fsanitize=address -stdlib=libstdc++ $FUZZ_FLAG"
export CPPFLAGS="$FUZZ_FLAG"

if [[ ! -d ${CURLDIR} ]]
then
    # Download cURL to the specified folder
    ./download_curl.sh ${CURLDIR}
fi

# Compile and install cURL to a second folder.
./install_curl.sh ${CURLDIR} /tmp/curl_install

# Compile and test the fuzzer.
./compile_fuzzer.sh /tmp/curl_install
