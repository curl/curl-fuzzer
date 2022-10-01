#!/bin/bash

set -ex

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

export CURLDIR=/tmp/curl
OPENSSLDIR=/tmp/openssl
NGHTTPDIR=/tmp/nghttp2
INSTALLDIR=/tmp/curl_install

# Parse the options.
OPTIND=1

while getopts "c:n:o:" opt
do
  case "$opt" in
    c) CURLDIR=$OPTARG
       ;;
    n) NGHTTPDIR=$OPTARG
       ;;
    o) OPENSSLDIR=$OPTARG
       ;;
  esac
done
shift $((OPTIND-1))

# Use clang to test the code as it allows use of libsanitizer.
export CC=clang
export CXX=clang++
FUZZ_FLAG="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CFLAGS="-fsanitize=address"
export CXXFLAGS="-fsanitize=address -stdlib=libstdc++ $FUZZ_FLAG"
export CPPFLAGS="$FUZZ_FLAG"
export OPENSSLFLAGS="-fno-sanitize=alignment"

# Install openssl
${SCRIPTDIR}/handle_x.sh openssl ${OPENSSLDIR} ${INSTALLDIR} || exit 1

# Install nghttp2
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTPDIR} ${INSTALLDIR} || exit 1

# Install curl after all other dependencies
${SCRIPTDIR}/handle_x.sh curl ${CURLDIR} ${INSTALLDIR} || exit 1

# Compile and test the fuzzers.
${SCRIPTDIR}/compile_fuzzer.sh ${INSTALLDIR} || exit 1
