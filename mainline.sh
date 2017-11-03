#!/bin/bash

set -ex

CURLDIR=/tmp/curl
OPENSSLDIR=/tmp/openssl
INSTALLDIR=/tmp/curl_install

# Parse the options.
OPTIND=1

while getopts "c:o:" opt
do
  case "$opt" in
    c) CURLDIR=$OPTARG
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
./handle_openssl.sh ${OPENSSLDIR} ${INSTALLDIR} || exit 1

# Install curl after all other dependencies
./handle_curl.sh ${CURLDIR} ${INSTALLDIR} || exit 1

# Compile and test the fuzzers.
./compile_fuzzer.sh ${INSTALLDIR} || exit 1
