#!/bin/bash

set -ex

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

CURLDIR=/tmp/curl
OPENSSLDIR=/tmp/openssl
NGHTTP2DIR=/tmp/nghttp2
NGHTTP3DIR=/tmp/nghttp3
NGTCP2DIR=/tmp/ngtcp2
OPENSLLQUICDIR=/tmp/openssl_quic
INSTALLDIR=/tmp/curl_install

# Parse the options.
OPTIND=1

while getopts "c:n:o:t:" opt
do
  case "$opt" in
    c) CURLDIR=$OPTARG
       ;;
    n) NGHTTP2DIR=$OPTARG
       ;;
    o) OPENSSLDIR=$OPTARG
       ;;
    t) NGTCP2DIR=$OPTARG
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
export OPENSSLFLAGS="-fno-sanitize=alignment -lstdc++"

# Install openssl_quic (need openssl_quic, nghttp3, and ngtcp2 for HTTP3 support)
${SCRIPTDIR}/handle_x.sh openssl_quic ${OPENSLLQUICDIR} ${INSTALLDIR} || exit 1

# Install openssl
# ${SCRIPTDIR}/handle_x.sh openssl ${OPENSSLDIR} ${INSTALLDIR} || exit 1

# Install nghttp2
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTP2DIR} ${INSTALLDIR} || exit 1

# Install nghttp3
${SCRIPTDIR}/handle_x.sh nghttp3 ${NGHTTP3DIR} ${INSTALLDIR} || exit 1

# Install ngtcp2
${SCRIPTDIR}/handle_x.sh ngtcp2 ${NGTCP2DIR} ${INSTALLDIR} || exit 1

# Install curl after all other dependencies
${SCRIPTDIR}/handle_x.sh curl ${CURLDIR} ${INSTALLDIR} || exit 1

# Compile and test the fuzzers.
${SCRIPTDIR}/compile_fuzzer.sh ${INSTALLDIR} || exit 1
