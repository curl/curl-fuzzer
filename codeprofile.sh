#!/bin/bash

set -ex

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

CURLDIR=/tmp/curlprof
OPENSSLDIR=/tmp/openssl
INSTALLDIR=/tmp/curlprof_install

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
export CC=gcc
export CXX=g++
export CFLAGS="-pg"
export CXXFLAGS="-pg"

# Install openssl
${SCRIPTDIR}/handle_x.sh openssl ${OPENSSLDIR} ${INSTALLDIR} || exit 1

# Install curl after all other dependencies
${SCRIPTDIR}/handle_x.sh curl ${CURLDIR} ${INSTALLDIR} || exit 1

# Compile and test the fuzzers.
${SCRIPTDIR}/compile_fuzzer.sh ${INSTALLDIR} || exit 1

gprof ${BUILD_ROOT}/curl_fuzzer
