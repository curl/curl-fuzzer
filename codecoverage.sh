#!/bin/bash

set -ex

# Use gcc to test the code as code coverage is easier.
export CC=gcc
export CXX=g++
FUZZ_FLAG="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CFLAGS=""
export CXXFLAGS="$FUZZ_FLAG"
export CPPFLAGS="$FUZZ_FLAG"

OPENSSLDIR=/tmp/openssl
INSTALLDIR=/tmp/curlcov_install

# Install openssl
./handle_openssl.sh ${OPENSSLDIR} ${INSTALLDIR} || exit 1

# Download cURL to a temporary folder.
./download_curl.sh /tmp/curlcov

# Move cURL to a subfolder of this folder to get the paths right.
if [[ -d ./curl ]]
then
  rm -rf ./curl
fi
mv /tmp/curlcov ./curl

# Compile and install cURL to a second folder with code coverage.
./install_curl.sh -c ./curl ${INSTALLDIR}

# Compile and test the fuzzer with code coverage
./compile_fuzzer.sh -c ${INSTALLDIR}

# Do a "make check-code-coverage" run to generate the coverage info.
make check-code-coverage
