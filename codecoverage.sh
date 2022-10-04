#!/bin/bash

set -ex

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

# Use gcc to test the code as code coverage is easier.
export CC=gcc
export CXX=g++
FUZZ_FLAG="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CFLAGS=""
export CXXFLAGS="$FUZZ_FLAG"
export CPPFLAGS="$FUZZ_FLAG"

OPENSSLDIR=/tmp/openssl
NGHTTPDIR=/tmp/nghttp2
INSTALLDIR=/tmp/curlcov_install

# mainline.sh and codecoverage.sh use different compilers and the ASAN and
# other LLVM specific things don't work with GCC so make sure we clean up
# if there have been earlier mainline runs locally
if [[ -d .deps/ && -f Makefile ]]
then
	make distclean
fi

# Install openssl
${SCRIPTDIR}/handle_x.sh openssl ${OPENSSLDIR} ${INSTALLDIR} || exit 1

# Install nghttp2
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTPDIR} ${INSTALLDIR} || exit 1

# Download cURL to a temporary folder.
${SCRIPTDIR}/download_curl.sh /tmp/curlcov

# Move cURL to a subfolder of this folder to get the paths right.
if [[ -d ${BUILD_ROOT}/curl ]]
then
  rm -rf ${BUILD_ROOT}/curl
fi
mv /tmp/curlcov ${BUILD_ROOT}/curl

# Compile and install cURL to a second folder with code coverage.
${SCRIPTDIR}/install_curl.sh -c ${BUILD_ROOT}/curl ${INSTALLDIR}

# Compile and test the fuzzer with code coverage
${SCRIPTDIR}/compile_fuzzer.sh -c ${INSTALLDIR}

# Do a "make check-code-coverage" run to generate the coverage info.
make check-code-coverage
