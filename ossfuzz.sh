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

. ${SCRIPTDIR}/fuzz_targets

ZLIBDIR=/src/zlib
OPENSSLDIR=/src/openssl
NGHTTP2DIR=/src/nghttp2
NGHTTP3DIR=/src/nghttp3
NGTCP2DIR=/src/ngtcp2
GDBDIR=/src/gdb

# Check for GDB-specific behaviour by checking for the GDBMODE flag.
# - Compile with -O0 so that DEBUGASSERTs can be debugged in gdb.
if [[ -n ${GDBMODE:-} ]]
then
  export CFLAGS="$CFLAGS -O0"
  export CXXFLAGS="$CXXFLAGS -O0"
fi

echo "BUILD_ROOT: $BUILD_ROOT"
echo "SRC: ${SRC:-undefined}"
echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"
echo "ARCHITECTURE: $ARCHITECTURE"
echo "FUZZ_TARGETS: $FUZZ_TARGETS"

export MAKEFLAGS+="-j$(nproc)"

# Make an install directory
export INSTALLDIR=/src/curl_install

# Check for GDB-specific behaviour by checking for the GDBMODE flag.
# - Compile and installing GDB if necessary.
if [[ -n ${GDBMODE:-} ]]
then
  if ! type gdb 2>/dev/null
  then
    # If gdb isn't found, then download and install GDB.
    # This installs to the default configure location.
    ${SCRIPTDIR}/handle_x.sh gdb ${GDBDIR} system || exit 1
  fi
fi

# Install zlib
${SCRIPTDIR}/handle_x.sh zlib ${ZLIBDIR} ${INSTALLDIR} || exit 1

# For the memory sanitizer build, turn off OpenSSL as it causes bugs we can't
# affect (see 16697, 17624)
if [[ ${SANITIZER} != "memory" ]]
then
    # Install openssl_quic (need openssl_quic, nghttp3, and ngtcp2 for HTTP3 support)
    export OPENSSLFLAGS="-fno-sanitize=alignment"
    ${SCRIPTDIR}/handle_x.sh openssl_quic ${OPENSSLDIR} ${INSTALLDIR} || exit 1

    # HTTP3 requires SSL, so we also install it here
    # Install nghttp3
    ${SCRIPTDIR}/handle_x.sh nghttp3 ${NGHTTP3DIR} ${INSTALLDIR} || exit 1

    # Install ngtcp2
    ${SCRIPTDIR}/handle_x.sh ngtcp2 ${NGTCP2DIR} ${INSTALLDIR} || exit 1
fi

# Install nghttp2
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTP2DIR} ${INSTALLDIR} || exit 1

# Compile curl
${SCRIPTDIR}/install_curl.sh /src/curl ${INSTALLDIR}

# Build the fuzzers.
${SCRIPTDIR}/compile_fuzzer.sh ${INSTALLDIR}
make zip

# Copy the fuzzers over.
for TARGET in $FUZZ_TARGETS
do
  cp -v ${TARGET} ${TARGET}_seed_corpus.zip $OUT/
done

# Copy dictionary and options file to $OUT.
cp -v ossconfig/*.dict ossconfig/*.options $OUT/
