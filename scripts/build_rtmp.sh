#!/bin/bash -eu
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
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

set -euxo pipefail

RTMP_SOURCE_DIR=${1}
LIBRTMP_SOURCE_DIR=${RTMP_SOURCE_DIR}/librtmp
LIBRTMP_INSTALL_DIR=${2}
OPENSSL_INSTALL_DIR=${3}
ZLIB_INSTALL_DIR=${4}

echo "Building librtmp from source: ${LIBRTMP_SOURCE_DIR}"

pushd ${LIBRTMP_SOURCE_DIR}
make \
    INC="-I${OPENSSL_INSTALL_DIR}/include -I${ZLIB_INSTALL_DIR}/include" \
    LIB="-L${OPENSSL_INSTALL_DIR}/lib -L${ZLIB_INSTALL_DIR}/lib" \
    LIB_OPENSSL="-l:libssl.a -l:libcrypto.a -l:libz.a" \
    SHARED= \
    librtmp.a
