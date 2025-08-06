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

TARGET=${1:-fuzz}

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export BUILD_ROOT=$(readlink -f "${SCRIPTDIR}/..")

# Check for GDB-specific behaviour by checking for the GDBMODE flag.
# - Compile with -O0 so that DEBUGASSERTs can be debugged in gdb.
if [[ -n ${GDBMODE:-} ]]
then
    [[ -n ${CFLAGS:-} ]] && export CFLAGS="${CFLAGS} -O0" || export CFLAGS="-O0"
    [[ -n ${CXXFLAGS:-} ]] && export CXXFLAGS="${CXXFLAGS} -O0" || export CXXFLAGS="-O0"
    CMAKE_GDB_FLAG="-DBUILD_GDB=ON"
else
    CMAKE_GDB_FLAG="-DBUILD_GDB=OFF"
fi

echo "BUILD_ROOT: $BUILD_ROOT"
echo "SRC: ${SRC:-undefined}"
echo "CC: ${CC:-undefined}"
echo "CXX: ${CXX:-undefined}"
echo "LIB_FUZZING_ENGINE: ${LIB_FUZZING_ENGINE:-undefined}"
echo "CFLAGS: ${CFLAGS:-undefined}"
echo "CXXFLAGS: ${CXXFLAGS:-undefined}"
echo "ARCHITECTURE: ${ARCHITECTURE:-undefined}"

if [[ "${ARCHITECTURE:-}" == "i386" ]]
then
    CMAKE_VERBOSE_FLAG="-v"
else
    CMAKE_VERBOSE_FLAG=""
fi

export MAKEFLAGS="-j$(($(nproc) + 1))"
echo "MAKEFLAGS: ${MAKEFLAGS}"

# Create a build directory for the dependencies.
BUILD_DIR=${BUILD_ROOT}/build
mkdir -p ${BUILD_DIR}

options=''
command -v ninja >/dev/null 2>&1 && options+=' -G Ninja'

# Compile the dependencies.
pushd ${BUILD_DIR}
cmake ${CMAKE_GDB_FLAG} .. ${options}
cmake --build . --target ${TARGET} ${CMAKE_VERBOSE_FLAG}
popd
