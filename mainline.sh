#!/bin/bash

set -ex

# Save off the current folder as the build root.
export BUILD_ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPTDIR=${BUILD_ROOT}/scripts

# Parse the options.
OPTIND=1
TARGET=fuzz

while getopts "c:t:" opt
do
  case "$opt" in
    c) export CURL_SOURCE_DIR=$OPTARG
       ;;
    t) TARGET=$OPTARG
       ;;
  esac
done
shift $((OPTIND-1))

# Use clang to test the code as it allows use of libsanitizer.
export CC=clang
export CXX=clang++
FUZZ_FLAG="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CFLAGS="-fsanitize=address,fuzzer-no-link"
export CXXFLAGS="-fsanitize=address,fuzzer-no-link -stdlib=libstdc++ $FUZZ_FLAG"
export CPPFLAGS="$FUZZ_FLAG"
export OPENSSLFLAGS="-fno-sanitize=alignment -lstdc++"

${SCRIPTDIR}/compile_target.sh ${TARGET}
