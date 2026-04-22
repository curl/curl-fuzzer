#!/usr/bin/env bash
#
# Build every fuzzer with LLVM source-based coverage instrumentation *on
# libcurl and the fuzzer binaries only*, then replay the checked-in corpora
# through them to produce a coverage summary and HTML report restricted to
# curl's own sources.
#
# Deps (openssl, zlib, zstd, nghttp2, libidn2, openldap, LPM + protobuf +
# abseil) are intentionally built without coverage flags: they'd add no signal
# to the report and their combined instrumented link-time footprint was big
# enough to OOM the linker on a stock 16 GB runner for curl_fuzzer_proto.
#
# Output:
#   build-coverage/coverage/summary.txt  - llvm-cov report (curl lib/ + src/)
#   build-coverage/coverage/html/        - llvm-cov show (HTML report)

set -ex

# Save off the current folder as the build root.
export BUILD_ROOT; BUILD_ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPTDIR=${BUILD_ROOT}/scripts

# Use a separate build directory from mainline.sh so sanitizer/coverage objects
# don't fight over the same tree.
export BUILD_DIR="${BUILD_ROOT}/build-coverage"

# Parse the options.
OPTIND=1
while getopts "c:" opt
do
  case "$opt" in
    c) export CURL_SOURCE_DIR=$OPTARG
       ;;
  esac
done
shift $((OPTIND-1))

# Same clang toolchain as mainline.sh, minus -fsanitize=. Coverage flags are
# applied selectively by CMake (ENABLE_COVERAGE=ON below): curl's own cmake
# call picks them up via CMAKE_C/CXX_FLAGS, and the fuzzer binaries pick them
# up via COMMON_FLAGS / COMMON_LINK_OPTIONS. Deps inherit only the fuzzing
# define from CFLAGS/CXXFLAGS.
export CC=clang
export CXX=clang++
FUZZ_FLAG="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CFLAGS="${FUZZ_FLAG}"
export CXXFLAGS="-stdlib=libstdc++ ${FUZZ_FLAG}"
export CPPFLAGS="${FUZZ_FLAG}"
# SANITIZER=coverage lets check_data.sh and other scripts tell a coverage run
# apart from the asan/msan sanitizer runs.
export SANITIZER=coverage

# Turn on the ENABLE_COVERAGE option; compile_target.sh passes it through.
export EXTRA_CMAKE_ARGS="-DENABLE_COVERAGE=ON"

"${SCRIPTDIR}"/compile_target.sh fuzz
"${SCRIPTDIR}"/run_coverage.sh
