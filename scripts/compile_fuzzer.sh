#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Exit if the build root has not been defined.
[[ -d ${BUILD_ROOT} ]] || exit 1

# Parse the options.
OPTIND=1
CODE_COVERAGE_OPTION=""

while getopts "c" opt
do
	case "$opt" in
		c) CODE_COVERAGE_OPTION="--enable-code-coverage"
           ;;
    esac
done
shift $((OPTIND-1))

# Check that the installation directory exists.
export INSTALLDIR=$1
[[ -d ${INSTALLDIR} ]] || exit 1

# Build the fuzzers.
${BUILD_ROOT}/buildconf || exit 2
${BUILD_ROOT}/configure ${CODE_COVERAGE_OPTION} || exit 3
make || exit 4
make check || exit 5
