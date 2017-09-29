#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

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

export INSTALLDIR=$1

if [[ ! -d ${INSTALLDIR} ]]
then
  exit 1
fi

# Build the fuzzer.
./buildconf
./configure ${CODE_COVERAGE_OPTION}
make
make check
