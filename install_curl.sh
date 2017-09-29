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

SRCDIR=$1
INSTALLDIR=$2

if [[ ! -d ${INSTALLDIR} ]]
then
  # Make an install target for curl.
  mkdir ${INSTALLDIR}
fi

pushd ${SRCDIR}

# Build the library.
./buildconf
./configure --prefix=${INSTALLDIR} --disable-shared --enable-debug --enable-maintainer-mode ${CODE_COVERAGE_OPTION}
make
make install

popd
