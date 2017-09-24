#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Import compiler settings
. compile_settings

export INSTALLDIR=$1

if [[ ! -d ${INSTALLDIR} ]]
then
  exit 1
fi

# Build the fuzzer.
./buildconf
./configure
make
make check
