#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Import compiler settings
. compile_settings

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
./configure --prefix=${INSTALLDIR} --disable-shared --enable-debug --enable-maintainer-mode
make
make install

popd
