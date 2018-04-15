#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

SRCDIR=$1
INSTALLDIR=$2

if [[ ! -d ${INSTALLDIR} ]]
then
  # Make an install target directory.
  mkdir ${INSTALLDIR}
fi

pushd ${SRCDIR}

# Build the library.
autoreconf -i
./configure --prefix=${INSTALLDIR} \
            --disable-shared \
            --enable-static \
            --disable-threads

make
make install

popd
