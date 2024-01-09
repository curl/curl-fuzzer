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

autoreconf -fi
./configure PKG_CONFIG_PATH=${INSTALLDIR}/lib/pkgconfig \
            LDFLAGS="-Wl,-rpath,${INSTALLDIR}" \
            --prefix=${INSTALLDIR} \
            --disable-shared \
            --enable-static \
            --enable-lib-only \
            --with-openssl \
            

make
make install
