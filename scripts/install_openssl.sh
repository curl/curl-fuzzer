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
./config --prefix=${INSTALLDIR} \
         --debug \
         enable-fuzz-libfuzzer \
         -DPEDANTIC \
         -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
         no-shared \
         enable-tls1_3 \
         enable-rc5 \
         enable-md2 \
         enable-ec_nistp_64_gcc_128 \
         enable-ssl3 \
         enable-ssl3-method \
         enable-nextprotoneg \
         enable-weak-ssl-ciphers \
         $CFLAGS \
         ${OPENSSLFLAGS}

make
make install

popd
