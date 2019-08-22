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

# For i386, set a specific crosscompile mode
if [[ ${ARCHITECTURE} == "i386" ]]
then
    ARCH_PROG="setarch i386"
    EC_FLAG=""
else
    ARCH_PROG=""
    EC_FLAG="enable-ec_nistp_64_gcc_128"
fi

pushd ${SRCDIR}

# Build the library.
${ARCH_PROG} ./config --prefix=${INSTALLDIR} \
                      --debug \
                      enable-fuzz-libfuzzer \
                      -DPEDANTIC \
                      -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
                      no-shared \
                      enable-tls1_3 \
                      enable-rc5 \
                      enable-md2 \
                      enable-ssl3 \
                      ${EC_FLAG} \
                      enable-ssl3-method \
                      enable-nextprotoneg \
                      enable-weak-ssl-ciphers \
                      $CFLAGS \
                      ${OPENSSLFLAGS}

make
make install

popd
