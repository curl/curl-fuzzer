#!/bin/bash

set -ex

OPENSSLDIR=$1
INSTALLDIR=$2

if [[ -z ${OPENSSLDIR} ]]
then
  OPENSSLDIR=/tmp/openssl
fi

# Download the code if it isn't present
if [[ ! -d ${OPENSSLDIR} ]]
then
  ./download_openssl.sh ${OPENSSLDIR}
fi

# Compile and install openssl
./install_openssl.sh ${OPENSSLDIR} ${INSTALLDIR}

