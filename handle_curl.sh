#!/bin/bash

set -ex

CURLDIR=$1
INSTALLDIR=$2

if [[ -z ${CURLDIR} ]]
then
  CURLDIR=/tmp/curl
fi

# Download the code if it isn't present
if [[ ! -d ${CURLDIR} ]]
then
  ./download_curl.sh ${CURLDIR}
fi

# Compile and install the code
./install_curl.sh ${CURLDIR} ${INSTALLDIR}

