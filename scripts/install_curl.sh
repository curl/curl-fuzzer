#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Exit if the build root has not been defined.
[[ -d ${BUILD_ROOT} ]] || exit 1

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

if [[ -f ${INSTALLDIR}/lib/libssl.a ]]
then
  SSLOPTION=--with-ssl=${INSTALLDIR}
else
  SSLOPTION=--without-ssl
fi

if [[ -f ${INSTALLDIR}/lib/libnghttp2.a ]]
then
  NGHTTP2OPTION=--with-nghttp2=${INSTALLDIR}
else
  NGHTTP2OPTION=--without-nghttp2
fi

if [[ -f ${INSTALLDIR}/lib/libnghttp3.a ]]
then
  NGHTTP3OPTION=--with-nghttp3=${INSTALLDIR}
else
  NGHTTP3OPTION=--without-nghttp3
fi

if [[ -f ${INSTALLDIR}/lib/libngtcp2.a ]]
then
  NGTCP2OPTION=--with-ngtcp2=${INSTALLDIR}
else
  NGTCP2OPTION=--without-ngtcp2
fi

pushd ${SRCDIR}

# Build the library.
./buildconf
./configure PKG_CONFIG_PATH=${INSTALLDIR}/lib/pkgconfig \
            --prefix=${INSTALLDIR} \
            --disable-shared \
            --enable-debug \
            --enable-maintainer-mode \
            --disable-symbol-hiding \
            --enable-ipv6 \
            --enable-websockets \
            --with-random=/dev/null \
            ${SSLOPTION} \
            ${NGHTTP2OPTION} \
            ${NGHTTP3OPTION} \
            ${NGTCP2OPTION} \
            ${CODE_COVERAGE_OPTION}

make V=1
make install

# Make any explicit folders which are post install
UTFUZZDIR=${INSTALLDIR}/utfuzzer
mkdir -p ${UTFUZZDIR}

# Copy header files.
cp -v lib/curl_fnmatch.h ${UTFUZZDIR}

popd
