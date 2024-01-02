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
  NGHTTPOPTION=--with-nghttp2=${INSTALLDIR}
else
  NGHTTPOPTION=--without-nghttp2
fi

pushd ${SRCDIR}

# TODO: Ignore HTTP3 socket connection failures
pushd $1
patch -p1 <<'EOF'
diff --git a/lib/cf-socket.c b/lib/cf-socket.c
index e42b4a87b..f99fcd80c 100644
--- a/lib/cf-socket.c
+++ b/lib/cf-socket.c
@@ -1650,7 +1650,7 @@ static CURLcode cf_udp_setup_quic(struct Curl_cfilter *cf,
 
   rc = connect(ctx->sock, &ctx->addr.sa_addr, ctx->addr.addrlen);
   if(-1 == rc) {
-    return socket_connect_result(data, ctx->r_ip, SOCKERRNO);
+    /* return socket_connect_result(data, ctx->r_ip, SOCKERRNO); */
   }
   set_local_ip(cf, data);
   CURL_TRC_CF(data, cf, "%s socket %" CURL_FORMAT_SOCKET_T
EOF
popd

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
            --with-openssl \
            --with-nghttp3 \
            --with-ngtcp2 \
            ${SSLOPTION} \
            ${NGHTTPOPTION} \
            ${CODE_COVERAGE_OPTION}

make V=1
make install

# Make any explicit folders which are post install
UTFUZZDIR=${INSTALLDIR}/utfuzzer
mkdir -p ${UTFUZZDIR}

# Copy header files.
cp -v lib/curl_fnmatch.h ${UTFUZZDIR}

popd
