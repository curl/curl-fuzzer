#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Clone the curl repository to the specified directory.
git clone http://github.com/curl/curl $1

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
