#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Clone the repository to the specified directory.
git clone --depth 1 --branch v1.1.0 https://github.com/ngtcp2/ngtcp2 $1

# Teach ngtcp2 about sockets
pushd $1
patch -p1 <<'EOF'
From 52690d08112ccd9a5c01b5991735bf3f8e5121b0 Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?Emilio=20L=C3=B3pez?= <emilio.lopez@trailofbits.com>
Date: Sat, 16 Dec 2023 21:33:17 +0000
Subject: [PATCH] Teach ngtcp2 about sockets

---
 crypto/shared.c              | 4 ++++
 lib/includes/ngtcp2/ngtcp2.h | 5 +++++
 lib/ngtcp2_addr.c            | 8 ++++++++
 3 files changed, 17 insertions(+)

diff --git a/crypto/shared.c b/crypto/shared.c
index 162094a3..08c9ed44 100644
--- a/crypto/shared.c
+++ b/crypto/shared.c
@@ -1096,6 +1096,10 @@ static size_t crypto_generate_regular_token_aad(uint8_t *dest,
         (const uint8_t *)&((const ngtcp2_sockaddr_in6 *)(void *)sa)->sin6_addr;
     addrlen = sizeof(((const ngtcp2_sockaddr_in6 *)(void *)sa)->sin6_addr);
     break;
+  case NGTCP2_AF_UNIX:
+    addr = NULL;
+    addrlen = 0;
+    break;
   default:
     assert(0);
     abort();
diff --git a/lib/includes/ngtcp2/ngtcp2.h b/lib/includes/ngtcp2/ngtcp2.h
index a8d4b4af..63958e4c 100644
--- a/lib/includes/ngtcp2/ngtcp2.h
+++ b/lib/includes/ngtcp2/ngtcp2.h
@@ -1235,6 +1235,10 @@ typedef struct ngtcp2_pkt_stateless_reset {
 #    error NGTCP2_AF_INET6 must be defined
 #  endif /* !NGTCP2_AF_INET6 */
 
+#  ifndef NGTCP2_AF_UNIX
+#    error NGTCP2_AF_UNIX must be defined
+#  endif /* !NGTCP2_AF_UNIX */
+
 typedef unsigned short int ngtcp2_sa_family;
 typedef uint16_t ngtcp2_in_port;
 
@@ -1270,6 +1274,7 @@ typedef uint32_t ngtcp2_socklen;
 #else /* !NGTCP2_USE_GENERIC_SOCKADDR */
 #  define NGTCP2_AF_INET AF_INET
 #  define NGTCP2_AF_INET6 AF_INET6
+#  define NGTCP2_AF_UNIX AF_UNIX
 
 /**
  * @typedef
diff --git a/lib/ngtcp2_addr.c b/lib/ngtcp2_addr.c
index f389abe7..26b57f3d 100644
--- a/lib/ngtcp2_addr.c
+++ b/lib/ngtcp2_addr.c
@@ -67,6 +67,10 @@ static int sockaddr_eq(const ngtcp2_sockaddr *a, const ngtcp2_sockaddr *b) {
     return ai->sin6_port == bi->sin6_port &&
            memcmp(&ai->sin6_addr, &bi->sin6_addr, sizeof(ai->sin6_addr)) == 0;
   }
+  case NGTCP2_AF_UNIX: {
+    // TODO: see what makes sense here
+    return 1;
+  }
   default:
     ngtcp2_unreachable();
   }
@@ -109,6 +113,10 @@ uint32_t ngtcp2_addr_compare(const ngtcp2_addr *aa, const ngtcp2_addr *bb) {
     }
     return flags;
   }
+  case NGTCP2_AF_UNIX: {
+    // TODO: see what makes sense here?
+    return 0;
+  }
   default:
     ngtcp2_unreachable();
   }
EOF
popd
