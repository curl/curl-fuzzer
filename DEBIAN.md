# Running curl-fuzzer on Debian Unstable

Currently clang-19 is the latest. Let's use this.

## install

    apt install libfuzzer-19-dev

## build

Patch the build script to use the correct libfuzzer

~~~diff
diff --git a/scripts/install_openssl.sh b/scripts/install_openssl.sh
index 91f90dfc..f8a1bf70 100755
--- a/scripts/install_openssl.sh
+++ b/scripts/install_openssl.sh
@@ -38,11 +38,11 @@ pushd ${SRCDIR}
 # Build the library.
 ${ARCH_PROG} ./config --prefix=${INSTALLDIR} \
                       --libdir=lib \
                       --debug \
                       enable-fuzz-libfuzzer \
-                      --with-fuzzer-lib=/usr/lib/libFuzzingEngine \
+                      --with-fuzzer-lib=/usr/lib/llvm-19/lib/libFuzzer \
                       -DPEDANTIC \
                       -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
                       no-shared \
                       ${ASM_FLAG} \
                       enable-tls1_3 \
~~~
