# Build the static HTTP/3 dependency stack used by curl's ngtcp2 backend.
#
# Curl's ngtcp2 integration needs libngtcp2, its OpenSSL crypto adapter, and
# libnghttp3. The mock peer also uses ngtcp2's OpenSSL crypto adapter, so the
# project's shared OpenSSL build can retain its normal unsafe TLS-fuzzing
# behavior without exercising OpenSSL's incompatible native-QUIC shortcuts.
# ngtcp2 and nghttp3 are configured library-only to keep OSS-Fuzz builds and
# cached install prefixes small.

include_guard(GLOBAL)
include(ExternalProject)

if(NOT UNIX)
    message(FATAL_ERROR
        "The hermetic HTTP/3 dependency stack currently supports Unix hosts only")
endif()

if(NOT DEFINED OPENSSL_VERSION OR OPENSSL_VERSION VERSION_LESS 3.5.0)
    message(FATAL_ERROR
        "The ngtcp2 OpenSSL backend requires OpenSSL 3.5.0 or newer")
endif()
if(NOT DEFINED OPENSSL_INSTALL_DIR OR NOT TARGET openssl_external)
    message(FATAL_ERROR
        "Http3Dependencies.cmake requires the shared OpenSSL dependency")
endif()

# Keep the marker compatible with scripts/trim_cache.sh. The top-level project
# owns this recipe name; provide the same default when this module is exercised
# by a small standalone configure project.
if(NOT DEFINED MINIMAL_INSTALL_RECIPE)
    set(MINIMAL_INSTALL_RECIPE minimal-install-v1)
endif()
if(NOT DEFINED MINIMAL_INSTALL_STAMP_NAME)
    set(MINIMAL_INSTALL_STAMP_NAME
        .curl-fuzzer-${MINIMAL_INSTALL_RECIPE})
endif()

set(HTTP3_OPENSSL_INSTALL_DIR ${OPENSSL_INSTALL_DIR})
set(HTTP3_OPENSSL_INCLUDE_DIR ${HTTP3_OPENSSL_INSTALL_DIR}/include)
set(HTTP3_OPENSSL_SSL_STATIC_LIB
    ${HTTP3_OPENSSL_INSTALL_DIR}/lib/libssl.a)
set(HTTP3_OPENSSL_CRYPTO_STATIC_LIB
    ${HTTP3_OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
set(HTTP3_OPENSSL_STATIC_LIBS
    ${HTTP3_OPENSSL_SSL_STATIC_LIB}
    ${HTTP3_OPENSSL_CRYPTO_STATIC_LIB})
set(HTTP3_OPENSSL_DEP openssl_external)

# renovate: datasource=github-releases depName=ngtcp2/nghttp3
set(HTTP3_NGHTTP3_VERSION 1.18.0)
set(HTTP3_NGHTTP3_INSTALL_DIR
    ${CMAKE_BINARY_DIR}/nghttp3-${HTTP3_NGHTTP3_VERSION}-install)
set(HTTP3_NGHTTP3_INCLUDE_DIR ${HTTP3_NGHTTP3_INSTALL_DIR}/include)
set(HTTP3_NGHTTP3_STATIC_LIB
    ${HTTP3_NGHTTP3_INSTALL_DIR}/lib/libnghttp3.a)
set(HTTP3_NGHTTP3_INSTALL_STAMP
    ${HTTP3_NGHTTP3_INSTALL_DIR}/${MINIMAL_INSTALL_STAMP_NAME})

if(NOT EXISTS ${HTTP3_NGHTTP3_INSTALL_STAMP} OR
   NOT EXISTS ${HTTP3_NGHTTP3_STATIC_LIB})
    ExternalProject_Add(http3_nghttp3_external
        URL
            https://github.com/ngtcp2/nghttp3/releases/download/v${HTTP3_NGHTTP3_VERSION}/nghttp3-${HTTP3_NGHTTP3_VERSION}.tar.xz
        PREFIX
            ${CMAKE_BINARY_DIR}/nghttp3-${HTTP3_NGHTTP3_VERSION}-${MINIMAL_INSTALL_RECIPE}
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${HTTP3_NGHTTP3_INSTALL_DIR}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            "-DCMAKE_C_FLAGS=$ENV{CFLAGS}"
            "-DCMAKE_EXE_LINKER_FLAGS=$ENV{LDFLAGS}"
            -DENABLE_LIB_ONLY=ON
            -DENABLE_STATIC_LIB=ON
            -DENABLE_SHARED_LIB=OFF
            -DBUILD_TESTING=OFF
            -DENABLE_WERROR=OFF
        BUILD_COMMAND
            ${CMAKE_COMMAND} --build <BINARY_DIR> --target nghttp3_static
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E remove_directory
                ${HTTP3_NGHTTP3_INSTALL_DIR}
        COMMAND ${CMAKE_COMMAND} --install <BINARY_DIR>
        COMMAND ${CMAKE_COMMAND} -E touch ${HTTP3_NGHTTP3_INSTALL_STAMP}
        BUILD_BYPRODUCTS
            ${HTTP3_NGHTTP3_STATIC_LIB}
            ${HTTP3_NGHTTP3_INSTALL_STAMP}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS
        "nghttp3 already installed at ${HTTP3_NGHTTP3_INSTALL_DIR}, skipping build")
    add_custom_target(http3_nghttp3_external)
endif()

# renovate: datasource=github-releases depName=ngtcp2/ngtcp2
set(HTTP3_NGTCP2_VERSION 1.25.0)
set(HTTP3_NGTCP2_INSTALL_DIR
    ${CMAKE_BINARY_DIR}/ngtcp2-${HTTP3_NGTCP2_VERSION}-install)
set(HTTP3_NGTCP2_INCLUDE_DIR ${HTTP3_NGTCP2_INSTALL_DIR}/include)
set(HTTP3_NGTCP2_STATIC_LIB
    ${HTTP3_NGTCP2_INSTALL_DIR}/lib/libngtcp2.a)
set(HTTP3_NGTCP2_CRYPTO_OSSL_STATIC_LIB
    ${HTTP3_NGTCP2_INSTALL_DIR}/lib/libngtcp2_crypto_ossl.a)
set(HTTP3_NGTCP2_INSTALL_STAMP
    ${HTTP3_NGTCP2_INSTALL_DIR}/${MINIMAL_INSTALL_STAMP_NAME})

if(NOT EXISTS ${HTTP3_NGTCP2_INSTALL_STAMP} OR
   NOT EXISTS ${HTTP3_NGTCP2_STATIC_LIB} OR
   NOT EXISTS ${HTTP3_NGTCP2_CRYPTO_OSSL_STATIC_LIB})
    ExternalProject_Add(http3_ngtcp2_external
        URL
            https://github.com/ngtcp2/ngtcp2/releases/download/v${HTTP3_NGTCP2_VERSION}/ngtcp2-${HTTP3_NGTCP2_VERSION}.tar.xz
        PREFIX
            ${CMAKE_BINARY_DIR}/ngtcp2-${HTTP3_NGTCP2_VERSION}-${MINIMAL_INSTALL_RECIPE}
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${HTTP3_NGTCP2_INSTALL_DIR}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            "-DCMAKE_C_FLAGS=$ENV{CFLAGS}"
            "-DCMAKE_EXE_LINKER_FLAGS=$ENV{LDFLAGS}"
            -DCMAKE_PREFIX_PATH=${HTTP3_OPENSSL_INSTALL_DIR}
            -DOPENSSL_ROOT_DIR=${HTTP3_OPENSSL_INSTALL_DIR}
            -DOPENSSL_INCLUDE_DIR=${HTTP3_OPENSSL_INCLUDE_DIR}
            -DOPENSSL_SSL_LIBRARY=${HTTP3_OPENSSL_SSL_STATIC_LIB}
            -DOPENSSL_CRYPTO_LIBRARY=${HTTP3_OPENSSL_CRYPTO_STATIC_LIB}
            -DOPENSSL_USE_STATIC_LIBS=ON
            -DENABLE_LIB_ONLY=ON
            -DENABLE_STATIC_LIB=ON
            -DENABLE_SHARED_LIB=OFF
            -DBUILD_TESTING=OFF
            -DENABLE_WERROR=OFF
            -DENABLE_OPENSSL=ON
            -DENABLE_BORINGSSL=OFF
            -DENABLE_GNUTLS=OFF
            -DENABLE_PICOTLS=OFF
            -DENABLE_WOLFSSL=OFF
            -DENABLE_JEMALLOC=OFF
            # ngtcp2's single OpenSSL switch selects between QuicTLS and the
            # native OpenSSL 3.5+ adapter by probing these two symbols. An
            # OSS-Fuzz-instrumented static libssl cannot be try-linked without
            # the sanitizer runtime, so tell CMake the result guaranteed by
            # the OpenSSL version check above instead of accepting a false
            # negative and rejecting the backend.
            -DHAVE_SSL_PROVIDE_QUIC_DATA=OFF
            -DHAVE_SSL_SET_QUIC_TLS_CBS=ON
        BUILD_COMMAND
            ${CMAKE_COMMAND} --build <BINARY_DIR>
                --target ngtcp2_static ngtcp2_crypto_ossl_static
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E remove_directory
                ${HTTP3_NGTCP2_INSTALL_DIR}
        COMMAND ${CMAKE_COMMAND} --install <BINARY_DIR>
        COMMAND ${CMAKE_COMMAND} -E touch ${HTTP3_NGTCP2_INSTALL_STAMP}
        DEPENDS ${HTTP3_OPENSSL_DEP}
        BUILD_BYPRODUCTS
            ${HTTP3_NGTCP2_STATIC_LIB}
            ${HTTP3_NGTCP2_CRYPTO_OSSL_STATIC_LIB}
            ${HTTP3_NGTCP2_INSTALL_STAMP}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS
        "ngtcp2 already installed at ${HTTP3_NGTCP2_INSTALL_DIR}, skipping build")
    add_custom_target(http3_ngtcp2_external)
    add_dependencies(http3_ngtcp2_external ${HTTP3_OPENSSL_DEP})
endif()

add_custom_target(http3_dependencies
    DEPENDS
        ${HTTP3_OPENSSL_DEP}
        http3_nghttp3_external
        http3_ngtcp2_external)

# Put dependent archives first for a conventional one-pass static link:
# libngtcp2_crypto_ossl calls libngtcp2 and then the shared OpenSSL stack.
set(HTTP3_STATIC_LIBS
    ${HTTP3_NGHTTP3_STATIC_LIB}
    ${HTTP3_NGTCP2_CRYPTO_OSSL_STATIC_LIB}
    ${HTTP3_NGTCP2_STATIC_LIB}
)
set(HTTP3_SYSTEM_LIBS ${CMAKE_DL_LIBS})
set(HTTP3_EXTERNAL_DEP http3_dependencies)
set(HTTP3_EXTERNAL_DEPS
    ${HTTP3_OPENSSL_DEP}
    http3_nghttp3_external
    http3_ngtcp2_external
)
set(HTTP3_CACHE_INSTALL_DIRS
    ${HTTP3_NGHTTP3_INSTALL_DIR}
    ${HTTP3_NGTCP2_INSTALL_DIR}
)

# Arguments consumed by the dedicated curl HTTP/3 variant. Direct paths keep
# detection hermetic even though the minimal OpenSSL install intentionally
# removes pkg-config metadata.
set(HTTP3_CURL_CMAKE_ARGS
    -DUSE_NGTCP2=ON
    -DUSE_QUICHE=OFF
    -DOPENSSL_ROOT_DIR=${HTTP3_OPENSSL_INSTALL_DIR}
    -DOPENSSL_USE_STATIC_LIBS=ON
    -DOPENSSL_INCLUDE_DIR=${HTTP3_OPENSSL_INCLUDE_DIR}
    -DOPENSSL_SSL_LIBRARY=${HTTP3_OPENSSL_SSL_STATIC_LIB}
    -DOPENSSL_CRYPTO_LIBRARY=${HTTP3_OPENSSL_CRYPTO_STATIC_LIB}
    # Curl repeats the same native-QUIC symbol probe while selecting the
    # ngtcp2 "ossl" component. Avoid the same sanitizer try-link failure.
    -DHAVE_SSL_SET_QUIC_TLS_CBS=ON
    -DNGHTTP3_USE_STATIC_LIBS=ON
    -DNGHTTP3_INCLUDE_DIR=${HTTP3_NGHTTP3_INCLUDE_DIR}
    -DNGHTTP3_LIBRARY=${HTTP3_NGHTTP3_STATIC_LIB}
    -DNGTCP2_USE_STATIC_LIBS=ON
    -DNGTCP2_INCLUDE_DIR=${HTTP3_NGTCP2_INCLUDE_DIR}
    -DNGTCP2_LIBRARY=${HTTP3_NGTCP2_STATIC_LIB}
    -DNGTCP2_CRYPTO_OSSL_LIBRARY=${HTTP3_NGTCP2_CRYPTO_OSSL_STATIC_LIB}
)

# CMake validates interface include paths while generating, before the
# ExternalProjects have installed them. Create only the empty roots here; the
# dependency chain populates them before any consumer is compiled.
file(MAKE_DIRECTORY
    ${HTTP3_OPENSSL_INCLUDE_DIR}
    ${HTTP3_NGHTTP3_INCLUDE_DIR}
    ${HTTP3_NGTCP2_INCLUDE_DIR})
add_library(curl_fuzzer_http3_dependencies INTERFACE)
target_include_directories(curl_fuzzer_http3_dependencies INTERFACE
    ${HTTP3_NGHTTP3_INCLUDE_DIR}
    ${HTTP3_NGTCP2_INCLUDE_DIR}
    ${HTTP3_OPENSSL_INCLUDE_DIR})
target_link_libraries(curl_fuzzer_http3_dependencies INTERFACE
    ${HTTP3_STATIC_LIBS}
    ${HTTP3_OPENSSL_STATIC_LIBS}
    ${HTTP3_SYSTEM_LIBS})
add_dependencies(curl_fuzzer_http3_dependencies http3_dependencies)
add_library(curl_fuzzer::http3_dependencies ALIAS
    curl_fuzzer_http3_dependencies)
