# Build the static Mbed TLS stack used by curl's mbedTLS backend.
#
# Mbed TLS 4 ships TF-PSA-Crypto in its official release archive. Building
# that archive directly keeps the dependency hermetic: generated sources and
# both upstream submodules are present without requiring a Git checkout.

include_guard(GLOBAL)
include(ExternalProject)

if(NOT UNIX)
    message(FATAL_ERROR "The hermetic Mbed TLS dependency currently supports Unix hosts only")
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

# renovate: datasource=github-releases depName=Mbed-TLS/mbedtls
set(MBEDTLS_VERSION 4.2.0)
set(MBEDTLS_INSTALL_DIR
    ${CMAKE_BINARY_DIR}/mbedtls-${MBEDTLS_VERSION}-install)
set(MBEDTLS_INCLUDE_DIR ${MBEDTLS_INSTALL_DIR}/include)
set(MBEDTLS_TLS_STATIC_LIB ${MBEDTLS_INSTALL_DIR}/lib/libmbedtls.a)
set(MBEDTLS_X509_STATIC_LIB ${MBEDTLS_INSTALL_DIR}/lib/libmbedx509.a)
set(MBEDTLS_CRYPTO_STATIC_LIB
    ${MBEDTLS_INSTALL_DIR}/lib/libtfpsacrypto.a)
set(MBEDTLS_INSTALL_STAMP
    ${MBEDTLS_INSTALL_DIR}/${MINIMAL_INSTALL_STAMP_NAME})

if(NOT EXISTS ${MBEDTLS_INSTALL_STAMP} OR
   NOT EXISTS ${MBEDTLS_TLS_STATIC_LIB} OR
   NOT EXISTS ${MBEDTLS_X509_STATIC_LIB} OR
   NOT EXISTS ${MBEDTLS_CRYPTO_STATIC_LIB})
    ExternalProject_Add(mbedtls_external
        URL
            https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2
        PREFIX
            ${CMAKE_BINARY_DIR}/mbedtls-${MBEDTLS_VERSION}-${MINIMAL_INSTALL_RECIPE}
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${MBEDTLS_INSTALL_DIR}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            "-DCMAKE_C_FLAGS=$ENV{CFLAGS}"
            "-DCMAKE_CXX_FLAGS=$ENV{CXXFLAGS}"
            "-DCMAKE_EXE_LINKER_FLAGS=$ENV{LDFLAGS}"
            "-DCMAKE_SHARED_LINKER_FLAGS=$ENV{LDFLAGS}"
            -DENABLE_PROGRAMS=OFF
            -DENABLE_TESTING=OFF
            -DGEN_FILES=OFF
            -DUSE_STATIC_MBEDTLS_LIBRARY=ON
            -DUSE_SHARED_MBEDTLS_LIBRARY=OFF
            -DDISABLE_PACKAGE_CONFIG_AND_INSTALL=OFF
        BUILD_COMMAND
            ${CMAKE_COMMAND} --build <BINARY_DIR> --target lib
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E remove_directory ${MBEDTLS_INSTALL_DIR}
        COMMAND ${CMAKE_COMMAND} --install <BINARY_DIR>
        COMMAND ${CMAKE_COMMAND} -E touch ${MBEDTLS_INSTALL_STAMP}
        BUILD_BYPRODUCTS
            ${MBEDTLS_TLS_STATIC_LIB}
            ${MBEDTLS_X509_STATIC_LIB}
            ${MBEDTLS_CRYPTO_STATIC_LIB}
            ${MBEDTLS_INSTALL_STAMP}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS
        "Mbed TLS already installed at ${MBEDTLS_INSTALL_DIR}, skipping build")
    add_custom_target(mbedtls_external)
endif()

add_custom_target(mbedtls_dependencies DEPENDS mbedtls_external)

# Archive order matters for a static final link: the TLS library calls X.509,
# and X.509 calls the TF-PSA-Crypto implementation bundled with Mbed TLS 4.
set(MBEDTLS_STATIC_LIBS
    ${MBEDTLS_TLS_STATIC_LIB}
    ${MBEDTLS_X509_STATIC_LIB}
    ${MBEDTLS_CRYPTO_STATIC_LIB}
)
set(MBEDTLS_SYSTEM_LIBS "")
set(MBEDTLS_EXTERNAL_DEP mbedtls_external)
set(MBEDTLS_CACHE_INSTALL_DIRS ${MBEDTLS_INSTALL_DIR})

# Arguments consumed by curl's own CMake configure. The final fuzzer link must
# still use MBEDTLS_STATIC_LIBS because libcurl.a cannot retain private static
# dependencies.
set(MBEDTLS_CURL_CMAKE_ARGS
    -DCURL_ENABLE_SSL=ON
    -DCURL_USE_OPENSSL=OFF
    -DCURL_USE_GNUTLS=OFF
    -DCURL_USE_MBEDTLS=ON
    -DMBEDTLS_USE_STATIC_LIBS=ON
    -DMBEDTLS_INCLUDE_DIR=${MBEDTLS_INCLUDE_DIR}
    -DMBEDTLS_LIBRARY=${MBEDTLS_TLS_STATIC_LIB}
    -DMBEDX509_LIBRARY=${MBEDTLS_X509_STATIC_LIB}
    -DMBEDCRYPTO_LIBRARY=${MBEDTLS_CRYPTO_STATIC_LIB}
)

# This target is convenient for final fuzzer links. CMake validates interface
# include paths while generating, before ExternalProject has installed them, so
# create only the empty directory here; the dependency chain populates it
# before any consumer is compiled.
file(MAKE_DIRECTORY ${MBEDTLS_INCLUDE_DIR})
add_library(curl_fuzzer_mbedtls_dependencies INTERFACE)
target_include_directories(curl_fuzzer_mbedtls_dependencies INTERFACE
    ${MBEDTLS_INCLUDE_DIR})
target_link_libraries(curl_fuzzer_mbedtls_dependencies INTERFACE
    ${MBEDTLS_STATIC_LIBS}
    ${MBEDTLS_SYSTEM_LIBS})
add_dependencies(curl_fuzzer_mbedtls_dependencies mbedtls_external)
add_library(curl_fuzzer::mbedtls_dependencies ALIAS
    curl_fuzzer_mbedtls_dependencies)
