# Build the static dependency stack used by curl's GnuTLS backend.
#
# GnuTLS can use the libtasn1 and libunistring copies shipped in its release
# tarball. Curl also calls Nettle directly, so the smallest hermetic stack is
# GMP -> Nettle -> GnuTLS. All three builds deliberately disable assembler and
# optional dynamic integrations: sanitizer instrumentation then covers every
# dependency path and the resulting fuzzer has no non-system runtime library
# dependency.

include_guard(GLOBAL)
include(ExternalProject)

if(NOT UNIX)
    message(FATAL_ERROR "The hermetic GnuTLS dependency stack currently supports Unix hosts only")
endif()

if(DEFINED MAKE)
    set(_GNUTLS_DEPS_MAKE ${MAKE})
elseif(NOT "$ENV{MAKE}" STREQUAL "")
    set(_GNUTLS_DEPS_MAKE "$ENV{MAKE}")
else()
    set(_GNUTLS_DEPS_MAKE make)
endif()

if(CMAKE_C_COMPILER)
    set(_GNUTLS_DEPS_CC ${CMAKE_C_COMPILER})
elseif(NOT "$ENV{CC}" STREQUAL "")
    set(_GNUTLS_DEPS_CC "$ENV{CC}")
else()
    set(_GNUTLS_DEPS_CC cc)
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

# renovate: datasource=custom.gnu depName=gmp
set(GNUTLS_GMP_VERSION 6.3.0)
set(GNUTLS_GMP_INSTALL_DIR
    ${CMAKE_BINARY_DIR}/gmp-${GNUTLS_GMP_VERSION}-install)
set(GNUTLS_GMP_INCLUDE_DIR ${GNUTLS_GMP_INSTALL_DIR}/include)
set(GNUTLS_GMP_STATIC_LIB ${GNUTLS_GMP_INSTALL_DIR}/lib/libgmp.a)
set(GNUTLS_GMP_INSTALL_STAMP
    ${GNUTLS_GMP_INSTALL_DIR}/${MINIMAL_INSTALL_STAMP_NAME})

if(NOT EXISTS ${GNUTLS_GMP_INSTALL_STAMP} OR
   NOT EXISTS ${GNUTLS_GMP_STATIC_LIB})
    ExternalProject_Add(gnutls_gmp_external
        URL
            https://ftp.gnu.org/gnu/gmp/gmp-${GNUTLS_GMP_VERSION}.tar.xz
            https://ftpmirror.gnu.org/gmp/gmp-${GNUTLS_GMP_VERSION}.tar.xz
        PREFIX
            ${CMAKE_BINARY_DIR}/gmp-${GNUTLS_GMP_VERSION}-${MINIMAL_INSTALL_RECIPE}
        CONFIGURE_COMMAND
            ${CMAKE_COMMAND} -E env
                "CC=${_GNUTLS_DEPS_CC}"
                "CFLAGS=$ENV{CFLAGS}"
                "CPPFLAGS=$ENV{CPPFLAGS}"
                "LDFLAGS=$ENV{LDFLAGS}"
                <SOURCE_DIR>/configure
                    --prefix=${GNUTLS_GMP_INSTALL_DIR}
                    --libdir=${GNUTLS_GMP_INSTALL_DIR}/lib
                    --disable-shared
                    --enable-static
                    --disable-assembly
                    --disable-fat
        BUILD_COMMAND ${_GNUTLS_DEPS_MAKE}
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E remove_directory ${GNUTLS_GMP_INSTALL_DIR}
        COMMAND ${_GNUTLS_DEPS_MAKE} install
        COMMAND ${CMAKE_COMMAND} -E touch ${GNUTLS_GMP_INSTALL_STAMP}
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS
            ${GNUTLS_GMP_STATIC_LIB}
            ${GNUTLS_GMP_INSTALL_STAMP}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS
        "GMP for GnuTLS already installed at ${GNUTLS_GMP_INSTALL_DIR}, skipping build")
    add_custom_target(gnutls_gmp_external)
endif()

# renovate: datasource=custom.gnu depName=nettle
set(GNUTLS_NETTLE_VERSION 3.10.2)
set(GNUTLS_NETTLE_INSTALL_DIR
    ${CMAKE_BINARY_DIR}/nettle-${GNUTLS_NETTLE_VERSION}-install)
set(GNUTLS_NETTLE_INCLUDE_DIR ${GNUTLS_NETTLE_INSTALL_DIR}/include)
set(GNUTLS_NETTLE_STATIC_LIB
    ${GNUTLS_NETTLE_INSTALL_DIR}/lib/libnettle.a)
set(GNUTLS_HOGWEED_STATIC_LIB
    ${GNUTLS_NETTLE_INSTALL_DIR}/lib/libhogweed.a)
set(GNUTLS_NETTLE_INSTALL_STAMP
    ${GNUTLS_NETTLE_INSTALL_DIR}/${MINIMAL_INSTALL_STAMP_NAME})

set(_GNUTLS_NETTLE_PKG_CONFIG_PATH
    "${GNUTLS_GMP_INSTALL_DIR}/lib/pkgconfig")
if(NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
    string(APPEND _GNUTLS_NETTLE_PKG_CONFIG_PATH ":$ENV{PKG_CONFIG_PATH}")
endif()
set(_GNUTLS_NETTLE_CPPFLAGS "$ENV{CPPFLAGS}")
string(APPEND _GNUTLS_NETTLE_CPPFLAGS
    " -I${GNUTLS_GMP_INCLUDE_DIR}")
set(_GNUTLS_NETTLE_LDFLAGS "$ENV{LDFLAGS}")
string(APPEND _GNUTLS_NETTLE_LDFLAGS
    " -L${GNUTLS_GMP_INSTALL_DIR}/lib")

if(NOT EXISTS ${GNUTLS_NETTLE_INSTALL_STAMP} OR
   NOT EXISTS ${GNUTLS_NETTLE_STATIC_LIB} OR
   NOT EXISTS ${GNUTLS_HOGWEED_STATIC_LIB})
    ExternalProject_Add(gnutls_nettle_external
        URL
            https://ftp.gnu.org/gnu/nettle/nettle-${GNUTLS_NETTLE_VERSION}.tar.gz
            https://ftpmirror.gnu.org/nettle/nettle-${GNUTLS_NETTLE_VERSION}.tar.gz
        PREFIX
            ${CMAKE_BINARY_DIR}/nettle-${GNUTLS_NETTLE_VERSION}-${MINIMAL_INSTALL_RECIPE}
        CONFIGURE_COMMAND
            ${CMAKE_COMMAND} -E env
                "CC=${_GNUTLS_DEPS_CC}"
                "CFLAGS=$ENV{CFLAGS}"
                "CPPFLAGS=${_GNUTLS_NETTLE_CPPFLAGS}"
                "LDFLAGS=${_GNUTLS_NETTLE_LDFLAGS}"
                "PKG_CONFIG_PATH=${_GNUTLS_NETTLE_PKG_CONFIG_PATH}"
                <SOURCE_DIR>/configure
                    --prefix=${GNUTLS_NETTLE_INSTALL_DIR}
                    --libdir=${GNUTLS_NETTLE_INSTALL_DIR}/lib
                    --disable-shared
                    --enable-static
                    --disable-openssl
                    --disable-documentation
                    --disable-assembler
                    --disable-fat
        BUILD_COMMAND
            ${_GNUTLS_DEPS_MAKE} libnettle.a libhogweed.a
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E remove_directory ${GNUTLS_NETTLE_INSTALL_DIR}
        COMMAND
            ${_GNUTLS_DEPS_MAKE}
                install-headers
                install-static
                install-pkgconfig
        COMMAND ${CMAKE_COMMAND} -E touch ${GNUTLS_NETTLE_INSTALL_STAMP}
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS
            ${GNUTLS_NETTLE_STATIC_LIB}
            ${GNUTLS_HOGWEED_STATIC_LIB}
            ${GNUTLS_NETTLE_INSTALL_STAMP}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
    add_dependencies(gnutls_nettle_external gnutls_gmp_external)
else()
    message(STATUS
        "Nettle for GnuTLS already installed at ${GNUTLS_NETTLE_INSTALL_DIR}, skipping build")
    add_custom_target(gnutls_nettle_external)
    add_dependencies(gnutls_nettle_external gnutls_gmp_external)
endif()

# renovate: datasource=gitlab-tags depName=gnutls/gnutls
set(GNUTLS_VERSION 3.8.13)
string(REGEX MATCH "^[0-9]+\\.[0-9]+" GNUTLS_SERIES "${GNUTLS_VERSION}")
set(GNUTLS_INSTALL_DIR ${CMAKE_BINARY_DIR}/gnutls-${GNUTLS_VERSION}-install)
set(GNUTLS_INCLUDE_DIR ${GNUTLS_INSTALL_DIR}/include)
set(GNUTLS_STATIC_LIB ${GNUTLS_INSTALL_DIR}/lib/libgnutls.a)
set(GNUTLS_INSTALL_STAMP
    ${GNUTLS_INSTALL_DIR}/${MINIMAL_INSTALL_STAMP_NAME})

set(_GNUTLS_PKG_CONFIG_PATH
    "${GNUTLS_NETTLE_INSTALL_DIR}/lib/pkgconfig:${GNUTLS_GMP_INSTALL_DIR}/lib/pkgconfig")
if(NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
    string(APPEND _GNUTLS_PKG_CONFIG_PATH ":$ENV{PKG_CONFIG_PATH}")
endif()
set(_GNUTLS_CPPFLAGS "$ENV{CPPFLAGS}")
string(APPEND _GNUTLS_CPPFLAGS
    " -I${GNUTLS_NETTLE_INCLUDE_DIR} -I${GNUTLS_GMP_INCLUDE_DIR}")
set(_GNUTLS_LDFLAGS "$ENV{LDFLAGS}")
string(APPEND _GNUTLS_LDFLAGS
    " -L${GNUTLS_NETTLE_INSTALL_DIR}/lib -L${GNUTLS_GMP_INSTALL_DIR}/lib")

if(NOT EXISTS ${GNUTLS_INSTALL_STAMP} OR
   NOT EXISTS ${GNUTLS_STATIC_LIB})
    ExternalProject_Add(gnutls_external
        URL
            https://www.gnupg.org/ftp/gcrypt/gnutls/v${GNUTLS_SERIES}/gnutls-${GNUTLS_VERSION}.tar.xz
        PREFIX
            ${CMAKE_BINARY_DIR}/gnutls-${GNUTLS_VERSION}-${MINIMAL_INSTALL_RECIPE}
        CONFIGURE_COMMAND
            ${CMAKE_COMMAND} -E env
                "CC=${_GNUTLS_DEPS_CC}"
                "CFLAGS=$ENV{CFLAGS}"
                "CPPFLAGS=${_GNUTLS_CPPFLAGS}"
                "LDFLAGS=${_GNUTLS_LDFLAGS}"
                "PKG_CONFIG_PATH=${_GNUTLS_PKG_CONFIG_PATH}"
                <SOURCE_DIR>/configure
                    --prefix=${GNUTLS_INSTALL_DIR}
                    --libdir=${GNUTLS_INSTALL_DIR}/lib
                    --disable-shared
                    --enable-static
                    --disable-doc
                    --disable-tests
                    --disable-tools
                    --disable-cxx
                    --disable-maintainer-mode
                    --disable-libdane
                    --disable-nls
                    --disable-hardware-acceleration
                    --with-included-libtasn1
                    --with-included-unistring
                    --without-idn
                    --without-p11-kit
                    --without-tpm
                    --with-tpm2=no
                    --without-zlib
                    --without-brotli
                    --without-zstd
        BUILD_COMMAND ${_GNUTLS_DEPS_MAKE}
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E remove_directory ${GNUTLS_INSTALL_DIR}
        COMMAND ${_GNUTLS_DEPS_MAKE} install
        COMMAND ${CMAKE_COMMAND} -E touch ${GNUTLS_INSTALL_STAMP}
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS
            ${GNUTLS_STATIC_LIB}
            ${GNUTLS_INSTALL_STAMP}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
    add_dependencies(gnutls_external gnutls_nettle_external)
else()
    message(STATUS
        "GnuTLS already installed at ${GNUTLS_INSTALL_DIR}, skipping build")
    add_custom_target(gnutls_external)
    add_dependencies(gnutls_external gnutls_nettle_external)
endif()

add_custom_target(gnutls_dependencies DEPENDS gnutls_external)

# Archive order matters when consumers link statically: GnuTLS calls Hogweed
# and Nettle, while Hogweed and Nettle call GMP.
set(GNUTLS_STATIC_LIBS
    ${GNUTLS_STATIC_LIB}
    ${GNUTLS_HOGWEED_STATIC_LIB}
    ${GNUTLS_NETTLE_STATIC_LIB}
    ${GNUTLS_GMP_STATIC_LIB}
)
set(GNUTLS_SYSTEM_LIBS ${CMAKE_DL_LIBS})
if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    # GnuTLS' configure records this in Libs.private on Linux. Keep it after
    # the four archives so Clang can resolve the atomic helpers they use.
    list(APPEND GNUTLS_SYSTEM_LIBS atomic)
endif()
set(GNUTLS_EXTERNAL_DEP gnutls_external)
set(GNUTLS_CACHE_INSTALL_DIRS
    ${GNUTLS_GMP_INSTALL_DIR}
    ${GNUTLS_NETTLE_INSTALL_DIR}
    ${GNUTLS_INSTALL_DIR}
)

# Arguments consumed by curl's own CMake configure. The final fuzzer link must
# still use GNUTLS_STATIC_LIBS because libcurl.a cannot retain private static
# dependencies.
set(GNUTLS_CURL_CMAKE_ARGS
    -DCURL_ENABLE_SSL=ON
    -DCURL_USE_OPENSSL=OFF
    -DCURL_USE_GNUTLS=ON
    -DGNUTLS_INCLUDE_DIR=${GNUTLS_INCLUDE_DIR}
    -DGNUTLS_LIBRARY=${GNUTLS_STATIC_LIB}
    -DNETTLE_INCLUDE_DIR=${GNUTLS_NETTLE_INCLUDE_DIR}
    -DNETTLE_HOGWEED_LIBRARY=${GNUTLS_HOGWEED_STATIC_LIB}
    -DNETTLE_LIBRARY=${GNUTLS_NETTLE_STATIC_LIB}
)

# This target is convenient for final fuzzer links. CMake validates interface
# include paths while generating, before ExternalProject has installed them, so
# create only the empty directories here; the dependency chain populates them
# before any consumer is compiled.
file(MAKE_DIRECTORY
    ${GNUTLS_INCLUDE_DIR}
    ${GNUTLS_NETTLE_INCLUDE_DIR}
    ${GNUTLS_GMP_INCLUDE_DIR})
add_library(curl_fuzzer_gnutls_dependencies INTERFACE)
target_include_directories(curl_fuzzer_gnutls_dependencies INTERFACE
    ${GNUTLS_INCLUDE_DIR}
    ${GNUTLS_NETTLE_INCLUDE_DIR}
    ${GNUTLS_GMP_INCLUDE_DIR})
target_link_libraries(curl_fuzzer_gnutls_dependencies INTERFACE
    ${GNUTLS_STATIC_LIBS}
    ${GNUTLS_SYSTEM_LIBS})
add_dependencies(curl_fuzzer_gnutls_dependencies gnutls_external)
add_library(curl_fuzzer::gnutls_dependencies ALIAS
    curl_fuzzer_gnutls_dependencies)

unset(_GNUTLS_DEPS_MAKE)
unset(_GNUTLS_DEPS_CC)
unset(_GNUTLS_NETTLE_PKG_CONFIG_PATH)
unset(_GNUTLS_NETTLE_CPPFLAGS)
unset(_GNUTLS_NETTLE_LDFLAGS)
unset(_GNUTLS_PKG_CONFIG_PATH)
unset(_GNUTLS_CPPFLAGS)
unset(_GNUTLS_LDFLAGS)
