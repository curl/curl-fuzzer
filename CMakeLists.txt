cmake_minimum_required(VERSION 3.11)
project(curl_fuzzer_deps)

include(ExternalProject)

# Install zlib
#
# renovate: datasource=github-tags depName=madler/zlib
set(ZLIB_VERSION 1.3.1)
set(ZLIB_URL https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz)
set(ZLIB_INSTALL_DIR ${CMAKE_BINARY_DIR}/zlib-install)

ExternalProject_Add(
    zlib_external
    URL ${ZLIB_URL}
    PREFIX ${CMAKE_BINARY_DIR}/zlib
    SOURCE_SUBDIR .
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --static --prefix=${ZLIB_INSTALL_DIR}
    BUILD_COMMAND $(MAKE)
    INSTALL_COMMAND $(MAKE) install
    BUILD_IN_SOURCE 1
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(ZLIB_STATIC_LIB ${ZLIB_INSTALL_DIR}/lib/libz.a)

# Install zstd
#
# renovate: datasource=github-tags depName=facebook/zstd
set(ZSTD_VERSION 1.5.7)
set(ZSTD_URL https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz)
set(ZSTD_INSTALL_DIR ${CMAKE_BINARY_DIR}/zstd-install)

ExternalProject_Add(
    zstd_external
    URL ${ZSTD_URL}
    PREFIX ${CMAKE_BINARY_DIR}/zstd
    SOURCE_SUBDIR build/cmake
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ZSTD_INSTALL_DIR} -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON
    BUILD_COMMAND $(MAKE)
    INSTALL_COMMAND $(MAKE) install
    BUILD_IN_SOURCE 0
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(ZSTD_STATIC_LIB ${ZSTD_INSTALL_DIR}/lib/libzstd.a)

# For the memory sanitizer build, turn off OpenSSL as it causes bugs we can't
# affect (see 16697, 17624)
if(NOT (DEFINED ENV{SANITIZER} AND "$ENV{SANITIZER}" STREQUAL "memory"))
    message(STATUS "Building OpenSSL as a dependency")
    # Install openssl
    #
    # renovate: datasource=github-tags depName=openssl/openssl
    set(OPENSSL_VERSION 3.5.0)
    set(OPENSSL_URL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz)
    set(OPENSSL_INSTALL_DIR ${CMAKE_BINARY_DIR}/openssl-install)
    set(OPENSSL_SRC_DIR ${CMAKE_BINARY_DIR}/openssl/src/openssl_external)

    # Architecture and sanitizer logic
    set(OPENSSL_ARCH_TARGET "")
    set(OPENSSL_ARCH_FLAG "")
    set(OPENSSL_EC_FLAG "enable-ec_nistp_64_gcc_128")
    if(DEFINED ENV{ARCHITECTURE} AND "$ENV{ARCHITECTURE}" STREQUAL "i386")
        set(OPENSSL_ARCH_TARGET "linux-generic32")
        set(OPENSSL_ARCH_FLAG "386")
        set(OPENSSL_EC_FLAG "no-threads")
    endif()

    set(OPENSSL_ASM_FLAG "")
    if(DEFINED ENV{SANITIZER} AND "$ENV{SANITIZER}" STREQUAL "memory")
        set(OPENSSL_ASM_FLAG "no-asm")
    endif()

    # Compose the config command
    set(OPENSSL_CONFIGURE_COMMAND
        ./Configure
        ${OPENSSL_ARCH_TARGET}
        --prefix=${OPENSSL_INSTALL_DIR}
        --libdir=lib
        --debug
        -DPEDANTIC
        -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        no-shared
        no-tests
        ${OPENSSL_ASM_FLAG}
        ${OPENSSL_ARCH_FLAG}
        enable-tls1_3
        enable-rc5
        enable-md2
        enable-ssl3
        ${OPENSSL_EC_FLAG}
        enable-ssl3-method
        enable-nextprotoneg
        enable-weak-ssl-ciphers
        --with-zlib-include=${ZLIB_INSTALL_DIR}/include
        --with-zlib-lib=${ZLIB_INSTALL_DIR}/lib
        $ENV{OPENSSLFLAGS}
    )

    ExternalProject_Add(
        openssl_external
        URL ${OPENSSL_URL}
        PREFIX ${CMAKE_BINARY_DIR}/openssl
        SOURCE_SUBDIR .
        CONFIGURE_COMMAND ${OPENSSL_CONFIGURE_COMMAND}
        BUILD_COMMAND $(MAKE)
        INSTALL_COMMAND $(MAKE) install_sw
        BUILD_IN_SOURCE 1
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )

    # Build zlib before openssl
    add_dependencies(openssl_external zlib_external)

    # Set the OpenSSL option for nghttp2
    set(NGHTTP2_OPENSSL_OPTION --with-openssl=${OPENSSL_INSTALL_DIR})

    # Set the dependency option for openssl
    set(OPENSSL_DEP openssl_external)
    set(OPENSSL_STATIC_LIB ${OPENSSL_INSTALL_DIR}/lib/libssl.a ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
else()
    message(STATUS "Not building OpenSSL")
    set(NGHTTP2_OPENSSL_OPTION --without-openssl)
    set(OPENSSL_DEP "")
    set(OPENSSL_STATIC_LIB "")
endif()

# Install nghttp2
#
# renovate: datasource=github-tags depName=nghttp2/nghttp2
set(NGHTTP2_VERSION 1.66.0)
set(NGHTTP2_URL https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.gz)
set(NGHTTP2_INSTALL_DIR ${CMAKE_BINARY_DIR}/nghttp2-install)

set(NGHTTP2_CONFIGURE_COMMAND
    autoreconf -i &&
    ./configure --prefix=${NGHTTP2_INSTALL_DIR}
                --disable-shared
                --enable-static
                --disable-threads
                --enable-lib-only
                --with-zlib=${ZLIB_INSTALL_DIR}
                ${NGHTTP2_OPENSSL_OPTION}
)

ExternalProject_Add(
    nghttp2_external
    URL ${NGHTTP2_URL}
    PREFIX ${CMAKE_BINARY_DIR}/nghttp2
    SOURCE_SUBDIR .
    CONFIGURE_COMMAND ${NGHTTP2_CONFIGURE_COMMAND}
    BUILD_COMMAND $(MAKE)
    INSTALL_COMMAND $(MAKE) install
    BUILD_IN_SOURCE 1
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(NGHTTP2_STATIC_LIB ${NGHTTP2_INSTALL_DIR}/lib/libnghttp2.a)

# Ensure zlib and openssl are built before nghttp2
add_dependencies(nghttp2_external ${OPENSSL_DEP} zlib_external)

# Install libidn2
#
# renovate: datasource=github-tags depName=libidn/libidn2
set(LIBIDN2_VERSION 2.3.8)
set(LIBIDN2_URL https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VERSION}.tar.gz)
set(LIBIDN2_INSTALL_DIR ${CMAKE_BINARY_DIR}/libidn2-install)

ExternalProject_Add(
    libidn2_external
    URL ${LIBIDN2_URL}
    PREFIX ${CMAKE_BINARY_DIR}/libidn2
    SOURCE_SUBDIR .
    CONFIGURE_COMMAND ./configure --prefix=${LIBIDN2_INSTALL_DIR} --disable-shared --enable-static
    BUILD_COMMAND $(MAKE)
    INSTALL_COMMAND $(MAKE) install
    BUILD_IN_SOURCE 1
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(LIBIDN2_STATIC_LIB ${LIBIDN2_INSTALL_DIR}/lib/libidn2.a)

# Install GDB if GDBMODE is set
set(GDB_VERSION 13.2)
set(GDB_URL https://ftp.gnu.org/gnu/gdb/gdb-${GDB_VERSION}.tar.gz)
set(GDB_INSTALL_DIR ${CMAKE_BINARY_DIR}/gdb-install)

option(BUILD_GDB "Build GDB as an external project" OFF)
if(BUILD_GDB)
    ExternalProject_Add(
        gdb_external
        URL ${GDB_URL}
        PREFIX ${CMAKE_BINARY_DIR}/gdb
        SOURCE_SUBDIR .
        CONFIGURE_COMMAND ./configure --prefix=${GDB_INSTALL_DIR}
        BUILD_COMMAND $(MAKE)
        INSTALL_COMMAND $(MAKE) install
        BUILD_IN_SOURCE 1
    )
    set(GDB_DEP gdb_external)
else()
    set(GDB_DEP "")
endif()

# Group non-curl dependencies into a single target
add_custom_target(deps
    DEPENDS
        zlib_external
        ${OPENSSL_DEP}
        nghttp2_external
        zstd_external
        libidn2_external
        ${GDB_DEP}
)

# Now for the main dependencies!
#
# Compile and install curl.
set(CURL_INSTALL_DIR ${CMAKE_BINARY_DIR}/curl-install)

# Determine SSL and nghttp2 options
if(TARGET openssl_external)
    set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")
else()
    set(CURL_SSL_OPTION "--without-ssl")
endif()

set(CURL_CONFIGURE_COMMAND
    autoreconf -fi &&
    ./configure
        --prefix=${CURL_INSTALL_DIR}
        --disable-shared
        --enable-debug
        --enable-maintainer-mode
        --disable-symbol-hiding
        --disable-docs
        --enable-ipv6
        --enable-websockets
        --without-libpsl
        --with-random=/dev/null
        ${CURL_SSL_OPTION}
        --with-zlib=${ZLIB_INSTALL_DIR}
        --with-nghttp2=${NGHTTP2_INSTALL_DIR}
        --with-zstd=${ZSTD_INSTALL_DIR}
        --with-libidn2=${LIBIDN2_INSTALL_DIR}
)

set(CURL_POST_INSTALL_COMMAND
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CURL_INSTALL_DIR}/utfuzzer
    COMMAND ${CMAKE_COMMAND} -E copy_if_different <SOURCE_DIR>/lib/curl_fnmatch.h ${CURL_INSTALL_DIR}/utfuzzer/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different <SOURCE_DIR>/lib/bufq.h ${CURL_INSTALL_DIR}/utfuzzer/
    COMMAND ${CMAKE_COMMAND} -E touch ${CURL_INSTALL_DIR}/utfuzzer/curl_setup.h
)

# Conditionally check to see if there's a source directory or not.
# If there is, use it. Otherwise, download the latest version.
#
if (DEFINED ENV{CURL_SOURCE_DIR})
    message(STATUS "Building curl from source directory: $ENV{CURL_SOURCE_DIR}")
    ExternalProject_Add(
        curl_external
        SOURCE_DIR $ENV{CURL_SOURCE_DIR}
        CONFIGURE_COMMAND ${CURL_CONFIGURE_COMMAND}
        BUILD_COMMAND $(MAKE)
        INSTALL_COMMAND $(MAKE) install
        ${CURL_POST_INSTALL_COMMAND}
        BUILD_IN_SOURCE 1
    )
else()
    message(STATUS "Building curl from git master")
    set(CURL_URL "https://github.com/curl/curl")
    ExternalProject_Add(
        curl_external
        GIT_REPOSITORY ${CURL_URL}
        GIT_SHALLOW 1
        PREFIX ${CMAKE_BINARY_DIR}/curl
        CONFIGURE_COMMAND ${CURL_CONFIGURE_COMMAND}
        BUILD_COMMAND $(MAKE)
        INSTALL_COMMAND $(MAKE) install
        ${CURL_POST_INSTALL_COMMAND}
        BUILD_IN_SOURCE 1
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
endif()

set(CURL_STATIC_LIB ${CURL_INSTALL_DIR}/lib/libcurl.a)
set(CURL_DEPS
    nghttp2_external
    ${OPENSSL_DEP}
    zlib_external
    zstd_external
    libidn2_external
)

# Add dependencies for curl
add_dependencies(curl_external ${CURL_DEPS})

# Now it's time for the main targets!
#
# Read environment variables for compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{CFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} $ENV{CXXFLAGS}")

# Paths to curl install (adjust as needed)
set(CURL_INCLUDE_DIRS
    ${CURL_INSTALL_DIR}/include
    ${CURL_INSTALL_DIR}/utfuzzer
)
set(CURL_LIB_DIR ${CURL_INSTALL_DIR}/lib)

# Fuzzing engine
if (DEFINED ENV{LIB_FUZZING_ENGINE})
    # Check to see if ENV{LIB_FUZZING_ENGINE} is a file. If so, use it directly.
    # Otherwise, assume it's a flag to the compiler.
    if (EXISTS $ENV{LIB_FUZZING_ENGINE})
        message(STATUS "Using LIB_FUZZING_ENGINE file: $ENV{LIB_FUZZING_ENGINE}")
        set(LIB_FUZZING_ENGINE $ENV{LIB_FUZZING_ENGINE})
        set(LIB_FUZZING_ENGINE_FLAG "")
    else()
        message(STATUS "Using LIB_FUZZING_ENGINE as a compiler flag: $ENV{LIB_FUZZING_ENGINE}")
        set(LIB_FUZZING_ENGINE_FLAG $ENV{LIB_FUZZING_ENGINE})
    endif()
    set(LIB_FUZZING_ENGINE_DEP "")
else()
    message(STATUS "Compiling standaloneengine as LIB_FUZZING_ENGINE")
    add_library(standaloneengine STATIC standalone_fuzz_target_runner.cc)
    set(LIB_FUZZING_ENGINE ${CMAKE_BINARY_DIR}/libstandaloneengine.a)
    set(LIB_FUZZING_ENGINE_FLAG "")
    set(LIB_FUZZING_ENGINE_DEP standaloneengine)
endif()

# Common sources and flags
set(COMMON_SOURCES curl_fuzzer.cc curl_fuzzer_tlv.cc curl_fuzzer_callback.cc)
set(COMMON_FLAGS -g -DCURL_DISABLE_DEPRECATION)
set(COMMON_LINK_LIBS
    ${CURL_LIB_DIR}/libcurl.a
    ${NGHTTP2_STATIC_LIB}
    ${OPENSSL_STATIC_LIB}
    ${ZLIB_STATIC_LIB}
    ${ZSTD_STATIC_LIB}
    ${LIBIDN2_STATIC_LIB}
    ${LIB_FUZZING_ENGINE}
    pthread
    m
)
set(COMMON_LINK_OPTIONS ${LIB_FUZZING_ENGINE_FLAG})

# Ensure that curl and its dependencies are built before the fuzzers
set(FUZZ_DEPS curl_external ${CURL_DEPS} ${LIB_FUZZING_ENGINE_DEP})

# Helper macro to define a fuzzer target
macro(add_curl_fuzzer name proto)
    add_executable(${name} ${COMMON_SOURCES})
    target_compile_options(${name} PRIVATE ${COMMON_FLAGS} -DFUZZ_PROTOCOLS_${proto})
    target_include_directories(${name} PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(${name} PRIVATE ${COMMON_LINK_LIBS})
    target_link_options(${name} PRIVATE ${COMMON_LINK_OPTIONS})
    add_dependencies(${name} ${FUZZ_DEPS})
endmacro()

# Main fuzzer and protocol-specific fuzzers
add_curl_fuzzer(curl_fuzzer           ALL)
add_curl_fuzzer(curl_fuzzer_dict      DICT)
add_curl_fuzzer(curl_fuzzer_file      FILE)
add_curl_fuzzer(curl_fuzzer_ftp       FTP)
add_curl_fuzzer(curl_fuzzer_gopher    GOPHER)
add_curl_fuzzer(curl_fuzzer_http      HTTP)
add_curl_fuzzer(curl_fuzzer_https     HTTPS)
add_curl_fuzzer(curl_fuzzer_imap      IMAP)
add_curl_fuzzer(curl_fuzzer_mqtt      MQTT)
add_curl_fuzzer(curl_fuzzer_pop3      POP3)
add_curl_fuzzer(curl_fuzzer_rtsp      RTSP)
add_curl_fuzzer(curl_fuzzer_smb       SMB)
add_curl_fuzzer(curl_fuzzer_smtp      SMTP)
add_curl_fuzzer(curl_fuzzer_tftp      TFTP)
add_curl_fuzzer(curl_fuzzer_ws        WS)

# BUFQ fuzzer
# temporary disable bufq fuzzer for merging API change
# add_executable(curl_fuzzer_bufq fuzz_bufq.cc)
# target_compile_options(curl_fuzzer_bufq PRIVATE ${COMMON_FLAGS})
# target_include_directories(curl_fuzzer_bufq PRIVATE ${CURL_INCLUDE_DIRS})
# target_link_libraries(curl_fuzzer_bufq PRIVATE ${COMMON_LINK_LIBS})
# target_link_options(curl_fuzzer_bufq PRIVATE ${COMMON_LINK_OPTIONS})
# add_dependencies(curl_fuzzer_bufq ${FUZZ_DEPS})

# URL fuzzer
add_executable(fuzz_url fuzz_url.cc)
target_compile_options(fuzz_url PRIVATE ${COMMON_FLAGS})
target_include_directories(fuzz_url PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(fuzz_url PRIVATE ${COMMON_LINK_LIBS})
target_link_options(fuzz_url PRIVATE ${COMMON_LINK_OPTIONS})
add_dependencies(fuzz_url ${FUZZ_DEPS})

# Unit test fuzzer
add_executable(curl_fuzzer_fnmatch fuzz_fnmatch.cc)
target_compile_options(curl_fuzzer_fnmatch PRIVATE ${COMMON_FLAGS})
target_include_directories(curl_fuzzer_fnmatch PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(curl_fuzzer_fnmatch PRIVATE ${COMMON_LINK_LIBS})
target_link_options(curl_fuzzer_fnmatch PRIVATE ${COMMON_LINK_OPTIONS})
add_dependencies(curl_fuzzer_fnmatch ${FUZZ_DEPS})

# Create a custom target for all fuzzers
add_custom_target(fuzz
    DEPENDS
        curl_fuzzer
        curl_fuzzer_dict
        curl_fuzzer_file
        curl_fuzzer_ftp
        curl_fuzzer_gopher
        curl_fuzzer_http
        curl_fuzzer_https
        curl_fuzzer_imap
        curl_fuzzer_mqtt
        curl_fuzzer_pop3
        curl_fuzzer_rtsp
        curl_fuzzer_smb
        curl_fuzzer_smtp
        curl_fuzzer_tftp
        curl_fuzzer_ws
        # curl_fuzzer_bufq
        fuzz_url
        curl_fuzzer_fnmatch
)
