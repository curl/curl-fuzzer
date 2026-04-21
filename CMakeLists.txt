cmake_minimum_required(VERSION 3.11)
project(curl_fuzzer_deps)

if(NOT "$ENV{MAKE}" STREQUAL "")
    set(MAKE "$ENV{MAKE}")
else()
    set(MAKE "make")
endif()

include(ExternalProject)

# Install zlib
#
# renovate: datasource=github-tags depName=madler/zlib
set(ZLIB_VERSION 1.3.1)
set(ZLIB_URL https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.xz
             https://zlib.net/zlib-${ZLIB_VERSION}.tar.xz)
set(ZLIB_INSTALL_DIR ${CMAKE_BINARY_DIR}/zlib-install)
set(ZLIB_STATIC_LIB ${ZLIB_INSTALL_DIR}/lib/libz.a)

ExternalProject_Add(zlib_external
    URL ${ZLIB_URL}
    PREFIX ${CMAKE_BINARY_DIR}/zlib
    CONFIGURE_COMMAND ./configure --static --prefix=${ZLIB_INSTALL_DIR}
    BUILD_IN_SOURCE 1
    BUILD_BYPRODUCTS ${ZLIB_STATIC_LIB}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    DOWNLOAD_NO_PROGRESS 1
)

# Install zstd
#
# renovate: datasource=github-tags depName=facebook/zstd
set(ZSTD_VERSION 1.5.7)
set(ZSTD_URL https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz)
set(ZSTD_INSTALL_DIR ${CMAKE_BINARY_DIR}/zstd-install)
set(ZSTD_STATIC_LIB ${ZSTD_INSTALL_DIR}/lib/libzstd.a)

ExternalProject_Add(zstd_external
    URL ${ZSTD_URL}
    PREFIX ${CMAKE_BINARY_DIR}/zstd
    SOURCE_SUBDIR build/cmake
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ZSTD_INSTALL_DIR}
        -DCMAKE_INSTALL_LIBDIR=lib
        -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_CONTRIB=OFF -DZSTD_BUILD_TESTS=OFF
    BUILD_BYPRODUCTS ${ZSTD_STATIC_LIB}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    DOWNLOAD_NO_PROGRESS 1
)

# For the memory sanitizer build, turn off OpenSSL as it causes bugs we can't
# affect (see 16697, 17624)
if(NOT "$ENV{SANITIZER}" STREQUAL "memory")
    message(STATUS "Building OpenSSL as a dependency")
    # Install openssl
    #
    # renovate: datasource=github-tags depName=openssl/openssl
    set(OPENSSL_VERSION 3.6.2)
    set(OPENSSL_URL
        https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz)
    set(OPENSSL_INSTALL_DIR ${CMAKE_BINARY_DIR}/openssl-install)
    set(OPENSSL_SRC_DIR ${CMAKE_BINARY_DIR}/openssl/src/openssl_external)
    set(OPENSSL_STATIC_LIB ${OPENSSL_INSTALL_DIR}/lib/libssl.a ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)

    # Architecture and sanitizer logic
    set(OPENSSL_ARCH_TARGET "")
    set(OPENSSL_ARCH_FLAG "")
    set(OPENSSL_EC_FLAG "enable-ec_nistp_64_gcc_128")
    if("$ENV{ARCHITECTURE}" STREQUAL "i386")
        set(OPENSSL_ARCH_TARGET "linux-generic32")
        set(OPENSSL_ARCH_FLAG "386")
        set(OPENSSL_EC_FLAG "no-threads")
    endif()

    set(OPENSSL_ASM_FLAG "")
    if("$ENV{SANITIZER}" STREQUAL "memory")
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
        no-apps
        no-makedepend
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

    ExternalProject_Add(openssl_external
        URL ${OPENSSL_URL}
        PREFIX ${CMAKE_BINARY_DIR}/openssl
        CONFIGURE_COMMAND ${OPENSSL_CONFIGURE_COMMAND}
        INSTALL_COMMAND ${MAKE} install_sw
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${OPENSSL_STATIC_LIB}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )

    # Build zlib before openssl
    add_dependencies(openssl_external zlib_external)

    # Set the OpenSSL option for nghttp2
    set(NGHTTP2_OPENSSL_OPTION -DOPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR})

    # Set the dependency option for openssl
    set(OPENSSL_DEP openssl_external)
else()
    message(STATUS "Not building OpenSSL")
    set(NGHTTP2_OPENSSL_OPTION -DOPENSSL_INCLUDE_DIR=)
    set(OPENSSL_DEP "")
    set(OPENSSL_STATIC_LIB "")
endif()

# Install nghttp2
#
# renovate: datasource=github-tags depName=nghttp2/nghttp2
set(NGHTTP2_VERSION 1.69.0)
set(NGHTTP2_URL https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.xz)
set(NGHTTP2_INSTALL_DIR ${CMAKE_BINARY_DIR}/nghttp2-install)
set(NGHTTP2_STATIC_LIB ${NGHTTP2_INSTALL_DIR}/lib/libnghttp2.a)

ExternalProject_Add(nghttp2_external
    URL ${NGHTTP2_URL}
    PREFIX ${CMAKE_BINARY_DIR}/nghttp2
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${NGHTTP2_INSTALL_DIR} -DCMAKE_INSTALL_LIBDIR=lib
        -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF
        -DENABLE_LIB_ONLY=ON -DENABLE_THREADS=OFF -DBUILD_TESTING=OFF -DENABLE_DOC=OFF ${NGHTTP2_OPENSSL_OPTION}
    BUILD_BYPRODUCTS ${NGHTTP2_STATIC_LIB}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    DOWNLOAD_NO_PROGRESS 1
)

# Ensure zlib and openssl are built before nghttp2
add_dependencies(nghttp2_external ${OPENSSL_DEP} zlib_external)

# Install libidn2
#
# renovate: datasource=github-tags depName=libidn/libidn2
set(LIBIDN2_VERSION 2.3.8)
set(LIBIDN2_URL https://ftpmirror.gnu.org/libidn/libidn2-${LIBIDN2_VERSION}.tar.gz
                https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VERSION}.tar.gz)
set(LIBIDN2_INSTALL_DIR ${CMAKE_BINARY_DIR}/libidn2-install)
set(LIBIDN2_STATIC_LIB ${LIBIDN2_INSTALL_DIR}/lib/libidn2.a)

ExternalProject_Add(libidn2_external
    URL ${LIBIDN2_URL}
    PREFIX ${CMAKE_BINARY_DIR}/libidn2
    CONFIGURE_COMMAND ./configure --disable-dependency-tracking --prefix=${LIBIDN2_INSTALL_DIR} --disable-shared --enable-static
        --disable-doc
    BUILD_IN_SOURCE 1
    BUILD_BYPRODUCTS ${LIBIDN2_STATIC_LIB}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    DOWNLOAD_NO_PROGRESS 1
)

# Install GDB if GDBMODE is set
set(GDB_VERSION 13.2)
set(GDB_URL https://ftpmirror.gnu.org/gdb/gdb-${GDB_VERSION}.tar.gz
            https://ftp.gnu.org/gnu/gdb/gdb-${GDB_VERSION}.tar.gz)
set(GDB_INSTALL_DIR ${CMAKE_BINARY_DIR}/gdb-install)

option(BUILD_GDB "Build GDB as an external project" OFF)
if(BUILD_GDB)
    ExternalProject_Add(gdb_external
        URL ${GDB_URL}
        PREFIX ${CMAKE_BINARY_DIR}/gdb
        CONFIGURE_COMMAND ./configure --disable-dependency-tracking --prefix=${GDB_INSTALL_DIR}
        BUILD_IN_SOURCE 1
    )
    set(GDB_DEP gdb_external)
else()
    set(GDB_DEP "")
endif()

# Install OpenLDAP
set(OPENLDAP_VERSION 2.6.12)
set(OPENLDAP_URL https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz
                 https://mirror.lyrahosting.com/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz)
set(OPENLDAP_INSTALL_DIR ${CMAKE_BINARY_DIR}/openldap-install)
set(OPENLDAP_STATIC_LIB_LDAP ${OPENLDAP_INSTALL_DIR}/lib/libldap.a)
set(OPENLDAP_STATIC_LIB_LBER ${OPENLDAP_INSTALL_DIR}/lib/liblber.a)

ExternalProject_Add(openldap_external
    URL ${OPENLDAP_URL}
    PREFIX ${CMAKE_BINARY_DIR}/openldap
    CONFIGURE_COMMAND ./configure --prefix=${OPENLDAP_INSTALL_DIR} --disable-shared --enable-static --without-tls --disable-slapd
    BUILD_IN_SOURCE 1
    BUILD_BYPRODUCTS ${OPENLDAP_STATIC_LIB_LDAP} ${OPENLDAP_STATIC_LIB_LBER}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    DOWNLOAD_NO_PROGRESS 1
)

if(TARGET openssl_external)
    add_dependencies(openldap_external openssl_external)
else()
    message(STATUS "Not building OpenLDAP with OpenSSL")
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
        openldap_external
)

# Now for the main dependencies!
#
# Compile and install curl.
set(CURL_INSTALL_DIR ${CMAKE_BINARY_DIR}/curl-install)

# Determine SSL and nghttp2 options
if(TARGET openssl_external)
    set(CURL_SSL_OPTION -DCURL_USE_OPENSSL=ON -DOPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR})
else()
    set(CURL_SSL_OPTION -DCURL_USE_OPENSSL=OFF)
endif()

set(CURL_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CURL_INSTALL_DIR}
    -DCMAKE_INSTALL_LIBDIR=lib
    -DBUILD_SHARED_LIBS=OFF
    -DENABLE_DEBUG=ON
    -DCURL_HIDDEN_SYMBOLS=OFF
    -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF
    -DCURL_USE_LIBPSL=OFF
    ${CURL_SSL_OPTION}
    -DZLIB_INCLUDE_DIR=${ZLIB_INSTALL_DIR}/include
    -DZLIB_LIBRARY=${ZLIB_STATIC_LIB}
    -DNGHTTP2_INCLUDE_DIR=${NGHTTP2_INSTALL_DIR}/include
    -DNGHTTP2_LIBRARY=${NGHTTP2_STATIC_LIB}
    -DZSTD_INCLUDE_DIR=${ZSTD_INSTALL_DIR}/include
    -DZSTD_LIBRARY=${ZSTD_STATIC_LIB}
    -DLIBIDN2_INCLUDE_DIR=${LIBIDN2_INSTALL_DIR}/include
    -DLIBIDN2_LIBRARY=${LIBIDN2_STATIC_LIB}
    -DLDAP_INCLUDE_DIR=${OPENLDAP_INSTALL_DIR}/include
    -DLDAP_LIBRARY=${OPENLDAP_STATIC_LIB_LDAP}
    -DLDAP_LBER_LIBRARY=${OPENLDAP_STATIC_LIB_LBER}
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
if(NOT "$ENV{CURL_SOURCE_DIR}" STREQUAL "")
    message(STATUS "Building curl from source directory: $ENV{CURL_SOURCE_DIR}")
    ExternalProject_Add(curl_external
        SOURCE_DIR $ENV{CURL_SOURCE_DIR}
        PATCH_COMMAND ${CMAKE_COMMAND} -E echo "pre-build commands"
        ${CURL_POST_INSTALL_COMMAND}
        CMAKE_ARGS ${CURL_CMAKE_ARGS}
        BUILD_BYPRODUCTS ${CURL_INSTALL_DIR}/lib/libcurl.a
    )
else()
    message(STATUS "Building curl from git master")
    set(CURL_URL "https://github.com/curl/curl")
    ExternalProject_Add(curl_external
        GIT_REPOSITORY ${CURL_URL}
        GIT_SHALLOW 1
        PREFIX ${CMAKE_BINARY_DIR}/curl
        PATCH_COMMAND ${CMAKE_COMMAND} -E echo "pre-build commands"
        ${CURL_POST_INSTALL_COMMAND}
        CMAKE_ARGS ${CURL_CMAKE_ARGS}
        BUILD_BYPRODUCTS ${CURL_INSTALL_DIR}/lib/libcurl.a
    )
endif()

set(CURL_STATIC_LIB ${CURL_INSTALL_DIR}/lib/libcurl.a)
set(CURL_DEPS
    nghttp2_external
    ${OPENSSL_DEP}
    zlib_external
    zstd_external
    libidn2_external
    openldap_external
)

# Add dependencies for curl
add_dependencies(curl_external ${CURL_DEPS})

# Now it's time for the main targets!

# Paths to curl install (adjust as needed)
set(CURL_INCLUDE_DIRS
    ${CURL_INSTALL_DIR}/include
    ${CURL_INSTALL_DIR}/utfuzzer
)
set(CURL_LIB_DIR ${CURL_INSTALL_DIR}/lib)

# Fuzzing engine
if(NOT "$ENV{LIB_FUZZING_ENGINE}" STREQUAL "")
    # Check to see if ENV{LIB_FUZZING_ENGINE} is a file. If so, use it directly.
    # Otherwise, assume it's a flag to the compiler.
    if(EXISTS "$ENV{LIB_FUZZING_ENGINE}")
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
    ${OPENLDAP_STATIC_LIB_LDAP}
    ${OPENLDAP_STATIC_LIB_LBER}
    ${LIB_FUZZING_ENGINE}
    pthread
    m
)
set(COMMON_LINK_OPTIONS ${LIB_FUZZING_ENGINE_FLAG})

# Ensure that curl and its dependencies are built before the fuzzers
set(FUZZ_DEPS curl_external ${CURL_DEPS} ${LIB_FUZZING_ENGINE_DEP})

# Helper macro to define a fuzzer target
macro(curl_add_fuzzer _name _proto)
    add_executable(${_name} ${COMMON_SOURCES})
    target_compile_options(${_name} PRIVATE ${COMMON_FLAGS} -DFUZZ_PROTOCOLS_${_proto})
    target_include_directories(${_name} PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(${_name} PRIVATE ${COMMON_LINK_LIBS})
    target_link_options(${_name} PRIVATE ${COMMON_LINK_OPTIONS})
    add_dependencies(${_name} ${FUZZ_DEPS})
endmacro()

# Main fuzzer and protocol-specific fuzzers
curl_add_fuzzer(curl_fuzzer           ALL)
curl_add_fuzzer(curl_fuzzer_dict      DICT)
curl_add_fuzzer(curl_fuzzer_file      FILE)
curl_add_fuzzer(curl_fuzzer_ftp       FTP)
curl_add_fuzzer(curl_fuzzer_gopher    GOPHER)
curl_add_fuzzer(curl_fuzzer_http      HTTP)
curl_add_fuzzer(curl_fuzzer_https     HTTPS)
curl_add_fuzzer(curl_fuzzer_imap      IMAP)
curl_add_fuzzer(curl_fuzzer_ldap      LDAP)
curl_add_fuzzer(curl_fuzzer_mqtt      MQTT)
curl_add_fuzzer(curl_fuzzer_pop3      POP3)
curl_add_fuzzer(curl_fuzzer_rtsp      RTSP)
curl_add_fuzzer(curl_fuzzer_smb       SMB)
curl_add_fuzzer(curl_fuzzer_smtp      SMTP)
curl_add_fuzzer(curl_fuzzer_tftp      TFTP)
curl_add_fuzzer(curl_fuzzer_ws        WS)

# BUFQ fuzzer
add_executable(curl_fuzzer_bufq fuzz_bufq.cc)
target_compile_options(curl_fuzzer_bufq PRIVATE ${COMMON_FLAGS})
target_include_directories(curl_fuzzer_bufq PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(curl_fuzzer_bufq PRIVATE ${COMMON_LINK_LIBS})
target_link_options(curl_fuzzer_bufq PRIVATE ${COMMON_LINK_OPTIONS})
add_dependencies(curl_fuzzer_bufq ${FUZZ_DEPS})

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
        curl_fuzzer_ldap
        curl_fuzzer_mqtt
        curl_fuzzer_pop3
        curl_fuzzer_rtsp
        curl_fuzzer_smb
        curl_fuzzer_smtp
        curl_fuzzer_tftp
        curl_fuzzer_ws
        curl_fuzzer_bufq
        fuzz_url
        curl_fuzzer_fnmatch
)

# -----------------------------------------------------------------------------
# Structured (libprotobuf-mutator) HTTP fuzzer
#
# This is a second fuzzer binary that lives entirely under proto_fuzzer/ and
# shares no source with the TLV fuzzers above. It is skipped on 32-bit builds
# so we don't have to drag LPM/protobuf through the i386 toolchain.
# -----------------------------------------------------------------------------
if(NOT "$ENV{ARCHITECTURE}" STREQUAL "i386")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    # renovate: datasource=github-tags depName=google/libprotobuf-mutator
    set(LPM_VERSION v1.5)
    set(LPM_INSTALL_DIR ${CMAKE_BINARY_DIR}/lpm-install)
    set(LPM_STATIC_LIB ${LPM_INSTALL_DIR}/lib/libprotobuf-mutator.a)
    set(LPM_LIBFUZZER_LIB ${LPM_INSTALL_DIR}/lib/libprotobuf-mutator-libfuzzer.a)

    # LPM drops its bundled protobuf build *inside* its own build tree (not the
    # install prefix). These paths match the layout set up by
    # cmake/external/protobuf.cmake inside LPM v1.5. We don't use the system
    # libprotobuf because OSS-Fuzz forces -stdlib=libc++ whereas the distro
    # package is built against libstdc++, and the ABI mismatch breaks linking
    # (every std::string symbol ends up mangled as std::__1::basic_string and
    # the distro libprotobuf.so doesn't export it).
    set(LPM_PB_DIR ${CMAKE_BINARY_DIR}/lpm/src/libprotobuf_mutator_external-build/external.protobuf)
    set(LPM_PB_INCLUDE ${LPM_PB_DIR}/include)
    set(LPM_PB_LIBDIR ${LPM_PB_DIR}/lib)
    set(LPM_PROTOC ${LPM_PB_DIR}/bin/protoc)

    ExternalProject_Add(libprotobuf_mutator_external
        GIT_REPOSITORY https://github.com/google/libprotobuf-mutator.git
        GIT_TAG ${LPM_VERSION}
        GIT_SHALLOW 1
        PREFIX ${CMAKE_BINARY_DIR}/lpm
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${LPM_INSTALL_DIR}
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
            # Have LPM fetch+build protobuf v29.3 from source, using the same
            # compiler and stdlib we're compiling with. This is what keeps the
            # libc++ ABI consistent end-to-end (LPM, protobuf, our .pb.cc, our
            # fuzzer binary).
            -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON
            -DLIB_PROTO_MUTATOR_TESTING=OFF
            # Disable the bundled examples (libxml2_example, expat_example,
            # ...): the libxml2 example hard-depends on liblzma at configure
            # time, which isn't present in the OSS-Fuzz image. We don't ship
            # LPM's examples.
            -DLIB_PROTO_MUTATOR_EXAMPLES=OFF
        BUILD_BYPRODUCTS ${LPM_STATIC_LIB} ${LPM_LIBFUZZER_LIB} ${LPM_PROTOC}
        DOWNLOAD_NO_PROGRESS 1
    )

    # Generate the expanded .proto and the C++ option manifest from curl.h.
    set(CURL_HEADER ${CURL_INSTALL_DIR}/include/curl/curl.h)
    set(PROTO_FUZZER_SCHEMA_DIR ${CMAKE_BINARY_DIR}/schemas)
    set(GEN_PROTO ${PROTO_FUZZER_SCHEMA_DIR}/curl_fuzzer.proto)
    set(GEN_MANIFEST ${CMAKE_BINARY_DIR}/curl_fuzzer_option_manifest.inc)
    set(GEN_PB_CC ${CMAKE_BINARY_DIR}/curl_fuzzer.pb.cc)
    set(GEN_PB_H ${CMAKE_BINARY_DIR}/curl_fuzzer.pb.h)

    add_custom_command(
        OUTPUT ${GEN_PROTO} ${GEN_MANIFEST}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTO_FUZZER_SCHEMA_DIR}
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/src/curl_fuzzer_tools/generate_option_manifest.py
                --curl-header    ${CURL_HEADER}
                --supported-list ${CMAKE_SOURCE_DIR}/schemas/curl_fuzzer_supported_curlopts.txt
                --proto-template ${CMAKE_SOURCE_DIR}/schemas/curl_fuzzer.proto
                --proto-out      ${GEN_PROTO}
                --manifest-out   ${GEN_MANIFEST}
        DEPENDS curl_external
                ${CMAKE_SOURCE_DIR}/schemas/curl_fuzzer.proto
                ${CMAKE_SOURCE_DIR}/schemas/curl_fuzzer_supported_curlopts.txt
                ${CMAKE_SOURCE_DIR}/src/curl_fuzzer_tools/generate_option_manifest.py
        COMMENT "Generating CurlOptionId enum and manifest from curl.h"
        VERBATIM
    )

    add_custom_command(
        OUTPUT ${GEN_PB_CC} ${GEN_PB_H}
        COMMAND ${LPM_PROTOC}
                --cpp_out=${CMAKE_BINARY_DIR}
                --proto_path=${PROTO_FUZZER_SCHEMA_DIR}
                ${GEN_PROTO}
        DEPENDS ${GEN_PROTO} libprotobuf_mutator_external
        COMMENT "protoc curl_fuzzer.proto"
        VERBATIM
    )

    # Write out a linker response file listing every .a the LPM install
    # produced — LPM's own libs (libprotobuf-mutator, libprotobuf-mutator-
    # libfuzzer) plus everything under its bundled protobuf (libprotobuf,
    # libutf8_validity, ~80 abseil libs). Everything goes inside one
    # --start-group/--end-group so we don't have to reason about the
    # transitive reference order across protobuf and libprotobuf-mutator.
    # We glob at build time from a -P script because these files don't exist
    # when CMake configures, and because the abseil component list would rot
    # every time protobuf's dep set moves.
    set(LPM_LINK_RSP ${CMAKE_BINARY_DIR}/lpm_protobuf_link.rsp)
    add_custom_command(
        OUTPUT ${LPM_LINK_RSP}
        COMMAND ${CMAKE_COMMAND}
                "-DLIBDIRS=${LPM_INSTALL_DIR}/lib;${LPM_PB_LIBDIR}"
                -DOUT=${LPM_LINK_RSP}
                -P ${CMAKE_SOURCE_DIR}/scripts/write_lpm_link_rsp.cmake
        DEPENDS libprotobuf_mutator_external
                ${CMAKE_SOURCE_DIR}/scripts/write_lpm_link_rsp.cmake
        COMMENT "Writing LPM protobuf link response file"
        VERBATIM
    )
    add_custom_target(lpm_link_rsp DEPENDS ${LPM_LINK_RSP})

    add_executable(curl_fuzzer_proto
        proto_fuzzer/fuzzer_main.cc
        proto_fuzzer/scenario_runner.cc
        proto_fuzzer/option_apply.cc
        proto_fuzzer/mock_server.cc
        proto_fuzzer/transfer.cc
        ${GEN_PB_CC}
    )
    target_compile_features(curl_fuzzer_proto PRIVATE cxx_std_17)
    target_compile_options(curl_fuzzer_proto PRIVATE
        ${COMMON_FLAGS} -DFUZZ_PROTOCOLS_HTTP)
    target_include_directories(curl_fuzzer_proto PRIVATE
        ${CURL_INCLUDE_DIRS}
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}
        ${LPM_INSTALL_DIR}/include
        # LPM's installed headers do `#include "port/protobuf.h"` and
        # `#include "src/libfuzzer/libfuzzer_macro.h"`, so the include root
        # needs to reach inside the `libprotobuf-mutator/` subdirectory too.
        ${LPM_INSTALL_DIR}/include/libprotobuf-mutator
        ${LPM_PB_INCLUDE}
    )
    target_link_libraries(curl_fuzzer_proto PRIVATE
        ${CURL_LIB_DIR}/libcurl.a
        ${NGHTTP2_STATIC_LIB}
        ${OPENSSL_STATIC_LIB}
        ${ZLIB_STATIC_LIB}
        ${ZSTD_STATIC_LIB}
        ${LIBIDN2_STATIC_LIB}
        ${OPENLDAP_STATIC_LIB_LDAP}
        ${OPENLDAP_STATIC_LIB_LBER}
        ${LIB_FUZZING_ENGINE}
        # -Wl,@file: ld reads the response file and substitutes its
        # contents — the absolute paths to every .a from LPM's install +
        # its bundled protobuf/abseil, wrapped in one
        # --start-group/--end-group. This has to come AFTER our object
        # files in the final link line (so the archives see unresolved
        # symbols to pull in), which means it belongs in
        # target_link_libraries (LINK_LIBRARIES slot), not
        # target_link_options (LINK_FLAGS slot, which is pre-objects).
        # The -Wl, prefix is what keeps CMake from mangling "@file" into
        # "-l@file" (treating it as a library name).
        "-Wl,@${LPM_LINK_RSP}"
        pthread
        m
    )
    target_link_options(curl_fuzzer_proto PRIVATE ${COMMON_LINK_OPTIONS})
    add_dependencies(curl_fuzzer_proto
        ${FUZZ_DEPS}
        libprotobuf_mutator_external
        lpm_link_rsp
    )
    add_dependencies(fuzz curl_fuzzer_proto)

    # Compile textproto seed scenarios into binary corpus entries. These are
    # derived artefacts — the textprotos in scenarios/ are the source of truth,
    # and corpora/curl_fuzzer_proto/ is gitignored.
    set(SCENARIO_SRC_DIR ${CMAKE_SOURCE_DIR}/scenarios/curl_fuzzer_proto)
    set(SCENARIO_OUT_DIR ${CMAKE_SOURCE_DIR}/corpora/curl_fuzzer_proto)
    file(GLOB SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/*.textproto)
    set(SCENARIO_BINARIES)
    foreach(textproto ${SCENARIO_TEXTPROTOS})
        get_filename_component(name ${textproto} NAME_WE)
        set(out ${SCENARIO_OUT_DIR}/${name}.scenario)
        add_custom_command(
            OUTPUT ${out}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${SCENARIO_OUT_DIR}
            COMMAND ${CMAKE_SOURCE_DIR}/scripts/encode_scenario.sh
                    ${LPM_PROTOC}
                    ${PROTO_FUZZER_SCHEMA_DIR}
                    ${GEN_PROTO}
                    ${textproto}
                    ${out}
            DEPENDS ${textproto} ${GEN_PROTO} libprotobuf_mutator_external
                    ${CMAKE_SOURCE_DIR}/scripts/encode_scenario.sh
            COMMENT "Encoding ${name}.textproto"
            VERBATIM
        )
        list(APPEND SCENARIO_BINARIES ${out})
    endforeach()
    add_custom_target(curl_fuzzer_proto_corpus
        DEPENDS ${SCENARIO_BINARIES})
    add_dependencies(curl_fuzzer_proto curl_fuzzer_proto_corpus)

    # Documentation lint. `cmake --build build --target doxygen-check` runs
    # Doxygen over proto_fuzzer/ with FAIL_ON_WARNINGS; any undocumented
    # non-static function/class/member fails the build. Optional (not a hard
    # dep of curl_fuzzer_proto) so builds in environments without
    # doxygen installed still succeed.
    find_program(DOXYGEN_EXECUTABLE doxygen)
    if(DOXYGEN_EXECUTABLE)
        set(PROTO_FUZZER_SRC_DIR ${CMAKE_SOURCE_DIR}/proto_fuzzer)
        set(DOXYGEN_OUTPUT_DIR ${CMAKE_BINARY_DIR}/proto_fuzzer_doxygen)
        set(DOXYFILE_OUT ${CMAKE_BINARY_DIR}/proto_fuzzer_Doxyfile)
        set(DOXYGEN_WARN_LOG ${CMAKE_BINARY_DIR}/proto_fuzzer_doxygen_warnings.log)
        configure_file(
            ${PROTO_FUZZER_SRC_DIR}/Doxyfile.in
            ${DOXYFILE_OUT}
            @ONLY)
        # Doxygen's own exit code is unreliable for some warning categories
        # in 1.9.1; instead, inspect the warn-log ourselves and fail if it is
        # non-empty.
        add_custom_target(doxygen-check
            COMMAND ${CMAKE_COMMAND} -E make_directory ${DOXYGEN_OUTPUT_DIR}
            COMMAND ${CMAKE_COMMAND} -E remove -f ${DOXYGEN_WARN_LOG}
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
            COMMAND ${CMAKE_COMMAND}
                    -DWARN_LOG=${DOXYGEN_WARN_LOG}
                    -P ${CMAKE_SOURCE_DIR}/scripts/doxygen_check_log.cmake
            COMMENT "Running Doxygen doc-coverage check on proto_fuzzer/"
            VERBATIM
        )
    endif()

    # Formatting lint. `cmake --build build --target clang-format-check` runs
    # clang-format --dry-run -Werror over proto_fuzzer/ using the scoped
    # .clang-format file in that directory. Optional (not a hard dep of
    # curl_fuzzer_proto) so builds in environments without clang-format
    # installed still succeed.
    find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format clang-format-20
                                               clang-format-19 clang-format-18)
    if(CLANG_FORMAT_EXECUTABLE)
        file(GLOB PROTO_FUZZER_FORMAT_SOURCES
             ${CMAKE_SOURCE_DIR}/proto_fuzzer/*.cc
             ${CMAKE_SOURCE_DIR}/proto_fuzzer/*.h)
        add_custom_target(clang-format-check
            COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run -Werror
                    --style=file ${PROTO_FUZZER_FORMAT_SOURCES}
            COMMENT "Running clang-format check on proto_fuzzer/"
            VERBATIM
        )
        add_custom_target(clang-format-fix
            COMMAND ${CLANG_FORMAT_EXECUTABLE} -i
                    --style=file ${PROTO_FUZZER_FORMAT_SOURCES}
            COMMENT "Applying clang-format fixes to proto_fuzzer/"
            VERBATIM
        )
    endif()

    # Aggregate lint target. `cmake --build build --target lint` runs whichever
    # of the individual lint targets were successfully configured (each is
    # gated on its tool being found). Missing tools are a soft skip rather
    # than a hard fail so the top-level lint.sh can report them separately.
    set(LINT_DEPS)
    if(DOXYGEN_EXECUTABLE)
        list(APPEND LINT_DEPS doxygen-check)
    endif()
    if(CLANG_FORMAT_EXECUTABLE)
        list(APPEND LINT_DEPS clang-format-check)
    endif()
    if(LINT_DEPS)
        add_custom_target(lint DEPENDS ${LINT_DEPS})
    endif()
endif()
