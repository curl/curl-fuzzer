cmake_minimum_required(VERSION 3.24)
project(curl_fuzzer_deps)

if(NOT "$ENV{MAKE}" STREQUAL "")
    set(MAKE "$ENV{MAKE}")
else()
    set(MAKE "make")
endif()

include(ExternalProject)

# LLVM source-based coverage, driven by codecoverage.sh. When ON, libcurl and
# the fuzzer binaries are compiled with -fprofile-instr-generate
# -fcoverage-mapping; third-party deps (openssl, zlib, zstd, brotli, nghttp2,
# libidn2, openldap, libprotobuf-mutator + its bundled protobuf/abseil) are
# left uninstrumented. Only curl is what we want covered, and leaving deps
# alone keeps the link size of the curl_fuzzer_proto binaries under the
# memory limits of a stock GitHub runner.
option(ENABLE_COVERAGE "Instrument libcurl + fuzzer binaries for LLVM coverage" OFF)
set(COVERAGE_COMPILE_FLAGS "")
set(COVERAGE_LINK_FLAGS "")
if(ENABLE_COVERAGE)
    set(COVERAGE_COMPILE_FLAGS -fprofile-instr-generate -fcoverage-mapping)
    set(COVERAGE_LINK_FLAGS -fprofile-instr-generate)
    message(STATUS "Coverage instrumentation: ENABLED for libcurl and fuzzers")
endif()

# Install zlib
#
# renovate: datasource=github-tags depName=madler/zlib
set(ZLIB_VERSION 1.3.2)
set(ZLIB_URL https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.xz
             https://zlib.net/zlib-${ZLIB_VERSION}.tar.xz)
set(ZLIB_BUILD_NAME zlib-${ZLIB_VERSION})
set(ZLIB_INSTALL_DIR ${CMAKE_BINARY_DIR}/${ZLIB_BUILD_NAME}-install)
set(ZLIB_STATIC_LIB ${ZLIB_INSTALL_DIR}/lib/libz.a)

if(NOT EXISTS ${ZLIB_STATIC_LIB})
    ExternalProject_Add(zlib_external
        URL ${ZLIB_URL}
        PREFIX ${CMAKE_BINARY_DIR}/${ZLIB_BUILD_NAME}
        CONFIGURE_COMMAND ./configure --static --prefix=${ZLIB_INSTALL_DIR}
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${ZLIB_STATIC_LIB}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS "zlib already installed at ${ZLIB_INSTALL_DIR}, skipping build")
    add_custom_target(zlib_external)
endif()

# Install zstd
#
# renovate: datasource=github-tags depName=facebook/zstd
set(ZSTD_VERSION 1.5.7)
set(ZSTD_URL https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz)
set(ZSTD_BUILD_NAME zstd-${ZSTD_VERSION})
set(ZSTD_INSTALL_DIR ${CMAKE_BINARY_DIR}/${ZSTD_BUILD_NAME}-install)
set(ZSTD_STATIC_LIB ${ZSTD_INSTALL_DIR}/lib/libzstd.a)

if(NOT EXISTS ${ZSTD_STATIC_LIB})
    ExternalProject_Add(zstd_external
        URL ${ZSTD_URL}
        PREFIX ${CMAKE_BINARY_DIR}/${ZSTD_BUILD_NAME}
        SOURCE_SUBDIR build/cmake
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ZSTD_INSTALL_DIR}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_CONTRIB=OFF -DZSTD_BUILD_TESTS=OFF
        BUILD_BYPRODUCTS ${ZSTD_STATIC_LIB}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS "zstd already installed at ${ZSTD_INSTALL_DIR}, skipping build")
    add_custom_target(zstd_external)
endif()

# Install Brotli
#
# renovate: datasource=github-tags depName=google/brotli
set(BROTLI_VERSION 1.2.0)
set(BROTLI_URL https://github.com/google/brotli/archive/refs/tags/v${BROTLI_VERSION}.tar.gz)
set(BROTLI_BUILD_NAME brotli-${BROTLI_VERSION})
set(BROTLI_INSTALL_DIR ${CMAKE_BINARY_DIR}/${BROTLI_BUILD_NAME}-install)
set(BROTLI_DEC_STATIC_LIB ${BROTLI_INSTALL_DIR}/lib/libbrotlidec.a)
set(BROTLI_COMMON_STATIC_LIB ${BROTLI_INSTALL_DIR}/lib/libbrotlicommon.a)
set(BROTLI_STATIC_LIBS ${BROTLI_DEC_STATIC_LIB} ${BROTLI_COMMON_STATIC_LIB})

if(NOT EXISTS ${BROTLI_DEC_STATIC_LIB} OR NOT EXISTS ${BROTLI_COMMON_STATIC_LIB})
    ExternalProject_Add(brotli_external
        URL ${BROTLI_URL}
        PREFIX ${CMAKE_BINARY_DIR}/${BROTLI_BUILD_NAME}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${BROTLI_INSTALL_DIR}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DBUILD_SHARED_LIBS=OFF
            -DBROTLI_BUILD_TOOLS=OFF
            -DBROTLI_DISABLE_TESTS=ON
        BUILD_BYPRODUCTS ${BROTLI_STATIC_LIBS}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS "Brotli already installed at ${BROTLI_INSTALL_DIR}, skipping build")
    add_custom_target(brotli_external)
endif()

# For the memory sanitizer build, turn off OpenSSL as it causes bugs we can't
# affect (see 16697, 17624)
if(NOT "$ENV{SANITIZER}" STREQUAL "memory")
    message(STATUS "Building OpenSSL as a dependency")
    # Install openssl
    #
    # renovate: datasource=github-tags depName=openssl/openssl
    set(OPENSSL_VERSION 4.0.2)
    set(OPENSSL_URL
        https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz)
    set(OPENSSL_BUILD_NAME openssl-${OPENSSL_VERSION})
    set(OPENSSL_INSTALL_DIR ${CMAKE_BINARY_DIR}/${OPENSSL_BUILD_NAME}-install)
    set(OPENSSL_SRC_DIR ${CMAKE_BINARY_DIR}/${OPENSSL_BUILD_NAME}/src/openssl_external)
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
        no-engine
        ${OPENSSL_ASM_FLAG}
        ${OPENSSL_ARCH_FLAG}
        enable-tls1_3
        enable-rc5
        enable-md2
        ${OPENSSL_EC_FLAG}
        enable-nextprotoneg
        enable-weak-ssl-ciphers
        --with-zlib-include=${ZLIB_INSTALL_DIR}/include
        --with-zlib-lib=${ZLIB_INSTALL_DIR}/lib
        $ENV{OPENSSLFLAGS}
    )

    if(NOT EXISTS ${OPENSSL_INSTALL_DIR}/lib/libssl.a)
        ExternalProject_Add(openssl_external
            URL ${OPENSSL_URL}
            PREFIX ${CMAKE_BINARY_DIR}/${OPENSSL_BUILD_NAME}
            CONFIGURE_COMMAND ${OPENSSL_CONFIGURE_COMMAND}
            INSTALL_COMMAND ${MAKE} install_sw
            BUILD_IN_SOURCE 1
            BUILD_BYPRODUCTS ${OPENSSL_STATIC_LIB}
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            DOWNLOAD_NO_PROGRESS 1
        )
        add_dependencies(openssl_external zlib_external)
    else()
        message(STATUS "OpenSSL already installed at ${OPENSSL_INSTALL_DIR}, skipping build")
        add_custom_target(openssl_external)
    endif()

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
set(NGHTTP2_VERSION 1.70.0)
set(NGHTTP2_URL https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.xz)
set(NGHTTP2_BUILD_NAME nghttp2-${NGHTTP2_VERSION})
set(NGHTTP2_INSTALL_DIR ${CMAKE_BINARY_DIR}/${NGHTTP2_BUILD_NAME}-install)
set(NGHTTP2_STATIC_LIB ${NGHTTP2_INSTALL_DIR}/lib/libnghttp2.a)

if(NOT EXISTS ${NGHTTP2_STATIC_LIB})
    ExternalProject_Add(nghttp2_external
        URL ${NGHTTP2_URL}
        PREFIX ${CMAKE_BINARY_DIR}/${NGHTTP2_BUILD_NAME}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${NGHTTP2_INSTALL_DIR} -DCMAKE_INSTALL_LIBDIR=lib
            -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF
            -DENABLE_LIB_ONLY=ON -DENABLE_THREADS=OFF -DBUILD_TESTING=OFF -DENABLE_DOC=OFF ${NGHTTP2_OPENSSL_OPTION}
        BUILD_BYPRODUCTS ${NGHTTP2_STATIC_LIB}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
    add_dependencies(nghttp2_external ${OPENSSL_DEP} zlib_external)
else()
    message(STATUS "nghttp2 already installed at ${NGHTTP2_INSTALL_DIR}, skipping build")
    add_custom_target(nghttp2_external)
endif()

# Install libidn2
#
# renovate: datasource=github-tags depName=libidn/libidn2
set(LIBIDN2_VERSION 2.3.8)
set(LIBIDN2_URL https://ftpmirror.gnu.org/libidn/libidn2-${LIBIDN2_VERSION}.tar.gz
                https://ftp.gnu.org/gnu/libidn/libidn2-${LIBIDN2_VERSION}.tar.gz)
set(LIBIDN2_BUILD_NAME libidn2-${LIBIDN2_VERSION})
set(LIBIDN2_INSTALL_DIR ${CMAKE_BINARY_DIR}/${LIBIDN2_BUILD_NAME}-install)
set(LIBIDN2_STATIC_LIB ${LIBIDN2_INSTALL_DIR}/lib/libidn2.a)

if(NOT EXISTS ${LIBIDN2_STATIC_LIB})
    ExternalProject_Add(libidn2_external
        URL ${LIBIDN2_URL}
        PREFIX ${CMAKE_BINARY_DIR}/${LIBIDN2_BUILD_NAME}
        CONFIGURE_COMMAND ./configure --disable-dependency-tracking --prefix=${LIBIDN2_INSTALL_DIR} --disable-shared --enable-static
            --disable-doc
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${LIBIDN2_STATIC_LIB}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        DOWNLOAD_NO_PROGRESS 1
    )
else()
    message(STATUS "libidn2 already installed at ${LIBIDN2_INSTALL_DIR}, skipping build")
    add_custom_target(libidn2_external)
endif()

# Install GDB if GDBMODE is set
set(GDB_VERSION 13.2)
set(GDB_URL https://ftpmirror.gnu.org/gdb/gdb-${GDB_VERSION}.tar.gz
            https://ftp.gnu.org/gnu/gdb/gdb-${GDB_VERSION}.tar.gz)
set(GDB_BUILD_NAME gdb-${GDB_VERSION})
set(GDB_INSTALL_DIR ${CMAKE_BINARY_DIR}/${GDB_BUILD_NAME}-install)

option(BUILD_GDB "Build GDB as an external project" OFF)
if(BUILD_GDB)
    # GDB is a host tool, not a fuzz target — build with system GCC and
    # clean flags so sanitizer/fuzzer flags don't break its build.
    ExternalProject_Add(gdb_external
        URL ${GDB_URL}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        PREFIX ${CMAKE_BINARY_DIR}/${GDB_BUILD_NAME}
        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
            "CC=gcc" "CXX=g++"
            "CFLAGS=-O2" "CXXFLAGS=-O2" "LDFLAGS=" "CPPFLAGS="
            ./configure --disable-dependency-tracking --prefix=${GDB_INSTALL_DIR}
        BUILD_IN_SOURCE 1
    )
    set(GDB_DEP gdb_external)
else()
    set(GDB_DEP "")
endif()

# Install OpenLDAP
set(OPENLDAP_VERSION 2.6.13)
set(OPENLDAP_URL https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz
                 https://mirror.lyrahosting.com/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz)
set(OPENLDAP_BUILD_NAME openldap-${OPENLDAP_VERSION})
set(OPENLDAP_INSTALL_DIR ${CMAKE_BINARY_DIR}/${OPENLDAP_BUILD_NAME}-install)
set(OPENLDAP_STATIC_LIB_LDAP ${OPENLDAP_INSTALL_DIR}/lib/libldap.a)
set(OPENLDAP_STATIC_LIB_LBER ${OPENLDAP_INSTALL_DIR}/lib/liblber.a)

if(NOT EXISTS ${OPENLDAP_STATIC_LIB_LDAP})
    ExternalProject_Add(openldap_external
        URL ${OPENLDAP_URL}
        PREFIX ${CMAKE_BINARY_DIR}/${OPENLDAP_BUILD_NAME}
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
else()
    message(STATUS "OpenLDAP already installed at ${OPENLDAP_INSTALL_DIR}, skipping build")
    add_custom_target(openldap_external)
endif()

# Group non-curl dependencies into a single target
add_custom_target(deps
    DEPENDS
        zlib_external
        ${OPENSSL_DEP}
        nghttp2_external
        zstd_external
        brotli_external
        libidn2_external
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
    # curl's tests and examples are not part of any packaged fuzz target. In
    # addition to saving build time, disabling them keeps the build inputs in
    # line with the libcurl surface described by the Introspector report.
    -DBUILD_TESTING=OFF
    -DBUILD_EXAMPLES=OFF
    -DENABLE_DEBUG=ON
    -DCURL_HIDDEN_SYMBOLS=OFF
    -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF
    -DCURL_USE_LIBPSL=OFF
    # These protocol parsers have no feature bits. Make their coverage
    # dependencies explicit and verify curl's advertised protocol list too,
    # so a default change cannot silently turn a dedicated target into a URL
    # rejection benchmark.
    -DCURL_DISABLE_TELNET=OFF
    -DCURL_DISABLE_FTP=OFF
    -DCURL_DISABLE_TFTP=OFF
    # SMB and NTLM are deprecated upstream and no longer fuzzed here. Keep
    # them disabled explicitly so curl default changes cannot restore either
    # surface to the aggregate legacy fuzzer.
    -DCURL_ENABLE_SMB=OFF
    -DCURL_ENABLE_NTLM=OFF
    # Keep the HTTPS resource-record parser available in every sanitizer
    # configuration, including MSan where this project deliberately omits a
    # TLS backend. ECH consumes these records when TLS is present, while the
    # standalone DoH target can exercise their wire decoder independently.
    -DUSE_HTTPSRR=ON
    ${CURL_SSL_OPTION}
    -DZLIB_INCLUDE_DIR=${ZLIB_INSTALL_DIR}/include
    -DZLIB_LIBRARY=${ZLIB_STATIC_LIB}
    -DNGHTTP2_INCLUDE_DIR=${NGHTTP2_INSTALL_DIR}/include
    -DNGHTTP2_LIBRARY=${NGHTTP2_STATIC_LIB}
    -DZSTD_INCLUDE_DIR=${ZSTD_INSTALL_DIR}/include
    -DZSTD_LIBRARY=${ZSTD_STATIC_LIB}
    -DCURL_BROTLI=ON
    -DBROTLI_INCLUDE_DIR=${BROTLI_INSTALL_DIR}/include
    -DBROTLIDEC_LIBRARY=${BROTLI_DEC_STATIC_LIB}
    -DBROTLICOMMON_LIBRARY=${BROTLI_COMMON_STATIC_LIB}
    -DBROTLI_USE_STATIC_LIBS=ON
    -DLIBIDN2_INCLUDE_DIR=${LIBIDN2_INSTALL_DIR}/include
    -DLIBIDN2_LIBRARY=${LIBIDN2_STATIC_LIB}
    -DLDAP_INCLUDE_DIR=${OPENLDAP_INSTALL_DIR}/include
    -DLDAP_LIBRARY=${OPENLDAP_STATIC_LIB_LDAP}
    -DLDAP_LBER_LIBRARY=${OPENLDAP_STATIC_LIB_LBER}
)

# These experimental features need crypto/TLS backend support. The bundled
# OpenSSL 4.x provides both HTTP Message Signature primitives and the ECH API;
# MSan intentionally has no OpenSSL and therefore retains curl's defaults.
if(TARGET openssl_external)
    list(APPEND CURL_CMAKE_ARGS
        -DCURL_DISABLE_HTTPSIG=OFF
        -DUSE_ECH=ON)
endif()

# Baseline CFLAGS passed to curl's own CMake. Always defines UNITTESTS so
# the UNITTEST macro in curl_setup.h flips from `static` to empty, giving
# external linkage to parsers we want to fuzz directly (e.g. doh_resp_decode,
# doh_req_encode via fuzz_doh). The knock-on is a slightly larger libcurl.a
# with more exported symbols — harmless for every target.
set(_CURL_BASE_C_FLAGS "$ENV{CFLAGS} -DUNITTESTS")
set(_CURL_BASE_CXX_FLAGS "$ENV{CXXFLAGS} -DUNITTESTS")

# If coverage is requested, layer the instrumentation flags on top. CMake
# treats the list elements here as space-separated once rendered into
# CMAKE_C_FLAGS / CXX_FLAGS on curl's own CMake command line, so we pass them
# as a single string.
if(ENABLE_COVERAGE)
    string(REPLACE ";" " " _COV_COMPILE_FLAGS_STR "${COVERAGE_COMPILE_FLAGS}")
    set(_CURL_BASE_C_FLAGS "${_CURL_BASE_C_FLAGS} ${_COV_COMPILE_FLAGS_STR}")
    set(_CURL_BASE_CXX_FLAGS "${_CURL_BASE_CXX_FLAGS} ${_COV_COMPILE_FLAGS_STR}")
endif()

list(APPEND CURL_CMAKE_ARGS
    "-DCMAKE_C_FLAGS=${_CURL_BASE_C_FLAGS}"
    "-DCMAKE_CXX_FLAGS=${_CURL_BASE_CXX_FLAGS}"
)

set(CURL_POST_INSTALL_COMMAND
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CURL_INSTALL_DIR}/utfuzzer
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
    brotli_external
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
set(COMMON_SOURCES
    legacy_fuzzer.cc
    curl_fuzzer_tlv.cc
    curl_fuzzer_callback.cc
    legacy_protocol_allowlist.cc
    legacy_tlv_mutator.cc
)
set(COMMON_FLAGS -g -DCURL_DISABLE_DEPRECATION ${COVERAGE_COMPILE_FLAGS})
set(CURL_STATIC_DEPENDENCY_LIBS
    ${NGHTTP2_STATIC_LIB}
    ${OPENSSL_STATIC_LIB}
    ${ZLIB_STATIC_LIB}
    ${ZSTD_STATIC_LIB}
    ${BROTLI_STATIC_LIBS}
    ${LIBIDN2_STATIC_LIB}
    ${OPENLDAP_STATIC_LIB_LDAP}
    ${OPENLDAP_STATIC_LIB_LBER}
)
set(COMMON_LINK_LIBS
    ${CURL_LIB_DIR}/libcurl.a
    ${CURL_STATIC_DEPENDENCY_LIBS}
    ${LIB_FUZZING_ENGINE}
    pthread
    m
)
set(COMMON_LINK_OPTIONS ${LIB_FUZZING_ENGINE_FLAG} ${COVERAGE_LINK_FLAGS})

# Ensure that curl and its dependencies are built before the fuzzers
set(FUZZ_DEPS curl_external ${CURL_DEPS} ${LIB_FUZZING_ENGINE_DEP})

# Helper macro to define a fuzzer target
macro(curl_add_fuzzer _name _proto)
    add_executable(${_name}
        fuzzer_entrypoints/${_name}.cc
        ${COMMON_SOURCES}
    )
    target_compile_options(${_name} PRIVATE ${COMMON_FLAGS} -DFUZZ_PROTOCOLS_${_proto}
        -DLEGACY_TLV_MUTATOR_CHECK_HARNESS_CONSTANTS)
    target_include_directories(${_name} PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CURL_INCLUDE_DIRS}
    )
    target_link_libraries(${_name} PRIVATE ${COMMON_LINK_LIBS})
    target_link_options(${_name} PRIVATE ${COMMON_LINK_OPTIONS})
    add_dependencies(${_name} ${FUZZ_DEPS})
endmacro()

# The mutator is deliberately independent of libcurl so its framing, bounds,
# repair, and crossover behavior can be tested without constructing a transfer.
include(CTest)
if(BUILD_TESTING)
    add_executable(legacy_tlv_mutator_test
        legacy_tlv_mutator.cc
        tests/legacy_tlv_mutator_test.cc
    )
    target_compile_features(legacy_tlv_mutator_test PRIVATE cxx_std_11)
    target_include_directories(legacy_tlv_mutator_test PRIVATE ${CMAKE_SOURCE_DIR})
    add_test(NAME legacy_tlv_mutator_test COMMAND legacy_tlv_mutator_test)
    # Kept separate from `fuzz` so OSS-Fuzz packaging does not build test-only
    # binaries. mainline.sh builds this target and then invokes CTest.
    add_custom_target(fuzzer_unit_tests DEPENDS legacy_tlv_mutator_test)

    # CURL_BROTLI=ON makes a missing library a configure error; this runtime
    # check also prevents a future curl/CMake change from silently producing a
    # library whose advertised feature set no longer matches the seeded corpus.
    add_executable(curl_features_test tests/curl_features_test.cc)
    target_compile_features(curl_features_test PRIVATE cxx_std_11)
    target_compile_options(curl_features_test PRIVATE ${COMMON_FLAGS})
    target_include_directories(curl_features_test PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(curl_features_test PRIVATE
        ${CURL_LIB_DIR}/libcurl.a
        ${CURL_STATIC_DEPENDENCY_LIBS}
        pthread
        m
    )
    target_link_options(curl_features_test PRIVATE ${COVERAGE_LINK_FLAGS})
    if(TARGET openssl_external)
        target_compile_definitions(curl_features_test PRIVATE
            CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)
    endif()
    add_dependencies(curl_features_test curl_external ${CURL_DEPS})
    add_test(NAME curl_features_test COMMAND curl_features_test)
    add_dependencies(fuzzer_unit_tests curl_features_test)

    add_executable(legacy_protocol_allowlist_test
        legacy_protocol_allowlist.cc
        tests/legacy_protocol_allowlist_test.cc
    )
    target_compile_features(legacy_protocol_allowlist_test PRIVATE cxx_std_11)
    target_compile_options(legacy_protocol_allowlist_test PRIVATE ${COMMON_FLAGS})
    target_include_directories(legacy_protocol_allowlist_test PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CURL_INCLUDE_DIRS}
    )
    target_link_libraries(legacy_protocol_allowlist_test PRIVATE
        ${CURL_LIB_DIR}/libcurl.a
        ${CURL_STATIC_DEPENDENCY_LIBS}
        pthread
        m
    )
    target_link_options(legacy_protocol_allowlist_test PRIVATE
        ${COVERAGE_LINK_FLAGS})
    add_dependencies(legacy_protocol_allowlist_test curl_external ${CURL_DEPS})
    add_test(NAME legacy_protocol_allowlist_test
        COMMAND legacy_protocol_allowlist_test)
    add_dependencies(fuzzer_unit_tests legacy_protocol_allowlist_test)
endif()

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
curl_add_fuzzer(curl_fuzzer_smtp      SMTP)
curl_add_fuzzer(curl_fuzzer_tftp      TFTP)
curl_add_fuzzer(curl_fuzzer_ws        WS)

# BUFQ fuzzer
add_executable(fuzz_bufq fuzz_bufq.cc)
target_compile_options(fuzz_bufq PRIVATE ${COMMON_FLAGS})
target_include_directories(fuzz_bufq PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(fuzz_bufq PRIVATE ${COMMON_LINK_LIBS})
target_link_options(fuzz_bufq PRIVATE ${COMMON_LINK_OPTIONS})
add_dependencies(fuzz_bufq ${FUZZ_DEPS})

# URL fuzzer
add_executable(fuzz_url fuzz_url.cc)
target_compile_options(fuzz_url PRIVATE ${COMMON_FLAGS})
target_include_directories(fuzz_url PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(fuzz_url PRIVATE ${COMMON_LINK_LIBS})
target_link_options(fuzz_url PRIVATE ${COMMON_LINK_OPTIONS})
add_dependencies(fuzz_url ${FUZZ_DEPS})

# DOH parser fuzzer. Forward-declares the UNITTEST-exposed entrypoints from
# lib/doh.c (doh_resp_decode, doh_req_encode, de_init, de_cleanup) so we don't
# have to pull in the full urldata.h include tree. Linkage depends on
# -DUNITTESTS being threaded through to curl's build — see CURL_CMAKE_ARGS.
add_executable(fuzz_doh fuzz_doh.cc)
target_compile_options(fuzz_doh PRIVATE ${COMMON_FLAGS})
target_include_directories(fuzz_doh PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(fuzz_doh PRIVATE ${COMMON_LINK_LIBS})
target_link_options(fuzz_doh PRIVATE ${COMMON_LINK_OPTIONS})
add_dependencies(fuzz_doh ${FUZZ_DEPS})

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
        curl_fuzzer_smtp
        curl_fuzzer_tftp
        curl_fuzzer_ws
        fuzz_bufq
        fuzz_url
        fuzz_doh
)

# -----------------------------------------------------------------------------
# Structured (libprotobuf-mutator) network target suite
#
# These binaries live entirely under proto_fuzzer/ and share no source with
# the TLV fuzzers above. They are skipped on 32-bit builds so we don't have to
# drag LPM/protobuf through the i386 toolchain.
# -----------------------------------------------------------------------------
if(NOT "$ENV{ARCHITECTURE}" STREQUAL "i386")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    # renovate: datasource=github-tags depName=google/libprotobuf-mutator
    set(LPM_VERSION v1.5)
    set(LPM_BUILD_NAME lpm-${LPM_VERSION})
    set(LPM_INSTALL_DIR ${CMAKE_BINARY_DIR}/${LPM_BUILD_NAME}-install)
    set(LPM_STATIC_LIB ${LPM_INSTALL_DIR}/lib/libprotobuf-mutator.a)
    set(LPM_LIBFUZZER_LIB ${LPM_INSTALL_DIR}/lib/libprotobuf-mutator-libfuzzer.a)

    # LPM drops its bundled protobuf build *inside* its own build tree (not the
    # install prefix). These paths match the layout set up by
    # cmake/external/protobuf.cmake inside LPM v1.5. We don't use the system
    # libprotobuf because OSS-Fuzz forces -stdlib=libc++ whereas the distro
    # package is built against libstdc++, and the ABI mismatch breaks linking
    # (every std::string symbol ends up mangled as std::__1::basic_string and
    # the distro libprotobuf.so doesn't export it).
    set(LPM_PB_DIR ${CMAKE_BINARY_DIR}/${LPM_BUILD_NAME}/src/libprotobuf_mutator_external-build/external.protobuf)
    set(LPM_PB_INCLUDE ${LPM_PB_DIR}/include)
    set(LPM_PB_LIBDIR ${LPM_PB_DIR}/lib)
    set(LPM_PROTOC ${LPM_PB_DIR}/bin/protoc)
    set(LPM_PB_SOURCE_DIR ${LPM_PB_DIR}/src/external.protobuf)
    set(HOST_PROTOC_BUILD_DIR
        ${CMAKE_BINARY_DIR}/${LPM_BUILD_NAME}-host-protoc-build)
    set(HOST_PROTOC_INSTALL_DIR
        ${CMAKE_BINARY_DIR}/${LPM_BUILD_NAME}-host-protoc-install)
    set(HOST_PROTOC ${HOST_PROTOC_INSTALL_DIR}/bin/protoc)

    # A cache created before the clean host tool existed contains LPM's install
    # outputs but not its protobuf source. Rebuild LPM once in that case so the
    # MSan-only host build below has the exact matching source available.
    set(HOST_PROTOC_NEEDS_SOURCE FALSE)
    if("$ENV{SANITIZER}" STREQUAL "memory" AND NOT EXISTS ${HOST_PROTOC})
        set(HOST_PROTOC_NEEDS_SOURCE TRUE)
    endif()
    if(NOT EXISTS ${LPM_STATIC_LIB} OR NOT EXISTS ${LPM_PROTOC} OR
       (HOST_PROTOC_NEEDS_SOURCE AND
        NOT EXISTS ${LPM_PB_SOURCE_DIR}/CMakeLists.txt))
        ExternalProject_Add(libprotobuf_mutator_external
            GIT_REPOSITORY https://github.com/google/libprotobuf-mutator.git
            GIT_TAG ${LPM_VERSION}
            GIT_SHALLOW 1
            UPDATE_DISCONNECTED ON
            PREFIX ${CMAKE_BINARY_DIR}/${LPM_BUILD_NAME}
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${LPM_INSTALL_DIR}
                -DCMAKE_BUILD_TYPE=Release
                -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON
                -DLIB_PROTO_MUTATOR_TESTING=OFF
                -DLIB_PROTO_MUTATOR_EXAMPLES=OFF
            BUILD_BYPRODUCTS ${LPM_STATIC_LIB} ${LPM_LIBFUZZER_LIB} ${LPM_PROTOC}
            DOWNLOAD_NO_PROGRESS 1
        )
    else()
        message(STATUS "LPM already installed at ${LPM_INSTALL_DIR}, skipping build")
        add_custom_target(libprotobuf_mutator_external)
    endif()

    set(GENERATOR_PROTOC ${LPM_PROTOC})
    set(GENERATOR_PROTOC_DEP libprotobuf_mutator_external)
    if("$ENV{SANITIZER}" STREQUAL "memory")
        # LPM correctly instruments its bundled protobuf libraries, but that
        # also instruments protoc. A host tool linked to the runner's ordinary
        # libstdc++ produces false MSan reports before it can generate inputs.
        # Build protoc again from the same source with clean flags, while
        # retaining the instrumented libraries linked into the fuzz targets.
        if(NOT EXISTS ${HOST_PROTOC})
            add_custom_command(
                OUTPUT ${HOST_PROTOC}
                COMMAND ${CMAKE_COMMAND} -E env
                        --unset=CFLAGS --unset=CXXFLAGS
                        --unset=CPPFLAGS --unset=LDFLAGS
                        ${CMAKE_COMMAND}
                        -S ${LPM_PB_SOURCE_DIR}
                        -B ${HOST_PROTOC_BUILD_DIR}
                        -G "${CMAKE_GENERATOR}"
                        -DCMAKE_INSTALL_PREFIX=${HOST_PROTOC_INSTALL_DIR}
                        -DCMAKE_BUILD_TYPE=Release
                        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                        -DCMAKE_C_FLAGS=
                        -DCMAKE_CXX_FLAGS=
                        -DCMAKE_EXE_LINKER_FLAGS=
                        -DCMAKE_CXX_STANDARD=14
                        -Dprotobuf_INSTALL=ON
                        -Dprotobuf_BUILD_TESTS=OFF
                        -Dprotobuf_BUILD_CONFORMANCE=OFF
                        -Dprotobuf_BUILD_EXAMPLES=OFF
                        -Dprotobuf_BUILD_LIBUPB=OFF
                        -Dprotobuf_BUILD_SHARED_LIBS=OFF
                        -Dprotobuf_WITH_ZLIB=OFF
                COMMAND ${CMAKE_COMMAND} --build ${HOST_PROTOC_BUILD_DIR}
                        --config Release --target protoc --parallel
                COMMAND ${CMAKE_COMMAND} --install ${HOST_PROTOC_BUILD_DIR}
                        --config Release --component protoc
                DEPENDS libprotobuf_mutator_external
                COMMENT "Building uninstrumented host protoc"
                VERBATIM
            )
            add_custom_target(host_protoc DEPENDS ${HOST_PROTOC})
        else()
            add_custom_target(host_protoc)
            add_dependencies(host_protoc libprotobuf_mutator_external)
        endif()
        set(GENERATOR_PROTOC ${HOST_PROTOC})
        set(GENERATOR_PROTOC_DEP host_protoc)
    endif()

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
        COMMAND ${GENERATOR_PROTOC}
                --cpp_out=${CMAKE_BINARY_DIR}
                --proto_path=${PROTO_FUZZER_SCHEMA_DIR}
                ${GEN_PROTO}
        DEPENDS ${GEN_PROTO} ${GENERATOR_PROTOC} ${GENERATOR_PROTOC_DEP}
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

    # The protocol runners, LPM adapter, and generated message are identical
    # for every structured target. Compile them once; each same-named thin
    # entrypoint passes its profile explicitly, giving Introspector an
    # unambiguous static-profile-to-coverage mapping without target-specific
    # compiler definitions.
    set(PROTO_FUZZER_TLS_SOURCES)
    if(TARGET openssl_external)
        list(APPEND PROTO_FUZZER_TLS_SOURCES
            proto_fuzzer/h2_proxy_mock_server.cc
            proto_fuzzer/tls_mock_server.cc)
    endif()
    add_library(curl_fuzzer_proto_runtime OBJECT
        proto_fuzzer/api_lifecycle.cc
        proto_fuzzer/fuzzer_main.cc
        proto_fuzzer/ftp_mock_server.cc
        proto_fuzzer/scenario_runner.cc
        proto_fuzzer/option_apply.cc
        proto_fuzzer/request_data.cc
        proto_fuzzer/mock_server.cc
        proto_fuzzer/mock_server_base.cc
        proto_fuzzer/multi_socket_driver.cc
        proto_fuzzer/multi_transfer_runner.cc
        proto_fuzzer/target_policy.cc
        proto_fuzzer/telnet_mock_server.cc
        proto_fuzzer/telnet_scenario.cc
        proto_fuzzer/tftp_mock_server.cc
        ${PROTO_FUZZER_TLS_SOURCES}
        proto_fuzzer/websocket_mock_server.cc
        proto_fuzzer/ws_frame.cc
        ${GEN_PB_CC}
    )
    target_compile_features(curl_fuzzer_proto_runtime PRIVATE cxx_std_17)
    target_compile_options(curl_fuzzer_proto_runtime PRIVATE
        ${COMMON_FLAGS} -DFUZZ_PROTOCOLS_HTTP)
    target_include_directories(curl_fuzzer_proto_runtime PRIVATE
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
    if(TARGET openssl_external)
        target_compile_definitions(curl_fuzzer_proto_runtime PRIVATE
            PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
        target_include_directories(curl_fuzzer_proto_runtime PRIVATE
            ${OPENSSL_INSTALL_DIR}/include)
    endif()
    add_dependencies(curl_fuzzer_proto_runtime
        ${FUZZ_DEPS}
        libprotobuf_mutator_external
        lpm_link_rsp
    )

    # Build one compatibility binary plus fixed protocol/cost lanes. Each
    # entrypoint binds its TargetProfile in ordinary C++, keeping build-system
    # wiring independent of mutation and execution behaviour.
    function(curl_add_proto_fuzzer _name)
        add_executable(${_name}
            fuzzer_entrypoints/${_name}.cc
            $<TARGET_OBJECTS:curl_fuzzer_proto_runtime>
        )
        target_compile_features(${_name} PRIVATE cxx_std_17)
        target_compile_options(${_name} PRIVATE
            ${COMMON_FLAGS} -DFUZZ_PROTOCOLS_HTTP)
        target_include_directories(${_name} PRIVATE
            ${CURL_INCLUDE_DIRS}
            ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}
            ${LPM_INSTALL_DIR}/include
            ${LPM_INSTALL_DIR}/include/libprotobuf-mutator
            ${LPM_PB_INCLUDE}
        )
        target_link_libraries(${_name} PRIVATE
            ${CURL_LIB_DIR}/libcurl.a
            ${CURL_STATIC_DEPENDENCY_LIBS}
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
        target_link_options(${_name} PRIVATE ${COMMON_LINK_OPTIONS})
        add_dependencies(${_name}
            ${FUZZ_DEPS}
            curl_fuzzer_proto_runtime
            libprotobuf_mutator_external
            lpm_link_rsp
        )
        add_dependencies(fuzz ${_name})
    endfunction()

    # Preserve the original mixed target's behavior under its original name:
    # OSS-Fuzz keys accumulated corpora and regression testcases by target
    # basename, so changing its profile would silently change their semantics.
    curl_add_proto_fuzzer(curl_fuzzer_proto)
    curl_add_proto_fuzzer(curl_fuzzer_proto_http)
    curl_add_proto_fuzzer(curl_fuzzer_proto_http_deep)
    curl_add_proto_fuzzer(curl_fuzzer_proto_https)
    curl_add_proto_fuzzer(curl_fuzzer_proto_h2_proxy)
    curl_add_proto_fuzzer(curl_fuzzer_proto_ws)
    curl_add_proto_fuzzer(curl_fuzzer_proto_wss)
    curl_add_proto_fuzzer(curl_fuzzer_proto_telnet)
    curl_add_proto_fuzzer(curl_fuzzer_proto_ftp)
    curl_add_proto_fuzzer(curl_fuzzer_proto_tftp)
    curl_add_proto_fuzzer(curl_fuzzer_proto_api)
    curl_add_proto_fuzzer(curl_fuzzer_proto_multi)
    curl_add_proto_fuzzer(curl_fuzzer_proto_timing)

    # Compile textproto seed scenarios into binary corpus entries. These are
    # derived artefacts — the textprotos in scenarios/ are the source of truth,
    # so outputs belong in the build tree rather than beside checked-in corpora.
    set(SCENARIO_SRC_DIR ${CMAKE_SOURCE_DIR}/scenarios/curl_fuzzer_proto)
    file(GLOB HTTP_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/http/*.textproto)
    file(GLOB HTTPS_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/https/*.textproto)
    file(GLOB H2_PROXY_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/h2_proxy/*.textproto)
    file(GLOB WS_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/ws/*.textproto)
    file(GLOB WSS_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/wss/*.textproto)
    file(GLOB TELNET_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/telnet/*.textproto)
    file(GLOB FTP_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/ftp/*.textproto)
    file(GLOB TFTP_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/tftp/*.textproto)
    file(GLOB API_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/api/*.textproto)
    file(GLOB MULTI_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/multi/*.textproto)
    file(GLOB_RECURSE TIMING_SCENARIO_TEXTPROTOS CONFIGURE_DEPENDS
         ${SCENARIO_SRC_DIR}/*backpressure*.textproto)

    # Backpressure seeds carry deliberately large uploads and make LPM spend a
    # disproportionate share of mutations copying those messages. Keep them in
    # the compatibility corpus and dedicated timing target. The deep HTTP lane
    # retains every other HTTP seed so coverage-rich behavior remains available
    # without imposing its mutation cost on the throughput-oriented lane.
    set(DEEP_HTTP_SCENARIO_TEXTPROTOS ${HTTP_SCENARIO_TEXTPROTOS})
    set(FAST_WS_SCENARIO_TEXTPROTOS ${WS_SCENARIO_TEXTPROTOS})
    list(FILTER DEEP_HTTP_SCENARIO_TEXTPROTOS EXCLUDE REGEX "backpressure")
    list(FILTER FAST_WS_SCENARIO_TEXTPROTOS EXCLUDE REGEX "backpressure")

    # Keep the fast seed population deliberately small and explicit. LPM's
    # seed choice materially affects executions per second even when the lane
    # postprocessor later removes deep-only fields, so an unconstrained glob
    # would quietly erode throughput whenever a coverage seed is added.
    set(FAST_HTTP_SCENARIO_TEXTPROTOS
        ${SCENARIO_SRC_DIR}/http/basic_get.textproto
        ${SCENARIO_SRC_DIR}/http/chunked_response.textproto
        ${SCENARIO_SRC_DIR}/http/http09_allowed.textproto
        ${SCENARIO_SRC_DIR}/http/http2_control_frames.textproto
        ${SCENARIO_SRC_DIR}/http/http2_invalid_preface.textproto
        ${SCENARIO_SRC_DIR}/http/http2_prior_knowledge.textproto
        ${SCENARIO_SRC_DIR}/http/http2_truncated_headers_frame.textproto
        ${SCENARIO_SRC_DIR}/http/http_brotli_decode.textproto
        ${SCENARIO_SRC_DIR}/http/http_chunk_extensions_trailers.textproto
        ${SCENARIO_SRC_DIR}/http/http_conflicting_framing.textproto
        ${SCENARIO_SRC_DIR}/http/http_cookie_rejections.textproto
        ${SCENARIO_SRC_DIR}/http/http_custom_request_headers.textproto
        ${SCENARIO_SRC_DIR}/http/http_decoding_controls_conflicting_length.textproto
        ${SCENARIO_SRC_DIR}/http/http_deflate_raw_fallback.textproto
        ${SCENARIO_SRC_DIR}/http/http_deflate_zlib.textproto
        ${SCENARIO_SRC_DIR}/http/http_empty_host_header.textproto
        ${SCENARIO_SRC_DIR}/http/http_failonerror_418.textproto
        ${SCENARIO_SRC_DIR}/http/http_gzip_decode.textproto
        ${SCENARIO_SRC_DIR}/http/http_head_nobody.textproto
        ${SCENARIO_SRC_DIR}/http/http_interim_1xx.textproto
        ${SCENARIO_SRC_DIR}/http/http_maxfilesize_reject.textproto
        ${SCENARIO_SRC_DIR}/http/http_range_206.textproto
        ${SCENARIO_SRC_DIR}/http/http_request_target_path_as_is.textproto
        ${SCENARIO_SRC_DIR}/http/http_resume_filetime_206.textproto
        ${SCENARIO_SRC_DIR}/http/http_small_receive_buffer.textproto
        ${SCENARIO_SRC_DIR}/http/http_truncated_chunk.textproto
        ${SCENARIO_SRC_DIR}/http/http_unsupported_content_encoding.textproto
        ${SCENARIO_SRC_DIR}/http/http_zstd_decode.textproto
        ${SCENARIO_SRC_DIR}/http/url_authority_ipv6_zone.textproto
        ${SCENARIO_SRC_DIR}/http/url_disallow_userinfo.textproto
        ${SCENARIO_SRC_DIR}/http/url_idn_percent_edges.textproto
        ${SCENARIO_SRC_DIR}/http/url_malformed_authority.textproto
    )
    list(LENGTH FAST_HTTP_SCENARIO_TEXTPROTOS FAST_HTTP_SCENARIO_COUNT)
    if(NOT FAST_HTTP_SCENARIO_COUNT EQUAL 32)
        message(FATAL_ERROR
            "The fast HTTP corpus must contain exactly 32 seed declarations")
    endif()
    foreach(fast_http_textproto ${FAST_HTTP_SCENARIO_TEXTPROTOS})
        if(NOT EXISTS "${fast_http_textproto}")
            message(FATAL_ERROR
                "Fast HTTP corpus seed does not exist: ${fast_http_textproto}")
        endif()
    endforeach()

    # Emit a flat, target-specific corpus. Keeping the generated directories
    # distinct ensures packaging and coverage replay never feed WS-only seeds
    # to HTTP or ordinary seeds to the intentionally slow timing lane.
    set(PROTO_CORPUS_MANIFEST_DIR ${CMAKE_BINARY_DIR}/corpus_manifests)
    file(MAKE_DIRECTORY ${PROTO_CORPUS_MANIFEST_DIR})
    function(add_proto_fuzzer_corpus _corpus_target _output_name)
        set(scenario_out_dir
            ${CMAKE_BINARY_DIR}/generated_corpora/${_output_name})
        file(MAKE_DIRECTORY ${scenario_out_dir})
        set(scenario_binaries)
        set(seed_manifest "")
        foreach(textproto ${ARGN})
            get_filename_component(name ${textproto} NAME_WE)
            set(out ${scenario_out_dir}/${name}.scenario)
            add_custom_command(
                OUTPUT ${out}
                COMMAND ${CMAKE_COMMAND} -E make_directory ${scenario_out_dir}
                COMMAND ${CMAKE_SOURCE_DIR}/scripts/encode_scenario.sh
                        ${GENERATOR_PROTOC}
                        ${PROTO_FUZZER_SCHEMA_DIR}
                        ${GEN_PROTO}
                        ${textproto}
                        ${out}
                DEPENDS ${textproto} ${GEN_PROTO} ${GENERATOR_PROTOC}
                        ${GENERATOR_PROTOC_DEP}
                        ${CMAKE_SOURCE_DIR}/scripts/encode_scenario.sh
                COMMENT "Encoding ${name}.textproto for ${_output_name}"
                VERBATIM
            )
            list(APPEND scenario_binaries ${out})
            string(APPEND seed_manifest "${name}.scenario\n")
        endforeach()

        # Remove obsolete derived entries at configure time. Packaging still
        # consumes the exact allowlist below as a second line of defence, but
        # local replay and source-coverage tools walk this directory directly;
        # retaining a renamed seed there would silently inflate their results.
        file(GLOB previous_scenario_binaries "${scenario_out_dir}/*.scenario")
        foreach(previous_scenario ${previous_scenario_binaries})
            list(FIND scenario_binaries "${previous_scenario}" retained_index)
            if(retained_index EQUAL -1)
                file(REMOVE "${previous_scenario}")
            endif()
        endforeach()

        # create_zip.sh consumes this exact allowlist rather than archiving the
        # whole generated directory. This also guards packaging if an external
        # process writes an unrelated file after CMake has configured.
        # Keep both the allowlist and its generated inputs in the build tree so
        # a container build cannot leave root-owned artefacts that break later
        # host builds or masquerade as checked-in corpus entries.
        # Keep the allowlist outside the corpus directory: standalone runners
        # recursively treat every file below that directory as a fuzz input.
        file(WRITE ${PROTO_CORPUS_MANIFEST_DIR}/${_output_name}.seed_manifest
             "${seed_manifest}")
        add_custom_target(${_corpus_target} DEPENDS ${scenario_binaries})
    endfunction()

    add_proto_fuzzer_corpus(curl_fuzzer_proto_corpus
        curl_fuzzer_proto
        ${HTTP_SCENARIO_TEXTPROTOS} ${HTTPS_SCENARIO_TEXTPROTOS}
        ${WS_SCENARIO_TEXTPROTOS} ${WSS_SCENARIO_TEXTPROTOS}
        ${TELNET_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_http_corpus
        curl_fuzzer_proto_http ${FAST_HTTP_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_http_deep_corpus
        curl_fuzzer_proto_http_deep ${DEEP_HTTP_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_https_corpus
        curl_fuzzer_proto_https
        ${DEEP_HTTP_SCENARIO_TEXTPROTOS} ${HTTPS_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_h2_proxy_corpus
        curl_fuzzer_proto_h2_proxy ${H2_PROXY_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_ws_corpus
        curl_fuzzer_proto_ws ${FAST_WS_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_wss_corpus
        curl_fuzzer_proto_wss
        ${FAST_WS_SCENARIO_TEXTPROTOS} ${WSS_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_telnet_corpus
        curl_fuzzer_proto_telnet ${TELNET_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_ftp_corpus
        curl_fuzzer_proto_ftp ${FTP_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_tftp_corpus
        curl_fuzzer_proto_tftp ${TFTP_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_api_corpus
        curl_fuzzer_proto_api ${API_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_multi_corpus
        curl_fuzzer_proto_multi ${MULTI_SCENARIO_TEXTPROTOS})
    add_proto_fuzzer_corpus(curl_fuzzer_proto_timing_corpus
        curl_fuzzer_proto_timing ${TIMING_SCENARIO_TEXTPROTOS})
    add_dependencies(curl_fuzzer_proto curl_fuzzer_proto_corpus)
    add_dependencies(curl_fuzzer_proto_http curl_fuzzer_proto_http_corpus)
    add_dependencies(curl_fuzzer_proto_http_deep
        curl_fuzzer_proto_http_deep_corpus)
    add_dependencies(curl_fuzzer_proto_https curl_fuzzer_proto_https_corpus)
    add_dependencies(curl_fuzzer_proto_h2_proxy
        curl_fuzzer_proto_h2_proxy_corpus)
    add_dependencies(curl_fuzzer_proto_ws curl_fuzzer_proto_ws_corpus)
    add_dependencies(curl_fuzzer_proto_wss curl_fuzzer_proto_wss_corpus)
    add_dependencies(curl_fuzzer_proto_telnet
        curl_fuzzer_proto_telnet_corpus)
    add_dependencies(curl_fuzzer_proto_ftp curl_fuzzer_proto_ftp_corpus)
    add_dependencies(curl_fuzzer_proto_tftp curl_fuzzer_proto_tftp_corpus)
    add_dependencies(curl_fuzzer_proto_api curl_fuzzer_proto_api_corpus)
    add_dependencies(curl_fuzzer_proto_multi curl_fuzzer_proto_multi_corpus)
    add_dependencies(curl_fuzzer_proto_timing curl_fuzzer_proto_timing_corpus)

    # Policy tests need only the generated message and protobuf runtime. Keep
    # them separate from the full harness object library so CTest can validate
    # normalization without linking curl or running a fuzzing engine.
    if(BUILD_TESTING)
        add_executable(target_policy_test
            tests/target_policy_test.cc
            proto_fuzzer/target_policy.cc
            proto_fuzzer/telnet_scenario.cc
            ${GEN_PB_CC}
        )
        target_compile_features(target_policy_test PRIVATE cxx_std_17)
        target_compile_options(target_policy_test PRIVATE ${COMMON_FLAGS})
        target_include_directories(target_policy_test PRIVATE
            ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}
            ${LPM_PB_INCLUDE}
        )
        target_link_libraries(target_policy_test PRIVATE
            "-Wl,@${LPM_LINK_RSP}"
            pthread
            m
        )
        target_link_options(target_policy_test PRIVATE ${COVERAGE_LINK_FLAGS})
        add_dependencies(target_policy_test
            libprotobuf_mutator_external
            lpm_link_rsp
        )
        add_test(NAME target_policy_test COMMAND target_policy_test)
        add_dependencies(fuzzer_unit_tests target_policy_test)

        # This test links the real public MIME/header/callback APIs so
        # ownership, allocation budgets, and upload replay are checked under
        # the same sanitizers as curl.
        # Keeping it separate from the full runner avoids introducing mock
        # socket timing into a resource-lifetime unit test.
        add_executable(request_data_test
            tests/request_data_test.cc
            proto_fuzzer/option_apply.cc
            proto_fuzzer/request_data.cc
            ${GEN_PB_CC}
        )
        target_compile_features(request_data_test PRIVATE cxx_std_17)
        target_compile_options(request_data_test PRIVATE ${COMMON_FLAGS})
        target_include_directories(request_data_test PRIVATE
            ${CURL_INCLUDE_DIRS}
            ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}
            ${LPM_PB_INCLUDE}
        )
        target_link_libraries(request_data_test PRIVATE
            ${CURL_LIB_DIR}/libcurl.a
            ${CURL_STATIC_DEPENDENCY_LIBS}
            "-Wl,@${LPM_LINK_RSP}"
            pthread
            m
        )
        target_link_options(request_data_test PRIVATE ${COVERAGE_LINK_FLAGS})
        add_dependencies(request_data_test
            ${FUZZ_DEPS}
            libprotobuf_mutator_external
            lpm_link_rsp
        )
        add_test(NAME request_data_test COMMAND request_data_test)
        add_dependencies(fuzzer_unit_tests request_data_test)

        # Exercise the real socketpair implementation without involving DNS or
        # wall-clock waits. This catches script-order, connection-budget, and
        # old-peer lifetime regressions at the callback boundary where they
        # would otherwise look like ordinary curl transfer failures.
        add_executable(mock_server_test
            tests/mock_server_test.cc
            proto_fuzzer/api_lifecycle.cc
            proto_fuzzer/mock_server.cc
            proto_fuzzer/mock_server_base.cc
            proto_fuzzer/multi_socket_driver.cc
            proto_fuzzer/option_apply.cc
            proto_fuzzer/request_data.cc
            proto_fuzzer/telnet_mock_server.cc
            proto_fuzzer/telnet_scenario.cc
            ${PROTO_FUZZER_TLS_SOURCES}
            proto_fuzzer/websocket_mock_server.cc
            proto_fuzzer/ws_frame.cc
            ${GEN_PB_CC}
        )
        target_compile_features(mock_server_test PRIVATE cxx_std_17)
        target_compile_options(mock_server_test PRIVATE ${COMMON_FLAGS})
        target_include_directories(mock_server_test PRIVATE
            ${CURL_INCLUDE_DIRS}
            ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}
            ${LPM_PB_INCLUDE}
        )
        if(TARGET openssl_external)
            target_compile_definitions(mock_server_test PRIVATE
                PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
            target_include_directories(mock_server_test PRIVATE
                ${OPENSSL_INSTALL_DIR}/include)
        endif()
        target_link_libraries(mock_server_test PRIVATE
            ${CURL_LIB_DIR}/libcurl.a
            ${CURL_STATIC_DEPENDENCY_LIBS}
            "-Wl,@${LPM_LINK_RSP}"
            pthread
            m
        )
        target_link_options(mock_server_test PRIVATE ${COVERAGE_LINK_FLAGS})
        add_dependencies(mock_server_test
            ${FUZZ_DEPS}
            libprotobuf_mutator_external
            lpm_link_rsp
        )
        add_test(NAME mock_server_test COMMAND mock_server_test)
        set_tests_properties(mock_server_test PROPERTIES TIMEOUT 5)
        add_dependencies(fuzzer_unit_tests mock_server_test)

        # Keep concurrent scheduling checks independent of the TLS and
        # protocol integrations in mock_server_test. This focused executable
        # validates shared-multi ownership and completion accounting using
        # only the plaintext socketpair peer.
        add_executable(multi_transfer_runner_test
            tests/multi_transfer_runner_test.cc
            proto_fuzzer/mock_server.cc
            proto_fuzzer/mock_server_base.cc
            proto_fuzzer/multi_socket_driver.cc
            proto_fuzzer/multi_transfer_runner.cc
            proto_fuzzer/option_apply.cc
            proto_fuzzer/request_data.cc
            proto_fuzzer/ws_frame.cc
            ${GEN_PB_CC}
        )
        target_compile_features(multi_transfer_runner_test PRIVATE cxx_std_17)
        target_compile_options(multi_transfer_runner_test PRIVATE ${COMMON_FLAGS})
        target_include_directories(multi_transfer_runner_test PRIVATE
            ${CURL_INCLUDE_DIRS}
            ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}
            ${LPM_PB_INCLUDE}
        )
        target_link_libraries(multi_transfer_runner_test PRIVATE
            ${CURL_LIB_DIR}/libcurl.a
            ${CURL_STATIC_DEPENDENCY_LIBS}
            "-Wl,@${LPM_LINK_RSP}"
            pthread
            m
        )
        target_link_options(multi_transfer_runner_test PRIVATE ${COVERAGE_LINK_FLAGS})
        add_dependencies(multi_transfer_runner_test
            ${FUZZ_DEPS}
            libprotobuf_mutator_external
            lpm_link_rsp
        )
        add_test(NAME multi_transfer_runner_test COMMAND multi_transfer_runner_test)
        set_tests_properties(multi_transfer_runner_test PROPERTIES TIMEOUT 5)
        add_dependencies(fuzzer_unit_tests multi_transfer_runner_test)

        # Protocol peers that need multi-socket coordination have focused
        # executable tests. Keeping them outside mock_server_test makes their
        # real FTP/TFTP transfers independently attributable and keeps the
        # generic stream-mock test from becoming a protocol integration suite.
        function(curl_add_proto_peer_test _name _test_source _peer_source)
            add_executable(${_name}
                ${_test_source}
                ${_peer_source}
                proto_fuzzer/mock_server.cc
                proto_fuzzer/mock_server_base.cc
                proto_fuzzer/multi_socket_driver.cc
                proto_fuzzer/option_apply.cc
                proto_fuzzer/request_data.cc
                proto_fuzzer/ws_frame.cc
                ${GEN_PB_CC}
            )
            target_compile_features(${_name} PRIVATE cxx_std_17)
            target_compile_options(${_name} PRIVATE ${COMMON_FLAGS})
            target_include_directories(${_name} PRIVATE
                ${CURL_INCLUDE_DIRS}
                ${CMAKE_BINARY_DIR}
                ${CMAKE_SOURCE_DIR}
                ${LPM_PB_INCLUDE}
            )
            target_link_libraries(${_name} PRIVATE
                ${CURL_LIB_DIR}/libcurl.a
                ${CURL_STATIC_DEPENDENCY_LIBS}
                "-Wl,@${LPM_LINK_RSP}"
                pthread
                m
            )
            target_link_options(${_name} PRIVATE ${COVERAGE_LINK_FLAGS})
            add_dependencies(${_name}
                ${FUZZ_DEPS}
                libprotobuf_mutator_external
                lpm_link_rsp
            )
            add_test(NAME ${_name} COMMAND ${_name})
            set_tests_properties(${_name} PROPERTIES TIMEOUT 5)
            add_dependencies(fuzzer_unit_tests ${_name})
        endfunction()

        curl_add_proto_peer_test(tftp_mock_server_test
            tests/tftp_mock_server_test.cc
            proto_fuzzer/tftp_mock_server.cc)
        curl_add_proto_peer_test(ftp_mock_server_test
            tests/ftp_mock_server_test.cc
            proto_fuzzer/ftp_mock_server.cc)
    endif()

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
