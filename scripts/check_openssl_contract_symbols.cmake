# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# SPDX-License-Identifier: curl

foreach(_required IN ITEMS NM ARCHIVE WRAPPED_APIS ALLOWED_APIS)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

execute_process(
    COMMAND "${NM}" -u "${ARCHIVE}"
    RESULT_VARIABLE _nm_result
    OUTPUT_VARIABLE _undefined_symbols
    ERROR_VARIABLE _nm_error)
if(NOT _nm_result EQUAL 0)
    message(FATAL_ERROR
        "Could not inspect OpenSSL calls in ${ARCHIVE}: ${_nm_error}")
endif()

string(REPLACE "\n" ";" _nm_lines "${_undefined_symbols}")
set(_openssl_symbols "")
foreach(_line IN LISTS _nm_lines)
    # Match an entire nm symbol token so OSSL_* names are not mistaken for
    # public SSL_* APIs.
    if(_line MATCHES "(^|[ \t])SSL_[A-Za-z0-9_]+(@[^ \t]+)?$")
        string(REGEX MATCH "SSL_[A-Za-z0-9_]+" _symbol "${_line}")
        list(APPEND _openssl_symbols "${_symbol}")
    endif()
endforeach()
list(REMOVE_DUPLICATES _openssl_symbols)
list(SORT _openssl_symbols)

set(_unclassified_symbols "")
foreach(_symbol IN LISTS _openssl_symbols)
    # These APIs operate on related types rather than an SSL connection.
    if(_symbol MATCHES "^SSL_(CTX|SESSION|CIPHER|COMP)_")
        continue()
    endif()
    list(FIND WRAPPED_APIS "${_symbol}" _wrapped_index)
    list(FIND ALLOWED_APIS "${_symbol}" _allowed_index)
    if(_wrapped_index EQUAL -1 AND _allowed_index EQUAL -1)
        list(APPEND _unclassified_symbols "${_symbol}")
    endif()
endforeach()

if(_unclassified_symbols)
    list(JOIN _unclassified_symbols ", " _unclassified_list)
    message(FATAL_ERROR
        "${ARCHIVE} uses SSL APIs that the OpenSSL contract shim has not "
        "classified: ${_unclassified_list}")
endif()
