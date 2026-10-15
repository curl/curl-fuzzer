# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
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
        "Could not inspect GnuTLS calls in ${ARCHIVE}: ${_nm_error}")
endif()

string(REPLACE "\n" ";" _nm_lines "${_undefined_symbols}")
set(_gnutls_symbols "")
foreach(_line IN LISTS _nm_lines)
    if(_line MATCHES "(^|[ \t])gnutls_[A-Za-z0-9_]+(@[^ \t]+)?$")
        string(REGEX MATCH "gnutls_[A-Za-z0-9_]+" _symbol "${_line}")
        list(APPEND _gnutls_symbols "${_symbol}")
    endif()
endforeach()
list(REMOVE_DUPLICATES _gnutls_symbols)
list(SORT _gnutls_symbols)

set(_unclassified_symbols "")
foreach(_symbol IN LISTS _gnutls_symbols)
    list(FIND WRAPPED_APIS "${_symbol}" _wrapped_index)
    list(FIND ALLOWED_APIS "${_symbol}" _allowed_index)
    if(_wrapped_index EQUAL -1 AND _allowed_index EQUAL -1)
        list(APPEND _unclassified_symbols "${_symbol}")
    endif()
endforeach()

if(_unclassified_symbols)
    list(JOIN _unclassified_symbols ", " _unclassified_list)
    message(FATAL_ERROR
        "${ARCHIVE} uses GnuTLS APIs that the contract shim has not "
        "classified: ${_unclassified_list}")
endif()
