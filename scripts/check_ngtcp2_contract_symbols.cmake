# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# SPDX-License-Identifier: curl

foreach(_required IN ITEMS NM ARCHIVE WRAPPED_APIS ALLOWED_APIS)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

set(_undefined_symbols "")
foreach(_binary IN LISTS ARCHIVE)
    execute_process(
        COMMAND "${NM}" -u "${_binary}"
        RESULT_VARIABLE _nm_result
        OUTPUT_VARIABLE _binary_symbols
        ERROR_VARIABLE _nm_error)
    if(NOT _nm_result EQUAL 0)
        message(FATAL_ERROR
            "Could not inspect ngtcp2 calls in ${_binary}: ${_nm_error}")
    endif()
    string(APPEND _undefined_symbols "\n${_binary_symbols}")
endforeach()

string(REPLACE "\n" ";" _nm_lines "${_undefined_symbols}")
set(_ngtcp2_symbols "")
foreach(_line IN LISTS _nm_lines)
    if(_line MATCHES "(^|[ \t])ngtcp2_[A-Za-z0-9_]+(@[^ \t]+)?$")
        string(REGEX MATCH "ngtcp2_[A-Za-z0-9_]+" _symbol "${_line}")
        list(APPEND _ngtcp2_symbols "${_symbol}")
    endif()
endforeach()
list(REMOVE_DUPLICATES _ngtcp2_symbols)
list(SORT _ngtcp2_symbols)

set(_unclassified_symbols "")
foreach(_symbol IN LISTS _ngtcp2_symbols)
    list(FIND WRAPPED_APIS "${_symbol}" _wrapped_index)
    list(FIND ALLOWED_APIS "${_symbol}" _allowed_index)
    if(_wrapped_index EQUAL -1 AND _allowed_index EQUAL -1)
        list(APPEND _unclassified_symbols "${_symbol}")
    endif()
endforeach()

if(_unclassified_symbols)
    list(JOIN _unclassified_symbols ", " _unclassified_list)
    message(FATAL_ERROR
        "${ARCHIVE} uses ngtcp2 APIs that the contract shim has not "
        "classified: ${_unclassified_list}")
endif()
