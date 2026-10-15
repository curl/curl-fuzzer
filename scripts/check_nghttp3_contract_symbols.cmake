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
            "Could not inspect nghttp3 calls in ${_binary}: ${_nm_error}")
    endif()
    string(APPEND _undefined_symbols "\n${_binary_symbols}")
endforeach()

string(REPLACE "\n" ";" _nm_lines "${_undefined_symbols}")
set(_nghttp3_symbols "")
foreach(_line IN LISTS _nm_lines)
    # Match a complete undefined-symbol token. Archive member names such as
    # nghttp3_mem.c.o appear in nm headings and are not public API calls.
    if(_line MATCHES "(^|[ \t])nghttp3_[A-Za-z0-9_]+(@[^ \t]+)?$")
        string(REGEX MATCH "nghttp3_[A-Za-z0-9_]+" _symbol "${_line}")
        list(APPEND _nghttp3_symbols "${_symbol}")
    endif()
endforeach()
list(REMOVE_DUPLICATES _nghttp3_symbols)
list(SORT _nghttp3_symbols)

set(_unwrapped_symbols "")
foreach(_symbol IN LISTS _nghttp3_symbols)
    list(FIND WRAPPED_APIS "${_symbol}" _wrapped_index)
    list(FIND ALLOWED_APIS "${_symbol}" _allowed_index)
    if(_wrapped_index EQUAL -1 AND _allowed_index EQUAL -1)
        list(APPEND _unwrapped_symbols "${_symbol}")
    endif()
endforeach()

if(_unwrapped_symbols)
    list(JOIN _unwrapped_symbols ", " _unwrapped_list)
    message(FATAL_ERROR
        "${ARCHIVE} uses nghttp3 APIs that the contract shim has not "
        "classified: ${_unwrapped_list}")
endif()
