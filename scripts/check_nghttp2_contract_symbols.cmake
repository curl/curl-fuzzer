# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# SPDX-License-Identifier: curl

foreach(_required IN ITEMS NM ARCHIVE WRAPPED_APIS)
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
        "Could not inspect nghttp2 calls in ${ARCHIVE}: ${_nm_error}")
endif()

string(REGEX MATCHALL "nghttp2_(session|submit)_[A-Za-z0-9_]+"
    _nghttp2_symbols "${_undefined_symbols}")
list(REMOVE_DUPLICATES _nghttp2_symbols)
list(SORT _nghttp2_symbols)

set(_unwrapped_symbols "")
foreach(_symbol IN LISTS _nghttp2_symbols)
    # Callback-table APIs do not receive an nghttp2_session and remain valid
    # regardless of a separate session's state.
    if(_symbol MATCHES "^nghttp2_session_callbacks_")
        continue()
    endif()
    list(FIND WRAPPED_APIS "${_symbol}" _wrapped_index)
    if(_wrapped_index EQUAL -1)
        list(APPEND _unwrapped_symbols "${_symbol}")
    endif()
endforeach()

if(_unwrapped_symbols)
    list(JOIN _unwrapped_symbols ", " _unwrapped_list)
    message(FATAL_ERROR
        "libcurl uses session-bearing nghttp2 APIs that bypass the contract "
        "shim: ${_unwrapped_list}")
endif()
