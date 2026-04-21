# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# SPDX-License-Identifier: curl
#
# Invoked as: cmake -DLIBDIRS=<dir1;dir2;...> -DOUT=<file>
#                   -P write_lpm_link_rsp.cmake
#
# Globs every .a under each LIBDIRS entry and writes them to OUT as a linker
# response file, wrapped in --start-group/--end-group so inter-library
# reference order is solved for us. Runs at build time (after LPM has
# installed its bundled protobuf + abseil), so the glob sees real files.
# LPM's own libs live in one dir and its bundled protobuf+abseil libs live
# in another — both go inside the same group so nothing gets dropped as
# "unreferenced" between them.

if(NOT DEFINED LIBDIRS OR NOT DEFINED OUT)
    message(FATAL_ERROR "Usage: -DLIBDIRS=<dir1;dir2;...> -DOUT=<file>")
endif()

set(_libs)
foreach(_dir IN LISTS LIBDIRS)
    file(GLOB _dir_libs "${_dir}/*.a")
    list(APPEND _libs ${_dir_libs})
endforeach()
list(SORT _libs)
if(NOT _libs)
    message(FATAL_ERROR "No .a files found under: ${LIBDIRS}")
endif()

# Consumed by ld directly via `-Wl,@file`, so use ld-level syntax
# (--start-group / --end-group), not driver-level (-Wl,--start-group).
set(_content "--start-group\n")
foreach(_lib IN LISTS _libs)
    string(APPEND _content "${_lib}\n")
endforeach()
string(APPEND _content "--end-group\n")

file(WRITE "${OUT}" "${_content}")
