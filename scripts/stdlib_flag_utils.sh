#!/usr/bin/env bash
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

# shellcheck shell=bash

strip_flag()
{
	local var_name=$1
	local flag=$2
	local current=${!var_name-}

	if [[ -n ${current:-} ]]
	then
		# shellcheck disable=SC2140
		current=${current//${flag}/}
		current=$(echo "${current}" | tr -s ' ')
		export "${var_name}"="${current}"
	fi
}

_stdlib_compiler_supports_libstdcxx()
{
	local compiler_words

	if [[ -n ${CXX:-} ]]
	then
		# shellcheck disable=SC2206
		compiler_words=( ${CXX} )
	else
		compiler_words=( c++ )
	fi

	if ! command -v "${compiler_words[0]}" >/dev/null 2>&1
	then
		return 1
	fi

	local tmp_src tmp_obj
	tmp_src=$(mktemp)
	tmp_obj=$(mktemp)

	cat <<'EOF' > "${tmp_src}"
int main() { return 0; }
EOF

	if "${compiler_words[@]}" -x c++ "${tmp_src}" -c -o "${tmp_obj}" -stdlib=libstdc++ >/dev/null 2>&1
	then
		rm -f "${tmp_src}" "${tmp_obj}"
		return 0
	fi

	rm -f "${tmp_src}" "${tmp_obj}"
	return 1
}

ensure_libstdcxx_flag()
{
	local var_name=$1

	if _stdlib_compiler_supports_libstdcxx
	then
		if [[ ${!var_name:-} != *"-stdlib=libstdc++"* ]]
		then
			export "${var_name}"="${!var_name:-} -stdlib=libstdc++"
		fi
	else
		strip_flag "${var_name}" "-stdlib=libstdc++"
	fi
}