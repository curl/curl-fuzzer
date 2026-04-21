#!/usr/bin/env bash
# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
#
# SPDX-License-Identifier: curl
#
# Encode one textproto scenario into a binary libFuzzer corpus entry.
# Used by CMake's per-scenario custom_command; protoc --encode only reads
# stdin, and add_custom_command(VERBATIM) cannot express redirection.
#
# Usage: encode_scenario.sh <protoc> <proto_path> <proto_file> <textproto_in> <scenario_out>
set -euo pipefail

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <protoc> <proto_path> <proto_file> <textproto_in> <scenario_out>" >&2
    exit 2
fi

PROTOC="$1"
PROTO_PATH="$2"
PROTO_FILE="$3"
INFILE="$4"
OUTFILE="$5"

"${PROTOC}" \
    --proto_path="${PROTO_PATH}" \
    --encode=curl.fuzzer.proto.Scenario \
    "${PROTO_FILE}" \
    < "${INFILE}" \
    > "${OUTFILE}"
