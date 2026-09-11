#!/usr/bin/env python3
"""
Validate the Scenario schema and generate its curl option manifest.

This script reads the active CURLOPTs from the checked-in Scenario schema and
derives their value kinds from curl.h at build time. It:

* Verifies that every active ``CurlOptionId`` has the value defined by the
  selected curl.h, then stages an identical copy of the schema for the build.
* Emits a C++ ``.inc`` fragment defining ``kOptionManifest[]`` and a direct
  switch-based descriptor lookup for the fuzzer to dispatch on.

Every input and output path is passed on the command line so the script stays
independent of the repository layout and can be invoked directly by CMake.
The implementation uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import sys
from collections.abc import Iterable, Mapping

CURL_OPTIONS_BEGIN = "  // CURL-OPTIONS-BEGIN"
CURL_OPTIONS_END = "  // CURL-OPTIONS-END"

# Base numeric offsets for CURLOPTTYPE_* families. See curl.h.
TYPE_BASE_VALUES: dict[str, int] = {
    "CURLOPTTYPE_LONG": 0,
    "CURLOPTTYPE_VALUES": 0,
    "CURLOPTTYPE_OBJECTPOINT": 10000,
    "CURLOPTTYPE_STRINGPOINT": 10000,
    "CURLOPTTYPE_SLISTPOINT": 10000,
    "CURLOPTTYPE_CBPOINT": 10000,
    "CURLOPTTYPE_FUNCTIONPOINT": 20000,
    "CURLOPTTYPE_OFF_T": 30000,
    "CURLOPTTYPE_BLOB": 40000,
}

# Default kind derived from the curl type token. Pointer-like families need
# explicit per-option overrides below because they cover too many shapes.
BASE_KIND: dict[str, str] = {
    "CURLOPTTYPE_LONG": "uint",
    "CURLOPTTYPE_VALUES": "uint",
    "CURLOPTTYPE_STRINGPOINT": "string",
    "CURLOPTTYPE_OFF_T": "uint",
}

# Options whose kind cannot be inferred from the type token alone.
OPTION_KIND_OVERRIDES: dict[str, str] = {
    "CURLOPT_POSTFIELDS": "string",
    "CURLOPT_COPYPOSTFIELDS": "string",
    "CURLOPT_NOBODY": "bool",
    "CURLOPT_POST": "bool",
    "CURLOPT_HTTPGET": "bool",
    "CURLOPT_HEADER": "bool",
    "CURLOPT_FAILONERROR": "bool",
    "CURLOPT_AUTOREFERER": "bool",
    "CURLOPT_HTTP09_ALLOWED": "bool",
    "CURLOPT_CRLF": "bool",
    "CURLOPT_CERTINFO": "bool",
    "CURLOPT_FILETIME": "bool",
    "CURLOPT_PATH_AS_IS": "bool",
    "CURLOPT_KEEP_SENDING_ON_ERROR": "bool",
    "CURLOPT_TRANSFER_ENCODING": "bool",
    "CURLOPT_HTTP_TRANSFER_DECODING": "bool",
    "CURLOPT_HTTP_CONTENT_DECODING": "bool",
    "CURLOPT_IGNORE_CONTENT_LENGTH": "bool",
    "CURLOPT_DISALLOW_USERNAME_IN_URL": "bool",
    "CURLOPT_FRESH_CONNECT": "bool",
    "CURLOPT_FORBID_REUSE": "bool",
    "CURLOPT_UPLOAD": "bool",
    "CURLOPT_SSL_VERIFYPEER": "bool",
    "CURLOPT_SSL_SESSIONID_CACHE": "bool",
    "CURLOPT_SSL_ENABLE_ALPN": "bool",
    "CURLOPT_COOKIESESSION": "bool",
    "CURLOPT_UNRESTRICTED_AUTH": "bool",
    "CURLOPT_DIRLISTONLY": "bool",
    "CURLOPT_APPEND": "bool",
    "CURLOPT_TRANSFERTEXT": "bool",
    "CURLOPT_FTP_USE_EPSV": "bool",
    "CURLOPT_FTP_SKIP_PASV_IP": "bool",
    "CURLOPT_FTP_USE_PRET": "bool",
    "CURLOPT_WILDCARDMATCH": "bool",
    "CURLOPT_TFTP_NO_OPTIONS": "bool",
}

VALUE_KIND_SYMBOLS: dict[str, str] = {
    "string": "OptionValueKind::kString",
    "uint": "OptionValueKind::kUint",
    "bool": "OptionValueKind::kBool",
}


@dataclasses.dataclass(frozen=True)
class CurlOption:
    name: str
    type_token: str
    curl_value: int

    @property
    def kind(self) -> str:
        resolved = OPTION_KIND_OVERRIDES.get(self.name, BASE_KIND.get(self.type_token))
        if resolved is None:
            raise ValueError(
                f"No kind mapping for {self.name} ({self.type_token}). "
                "Extend BASE_KIND or OPTION_KIND_OVERRIDES."
            )
        return resolved


@dataclasses.dataclass(frozen=True)
class SchemaOption:
    name: str
    curl_value: int


def parse_proto_options(schema_text: str) -> list[SchemaOption]:
    """Parse and validate the active CurlOptionId entries from the schema."""
    if (
        schema_text.count(CURL_OPTIONS_BEGIN) != 1
        or schema_text.count(CURL_OPTIONS_END) != 1
    ):
        raise ValueError(
            "Proto schema must contain exactly one CURL-OPTIONS-BEGIN marker "
            "followed by exactly one CURL-OPTIONS-END marker."
        )

    begin_idx = schema_text.index(CURL_OPTIONS_BEGIN) + len(CURL_OPTIONS_BEGIN)
    end_idx = schema_text.index(CURL_OPTIONS_END)
    if end_idx < begin_idx:
        raise ValueError(
            "Proto schema CURL-OPTIONS-BEGIN marker must precede CURL-OPTIONS-END."
        )

    assignment = re.compile(r"^  (CURLOPT_[A-Z0-9_]+) = ([0-9]+);$")
    options: list[SchemaOption] = []
    for line in schema_text[begin_idx:end_idx].splitlines():
        if not line:
            continue
        match = assignment.fullmatch(line)
        if match is None:
            raise ValueError(
                f"Malformed CurlOptionId entry between CURL-OPTIONS markers: {line!r}."
            )
        name, value = match.groups()
        options.append(SchemaOption(name=name, curl_value=int(value)))

    if not options:
        raise ValueError("No CurlOptionId entries found between CURL-OPTIONS markers.")

    names = [option.name for option in options]
    duplicate_names = sorted({name for name in names if names.count(name) > 1})
    if duplicate_names:
        raise ValueError(
            "Duplicate CurlOptionId names between CURL-OPTIONS markers: "
            f"{', '.join(duplicate_names)}."
        )
    if names != sorted(names):
        raise ValueError(
            "CurlOptionId entries between CURL-OPTIONS markers must be "
            "alphabetized by name."
        )

    values = [option.curl_value for option in options]
    duplicate_values = sorted({value for value in values if values.count(value) > 1})
    if duplicate_values:
        rendered = ", ".join(str(value) for value in duplicate_values)
        raise ValueError(
            f"Duplicate CurlOptionId values between CURL-OPTIONS markers: {rendered}."
        )

    return options


def parse_curl_header(path: pathlib.Path) -> dict[str, CurlOption]:
    text = path.read_text()
    pattern = re.compile(
        r"CURLOPT(?:DEPRECATED)?\(\s*"
        r"(CURLOPT_[A-Z0-9_]+)\s*,\s*"
        r"(CURLOPTTYPE_[A-Z0-9_]+)\s*,\s*"
        r"([0-9]+)"
    )
    options: dict[str, CurlOption] = {}
    for match in pattern.finditer(text):
        name, type_token, offset_text = match.groups()
        if type_token not in TYPE_BASE_VALUES:
            raise ValueError(f"Unknown CURLOPT type token {type_token} for {name}")
        options[name] = CurlOption(
            name=name,
            type_token=type_token,
            curl_value=TYPE_BASE_VALUES[type_token] + int(offset_text),
        )
    if not options:
        raise ValueError(f"No CURLOPT definitions found in {path}")
    return options


def resolve_schema_options(
    schema_options: Iterable[SchemaOption],
    header_options: Mapping[str, CurlOption],
) -> list[CurlOption]:
    """Resolve schema entries to curl.h definitions and verify their IDs."""
    resolved: list[CurlOption] = []
    for schema_option in schema_options:
        header_option = header_options.get(schema_option.name)
        if header_option is None:
            raise ValueError(f"{schema_option.name} is not defined in curl.h.")
        if schema_option.curl_value != header_option.curl_value:
            raise ValueError(
                f"{schema_option.name} is {schema_option.curl_value} in the schema "
                f"but {header_option.curl_value} in curl.h."
            )
        resolved.append(header_option)
    return resolved


def render_manifest(entries: Iterable[CurlOption]) -> str:
    materialized = list(entries)
    lines = [
        "// Generated by src/curl_fuzzer_tools/generate_option_manifest.py.",
        "// Do not edit. Included once from proto_fuzzer/option_apply.cc.",
        "static constexpr OptionDescriptor kOptionManifest[] = {",
    ]
    for option in materialized:
        kind_symbol = VALUE_KIND_SYMBOLS[option.kind]
        lines.append(
            f"    {{curl::fuzzer::proto::{option.name}, "
            f'{kind_symbol}, "{option.name}", {option.name}}},'
        )
    lines.append("};")
    lines.extend(
        (
            "",
            "static constexpr const OptionDescriptor* LookupOptionDescriptor(",
            "    curl::fuzzer::proto::CurlOptionId id) {",
            "  switch (id) {",
        )
    )
    for index, option in enumerate(materialized):
        lines.extend(
            (
                f"    case curl::fuzzer::proto::{option.name}:",
                f"      return &kOptionManifest[{index}];",
            )
        )
    lines.extend(("    default:", "      return nullptr;", "  }", "}"))
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curl-header", required=True, type=pathlib.Path)
    parser.add_argument("--proto-schema", required=True, type=pathlib.Path)
    parser.add_argument("--proto-out", required=True, type=pathlib.Path)
    parser.add_argument("--manifest-out", required=True, type=pathlib.Path)
    return parser.parse_args(argv)


def write_if_changed(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        return
    path.write_text(content)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    schema_text = args.proto_schema.read_text()
    schema_options = parse_proto_options(schema_text)
    header_options = parse_curl_header(args.curl_header)
    resolved_options = resolve_schema_options(schema_options, header_options)

    write_if_changed(args.proto_out, schema_text)
    write_if_changed(args.manifest_out, render_manifest(resolved_options))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
