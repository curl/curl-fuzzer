#!/usr/bin/env python3
"""Parse native CURLOPT identities and type families from curl.h."""

from __future__ import annotations

import dataclasses
import pathlib
import re

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


@dataclasses.dataclass(frozen=True)
class CurlOption:
    """One native option declaration resolved to its public numeric value."""

    name: str
    type_token: str
    curl_value: int


def parse_curl_header(path: pathlib.Path) -> dict[str, CurlOption]:
    """Parse curl's option declarations without deciding protobuf value kinds."""
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
