"""Tests for native curl.h option identity parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from curl_fuzzer_tools.generate_option_manifest import CurlOption, parse_curl_header


def test_curl_header_resolves_type_family_offsets(tmp_path: Path) -> None:
    header = tmp_path / "curl.h"
    header.write_text(
        """
CURLOPT(CURLOPT_TIMEOUT, CURLOPTTYPE_LONG, 13),
CURLOPT(CURLOPT_URL, CURLOPTTYPE_STRINGPOINT, 2),
CURLOPTDEPRECATED(CURLOPT_OLD, CURLOPTTYPE_OFF_T, 7, 7.0),
"""
    )

    assert parse_curl_header(header) == {
        "CURLOPT_TIMEOUT": CurlOption("CURLOPT_TIMEOUT", "CURLOPTTYPE_LONG", 13),
        "CURLOPT_URL": CurlOption("CURLOPT_URL", "CURLOPTTYPE_STRINGPOINT", 10002),
        "CURLOPT_OLD": CurlOption("CURLOPT_OLD", "CURLOPTTYPE_OFF_T", 30007),
    }


def test_curl_header_rejects_unknown_type_family(tmp_path: Path) -> None:
    header = tmp_path / "curl.h"
    header.write_text("CURLOPT(CURLOPT_FAKE, CURLOPTTYPE_UNKNOWN, 1),\n")

    with pytest.raises(ValueError, match="Unknown CURLOPT type token"):
        parse_curl_header(header)


def test_curl_header_requires_option_declarations(tmp_path: Path) -> None:
    header = tmp_path / "curl.h"
    header.write_text("/* no option declarations */\n")

    with pytest.raises(ValueError, match="No CURLOPT definitions"):
        parse_curl_header(header)
