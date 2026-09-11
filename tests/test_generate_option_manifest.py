"""Value-kind invariants for the generated proto CURLOPT surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from curl_fuzzer_tools.generate_option_manifest import (
    CurlOption,
    SchemaOption,
    parse_proto_options,
    render_manifest,
    resolve_schema_options,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _entries() -> list[CurlOption]:
    return [
        CurlOption(
            name="CURLOPT_POSTFIELDS",
            type_token="CURLOPTTYPE_OBJECTPOINT",
            curl_value=10015,
        ),
        CurlOption(
            name="CURLOPT_FOLLOWLOCATION",
            type_token="CURLOPTTYPE_LONG",
            curl_value=52,
        ),
    ]


def _schema(option_lines: str) -> str:
    return f"""syntax = \"proto3\";

enum CurlOptionId {{
  CURL_OPTION_UNSPECIFIED = 0;
  // CURL-OPTIONS-BEGIN
{option_lines}
  // CURL-OPTIONS-END
}}
"""


def _kind(name: str, type_token: str = "CURLOPTTYPE_LONG") -> str:
    return CurlOption(name=name, type_token=type_token, curl_value=0).kind


def test_true_flags_use_boolean_mutations() -> None:
    """Keep flag mutations concentrated on the two values curl consumes."""
    for name in (
        "CURLOPT_UPLOAD",
        "CURLOPT_SSL_VERIFYPEER",
        "CURLOPT_SSL_SESSIONID_CACHE",
        "CURLOPT_SSL_ENABLE_ALPN",
        "CURLOPT_COOKIESESSION",
        "CURLOPT_UNRESTRICTED_AUTH",
        "CURLOPT_HTTP09_ALLOWED",
        "CURLOPT_CRLF",
        "CURLOPT_CERTINFO",
    ):
        assert _kind(name) == "bool"


def test_modes_and_bitmasks_retain_full_integer_values() -> None:
    """Do not collapse valid non-boolean modes into false/true."""
    for name in (
        "CURLOPT_FOLLOWLOCATION",
        "CURLOPT_CONNECT_ONLY",
        "CURLOPT_WS_OPTIONS",
        "CURLOPT_HTTPAUTH",
        "CURLOPT_ALTSVC_CTRL",
        "CURLOPT_HSTS_CTRL",
        "CURLOPT_TIMECONDITION",
        "CURLOPT_POSTREDIR",
        # VERIFYHOST consumes the historical 0/2 API values, while the other
        # TLS entries are version/bitmask selectors rather than booleans.
        "CURLOPT_SSL_VERIFYHOST",
        "CURLOPT_SSLVERSION",
        "CURLOPT_SSL_OPTIONS",
    ):
        assert _kind(name) == "uint"


def test_postfield_pointer_options_use_bounded_strings() -> None:
    """Both borrowed and copied POST bodies share the binary string path."""
    for name in ("CURLOPT_POSTFIELDS", "CURLOPT_COPYPOSTFIELDS"):
        assert _kind(name, "CURLOPTTYPE_OBJECTPOINT") == "string"


def test_manifest_generates_direct_switch_lookup() -> None:
    """Both runtime users should dispatch without scanning every option."""
    rendered = render_manifest(_entries())

    assert "switch (id)" in rendered
    assert "case curl::fuzzer::proto::CURLOPT_POSTFIELDS:" in rendered
    assert "return &kOptionManifest[0];" in rendered
    assert "case curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION:" in rendered
    assert "return &kOptionManifest[1];" in rendered
    assert "default:\n      return nullptr;" in rendered
    assert "kOptionManifestSize" not in rendered
    assert "for (" not in rendered


def test_proto_options_are_parsed_in_alphabetical_order() -> None:
    schema = _schema("  CURLOPT_FOLLOWLOCATION = 52;\n  CURLOPT_POSTFIELDS = 10015;")

    assert parse_proto_options(schema) == [
        SchemaOption(name="CURLOPT_FOLLOWLOCATION", curl_value=52),
        SchemaOption(name="CURLOPT_POSTFIELDS", curl_value=10015),
    ]


def test_proto_options_must_be_alphabetized() -> None:
    schema = _schema("  CURLOPT_POSTFIELDS = 10015;\n  CURLOPT_FOLLOWLOCATION = 52;")

    with pytest.raises(ValueError, match="alphabetized"):
        parse_proto_options(schema)


def test_proto_options_reject_duplicate_values() -> None:
    schema = _schema("  CURLOPT_FOLLOWLOCATION = 52;\n  CURLOPT_POSTFIELDS = 52;")

    with pytest.raises(ValueError, match="Duplicate CurlOptionId values"):
        parse_proto_options(schema)


def test_proto_options_reject_duplicate_names() -> None:
    schema = _schema("  CURLOPT_FOLLOWLOCATION = 52;\n  CURLOPT_FOLLOWLOCATION = 53;")

    with pytest.raises(ValueError, match="Duplicate CurlOptionId names"):
        parse_proto_options(schema)


def test_proto_options_reject_malformed_entries() -> None:
    schema = _schema("  CURLOPT_FOLLOWLOCATION: 52;")

    with pytest.raises(ValueError, match="Malformed CurlOptionId entry"):
        parse_proto_options(schema)


def test_proto_options_require_exactly_one_marker_pair() -> None:
    schema = _schema("  CURLOPT_FOLLOWLOCATION = 52;").replace(
        "  // CURL-OPTIONS-END", ""
    )

    with pytest.raises(ValueError, match="exactly one CURL-OPTIONS-BEGIN"):
        parse_proto_options(schema)


def test_schema_values_must_match_curl_header() -> None:
    schema_options = [SchemaOption(name="CURLOPT_FOLLOWLOCATION", curl_value=51)]
    header_options = {entry.name: entry for entry in _entries()}

    with pytest.raises(ValueError, match="51 in the schema but 52 in curl.h"):
        resolve_schema_options(schema_options, header_options)


def test_schema_options_must_exist_in_curl_header() -> None:
    schema_options = [SchemaOption(name="CURLOPT_NOT_REAL", curl_value=123)]

    with pytest.raises(ValueError, match="CURLOPT_NOT_REAL is not defined"):
        resolve_schema_options(schema_options, {})


def test_checked_in_option_block_is_valid() -> None:
    schema = (REPO_ROOT / "schemas" / "curl_fuzzer.proto").read_text()
    entries = parse_proto_options(schema)

    assert "CURLOPT_COPYPOSTFIELDS" in {entry.name for entry in entries}
