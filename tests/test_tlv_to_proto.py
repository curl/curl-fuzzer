from __future__ import annotations

import struct

from curl_fuzzer_tools.corpus import BaseType
from curl_fuzzer_tools.tlv_to_proto import convert_stream, render_textproto


def tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack(">HI", tlv_type, len(value)) + value


def test_url_becomes_runner_fields_instead_of_an_option() -> None:
    stream = b"".join(
        (
            tlv(BaseType.TYPE_URL, b"HTTP://example.test:8080/a\x00b"),
            tlv(BaseType.TYPE_RSP0, b"HTTP/1.1 204 No Content\r\n\r\n"),
            tlv(BaseType.TYPE_FOLLOWLOCATION, b"\x00\x00\x00\x01"),
        )
    )

    rendered = render_textproto("seed", convert_stream(stream))

    assert "scheme: SCHEME_HTTP" in rendered
    assert 'host_path: "example.test:8080/a\\x00b"' in rendered
    assert "option_id: CURLOPT_FOLLOWLOCATION uint_value: 1" in rendered
    assert "option_id: CURLOPT_URL" not in rendered


def test_unsupported_url_is_reported_and_does_not_make_a_runnable_scenario() -> None:
    rendered = render_textproto(
        "seed", convert_stream(tlv(BaseType.TYPE_URL, b"ftp://example.test/file"))
    )

    assert "# skipped TLV CURLOPT_URL" in rendered
    assert "scheme:" not in rendered
    assert "host_path:" not in rendered


def test_duplicate_url_remains_non_runnable_like_the_legacy_input() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(
            tlv(BaseType.TYPE_URL, b"http://example.test/first")
            + tlv(BaseType.TYPE_URL, b"http://example.test/second")
        ),
    )

    assert "# skipped TLV CURLOPT_URL" in rendered
    assert "scheme:" not in rendered
    assert "host_path:" not in rendered


def test_option_absent_from_manifest_is_reported_instead_of_emitted() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(tlv(BaseType.TYPE_POSTFIELDSIZE_LARGE, b"\x00\x00\x00\x04")),
    )

    assert "# skipped TLV CURLOPT_POSTFIELDSIZE_LARGE" in rendered
    assert "option_id: CURLOPT_POSTFIELDSIZE_LARGE" not in rendered


def test_ssl_verifypeer_is_preserved_for_secure_proto_seeds() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(
            tlv(BaseType.TYPE_URL, b"https://127.0.0.1/")
            + tlv(BaseType.TYPE_SSL_VERIFYPEER, b"\x00\x00\x00\x01")
        ),
    )

    assert "scheme: SCHEME_HTTPS" in rendered
    assert "option_id: CURLOPT_SSL_VERIFYPEER bool_value: true" in rendered


def test_followlocation_preserves_new_non_boolean_modes() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(tlv(BaseType.TYPE_FOLLOWLOCATION, b"\x00\x00\x00\x03")),
    )

    assert "option_id: CURLOPT_FOLLOWLOCATION uint_value: 3" in rendered


def test_http09_allowed_uses_the_manifest_boolean_field() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(tlv(BaseType.TYPE_HTTP09_ALLOWED, b"\x00\x00\x00\x01")),
    )

    assert "option_id: CURLOPT_HTTP09_ALLOWED bool_value: true" in rendered
