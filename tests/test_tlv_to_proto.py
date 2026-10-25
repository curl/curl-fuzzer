from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from google.protobuf import descriptor_pb2

from curl_fuzzer_tools.corpus import BaseType
from curl_fuzzer_tools.schema_eligibility import FieldRule
from curl_fuzzer_tools.tlv_to_proto import (
    BOOL_TAGS,
    SCHEME_NAMES,
    STRING_TAGS,
    UINT_TAGS,
    ConversionError,
    convert_stream,
    curlopt_field_name,
    curlopt_name,
    render_textproto,
    run,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


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
    assert "options { followlocation: 1 }" in rendered
    assert "options { url:" not in rendered


def test_unsupported_url_is_reported_without_populating_runner_fields() -> None:
    rendered = render_textproto(
        "seed", convert_stream(tlv(BaseType.TYPE_URL, b"rtmp://example.test/stream"))
    )

    assert "# skipped TLV CURLOPT_URL" in rendered
    assert "scheme:" not in rendered
    assert "host_path:" not in rendered


@pytest.mark.parametrize(("scheme", "enum_name"), sorted(SCHEME_NAMES.items()))
def test_every_migrated_url_scheme_is_recognized(scheme: bytes, enum_name: str) -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(tlv(BaseType.TYPE_URL, scheme + b"://example.test/path")),
    )

    assert f"scheme: {enum_name}" in rendered
    assert 'host_path: "example.test/path"' in rendered
    assert "# skipped TLV CURLOPT_URL" not in rendered


def test_url_scheme_mapping_covers_every_structured_scheme() -> None:
    schema = (REPO_ROOT / "schemas" / "curl_fuzzer.proto").read_text()
    scheme_enum = re.search(
        r"enum Scheme \{(?P<body>.*?)^\}", schema, re.MULTILINE | re.DOTALL
    )
    assert scheme_enum is not None
    schema_schemes = set(
        re.findall(
            r"^\s+(SCHEME_[A-Z0-9_]+)\s*=",
            scheme_enum.group("body"),
            re.MULTILINE,
        )
    )
    schema_schemes.remove("SCHEME_UNSPECIFIED")

    assert set(SCHEME_NAMES.values()) == schema_schemes


def test_duplicate_url_is_rejected() -> None:
    with pytest.raises(ConversionError, match="duplicate CURLOPT_URL"):
        convert_stream(
            tlv(BaseType.TYPE_URL, b"http://example.test/first")
            + tlv(BaseType.TYPE_URL, b"http://example.test/second")
        )


def test_option_absent_from_manifest_is_reported_instead_of_emitted() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(tlv(BaseType.TYPE_POSTFIELDSIZE_LARGE, b"\x00\x00\x00\x04")),
    )

    assert "# skipped TLV CURLOPT_POSTFIELDSIZE_LARGE" in rendered
    assert "options { postfieldsize_large:" not in rendered


def test_ssl_verifypeer_is_preserved_for_secure_proto_seeds() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(
            tlv(BaseType.TYPE_URL, b"https://127.0.0.1/")
            + tlv(BaseType.TYPE_SSL_VERIFYPEER, b"\x00\x00\x00\x01")
        ),
    )

    assert "scheme: SCHEME_HTTPS" in rendered
    assert "options { ssl_verifypeer: true }" in rendered


def test_followlocation_preserves_new_non_boolean_modes() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(tlv(BaseType.TYPE_FOLLOWLOCATION, b"\x00\x00\x00\x03")),
    )

    assert "options { followlocation: 3 }" in rendered


def test_http09_allowed_uses_the_manifest_boolean_field() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(tlv(BaseType.TYPE_HTTP09_ALLOWED, b"\x00\x00\x00\x01")),
    )

    assert "options { http09_allowed: true }" in rendered


@pytest.mark.parametrize("tag", sorted(BOOL_TAGS | UINT_TAGS), ids=curlopt_name)
@pytest.mark.parametrize("value", [b"", b"\x00" * 3, b"\x00" * 5])
def test_numeric_options_require_exactly_four_bytes(tag: int, value: bytes) -> None:
    with pytest.raises(ConversionError, match=f"expected 4 bytes.*got {len(value)}"):
        convert_stream(tlv(tag, value))


def test_declared_tlv_length_cannot_exceed_available_data() -> None:
    truncated = struct.pack(">HI", BaseType.TYPE_SASL_IR, 5) + b"\x00" * 4

    with pytest.raises(
        ConversionError,
        match=r"truncated TLV CURLOPT_SASL_IR: declared 5 bytes, only 4 available",
    ):
        convert_stream(truncated)


@pytest.mark.parametrize(
    "tag",
    sorted(STRING_TAGS | BOOL_TAGS | UINT_TAGS),
    ids=curlopt_name,
)
def test_duplicate_scalar_and_string_options_are_rejected(tag: int) -> None:
    value = b"value" if tag in STRING_TAGS else b"\x00\x00\x00\x01"
    with pytest.raises(ConversionError, match=f"duplicate {curlopt_name(tag)}"):
        convert_stream(tlv(tag, value) + tlv(tag, value))


def test_duplicate_upload_body_is_rejected() -> None:
    with pytest.raises(ConversionError, match="duplicate TYPE_UPLOAD1"):
        convert_stream(
            tlv(BaseType.TYPE_UPLOAD1, b"first") + tlv(BaseType.TYPE_UPLOAD1, b"second")
        )


@pytest.mark.parametrize(
    "stream",
    [
        b"",
        tlv(BaseType.TYPE_URL, b"not-a-url"),
        tlv(BaseType.TYPE_URL, b"rtmp://example.test/path"),
        (
            tlv(BaseType.TYPE_URL, b"http://example.test/first")
            + tlv(BaseType.TYPE_URL, b"http://example.test/second")
        ),
    ],
    ids=["absent", "malformed", "unsupported", "duplicate"],
)
def test_run_rejects_inputs_without_exactly_one_supported_url(
    tmp_path: Path, stream: bytes
) -> None:
    corpus_dir = tmp_path / "corpus"
    output_dir = tmp_path / "output"
    corpus_dir.mkdir()
    (corpus_dir / "seed").write_bytes(stream)

    assert run([str(corpus_dir), str(output_dir)]) == 1
    assert not (output_dir / "seed.textproto").exists()


def test_run_removes_stale_rejected_output_and_continues(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_dir = tmp_path / "corpus"
    output_dir = tmp_path / "output"
    corpus_dir.mkdir()
    output_dir.mkdir()
    truncated_option = struct.pack(">HI", BaseType.TYPE_SASL_IR, 5) + b"\x00" * 4
    (corpus_dir / "a-bad.seed").write_bytes(
        tlv(BaseType.TYPE_URL, b"smtp://example.test/") + truncated_option
    )
    (corpus_dir / "z-good.seed").write_bytes(
        tlv(BaseType.TYPE_URL, b"smtp://example.test/")
    )
    stale_path = output_dir / "a-bad.textproto"
    stale_path.write_text("stale output")

    assert run([str(corpus_dir), str(output_dir)]) == 1

    captured = capsys.readouterr()
    assert "rejected" in captured.err
    assert "a-bad.seed" in captured.err
    assert "truncated TLV CURLOPT_SASL_IR" in captured.err
    assert "converted 1 TLV inputs" in captured.out
    assert "rejected 1" in captured.out
    assert not stale_path.exists()
    assert "scheme: SCHEME_SMTP" in (output_dir / "z-good.textproto").read_text()


def test_run_returns_success_when_all_inputs_convert(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_dir = tmp_path / "corpus"
    output_dir = tmp_path / "output"
    corpus_dir.mkdir()
    (corpus_dir / "seed").write_bytes(tlv(BaseType.TYPE_URL, b"smtp://example.test/"))

    assert run([str(corpus_dir), str(output_dir)]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert "converted 1 TLV inputs" in captured.out
    assert "rejected 0" in captured.out
    assert (output_dir / "seed.textproto").exists()


def test_mail_authentication_options_preserve_their_value_kinds() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(
            tlv(BaseType.TYPE_LOGIN_OPTIONS, b"AUTH=PLAIN")
            + tlv(BaseType.TYPE_MAIL_AUTH, b"sender@example.test")
            + tlv(BaseType.TYPE_SASL_AUTHZID, b"authorization-id")
            + tlv(BaseType.TYPE_SASL_IR, b"\x00\x00\x00\x01")
        ),
    )

    assert 'options { login_options: "AUTH=PLAIN" }' in rendered
    assert 'options { mail_auth: "sender@example.test" }' in rendered
    assert 'options { sasl_authzid: "authorization-id" }' in rendered
    assert "options { sasl_ir: true }" in rendered


def _all_converter_option_textproto() -> str:
    stream = bytearray()
    for tag in sorted(STRING_TAGS):
        stream.extend(tlv(tag, b"value"))
    for tag in sorted(BOOL_TAGS):
        stream.extend(tlv(tag, b"\x00\x00\x00\x01"))
    for tag in sorted(UINT_TAGS):
        stream.extend(tlv(tag, b"\x00\x00\x00\x02"))
    return render_textproto("all-options", convert_stream(bytes(stream)))


def test_every_converter_option_exists_with_its_declared_typed_field(
    active_option_fields: dict[str, FieldRule],
) -> None:
    expected_types = (
        (STRING_TAGS, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES),
        (BOOL_TAGS, descriptor_pb2.FieldDescriptorProto.TYPE_BOOL),
        (UINT_TAGS, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64),
    )
    for tags, proto_type in expected_types:
        for tag in tags:
            name = curlopt_name(tag)
            field = active_option_fields[name]
            assert field.name == curlopt_field_name(tag)
            assert field.proto_type == proto_type
            if proto_type == descriptor_pb2.FieldDescriptorProto.TYPE_BYTES:
                value = b"value"
            else:
                value = b"\x00\x00\x00\x01"
            rendered = render_textproto("option", convert_stream(tlv(tag, value)))
            assert f"options {{ {field.name}:" in rendered
            assert f"# skipped TLV {name}" not in rendered


@pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc unavailable")
def test_every_converter_option_encodes_with_the_checked_in_schema() -> None:
    schema_dir = REPO_ROOT / "schemas"
    result = subprocess.run(
        [
            "protoc",
            "--encode=curl.fuzzer.proto.Scenario",
            "curl_fuzzer.proto",
        ],
        cwd=schema_dir,
        input=_all_converter_option_textproto().encode(),
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout


def test_smtp_upload_translates_to_mail_rcpt_and_upload_script() -> None:
    rendered = render_textproto(
        "seed",
        convert_stream(
            tlv(BaseType.TYPE_URL, b"smtp://127.0.0.1:9005/900")
            + tlv(BaseType.TYPE_RSP0, b"220 smtp.test ESMTP\r\n")
            + tlv(BaseType.TYPE_RSP1, b"250 OK\r\n")
            + tlv(BaseType.TYPE_MAIL_FROM, b"sender@example.com")
            + tlv(BaseType.TYPE_MAIL_RECIPIENT, b"recipient@example.com")
            + tlv(BaseType.TYPE_UPLOAD1, b"body")
        ),
    )

    assert "scheme: SCHEME_SMTP" in rendered
    assert 'host_path: "127.0.0.1:9005/900"' in rendered
    assert 'options { mail_from: "sender@example.com" }' in rendered
    assert 'mail_rcpt: "recipient@example.com"' in rendered
    assert "options { upload: true }" in rendered
    assert "options { infilesize_large: 4 }" in rendered
    assert "upload {" in rendered and 'data: "body"' in rendered
    assert 'initial_response: "220 smtp.test ESMTP\\r\\n"' in rendered
    assert 'on_readable: "250 OK\\r\\n"' in rendered


def test_smtps_url_translates_to_the_implicit_tls_scheme() -> None:
    rendered = render_textproto(
        "seed", convert_stream(tlv(BaseType.TYPE_URL, b"smtps://127.0.0.1/"))
    )

    assert "scheme: SCHEME_SMTPS" in rendered
    assert 'host_path: "127.0.0.1/"' in rendered


def test_imaps_url_translates_to_the_implicit_tls_scheme() -> None:
    rendered = render_textproto(
        "seed", convert_stream(tlv(BaseType.TYPE_URL, b"imaps://127.0.0.1/"))
    )

    assert "scheme: SCHEME_IMAPS" in rendered
    assert 'host_path: "127.0.0.1/"' in rendered


def test_pop3s_url_translates_to_the_implicit_tls_scheme() -> None:
    rendered = render_textproto(
        "seed", convert_stream(tlv(BaseType.TYPE_URL, b"pop3s://127.0.0.1/"))
    )

    assert "scheme: SCHEME_POP3S" in rendered
    assert 'host_path: "127.0.0.1/"' in rendered
