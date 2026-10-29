#!/usr/bin/env python3
"""
Convert legacy TLV corpus entries into textproto scenarios.

Legacy TLV corpus inputs are binary streams of
``[type(2 bytes, big-endian)][length(4 bytes, big-endian)][value]`` records.
This script walks a corpus directory, parses each record with the shared
``curl_fuzzer_tools.corpus`` decoder, and emits a textproto ``Scenario`` for
each representable input while reporting rejected inputs. A reviewed subset
of TLV tags maps onto ``SetOption``/``Connection`` fields.

Textproto output is produced by string formatting so the tool does not need
the ``protobuf`` Python package. ``protoc --encode`` (a build-time dependency
anyway) turns the textproto into binary corpus entries later.

Unmapped tags are not silently dropped: they surface as ``# skipped TLV
<CURLOPT_NAME>`` comments in the output so reviewers can spot data outside
the converter's supported field set.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from dataclasses import dataclass, field

from curl_fuzzer_tools.corpus import BaseType, TLVDecoder

# Tag classification. The supported subset mirrors the typed fields in
# schemas/curl_fuzzer.proto's SetOption oneof; a TLV tag landing in one of
# these sets becomes a SetOption, with its CURLOPT identity pulled straight
# from BaseType.TYPEMAP. Tags outside the sets are reported as skipped.
STRING_TAGS = frozenset(
    {
        BaseType.TYPE_CUSTOMREQUEST,
        BaseType.TYPE_USERAGENT,
        BaseType.TYPE_POSTFIELDS,
        BaseType.TYPE_ACCEPT_ENCODING,
        BaseType.TYPE_REFERER,
        # Mail/credential options shared by SMTP (and the IMAP/POP3 lanes).
        BaseType.TYPE_USERNAME,
        BaseType.TYPE_PASSWORD,
        BaseType.TYPE_USERPWD,
        BaseType.TYPE_MAIL_FROM,
        BaseType.TYPE_MAIL_AUTH,
        BaseType.TYPE_LOGIN_OPTIONS,
        BaseType.TYPE_SASL_AUTHZID,
        BaseType.TYPE_XOAUTH2_BEARER,
    }
)

BOOL_TAGS = frozenset(
    {
        BaseType.TYPE_NOBODY,
        BaseType.TYPE_POST,
        BaseType.TYPE_OPTHEADER,
        BaseType.TYPE_FAILONERROR,
        BaseType.TYPE_AUTOREFERER,
        BaseType.TYPE_HTTPGET,
        BaseType.TYPE_SSL_VERIFYPEER,
        BaseType.TYPE_HTTP09_ALLOWED,
        BaseType.TYPE_SASL_IR,
    }
)

UINT_TAGS = frozenset(
    {
        BaseType.TYPE_FOLLOWLOCATION,
        BaseType.TYPE_HTTP_VERSION,
        BaseType.TYPE_MAXREDIRS,
    }
)

RESPONSE_CHUNK_TAGS = frozenset(range(BaseType.TYPE_RSP1, BaseType.TYPE_RSP10 + 1))

SCHEME_NAMES = {
    b"dict": "SCHEME_DICT",
    b"file": "SCHEME_FILE",
    b"ftp": "SCHEME_FTP",
    b"ftps": "SCHEME_FTPS",
    b"gopher": "SCHEME_GOPHER",
    b"gophers": "SCHEME_GOPHERS",
    b"http": "SCHEME_HTTP",
    b"https": "SCHEME_HTTPS",
    b"imap": "SCHEME_IMAP",
    b"imaps": "SCHEME_IMAPS",
    b"ipfs": "SCHEME_IPFS",
    b"ipns": "SCHEME_IPNS",
    b"ldap": "SCHEME_LDAP",
    b"ldaps": "SCHEME_LDAPS",
    b"mqtt": "SCHEME_MQTT",
    b"mqtts": "SCHEME_MQTTS",
    b"pop3": "SCHEME_POP3",
    b"pop3s": "SCHEME_POP3S",
    b"rtsp": "SCHEME_RTSP",
    b"smtp": "SCHEME_SMTP",
    b"smtps": "SCHEME_SMTPS",
    b"telnet": "SCHEME_TELNET",
    b"tftp": "SCHEME_TFTP",
    b"ws": "SCHEME_WS",
    b"wss": "SCHEME_WSS",
}


class ConversionError(ValueError):
    """Raised when a legacy input cannot be represented faithfully."""


@dataclass
class ProtoOutput:
    """Accumulated fields for a single Scenario textproto."""

    scheme: str | None = None
    host_path: bytes | None = None
    options: list[str] = field(default_factory=list)
    mail_rcpt: list[bytes] = field(default_factory=list)
    upload_data: bytes | None = None
    initial_response: bytes | None = None
    response_chunks: list[tuple[int, bytes]] = field(default_factory=list)
    skipped: list[int] = field(default_factory=list)


def escape_bytes(value: bytes) -> str:
    """Produce a textproto-safe double-quoted byte string."""
    out: list[str] = ['"']
    for byte in value:
        if byte == 0x5C:  # backslash
            out.append("\\\\")
        elif byte == 0x22:  # double quote
            out.append('\\"')
        elif byte == 0x0A:
            out.append("\\n")
        elif byte == 0x0D:
            out.append("\\r")
        elif byte == 0x09:
            out.append("\\t")
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    out.append('"')
    return "".join(out)


def curlopt_name(tlv_type: int) -> str:
    """Look up the CURLOPT name for a TLV type, or raise if unknown."""
    name = BaseType.TYPEMAP.get(tlv_type)
    if name is None or not name.startswith("CURLOPT_"):
        raise KeyError(f"TLV type {tlv_type} has no CURLOPT_ mapping")
    return name


def curlopt_field_name(tlv_type: int) -> str:
    """Return the typed SetOption field associated with a legacy TLV tag."""
    return curlopt_name(tlv_type).removeprefix("CURLOPT_").lower()


def render_string_option(tlv_type: int, value: bytes) -> str:
    return f"options {{ {curlopt_field_name(tlv_type)}: {escape_bytes(value)} }}"


def decode_u32(tlv_type: int, value: bytes) -> int:
    """Decode the exact-width integer representation used by legacy TLVs."""
    if len(value) != 4:
        raise ConversionError(
            f"expected 4 bytes for {curlopt_name(tlv_type)}, got {len(value)}"
        )
    return int.from_bytes(value, "big")


def render_bool_option(tlv_type: int, value: bytes) -> str:
    # TLV booleans are 4-byte big-endian ints; non-zero is true.
    flag = bool(decode_u32(tlv_type, value))
    return (
        f"options {{ {curlopt_field_name(tlv_type)}: {'true' if flag else 'false'} }}"
    )


def render_uint_option(tlv_type: int, value: bytes) -> str:
    number = decode_u32(tlv_type, value)
    return f"options {{ {curlopt_field_name(tlv_type)}: {number} }}"


def record_option(tlv_type: int, seen_option_names: set[str]) -> None:
    """Reject repeated scalar/string options like the legacy parser does."""
    option_name = curlopt_name(tlv_type)
    if option_name in seen_option_names:
        raise ConversionError(f"duplicate {option_name}")
    seen_option_names.add(option_name)


def convert_stream(stream: bytes) -> ProtoOutput:
    """Decode a TLV corpus stream into accumulated Scenario fields."""
    out = ProtoOutput()
    url_seen = False
    upload_seen = False
    seen_option_names: set[str] = set()
    for tlv in TLVDecoder(stream):
        if len(tlv.data) != tlv.length:
            label = BaseType.TYPEMAP.get(tlv.type, f"0x{tlv.type:02x}")
            raise ConversionError(
                f"truncated TLV {label}: declared {tlv.length} bytes, "
                f"only {len(tlv.data)} available"
            )
        if tlv.type == BaseType.TYPE_URL:
            if url_seen:
                raise ConversionError("duplicate CURLOPT_URL")
            url_seen = True
            # RunScenario owns CURLOPT_URL: it composes it from these two
            # fields and deliberately does not expose CURLOPT_URL through the
            # typed SetOption surface. Preserve all bytes after the separator
            # verbatim so malformed authorities and paths remain fuzzable.
            scheme, separator, host_path = tlv.data.partition(b"://")
            scheme_name = SCHEME_NAMES.get(scheme.lower())
            if separator and scheme_name is not None and host_path:
                out.scheme = scheme_name
                out.host_path = host_path
            else:
                # Unsupported schemes cannot be represented by the current
                # proto schema. Make that loss visible instead of emitting an
                # option that protoc or RunScenario will ignore.
                out.skipped.append(tlv.type)
        elif tlv.type == BaseType.TYPE_RSP0:
            out.initial_response = tlv.data
        elif tlv.type in RESPONSE_CHUNK_TAGS:
            out.response_chunks.append((tlv.type, tlv.data))
        elif tlv.type == BaseType.TYPE_MAIL_RECIPIENT:
            # CURLOPT_MAIL_RCPT is an slist; the proto schema exposes it as the
            # repeated mail_rcpt field. One TLV record is one recipient.
            out.mail_rcpt.append(tlv.data)
        elif tlv.type == BaseType.TYPE_UPLOAD1:
            if upload_seen:
                raise ConversionError("duplicate TYPE_UPLOAD1")
            upload_seen = True
            # The legacy upload record is the message body served through the
            # read callback (CURLOPT_UPLOAD + CURLOPT_INFILESIZE_LARGE). The
            # proto runner drives uploads from the upload script instead.
            out.upload_data = tlv.data
            out.options.append("options { upload: true }")
            out.options.append(f"options {{ infilesize_large: {len(tlv.data)} }}")
        elif tlv.type in STRING_TAGS:
            record_option(tlv.type, seen_option_names)
            out.options.append(render_string_option(tlv.type, tlv.data))
        elif tlv.type in BOOL_TAGS:
            record_option(tlv.type, seen_option_names)
            out.options.append(render_bool_option(tlv.type, tlv.data))
        elif tlv.type in UINT_TAGS:
            record_option(tlv.type, seen_option_names)
            out.options.append(render_uint_option(tlv.type, tlv.data))
        else:
            out.skipped.append(tlv.type)
    return out


def render_textproto(source_name: str, data: ProtoOutput) -> str:
    """Serialise accumulated fields into a textproto Scenario string."""
    lines: list[str] = [f"# source: {source_name}"]
    for tag in data.skipped:
        label = BaseType.TYPEMAP.get(tag, f"0x{tag:02x}")
        lines.append(f"# skipped TLV {label}")
    if data.scheme is not None:
        lines.append(f"scheme: {data.scheme}")
    if data.host_path is not None:
        lines.append(f"host_path: {escape_bytes(data.host_path)}")
    lines.extend(data.options)

    lines.extend(f"mail_rcpt: {escape_bytes(rcpt)}" for rcpt in data.mail_rcpt)
    if data.upload_data is not None:
        lines.append("upload {")
        lines.append(f"  data: {escape_bytes(data.upload_data)}")
        lines.append("}")

    connection_lines: list[str] = []
    if data.initial_response is not None:
        connection_lines.append(
            f"  initial_response: {escape_bytes(data.initial_response)}"
        )
    for _, chunk in sorted(data.response_chunks):
        connection_lines.append(f"  on_readable: {escape_bytes(chunk)}")
    if connection_lines:
        lines.append("connection {")
        lines.extend(connection_lines)
        lines.append("}")

    return "\n".join(lines) + "\n"


def iter_corpus_files(root: pathlib.Path) -> list[pathlib.Path]:
    result: list[pathlib.Path] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_file():
            continue
        if entry.name.startswith("."):
            continue
        if entry.suffix in {".swp", ".tmp"}:
            continue
        result.append(entry)
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "corpus_dir",
        type=pathlib.Path,
        help="Directory of TLV corpus inputs (e.g. corpora/curl_fuzzer).",
    )
    parser.add_argument(
        "output_dir",
        type=pathlib.Path,
        help="Directory to write .textproto files into.",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.corpus_dir.is_dir():
        print(f"error: corpus directory {args.corpus_dir} not found", file=sys.stderr)
        return 1
    args.output_dir.mkdir(parents=True, exist_ok=True)

    converted = 0
    rejected = 0
    for corpus_file in iter_corpus_files(args.corpus_dir):
        out_path = args.output_dir / f"{corpus_file.stem}.textproto"
        try:
            data = convert_stream(corpus_file.read_bytes())
            if data.scheme is None or data.host_path is None:
                raise ConversionError(
                    "input does not contain exactly one valid supported URL"
                )
            rendered = render_textproto(
                source_name=f"{args.corpus_dir.name}/{corpus_file.name}",
                data=data,
            )
        except ConversionError as error:
            out_path.unlink(missing_ok=True)
            print(f"rejected {corpus_file}: {error}", file=sys.stderr)
            rejected += 1
            continue
        out_path.write_text(rendered)
        converted += 1
    print(f"converted {converted} TLV inputs to {args.output_dir}; rejected {rejected}")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(run())
