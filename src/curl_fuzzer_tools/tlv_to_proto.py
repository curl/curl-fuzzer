#!/usr/bin/env python3
"""
Convert legacy TLV corpus entries into textproto scenarios.

The TLV corpora under ``corpora/curl_fuzzer_http/`` are binary streams of
``[type(2 bytes, big-endian)][length(4 bytes, big-endian)][value]`` records.
This script walks a corpus directory, parses each record with the shared
``curl_fuzzer_tools.corpus`` decoder, and emits a textproto ``Scenario`` for
every input, mapping an HTTP-relevant subset of TLV tags onto
``SetOption``/``Connection`` fields.

Textproto output is produced by string formatting so the tool does not need
the ``protobuf`` Python package. ``protoc --encode`` (a build-time dependency
anyway) turns the textproto into binary corpus entries later.

Unmapped tags are not silently dropped: they surface as ``# skipped TLV
<CURLOPT_NAME>`` comments in the output so reviewers can spot HTTP-irrelevant
data that appeared in the TLV corpus.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from curl_fuzzer_tools.corpus import BaseType, TLVDecoder

# Tag classification. The HTTP-relevant subset mirrors
# schemas/curl_fuzzer_supported_curlopts.txt; a TLV tag landing in one of
# these sets becomes a SetOption, with its CURLOPT name pulled straight
# from BaseType.TYPEMAP. Tags outside the sets are reported as skipped.
STRING_TAGS = frozenset(
    {
        BaseType.TYPE_URL,
        BaseType.TYPE_CUSTOMREQUEST,
        BaseType.TYPE_USERAGENT,
        BaseType.TYPE_POSTFIELDS,
        BaseType.TYPE_ACCEPT_ENCODING,
        BaseType.TYPE_REFERER,
    }
)

BOOL_TAGS = frozenset(
    {
        BaseType.TYPE_FOLLOWLOCATION,
        BaseType.TYPE_NOBODY,
        BaseType.TYPE_POST,
        BaseType.TYPE_OPTHEADER,
        BaseType.TYPE_FAILONERROR,
        BaseType.TYPE_AUTOREFERER,
        BaseType.TYPE_HTTPGET,
    }
)

UINT_TAGS = frozenset(
    {
        BaseType.TYPE_HTTP_VERSION,
        BaseType.TYPE_HTTP09_ALLOWED,
        BaseType.TYPE_MAXREDIRS,
        BaseType.TYPE_POSTFIELDSIZE_LARGE,
    }
)

RESPONSE_CHUNK_TAGS = frozenset(range(BaseType.TYPE_RSP1, BaseType.TYPE_RSP10 + 1))


@dataclass
class ProtoOutput:
    """Accumulated fields for a single Scenario textproto."""

    options: List[str] = field(default_factory=list)
    initial_response: Optional[bytes] = None
    response_chunks: List[tuple[int, bytes]] = field(default_factory=list)
    skipped: List[int] = field(default_factory=list)


def escape_bytes(value: bytes) -> str:
    """Produce a textproto-safe double-quoted byte string."""
    out: List[str] = ['"']
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


def render_string_option(tlv_type: int, value: bytes) -> str:
    return (
        f"options {{ option_id: {curlopt_name(tlv_type)} "
        f"string_value: {escape_bytes(value)} }}"
    )


def render_bool_option(tlv_type: int, value: bytes) -> str:
    # TLV booleans are 4-byte big-endian ints; non-zero is true.
    flag = bool(int.from_bytes(value, "big")) if value else False
    return (
        f"options {{ option_id: {curlopt_name(tlv_type)} "
        f"bool_value: {'true' if flag else 'false'} }}"
    )


def render_uint_option(tlv_type: int, value: bytes) -> str:
    if len(value) != 4:
        # TLV numeric values are always 4-byte big-endian per to_u32().
        raise ValueError(
            f"expected 4 bytes for {curlopt_name(tlv_type)}, got {len(value)}"
        )
    number = int.from_bytes(value, "big")
    return f"options {{ option_id: {curlopt_name(tlv_type)} uint_value: {number} }}"


def convert_stream(stream: bytes) -> ProtoOutput:
    """Decode a TLV corpus stream into accumulated Scenario fields."""
    out = ProtoOutput()
    for tlv in TLVDecoder(stream):
        if tlv.type == BaseType.TYPE_RSP0:
            out.initial_response = tlv.data
        elif tlv.type in RESPONSE_CHUNK_TAGS:
            out.response_chunks.append((tlv.type, tlv.data))
        elif tlv.type in STRING_TAGS:
            out.options.append(render_string_option(tlv.type, tlv.data))
        elif tlv.type in BOOL_TAGS:
            out.options.append(render_bool_option(tlv.type, tlv.data))
        elif tlv.type in UINT_TAGS:
            out.options.append(render_uint_option(tlv.type, tlv.data))
        else:
            out.skipped.append(tlv.type)
    return out


def render_textproto(source_name: str, data: ProtoOutput) -> str:
    """Serialise accumulated fields into a textproto Scenario string."""
    lines: List[str] = [f"# source: {source_name}"]
    for tag in data.skipped:
        label = BaseType.TYPEMAP.get(tag, f"0x{tag:02x}")
        lines.append(f"# skipped TLV {label}")
    lines.extend(data.options)

    connection_lines: List[str] = []
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


def iter_corpus_files(root: pathlib.Path) -> List[pathlib.Path]:
    result: List[pathlib.Path] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_file():
            continue
        if entry.name.startswith("."):
            continue
        if entry.suffix in {".swp", ".tmp"}:
            continue
        result.append(entry)
    return result


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "corpus_dir",
        type=pathlib.Path,
        help="Directory of TLV corpus inputs (e.g. corpora/curl_fuzzer_http).",
    )
    parser.add_argument(
        "output_dir",
        type=pathlib.Path,
        help="Directory to write .textproto files into.",
    )
    return parser.parse_args(argv)


def run(argv: List[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.corpus_dir.is_dir():
        print(f"error: corpus directory {args.corpus_dir} not found", file=sys.stderr)
        return 1
    args.output_dir.mkdir(parents=True, exist_ok=True)

    converted = 0
    for corpus_file in iter_corpus_files(args.corpus_dir):
        data = convert_stream(corpus_file.read_bytes())
        rendered = render_textproto(
            source_name=f"{args.corpus_dir.name}/{corpus_file.name}",
            data=data,
        )
        out_path = args.output_dir / f"{corpus_file.stem}.textproto"
        out_path.write_text(rendered)
        converted += 1
    print(f"converted {converted} TLV inputs to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
