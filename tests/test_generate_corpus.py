"""Tests for coverage-oriented options in the legacy corpus generator."""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "src" / "curl_fuzzer_tools" / "generate_corpus.py"


def _decode_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    """Decode just enough of the stable TLV wire format to inspect output."""
    records: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tlv_type, length = struct.unpack_from(">HI", data, offset)
        offset += 6
        records.append((tlv_type, data[offset : offset + length]))
        offset += length
    assert offset == len(data)
    return records


def test_ssl_verifypeer_can_be_seeded_explicitly(tmp_path: Path) -> None:
    """Keep trust-store coverage seedable while verification defaults off."""
    output = tmp_path / "verify-peer.tlv"
    subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--output",
            str(output),
            "--url",
            "wss://127.0.0.1/",
            "--curl_test_dir",
            str(tmp_path),
            "--ssl-verifypeer",
            "1",
        ],
        check=True,
        cwd=REPO_ROOT,
    )

    assert _decode_tlvs(output.read_bytes()) == [
        (1, b"wss://127.0.0.1/"),
        (214, b"\x00\x00\x00\x01"),
    ]
