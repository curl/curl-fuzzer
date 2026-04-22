#!/usr/bin/env python3
"""
Decode a binary curl_fuzzer_proto corpus entry to textproto.

Wraps ``protoc --decode curl.fuzzer.proto.Scenario`` so crash inputs from the
libprotobuf-mutator fuzzer (e.g. ``crash-<sha1>`` files under oss-fuzz ``out``
directories) can be inspected as human-readable textproto without writing one
off decoders.

Resolves the expanded ``.proto`` (the one with CurlOptionId populated) in this
order: ``--proto-file`` flag, ``$CURL_FUZZER_PROTO`` env var, the in-tree
``build/schemas/curl_fuzzer.proto`` next to this checkout. Falls back to
``protoc --decode_raw`` (wire-level field numbers) if no proto file is
available.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
from typing import List, Optional

SCENARIO_MESSAGE = "curl.fuzzer.proto.Scenario"


def find_proto_file(explicit: Optional[pathlib.Path]) -> Optional[pathlib.Path]:
    """Resolve the expanded curl_fuzzer.proto, or None if not found."""
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"--proto-file {explicit} does not exist")
        return explicit
    env = os.environ.get("CURL_FUZZER_PROTO")
    if env:
        path = pathlib.Path(env)
        if path.is_file():
            return path
    # Walk up from this file looking for build/schemas/curl_fuzzer.proto.
    here = pathlib.Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "build" / "schemas" / "curl_fuzzer.proto"
        if candidate.is_file():
            return candidate
    return None


def decode(corpus_file: pathlib.Path, proto_file: Optional[pathlib.Path]) -> str:
    """Return the textproto decoding of ``corpus_file``."""
    data = corpus_file.read_bytes()
    if proto_file is not None:
        cmd = [
            "protoc",
            f"--proto_path={proto_file.parent}",
            f"--decode={SCENARIO_MESSAGE}",
            proto_file.name,
        ]
    else:
        cmd = ["protoc", "--decode_raw"]
    result = subprocess.run(cmd, input=data, capture_output=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"protoc failed ({result.returncode}): {stderr}")
    return result.stdout.decode("utf-8", errors="replace")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        type=pathlib.Path,
        help="Binary corpus entry (e.g. an oss-fuzz crash-<sha1> file).",
    )
    parser.add_argument(
        "--proto-file",
        type=pathlib.Path,
        default=None,
        help=(
            "Path to the expanded curl_fuzzer.proto (with CurlOptionId body "
            "populated). Default: auto-detect in build/schemas/, or fall back "
            "to protoc --decode_raw."
        ),
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Force protoc --decode_raw even if an expanded proto is available.",
    )
    return parser.parse_args(argv)


def run(argv: List[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.input.is_file():
        print(f"error: {args.input} does not exist", file=sys.stderr)
        return 1

    proto_file = None if args.raw else find_proto_file(args.proto_file)
    if not args.raw and proto_file is None:
        print(
            "warning: no expanded curl_fuzzer.proto found; falling back to "
            "protoc --decode_raw (field numbers only). Build the project "
            "once or pass --proto-file to get named fields.",
            file=sys.stderr,
        )

    sys.stdout.write(decode(args.input, proto_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
