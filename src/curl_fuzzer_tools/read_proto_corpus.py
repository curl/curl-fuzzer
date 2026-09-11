#!/usr/bin/env python3
"""
Decode a binary curl_fuzzer_proto corpus entry to textproto.

Wraps ``protoc --decode curl.fuzzer.proto.Scenario`` so crash inputs from the
libprotobuf-mutator fuzzer (e.g. ``crash-<sha1>`` files under oss-fuzz ``out``
directories) can be inspected as human-readable textproto without writing one
off decoders.

Resolves the complete ``.proto`` in this order: ``--proto-file`` flag,
``$CURL_FUZZER_PROTO`` env var, the checked-in
``schemas/curl_fuzzer.proto`` next to this checkout, then the staged
``build/schemas/curl_fuzzer.proto``. Falls back to ``protoc --decode_raw``
(wire-level field numbers) if no proto file is available.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys

SCENARIO_MESSAGE = "curl.fuzzer.proto.Scenario"


def find_proto_file(explicit: pathlib.Path | None) -> pathlib.Path | None:
    """Resolve curl_fuzzer.proto, or None if no usable schema is found."""
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"--proto-file {explicit} does not exist")
        return explicit
    env = os.environ.get("CURL_FUZZER_PROTO")
    if env:
        path = pathlib.Path(env)
        if path.is_file():
            return path
    # Prefer the authoritative checked-in schema so a stale local build copy
    # cannot affect decoding. The staged copy remains useful in distributions
    # such as the reproduction image, which do not contain the source tree.
    here = pathlib.Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "schemas" / "curl_fuzzer.proto"
        if candidate.is_file():
            return candidate
    for ancestor in here.parents:
        candidate = ancestor / "build" / "schemas" / "curl_fuzzer.proto"
        if candidate.is_file():
            return candidate
    return None


def decode(corpus_file: pathlib.Path, proto_file: pathlib.Path | None) -> str:
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


def parse_args(argv: list[str]) -> argparse.Namespace:
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
            "Path to curl_fuzzer.proto. Default: auto-detect the checked-in "
            "schema or staged build copy, or fall back to protoc --decode_raw."
        ),
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Force protoc --decode_raw even if a schema is available.",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.input.is_file():
        print(f"error: {args.input} does not exist", file=sys.stderr)
        return 1

    proto_file = None if args.raw else find_proto_file(args.proto_file)
    if not args.raw and proto_file is None:
        print(
            "warning: no curl_fuzzer.proto found; falling back to "
            "protoc --decode_raw (field numbers only). Run from a source "
            "checkout or pass --proto-file to get named fields.",
            file=sys.stderr,
        )

    sys.stdout.write(decode(args.input, proto_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
