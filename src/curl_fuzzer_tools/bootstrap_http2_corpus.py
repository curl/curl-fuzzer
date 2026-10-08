"""Bootstrap the native HTTP/2 corpus from historical Scenario inputs."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TypedDict

from curl_fuzzer_tools.fuzzer_corpus import (
    CorpusError,
    CorpusSnapshotBuilder,
    sha256_file,
)
from curl_fuzzer_tools.read_proto_corpus import decode, find_proto_file

# Match top-level SetOption blocks in protoc's canonical text output. Byte
# strings have escaped newlines; nested unknown-field groups are indented.
_OPTIONS = re.compile(r"^options \{\n(.*?)^\}", re.MULTILINE | re.DOTALL)
_VERSION_ID = re.compile(r"^  option_id: CURLOPT_HTTP_VERSION$", re.MULTILINE)
_PRIOR_KNOWLEDGE = re.compile(r"^  uint_value: 5$", re.MULTILINE)
_MAX_OPTIONS = 64  # proto_fuzzer::scenario_limits::kMaxOptions
_SELECTOR = "last HTTP_VERSION in first 64 options is uint_value=5"


class BootstrapManifest(TypedDict):
    """Stable identities and byte-level selection provenance for one handoff."""

    schema_version: int
    selector: str
    proto_schema_sha256: str
    protoc_version: str
    source: dict[str, object]
    selected: dict[str, object]
    selected_sha256: list[str]
    rejected_sha256: list[str]


def selects_prior_knowledge(text: str) -> bool:
    """
    Select an explicit final prior-knowledge setting in the option prefix.

    This conservative bootstrap predicate excludes conflicting later settings
    and ignored suffix options. It does not emulate curl's setopt validation or
    a target's normalization; original bytes are always retained.
    """
    selected = False
    for index, option in enumerate(_OPTIONS.findall(text)):
        if index >= _MAX_OPTIONS:
            break
        if _VERSION_ID.search(option):
            selected = _PRIOR_KNOWLEDGE.search(option) is not None
    return selected


def _atomic_write(path: Path, data: bytes, staging_dir: Path) -> None:
    """Publish a complete file, keeping interrupted writes outside replay dirs."""
    pending: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=staging_dir, prefix=f".{path.name}.", delete=False
        ) as output:
            pending = Path(output.name)
            output.write(data)
        os.replace(pending, path)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


def bootstrap(
    sources: Sequence[Path],
    destination: Path,
    manifest: Path,
    proto_file: Path,
    output_zip: Path | None = None,
) -> BootstrapManifest:
    """Add byte-exact selected inputs and write a reproducible handoff manifest."""
    protoc = shutil.which("protoc")
    if protoc is None:
        raise CorpusError("protoc is required; install protobuf-compiler")
    if not sources:
        raise CorpusError("no historical corpus found; download public corpora first")
    corpus_dirs = [destination.resolve(), *(p.resolve() for p in sources if p.is_dir())]
    for artifact in (manifest, output_zip):
        if artifact is not None and any(
            artifact.resolve().is_relative_to(root) for root in corpus_dirs
        ):
            raise CorpusError("manifest and ZIP must be outside corpus directories")
        if artifact is not None and artifact.resolve() in {
            source.resolve() for source in sources
        }:
            raise CorpusError("manifest and ZIP must not overwrite corpus sources")
    if output_zip is not None and output_zip.resolve() == manifest.resolve():
        raise CorpusError("manifest and ZIP must have different paths")
    if output_zip is not None and output_zip.exists():
        raise CorpusError(f"corpus archive already exists: {output_zip}")

    with tempfile.TemporaryDirectory(prefix="curl-http2-bootstrap-") as temporary:
        root = Path(temporary)
        # Validate the named schema and its append-only field/enum identities
        # before classifying individual parse failures. Scenario.options=3,
        # SetOption.option_id=1 (HTTP_VERSION=84), and uint_value=11.
        probe = root / "probe"
        probe.write_bytes(b"\x1a\x04\x08\x54\x58\x05")
        if not selects_prior_knowledge(decode(probe, proto_file)):
            raise CorpusError("schema does not describe the HTTP_VERSION selector")
        original = CorpusSnapshotBuilder(root / "original")
        selected = CorpusSnapshotBuilder(root / "selected")
        for source in sources:
            original.add(source)
        if not original.hashes:
            raise CorpusError("historical corpus is empty")
        rejected: list[str] = []
        for digest in sorted(original.hashes):
            source = original.destination / digest
            try:
                text = decode(source, proto_file)
            except RuntimeError:
                rejected.append(digest)
                continue
            if selects_prior_knowledge(text):
                selected.add(source)

        # Native/public entries are additive. Check every collision before
        # copying, and never delete or overwrite unrelated native inputs.
        for digest in selected.hashes:
            existing = destination / digest
            if existing.exists() and sha256_file(existing) != digest:
                raise CorpusError(f"destination hash collision: {existing}")
        destination.mkdir(parents=True, exist_ok=True)
        for digest in sorted(selected.hashes):
            target = destination / digest
            if not target.exists():
                _atomic_write(
                    target,
                    (selected.destination / digest).read_bytes(),
                    destination.parent,
                )
        if output_zip is not None:
            output_zip.parent.mkdir(parents=True, exist_ok=True)
            selected.write_zip(output_zip)

        document: BootstrapManifest = {
            "schema_version": 1,
            "selector": _SELECTOR,
            "proto_schema_sha256": sha256_file(proto_file),
            "protoc_version": subprocess.check_output(
                [protoc, "--version"], text=True
            ).strip(),
            "source": {
                key: value
                for key, value in original.metadata().items()
                if key != "sources"
            },
            "selected": {
                key: value
                for key, value in selected.metadata().items()
                if key != "sources"
            },
            "selected_sha256": sorted(selected.hashes),
            "rejected_sha256": rejected,
        }
        manifest.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            manifest,
            (json.dumps(document, indent=2) + "\n").encode(),
            manifest.parent,
        )
    return document


def main(argv: Sequence[str] | None = None) -> int:
    """Run the installed historical HTTP/2 corpus bootstrap command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--public-corpus-root", type=Path, default=Path("ossfuzz_corpus")
    )
    parser.add_argument(
        "--source",
        type=Path,
        action="append",
        help="Directory, ZIP, or input; repeatable.",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--output-zip", type=Path, help="Optional one-time upload archive."
    )
    parser.add_argument("--proto-file", type=Path)
    args = parser.parse_args(argv)
    public = args.public_corpus_root
    sources = args.source
    if sources is None:
        sources = [
            path
            for name in ("curl_fuzzer_proto", "curl_fuzzer_proto_http")
            if (path := public / name).is_dir()
        ]
    destination = args.output_dir or public / "curl_fuzzer_proto_http2"
    manifest = args.manifest or public / ".manifests" / "http2-bootstrap.json"
    try:
        proto_file = find_proto_file(args.proto_file)
        if proto_file is None:
            raise CorpusError("curl_fuzzer.proto is required; pass --proto-file")
        result = bootstrap(sources, destination, manifest, proto_file, args.output_zip)
    except (CorpusError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"HTTP/2 bootstrap: {len(result['selected_sha256'])} selected, "
        f"{len(result['rejected_sha256'])} malformed inputs skipped; manifest: {manifest}"
    )
    return 0
