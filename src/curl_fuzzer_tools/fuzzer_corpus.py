"""Discover corpus sources and build reproducible measurement snapshots."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import IO

COMPATIBLE_CORPUS_TARGETS = {
    "curl_fuzzer_proto_http2": ("curl_fuzzer_proto_https_h2",),
    "curl_fuzzer_proto_https_gnutls": ("curl_fuzzer_proto_https",),
    "curl_fuzzer_proto_https_mbedtls": ("curl_fuzzer_proto_https",),
    "curl_fuzzer_proto_http3": ("curl_fuzzer_proto_https",),
}
HISTORICAL_PROTO_CORPUS_TARGETS = frozenset(
    {
        "curl_fuzzer_proto_http",
        "curl_fuzzer_proto_http_deep",
        "curl_fuzzer_proto_https",
        "curl_fuzzer_proto_https_gnutls",
        "curl_fuzzer_proto_https_mbedtls",
        "curl_fuzzer_proto_http3",
        "curl_fuzzer_proto_ws",
        "curl_fuzzer_proto_wss",
        "curl_fuzzer_proto_telnet",
        "curl_fuzzer_proto_ftp",
        "curl_fuzzer_proto_tftp",
        "curl_fuzzer_proto_api",
        "curl_fuzzer_proto_multi",
        "curl_fuzzer_proto_timing",
    }
)


class CorpusError(RuntimeError):
    """Raised for invalid or unavailable corpus inputs."""


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CorpusSnapshotBuilder:
    """Build a deduplicated, content-addressed corpus directory."""

    def __init__(self, destination: Path) -> None:
        self.destination = destination
        self.destination.mkdir(parents=True)
        self.hashes: dict[str, int] = {}
        self.sources: list[str] = []

    def _record_file(self, source: Path) -> None:
        digest = sha256_file(source)
        if digest in self.hashes:
            return
        destination = self.destination / digest
        shutil.copy2(source, destination)
        self.hashes[digest] = destination.stat().st_size

    def _record_stream(self, source: IO[bytes]) -> None:
        digest = hashlib.sha256()
        with tempfile.NamedTemporaryFile(
            dir=self.destination, prefix=".incoming-", delete=False
        ) as pending:
            pending_path = Path(pending.name)
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                pending.write(chunk)

        content_hash = digest.hexdigest()
        if content_hash in self.hashes:
            pending_path.unlink()
            return
        destination = self.destination / content_hash
        os.replace(pending_path, destination)
        self.hashes[content_hash] = destination.stat().st_size

    def add(self, source: Path) -> None:
        """Add a directory tree, a zip archive, or one corpus file."""
        source = source.resolve()
        if not source.exists():
            raise CorpusError(f"corpus source does not exist: {source}")
        self.sources.append(str(source))

        if source.is_dir():
            for corpus_file in sorted(
                path for path in source.rglob("*") if path.is_file()
            ):
                self._record_file(corpus_file)
            return

        if zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                for member in sorted(
                    archive.infolist(), key=lambda item: item.filename
                ):
                    if member.is_dir():
                        continue
                    with archive.open(member) as archived_file:
                        self._record_stream(archived_file)
            return

        self._record_file(source)

    def metadata(self) -> dict[str, object]:
        """Return stable corpus identity and size metadata."""
        identity = hashlib.sha256()
        for digest, size in sorted(self.hashes.items()):
            identity.update(f"{digest}:{size}\n".encode())
        return {
            "count": len(self.hashes),
            "bytes": sum(self.hashes.values()),
            "sha256": identity.hexdigest(),
            "sources": self.sources,
        }


def parse_corpus_mappings(values: Iterable[str]) -> dict[str, list[Path]]:
    """Parse repeatable ``TARGET=PATH`` corpus overrides."""
    mappings: dict[str, list[Path]] = {}
    for value in values:
        if "=" not in value:
            raise CorpusError(f"invalid --corpus {value!r}; expected TARGET=PATH")
        target, raw_path = value.split("=", 1)
        if not target or not raw_path:
            raise CorpusError(f"invalid --corpus {value!r}; expected TARGET=PATH")
        mappings.setdefault(target, []).append(Path(raw_path))
    return mappings


def resolve_corpus_sources(
    target: str,
    binary_dir: Path,
    corpus_root: Path,
    public_corpus_root: Path | None,
    overrides: dict[str, list[Path]],
) -> list[Path]:
    """Resolve the ordered corpus inputs used to measure one target."""
    if target in overrides:
        return overrides[target]

    sources: list[Path] = []
    compatible_targets = (target, *COMPATIBLE_CORPUS_TARGETS.get(target, ()))
    for compatible_target in compatible_targets:
        checked_in = corpus_root / compatible_target
        if checked_in.is_dir() and any(
            path.is_file() for path in checked_in.rglob("*")
        ):
            sources.append(checked_in)

        seed_archive = binary_dir / f"{compatible_target}_seed_corpus.zip"
        if seed_archive.is_file():
            sources.append(seed_archive)

    if public_corpus_root is not None:
        public_targets = list(compatible_targets)
        if target in HISTORICAL_PROTO_CORPUS_TARGETS:
            public_targets.append("curl_fuzzer_proto")
        for public_target in public_targets:
            public = public_corpus_root / public_target
            if public.is_dir() and any(path.is_file() for path in public.rglob("*")):
                sources.append(public)

    if not sources:
        raise CorpusError(
            f"no corpus found for {target}; checked {checked_in} and {seed_archive}"
        )
    return sources
