#!/usr/bin/env python3
# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
# SPDX-License-Identifier: curl
"""Key and verify cached APT archives against a freshly resolved download plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

ARCHIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.:%~-]*\.deb")
SHA256 = re.compile(r"[0-9a-fA-F]{64}")
URI_RECORD = re.compile(
    r"'([A-Za-z][A-Za-z0-9+.-]*:[^'\s]+)'[ \t]+(\S+)[ \t]+(\S+)[ \t]+(\S+)"
)
URI_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s]")


@dataclass(frozen=True)
class Archive:
    """One package archive selected by APT, including transitive dependencies."""

    filename: str
    size: int
    sha256: str


def _archive(filename: object, size: object, sha256: object) -> Archive:
    if not isinstance(filename, str) or ARCHIVE_NAME.fullmatch(filename) is None:
        raise ValueError(f"unsafe APT archive filename: {filename!r}")
    if type(size) is not int or size <= 0:
        raise ValueError(f"invalid archive size for {filename}: {size!r}")
    if not isinstance(sha256, str) or SHA256.fullmatch(sha256) is None:
        raise ValueError(f"invalid SHA256 digest for {filename}")
    return Archive(filename, size, sha256.lower())


def parse_plan(text: str) -> list[Archive]:
    """Parse SHA256 ``apt-get --print-uris`` records, ignoring explanatory output."""
    archives: dict[str, Archive] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line.startswith(("'", '"')) and URI_PREFIX.match(line) is None:
            continue
        try:
            match = URI_RECORD.fullmatch(line)
            if match is None:
                raise ValueError("expected a quoted URI, filename, size and SHA256")
            # APT also emits mirror+file: URIs on hosted runners. APT owns URI
            # resolution; the manifest needs only the archive name and hash.
            _, filename, size, digest = match.groups()
            if not digest.startswith("SHA256:"):
                raise ValueError("expected SHA256; use Acquire::ForceHash=SHA256")
            archive = _archive(filename, int(size), digest.removeprefix("SHA256:"))
            if filename in archives:
                raise ValueError(f"duplicate archive filename: {filename}")
            archives[filename] = archive
        except ValueError as error:
            raise ValueError(
                f"APT download plan line {line_number}: {error}"
            ) from error
    return sorted(archives.values(), key=lambda archive: archive.filename)


def _manifest(archives: Sequence[Archive]) -> str:
    return json.dumps(
        [asdict(archive) for archive in archives], sort_keys=True, separators=(",", ":")
    )


def read_manifest(path: Path) -> list[Archive]:
    """Validate the fresh manifest before using any cached package files."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise TypeError("APT archive manifest must be a list")
    archives: dict[str, Archive] = {}
    for entry in document:
        if not isinstance(entry, dict) or set(entry) != {"filename", "size", "sha256"}:
            raise ValueError("invalid APT archive manifest entry")
        archive = _archive(entry["filename"], entry["size"], entry["sha256"])
        if archive.filename in archives:
            raise ValueError(f"duplicate archive filename: {archive.filename}")
        archives[archive.filename] = archive
    return sorted(archives.values(), key=lambda archive: archive.filename)


def verify_archives(archives: Sequence[Archive], directory: Path) -> tuple[int, int]:
    """Retain matching regular archives and remove files APT must download again."""
    expected = {archive.filename: archive for archive in archives}
    retained = removed = 0
    for path in directory.glob("*.deb"):
        details = path.lstat()
        archive = expected.get(path.name)
        valid = False
        if (
            stat.S_ISREG(details.st_mode)
            and archive is not None
            and details.st_size == archive.size
        ):
            digest = hashlib.sha256()
            try:
                with path.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                valid = digest.hexdigest() == archive.sha256
            except OSError:
                # Unreadable cache entries are misses; APT can fetch a fresh copy.
                pass
        if valid:
            retained += 1
        else:
            if stat.S_ISDIR(details.st_mode):
                shutil.rmtree(path)
            else:
                path.unlink()
            removed += 1
    return retained, removed


def main(argv: Sequence[str] | None = None) -> int:
    """Prepare the cache key or validate restored package archives."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="write a manifest from APT's download plan")
    plan.add_argument("plan_file", type=Path)
    plan.add_argument("manifest_file", type=Path)
    verify = commands.add_parser("verify", help="discard invalid restored archives")
    verify.add_argument("manifest_file", type=Path)
    verify.add_argument("archive_dir", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "plan":
            archives = parse_plan(arguments.plan_file.read_text(encoding="utf-8"))
            manifest = _manifest(archives)
            arguments.manifest_file.write_text(manifest + "\n", encoding="utf-8")
            print(f"key={hashlib.sha256(manifest.encode('utf-8')).hexdigest()}")
            print(f"has-downloads={'true' if archives else 'false'}")
        else:
            retained, removed = verify_archives(
                read_manifest(arguments.manifest_file), arguments.archive_dir
            )
            print(
                f"APT cache: retained {retained} verified archives; discarded {removed}"
            )
    except (OSError, UnicodeError, TypeError, ValueError) as error:
        print(f"APT cache failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
