#!/usr/bin/env python3
"""Package fuzzer build outputs into shards and emit their CI matrix."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import stat
import sys
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_SHARD_COUNT = 8
_SAFE_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


@dataclass(frozen=True)
class _TargetFiles:
    name: str
    executable: Path
    corpus: Path
    size: int


def validate_target_name(target: str) -> str:
    """Validate one fuzzer target name for filesystem and shell use."""
    if not _SAFE_TARGET.fullmatch(target) or target in {".", ".."}:
        raise ValueError(f"unsafe fuzzer target name: {target!r}")
    return target


def parse_targets(value: str) -> list[str]:
    """Parse and validate a whitespace-separated ``FUZZ_TARGETS`` value."""
    targets = value.split()
    if not targets:
        raise ValueError("FUZZ_TARGETS is empty")

    seen: set[str] = set()
    for target in targets:
        validate_target_name(target)
        if target in seen:
            raise ValueError(f"duplicate fuzzer target: {target}")
        seen.add(target)
    return targets


def _target_files(targets: Sequence[str], build_out: Path) -> list[_TargetFiles]:
    files: list[_TargetFiles] = []
    for target in targets:
        executable = build_out / target
        corpus = build_out / f"{target}_seed_corpus.zip"

        if not executable.is_file():
            raise FileNotFoundError(f"fuzzer executable not found: {executable}")
        if not stat.S_IMODE(executable.stat().st_mode) & 0o111:
            raise ValueError(f"fuzzer is not executable: {executable}")
        if not corpus.is_file():
            raise FileNotFoundError(f"seed corpus not found: {corpus}")

        files.append(
            _TargetFiles(
                name=target,
                executable=executable,
                corpus=corpus,
                size=executable.stat().st_size + corpus.stat().st_size,
            )
        )
    return files


def _partition(
    targets: Sequence[_TargetFiles], shard_count: int
) -> list[list[_TargetFiles]]:
    """Balance targets by size while keeping shard target counts within one."""
    minimum_count, remainder = divmod(len(targets), shard_count)
    maximum_count = minimum_count + bool(remainder)
    shards: list[list[_TargetFiles]] = [[] for _ in range(shard_count)]
    sizes = [0] * shard_count

    ordered = sorted(targets, key=lambda target: (-target.size, target.name))
    for position, target in enumerate(ordered):
        targets_left = len(ordered) - position
        minimum_slots_left = sum(max(0, minimum_count - len(shard)) for shard in shards)
        if targets_left == minimum_slots_left:
            candidates = [
                index
                for index, shard in enumerate(shards)
                if len(shard) < minimum_count
            ]
        else:
            candidates = [
                index
                for index, shard in enumerate(shards)
                if len(shard) < maximum_count
            ]

        shard_index = min(candidates, key=lambda index: (sizes[index], index))
        shards[shard_index].append(target)
        sizes[shard_index] += target.size

    return shards


def _sidecars(build_out: Path) -> list[Path]:
    return sorted(
        {
            path
            for pattern in ("*.dict", "*.options")
            for path in build_out.glob(pattern)
            if path.is_file()
        },
        key=lambda path: path.name,
    )


def _write_shard(
    archive: Path, targets: Sequence[_TargetFiles], sidecars: Sequence[Path]
) -> None:
    with tarfile.open(archive, mode="w") as output:
        for target in sorted(targets, key=lambda item: item.name):
            output.add(
                target.executable,
                arcname=f"build-out/{target.executable.name}",
                recursive=False,
            )
            output.add(
                target.corpus,
                arcname=f"build-out/{target.corpus.name}",
                recursive=False,
            )
        for sidecar in sidecars:
            output.add(
                sidecar,
                arcname=f"build-out/{sidecar.name}",
                recursive=False,
            )


def create_shards(
    targets: list[str], build_out: Path, output_dir: Path, shard_count: int
) -> dict[str, object]:
    """Create size-balanced tar shards and return a per-fuzzer CI matrix."""
    # Callers using this function directly get the same validation as the CLI.
    targets = parse_targets(" ".join(targets))
    if shard_count < 1:
        raise ValueError("shard count must be at least 1")
    if shard_count > len(targets):
        raise ValueError("shard count cannot exceed the number of fuzz targets")
    if not build_out.is_dir():
        raise FileNotFoundError(f"build output directory not found: {build_out}")

    target_files = _target_files(targets, build_out)
    shards = _partition(target_files, shard_count)
    width = max(2, len(str(shard_count - 1)))
    output_dir.mkdir(parents=True, exist_ok=True)
    sidecars = _sidecars(build_out)
    target_shards: dict[str, str] = {}

    for index, shard in enumerate(shards):
        shard_id = f"{index:0{width}d}"
        archive = output_dir / f"fuzz-shard-{shard_id}.tar"
        _write_shard(archive, shard, sidecars)
        for target in shard:
            target_shards[target.name] = shard_id
        log.info(
            "Created %s with %d targets (%d bytes before sidecars)",
            archive,
            len(shard),
            sum(target.size for target in shard),
        )

    matrix: dict[str, object] = {
        "include": [
            {
                "fuzzer": target,
                "shard": target_shards[target],
                "artifact": f"fuzz-shard-{target_shards[target]}",
            }
            for target in sorted(targets)
        ]
    }
    return matrix


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-out",
        type=Path,
        required=True,
        help="Directory containing fuzzer executables and seed corpora",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory in which to create shard tar files",
    )
    parser.add_argument(
        "--shard-count",
        type=int,
        default=_DEFAULT_SHARD_COUNT,
        help=f"Number of artifact shards (default: {_DEFAULT_SHARD_COUNT})",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> dict[str, object]:
    """Package the build output and print a GitHub Actions output value."""
    args = _parse_args(argv)
    try:
        targets = parse_targets(os.getenv("FUZZ_TARGETS", ""))
        matrix = create_shards(
            targets=targets,
            build_out=args.build_out,
            output_dir=args.output_dir,
            shard_count=args.shard_count,
        )
    except (FileNotFoundError, ValueError) as error:
        raise SystemExit(f"generate_matrix: {error}") from error

    print(f"matrix={json.dumps(matrix, separators=(',', ':'))}")
    return matrix


def run() -> None:
    """Run the command-line tool."""
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    main()


if __name__ == "__main__":
    run()
