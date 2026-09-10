#!/usr/bin/env python3
"""Extract one fuzzer and its supporting files from an artifact shard."""

from __future__ import annotations

import argparse
import re
import shutil
import stat
import tarfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

_ARCHIVE_ROOT = "build-out"
_SIDECAR_SUFFIXES = {".dict", ".options"}
_SAFE_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


def _validate_target_name(target: str) -> None:
    if not _SAFE_TARGET.fullmatch(target) or target in {".", ".."}:
        raise ValueError(f"unsafe fuzzer target name: {target!r}")


def _is_executable(path: Path) -> bool:
    return (
        not path.is_symlink()
        and path.is_file()
        and bool(stat.S_IMODE(path.stat().st_mode) & 0o111)
    )


def _select_members(
    archive: tarfile.TarFile, target: str
) -> dict[str, tarfile.TarInfo]:
    required = {target, f"{target}_seed_corpus.zip"}
    selected: dict[str, tarfile.TarInfo] = {}
    seen: set[str] = set()

    for member in archive.getmembers():
        member_path = PurePosixPath(member.name)
        if len(member_path.parts) != 2 or member_path.parts[0] != _ARCHIVE_ROOT:
            raise ValueError(f"unexpected archive member path: {member.name!r}")
        if not member.isfile():
            raise ValueError(f"archive member is not a regular file: {member.name!r}")

        basename = member_path.name
        if basename in seen:
            raise ValueError(f"duplicate archive member: {member.name!r}")
        seen.add(basename)

        if basename in required or member_path.suffix in _SIDECAR_SUFFIXES:
            selected[basename] = member

    if target not in selected:
        raise FileNotFoundError(
            f"shard does not contain fuzzer executable: {_ARCHIVE_ROOT}/{target}"
        )
    corpus_name = f"{target}_seed_corpus.zip"
    if corpus_name not in selected:
        raise FileNotFoundError(
            f"shard does not contain seed corpus: {_ARCHIVE_ROOT}/{corpus_name}"
        )
    if not stat.S_IMODE(selected[target].mode) & 0o111:
        raise ValueError(f"fuzzer is not executable in shard: {_ARCHIVE_ROOT}/{target}")
    return selected


def _validate_destinations(output_dir: Path, names: Sequence[str]) -> None:
    if output_dir.is_symlink():
        raise ValueError(f"output directory must not be a symlink: {output_dir}")
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"output path is not a directory: {output_dir}")

    for name in names:
        destination = output_dir / name
        if destination.is_symlink():
            raise ValueError(f"refusing to overwrite symlink: {destination}")
        if destination.exists() and not destination.is_file():
            raise ValueError(f"refusing to overwrite non-file: {destination}")


def _remove_other_executables(output_dir: Path, target: str) -> None:
    for path in output_dir.iterdir():
        if path.name != target and _is_executable(path):
            path.unlink()


def prepare_fuzzer(
    archive: Path, target: str, output_dir: Path = Path(_ARCHIVE_ROOT)
) -> None:
    """Extract one target, its corpus, and shared sidecars from a shard."""
    _validate_target_name(target)
    if not archive.is_file():
        raise FileNotFoundError(f"fuzzer shard not found: {archive}")

    with tarfile.open(archive, mode="r:*") as shard:
        selected = _select_members(shard, target)
        _validate_destinations(output_dir, list(selected))
        output_dir.mkdir(parents=True, exist_ok=True)
        _remove_other_executables(output_dir, target)

        for name, member in sorted(selected.items()):
            source = shard.extractfile(member)
            if source is None:
                raise ValueError(f"could not read archive member: {member.name!r}")
            destination = output_dir / name
            with source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(stat.S_IMODE(member.mode))

    executable = output_dir / target
    corpus = output_dir / f"{target}_seed_corpus.zip"
    if not _is_executable(executable):
        raise ValueError(f"prepared fuzzer is not executable: {executable}")
    if not corpus.is_file():
        raise FileNotFoundError(f"prepared seed corpus not found: {corpus}")

    executables = sorted(path for path in output_dir.iterdir() if _is_executable(path))
    if executables != [executable]:
        names = ", ".join(str(path) for path in executables) or "none"
        raise ValueError(f"expected only {executable} to be executable; found: {names}")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path(_ARCHIVE_ROOT))
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    """Prepare one fuzzer selected using command-line arguments."""
    args = _parse_args(argv)
    try:
        prepare_fuzzer(args.archive, args.target, args.output_dir)
    except (OSError, tarfile.TarError, ValueError) as error:
        raise SystemExit(f"prepare_fuzzer: {error}") from error
    print(f"Prepared {args.target} in {args.output_dir}")


if __name__ == "__main__":
    main()
