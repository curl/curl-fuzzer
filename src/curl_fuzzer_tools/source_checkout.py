"""Locate the curl-fuzzer source checkout used by installed tools."""

from __future__ import annotations

from pathlib import Path


def _is_repository_root(path: Path) -> bool:
    """Return whether a directory is recognizably this source repository."""
    return (
        (path / "pyproject.toml").is_file()
        and (path / "ossfuzz.sh").is_file()
        and (path / "corpora").is_dir()
    )


def find_source_checkout() -> Path | None:
    """Return a verified source checkout available to an installed tool."""
    package_checkout = Path(__file__).resolve().parents[2]
    if _is_repository_root(package_checkout):
        return package_checkout
    working_directory = Path.cwd()
    return working_directory if _is_repository_root(working_directory) else None
