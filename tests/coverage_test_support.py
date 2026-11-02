"""LLVM coverage mechanics shared by direct CTest regression checks."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

FunctionNameNormalizer = Callable[[object], str | None]


def run_profiled_binary(
    binary: Path,
    arguments: Sequence[str | Path],
    raw_directory: Path,
    profile_stem: str,
    *,
    run_name: str | None = None,
    timeout: float | None = None,
    capture_output: bool = False,
) -> list[Path]:
    """Run an instrumented binary and return the raw profiles it emitted."""
    raw_directory.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["LLVM_PROFILE_FILE"] = str(
        raw_directory / f"{profile_stem}-%m-%p.profraw"
    )
    completed = subprocess.run(
        [str(binary), *map(str, arguments)],
        check=False,
        env=environment,
        text=True,
        capture_output=capture_output,
        timeout=timeout,
    )
    description = run_name or profile_stem
    if completed.returncode != 0:
        details = "\n".join(
            part for part in (completed.stdout, completed.stderr) if part
        )
        raise SystemExit(
            f"{description} exited with status {completed.returncode}"
            + (f":\n{details}" if details else "")
        )

    profiles = sorted(raw_directory.glob(f"{profile_stem}-*.profraw"))
    if not profiles or any(profile.stat().st_size == 0 for profile in profiles):
        raise SystemExit(f"{description} emitted no nonempty raw coverage profile")
    return profiles


def merge_profiles(llvm_profdata: Path, profiles: Sequence[Path], output: Path) -> Path:
    """Merge raw LLVM profiles into ``output`` and return that path."""
    subprocess.run(
        [
            str(llvm_profdata),
            "merge",
            "-sparse",
            *map(str, profiles),
            "-o",
            str(output),
        ],
        check=True,
    )
    return output


def export_document(
    llvm_cov: Path,
    binary: Path,
    profdata: Path,
    sources: Sequence[Path],
) -> dict[str, object]:
    """Export coverage for ``sources`` and validate the top-level JSON value."""
    exported = subprocess.run(
        [
            str(llvm_cov),
            "export",
            str(binary),
            f"-instr-profile={profdata}",
            "--sources",
            *map(str, sources),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    document: object = json.loads(exported.stdout)
    if not isinstance(document, dict):
        raise SystemExit("llvm-cov export did not produce an object")
    return document


def function_counts(
    document: dict[str, object],
    *,
    name_normalizer: FunctionNameNormalizer | None = None,
) -> dict[str, int]:
    """Return maximum execution counts keyed by normalized function name."""
    counts: dict[str, int] = {}
    data = document.get("data")
    if not isinstance(data, list):
        return counts
    for datum in data:
        if not isinstance(datum, dict):
            continue
        functions = datum.get("functions")
        if not isinstance(functions, list):
            continue
        for function in functions:
            if not isinstance(function, dict):
                continue
            raw_name = function.get("name")
            name = (
                name_normalizer(raw_name) if name_normalizer is not None else raw_name
            )
            count = function.get("count")
            if (
                isinstance(name, str)
                and isinstance(count, int)
                and not isinstance(count, bool)
                and count >= 0
            ):
                counts[name] = max(counts.get(name, 0), count)
    return counts
