"""Checks that OSS-Fuzz can attribute every packaged target independently."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT_PATTERN = re.compile(r'extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput\s*\(')
LEGACY_TARGET_PATTERN = re.compile(
    r"^\s*curl_add_fuzzer\(\s*([a-z0-9_]+)", re.MULTILINE
)
PROTO_TARGET_PATTERN = re.compile(
    r"^\s*curl_add_proto_fuzzer\(\s*([a-z0-9_]+)", re.MULTILINE
)
STANDALONE_TARGETS = {"fuzz_bufq", "fuzz_doh", "fuzz_url"}


def _packaged_targets() -> set[str]:
    environment = os.environ.copy()
    environment["ARCHITECTURE"] = "x86_64"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; printf "%s\\n" $FUZZ_TARGETS',
            "entrypoint-test",
            str(REPO_ROOT / "scripts" / "fuzz_targets"),
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
        env=environment,
    )
    return set(result.stdout.splitlines())


def _checked_in_cpp_sources() -> list[Path]:
    sources = list(REPO_ROOT.glob("*.cc"))
    sources.extend((REPO_ROOT / "fuzzer_entrypoints").glob("*.cc"))
    sources.extend((REPO_ROOT / "proto_fuzzer").glob("*.cc"))
    sources.extend((REPO_ROOT / "src").rglob("*.cc"))
    sources.extend((REPO_ROOT / "tests").glob("*.cc"))
    return sources


def test_packaged_fuzzers_have_unique_same_named_entrypoints() -> None:
    """Keep Introspector's source basenames aligned with coverage reports."""
    packaged = _packaged_targets()
    discovered: dict[str, list[Path]] = {}

    for source in _checked_in_cpp_sources():
        contents = source.read_text(encoding="utf-8")
        if ENTRYPOINT_PATTERN.search(contents):
            discovered.setdefault(source.stem, []).append(source)

    assert set(discovered) == packaged
    for target, sources in discovered.items():
        assert len(sources) == 1, (
            f"{target} has multiple checked-in libFuzzer entrypoints: {sources}"
        )


def test_cmake_builds_every_packaged_entrypoint() -> None:
    """Prevent packaging and CMake's target declarations from drifting."""
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    cmake_targets = set(LEGACY_TARGET_PATTERN.findall(cmake))
    cmake_targets.update(PROTO_TARGET_PATTERN.findall(cmake))
    cmake_targets.update(STANDALONE_TARGETS)

    assert cmake_targets == _packaged_targets()
    assert cmake.count("fuzzer_entrypoints/${_name}.cc") == 2
