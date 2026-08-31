"""Regression checks for the Fuzz Introspector analysis boundary."""

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO_ROOT / "fuzz_introspector_exclusion.config"


def _exclusion_patterns() -> list[re.Pattern[str]]:
    lines = [
        line.strip()
        for line in CONFIG_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert lines[0] == "FILES_TO_AVOID"
    return [re.compile(pattern) for pattern in lines[1:]]


def _is_excluded(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(path) for pattern in patterns)


def test_introspector_excludes_only_declared_non_fuzz_surfaces() -> None:
    """Keep report cleanup from hiding curl/lib or packaged harness code."""
    patterns = _exclusion_patterns()

    excluded = {
        "/src/curl/CMake/CurlTests.c",
        "/src/curl/docs/examples/example.c",
        "/src/curl/projects/Windows/VC.c",
        "/src/curl/src/tool_operate.c",
        "/src/curl/tests/unit/unit1300.c",
        "/src/curl_fuzzer/standalone_fuzz_target_runner.cc",
        "/src/curl_fuzzer/tests/legacy_tlv_mutator_test.cc",
    }
    included = {
        "/src/curl/lib/http.c",
        "/src/curl/lib/vtls/openssl.c",
        "/src/curl_fuzzer/legacy_fuzzer.cc",
        "/src/curl_fuzzer/fuzzer_entrypoints/curl_fuzzer_http.cc",
        "/src/curl_fuzzer/proto_fuzzer/scenario_runner.cc",
        # Exact local-only file rules must not swallow similarly named code.
        "/src/curl_fuzzer/standalone_fuzz_target_runner.cc.backup",
    }

    assert all(_is_excluded(path, patterns) for path in excluded)
    assert not any(_is_excluded(path, patterns) for path in included)


def test_ossfuzz_exports_the_checked_in_config() -> None:
    """The config has no effect unless compiler-side analysis can find it."""
    ossfuzz = (REPO_ROOT / "ossfuzz.sh").read_text(encoding="utf-8")
    assert (
        "export FUZZ_INTROSPECTOR_CONFIG=${BUILD_ROOT}/"
        "fuzz_introspector_exclusion.config" in ossfuzz
    )
