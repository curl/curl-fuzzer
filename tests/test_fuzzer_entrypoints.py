"""Checks that OSS-Fuzz can attribute every packaged target independently."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT_PATTERN = re.compile(r'extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput\s*\(')
CUSTOM_MUTATOR_PATTERN = re.compile(
    r'extern\s+"C"\s+std::size_t\s+LLVMFuzzerCustomMutator\s*\('
)
CUSTOM_CROSSOVER_PATTERN = re.compile(
    r'extern\s+"C"\s+std::size_t\s+LLVMFuzzerCustomCrossOver\s*\('
)
LEGACY_TARGET_PATTERN = re.compile(
    r"^\s*curl_add_fuzzer\(\s*([a-z0-9_]+)", re.MULTILINE
)
PROTO_TARGET_PATTERN = re.compile(
    r"^\s*curl_add_proto_fuzzer\(\s*([a-z0-9_]+)", re.MULTILINE
)
STANDALONE_TARGETS = {"fuzz_bufq", "fuzz_doh", "fuzz_url"}
PROTO_TARGET_PROFILES = {
    "curl_fuzzer_proto": "kCompatibility",
    "curl_fuzzer_proto_http": "kFastHttp",
    "curl_fuzzer_proto_http_deep": "kDeepHttp",
    "curl_fuzzer_proto_https": "kFastHttps",
    "curl_fuzzer_proto_https_gnutls": "kFastHttps",
    "curl_fuzzer_proto_https_mbedtls": "kFastHttps",
    "curl_fuzzer_proto_http3": "kFastHttp3",
    "curl_fuzzer_proto_h2_proxy": "kH2Proxy",
    "curl_fuzzer_proto_ws": "kFastWebSocket",
    "curl_fuzzer_proto_wss": "kFastSecureWebSocket",
    "curl_fuzzer_proto_telnet": "kFastTelnet",
    "curl_fuzzer_proto_ftp": "kFastFtp",
    "curl_fuzzer_proto_tftp": "kFastTftp",
    "curl_fuzzer_proto_api": "kApi",
    "curl_fuzzer_proto_multi": "kMulti",
    "curl_fuzzer_proto_timing": "kTiming",
}


def _packaged_targets(
    *, architecture: str = "x86_64", sanitizer: str = "address"
) -> set[str]:
    environment = os.environ.copy()
    environment["ARCHITECTURE"] = architecture
    environment["SANITIZER"] = sanitizer
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


def test_optional_proto_targets_are_limited_to_supported_builds() -> None:
    """Keep packaging aligned with the CMake sanitizer/architecture gates."""
    targets = {
        "curl_fuzzer_proto_https_gnutls",
        "curl_fuzzer_proto_https_mbedtls",
        "curl_fuzzer_proto_http3",
    }

    assert targets <= _packaged_targets()
    assert targets.isdisjoint(_packaged_targets(sanitizer="memory"))
    assert targets.isdisjoint(_packaged_targets(architecture="i386"))


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


def test_proto_entrypoints_bind_profiles_in_source() -> None:
    """Keep target behaviour visible in C++, including mutation callbacks."""
    for target, profile in PROTO_TARGET_PROFILES.items():
        source = REPO_ROOT / "fuzzer_entrypoints" / f"{target}.cc"
        contents = source.read_text(encoding="utf-8")

        assert contents.count(f"TargetProfile::{profile}") == 1
        assert len(ENTRYPOINT_PATTERN.findall(contents)) == 1
        assert len(CUSTOM_MUTATOR_PATTERN.findall(contents)) == 1
        assert len(CUSTOM_CROSSOVER_PATTERN.findall(contents)) == 1

    shared_main = (REPO_ROOT / "proto_fuzzer" / "fuzzer_main.cc").read_text(
        encoding="utf-8"
    )
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "PROTO_FUZZER_TARGET_" not in shared_main
    assert "PROTO_FUZZER_TARGET_" not in cmake
