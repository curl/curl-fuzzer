"""Exercise corpus replay and separate source reports with real LLVM tools."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_source(root: Path, name: str, contents: str) -> Path:
    source = root / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(contents, encoding="utf-8")
    return source


def test_replay_reports_libcurl_and_harness_without_nested_build_sources(
    tmp_path: Path,
) -> None:
    """Keep generated/dependency/test regions out of the harness denominator."""
    compiler = shutil.which("clang++")
    llvm_cov = shutil.which("llvm-cov")
    llvm_profdata = shutil.which("llvm-profdata")
    if not all((compiler, llvm_cov, llvm_profdata)):
        pytest.skip("coverage integration needs clang++ and LLVM coverage tools")
    assert compiler is not None
    assert llvm_cov is not None
    assert llvm_profdata is not None

    checkout = tmp_path / "checkout with spaces"
    scripts = checkout / "scripts"
    scripts.mkdir(parents=True)
    for name in (
        "run_coverage.sh",
        "fuzz_targets",
        "fuzz_corpus_helpers.sh",
        "summarize_coverage.py",
    ):
        shutil.copyfile(REPO_ROOT / "scripts" / name, scripts / name)

    build = checkout / "build with spaces"
    build.mkdir()
    curl_source = build / "curl-source"
    target = "curl_fuzzer_full_coverage"
    local_corpus = checkout / "corpora" / target
    local_corpus.mkdir(parents=True)
    (local_corpus / "seed").write_bytes(b"seed")
    public_corpus = checkout / "ossfuzz_corpus" / target
    public_corpus.mkdir(parents=True)
    (public_corpus / "public-seed").write_bytes(b"public")

    _write_source(
        checkout,
        "harness.h",
        "inline int HeaderProbe(int value) { return value > 0 ? 1 : -1; }\n",
    )
    _write_source(
        curl_source,
        "include/curl/public.h",
        "inline int CurlHeaderProbe(int value) { return value > 0 ? 9 : 10; }\n",
    )
    sources = [
        _write_source(
            checkout,
            "harness.cc",
            '#include "harness.h"\nint HarnessProbe() { return HeaderProbe(1); }\n',
        ),
        _write_source(
            checkout,
            "full_coverage/probes.cc",
            "int FullCoverageProbe() { return 2; }\n",
        ),
        _write_source(
            checkout,
            "proto_fuzzer/runtime.cc",
            "int RuntimeProbe() { return 3; }\n",
        ),
        _write_source(
            checkout,
            f"fuzzer_entrypoints/{target}.cc",
            "#include <cstddef>\n#include <cstdint>\n"
            "int HarnessProbe();\nint FullCoverageProbe();\nint RuntimeProbe();\n"
            'extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) {\n'
            "  return HarnessProbe() + FullCoverageProbe() + RuntimeProbe();\n}\n",
        ),
        _write_source(
            curl_source,
            "lib/library.cc",
            '#include "../include/curl/public.h"\n'
            "int CurlProbe(int value) {\n"
            "  if (value) return CurlHeaderProbe(value) - 5;\n"
            "  return 5;\n}\n",
        ),
        _write_source(
            curl_source,
            "src/tool.cc",
            "int CurlToolProbe() { return 6; }\n",
        ),
        _write_source(
            build,
            "dependency/generated.cc",
            "int DependencyProbe() { return 7; }\n",
        ),
        _write_source(
            checkout,
            "tests/fixture_test.cc",
            "int UnitTestProbe() { return 8; }\n",
        ),
        _write_source(
            checkout,
            "standalone_fuzz_target_runner.cc",
            "#include <cstddef>\n#include <cstdint>\n"
            "#include <cstdlib>\n#include <fstream>\n"
            'extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t);\n'
            "int CurlProbe(int);\nint CurlToolProbe();\nint DependencyProbe();\n"
            "int UnitTestProbe();\n"
            "int main(int argc, char** argv) {\n"
            '  std::ofstream log(std::getenv("REPLAY_LOG"), std::ios::app);\n'
            "  for (int i = 1; i < argc; ++i) log << argv[i] << '\\n';\n"
            "  LLVMFuzzerTestOneInput(nullptr, 0);\n"
            "  return CurlProbe(1) + CurlToolProbe() + DependencyProbe() +\n"
            "         UnitTestProbe() == 25 ? 0 : 1;\n}\n",
        ),
    ]
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            *map(str, sources),
            "-o",
            str(build / target),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    coverage = build / "coverage"
    raw_profiles = coverage / "profraw"
    raw_profiles.mkdir(parents=True)
    stale_profile = raw_profiles / "stale.profraw"
    stale_profile.write_bytes(b"must be removed before merge")
    replay_log = tmp_path / "replay.log"
    environment = os.environ.copy()
    environment.pop("CURL_FUZZ_TARGET", None)
    environment.update(
        BUILD_DIR=str(build),
        CURL_SOURCE_DIR=str(curl_source),
        ARCHITECTURE="x86_64",
        SANITIZER="coverage",
        TARGETS=f"{target} missing_fuzzer",
        LLVM_COV=llvm_cov,
        LLVM_PROFDATA=llvm_profdata,
        REPLAY_LOG=str(replay_log),
    )
    result = subprocess.run(
        ["bash", str(scripts / "run_coverage.sh")],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert replay_log.read_text(encoding="utf-8").splitlines() == [
        str(local_corpus),
        str(public_corpus),
    ]
    assert "Skipping missing_fuzzer: binary not found" in result.stdout
    assert not stale_profile.exists()
    assert len(list(raw_profiles.glob("*.profraw"))) == 1
    assert (coverage / "html" / "index.html").is_file()
    assert (coverage / "harness-html" / "index.html").is_file()
    assert (coverage / "report.md").is_file()
    assert (coverage / "gaps.json").is_file()

    def report_sources(name: str) -> set[Path]:
        document = json.loads((coverage / name).read_text(encoding="utf-8"))
        assert {"lines", "functions", "regions", "branches"} <= set(
            document["data"][0]["totals"]
        )
        branches = document["data"][0]["totals"]["branches"]
        assert 0 < branches["covered"] < branches["count"]
        return {Path(item["filename"]) for item in document["data"][0]["files"]}

    assert report_sources("curl-coverage.json") == {
        curl_source / "lib" / "library.cc",
        curl_source / "include" / "curl" / "public.h",
        curl_source / "src" / "tool.cc",
    }
    assert report_sources("harness-coverage.json") == {
        checkout / "harness.cc",
        checkout / "harness.h",
        checkout / "full_coverage" / "probes.cc",
        checkout / "proto_fuzzer" / "runtime.cc",
        checkout / "fuzzer_entrypoints" / f"{target}.cc",
    }
    curl_summary = (coverage / "summary.txt").read_text(encoding="utf-8")
    harness_summary = (coverage / "harness-summary.txt").read_text(encoding="utf-8")
    assert "library.cc" in curl_summary
    assert "public.h" in curl_summary
    assert "harness.cc" not in curl_summary
    assert "harness.cc" in harness_summary
    assert "library.cc" not in harness_summary
    assert "public.h" not in harness_summary
    assert "generated.cc" not in harness_summary
    assert "fixture_test.cc" not in harness_summary
    assert "standalone_fuzz_target_runner.cc" not in harness_summary
