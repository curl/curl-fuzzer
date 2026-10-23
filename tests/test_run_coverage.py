"""Exercise corpus replay and separate source reports with real LLVM tools."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_source(root: Path, name: str, contents: str) -> Path:
    source = root / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(contents, encoding="utf-8")
    return source


def test_cmake_coverage_uses_atomic_profile_updates() -> None:
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    coverage_flags = cmake.split("if(ENABLE_COVERAGE)", maxsplit=1)[1].split(
        "endif()", maxsplit=1
    )[0]

    assert "-fprofile-instr-generate" in coverage_flags
    assert "-fcoverage-mapping" in coverage_flags
    assert "-fprofile-update=atomic" in coverage_flags


@pytest.fixture
def coverage_fixture(
    tmp_path: Path,
) -> dict[str, Any]:
    """Build an instrumented replay fixture with matching numeric sidecars."""
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
        "replay_status.py",
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
    # File names containing newlines must still count as exactly one input.
    (public_corpus / "public\nseed").write_bytes(b"public")

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
            "#include <cstdlib>\n#include <cstdio>\n#include <fstream>\n#include <filesystem>\n"
            'extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t);\n'
            "int CurlProbe(int);\nint CurlToolProbe();\nint DependencyProbe();\n"
            "int UnitTestProbe();\n"
            "int main(int argc, char** argv) {\n"
            '  std::ofstream log(std::getenv("REPLAY_LOG"), std::ios::app);\n'
            "  size_t inputs = 0;\n"
            "  for (int i = 1; i < argc; ++i) {\n"
            "    log << argv[i] << '\\n';\n"
            "    for(auto& file : std::filesystem::recursive_directory_iterator(argv[i]))\n"
            "      if(file.is_regular_file()) ++inputs;\n  }\n"
            "  for(size_t i = 0; i < inputs; ++i) LLVMFuzzerTestOneInput(nullptr, 0);\n"
            "  auto name = std::filesystem::path(argv[0]).filename().string();\n"
            '  if(name == "early_fuzzer") std::exit(0);\n'
            '  std::ofstream status(std::getenv("FUZZ_REPLAY_STATUS_FILE"));\n'
            '  status << "{\\"attempted\\":" << inputs << ",\\"completed\\":" << inputs\n'
            '         << ",\\"timed_out\\":0,\\"input_errors\\":0,\\"path_errors\\":0}";\n'
            '  if(name == "failed_fuzzer") { std::fputs("injected failure\\n", stderr); return 17; }\n'
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
            "-fprofile-update=atomic",
            *map(str, sources),
            "-o",
            str(build / target),
        ],
        check=True,
        env=dict(os.environ, TMPDIR=str(build)),
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
        TARGETS=target,
        LLVM_COV=llvm_cov,
        LLVM_PROFDATA=llvm_profdata,
        REPLAY_LOG=str(replay_log),
        TMPDIR=str(build),
    )
    return locals()


def _replay(
    fixture: dict[str, Any], **updates: str
) -> subprocess.CompletedProcess[str]:
    environment = dict(fixture["environment"], **updates)
    return subprocess.run(
        ["bash", str(fixture["scripts"] / "run_coverage.sh")],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_replay_reports_libcurl_and_harness_without_nested_build_sources(
    coverage_fixture: dict[str, Any],
) -> None:
    """Keep generated/dependency/test regions out of the harness denominator."""
    checkout = coverage_fixture["checkout"]
    curl_source = coverage_fixture["curl_source"]
    target = coverage_fixture["target"]
    coverage = coverage_fixture["coverage"]
    result = _replay(coverage_fixture)
    assert result.returncode == 0, result.stderr

    assert coverage_fixture["replay_log"].read_text(encoding="utf-8").splitlines() == [
        str(coverage_fixture["local_corpus"]),
        str(coverage_fixture["public_corpus"]),
    ]
    assert not coverage_fixture["stale_profile"].exists()
    assert len(list(coverage_fixture["raw_profiles"].glob("*.profraw"))) == 1
    status = json.loads((coverage / "replay-status.json").read_text())
    assert status["complete"] is True
    assert status["targets"][0]["outcome"] == "complete"
    assert status["targets"][0]["expected_inputs"] == 2
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


def test_failed_and_skipped_replays_keep_later_coverage_marked_partial(
    coverage_fixture: dict[str, Any],
) -> None:
    fixture = coverage_fixture
    for name in ("failed_fuzzer", "early_fuzzer", "no_corpus", "empty_corpus"):
        shutil.copyfile(fixture["build"] / fixture["target"], fixture["build"] / name)
        (fixture["build"] / name).chmod(0o755)
        if name != "no_corpus":
            corpus = fixture["checkout"] / "corpora" / name
            corpus.mkdir()
            if name != "empty_corpus":
                (corpus / "seed").write_bytes(b"seed")
    targets = f"failed_fuzzer early_fuzzer {fixture['target']} missing_fuzzer no_corpus empty_corpus"

    result = _replay(fixture, TARGETS=targets)

    assert result.returncode == 0, result.stderr
    document = json.loads((fixture["coverage"] / "gaps.json").read_text())
    assert document["replay"]["complete"] is False
    rows = document["replay"]["targets"]
    assert [row["outcome"] for row in rows] == [
        "failed",
        "incomplete",
        "complete",
        "missing_binary",
        "no_corpus",
        "empty_corpus",
    ]
    assert rows[0]["exit_code"] == 17
    assert "injected failure" in Path(rows[0]["log"]).read_text()
    assert rows[1]["exit_code"] == 0 and rows[1]["counters"] is None
    report = (fixture["coverage"] / "report.md").read_text()
    assert "Replay is **partial**: 1 / 6" in report
    assert report.index("Selected corpus replay") < report.index("## libcurl")


@pytest.mark.parametrize("keep_plain_inputs", [False, True])
@pytest.mark.parametrize("link_corpus_directory", [False, True])
def test_replay_counts_linked_files_without_following_linked_directories(
    coverage_fixture: dict[str, Any],
    keep_plain_inputs: bool,
    link_corpus_directory: bool,
) -> None:
    """Replay linked seeds even when they are the corpus's only inputs."""
    fixture = coverage_fixture
    if not keep_plain_inputs:
        for corpus in (fixture["local_corpus"], fixture["public_corpus"]):
            for seed in corpus.iterdir():
                seed.unlink()
    external = fixture["checkout"] / "external-corpus"
    external.mkdir()
    seed = external / "seed"
    seed.write_bytes(b"linked seed")
    (fixture["local_corpus"] / "linked-seed").symlink_to(seed)
    (fixture["local_corpus"] / "linked-directory").symlink_to(external)
    if link_corpus_directory:
        corpus = fixture["checkout"] / "linked-corpus-root"
        fixture["local_corpus"].rename(corpus)
        fixture["local_corpus"].symlink_to(corpus)

    result = _replay(fixture)

    assert result.returncode == 0, result.stderr
    status = json.loads((fixture["coverage"] / "replay-status.json").read_text())
    assert status["complete"] is True
    row = status["targets"][0]
    expected = 3 if keep_plain_inputs else 1
    assert row["expected_inputs"] == expected
    assert row["counters"]["attempted"] == expected
    assert row["counters"]["completed"] == expected
    assert row["outcome"] == "complete"
    assert (fixture["coverage"] / "report.md").is_file()


def test_corpus_symlink_loop_keeps_later_targets_running(
    coverage_fixture: dict[str, Any],
) -> None:
    """Retain link errors and complete later targets after a failed replay."""
    fixture = coverage_fixture
    target = "broken_links_fuzzer"
    binary = fixture["build"] / target
    shutil.copyfile(fixture["build"] / fixture["target"], binary)
    binary.chmod(0o755)
    corpus = fixture["checkout"] / "corpora" / target
    corpus.mkdir()
    (corpus / "seed").write_bytes(b"normal")
    link = corpus / "invalid-link"
    link.symlink_to(link)

    result = _replay(fixture, TARGETS=f"{target} {fixture['target']}")

    assert result.returncode == 0, result.stderr
    status = json.loads((fixture["coverage"] / "replay-status.json").read_text())
    broken, normal = status["targets"]
    assert status["complete"] is False
    assert broken["outcome"] == "failed"
    assert broken["count_errors"] == 1
    assert Path(broken["log"]).read_text()
    assert normal["outcome"] == "complete"
    assert normal["counters"]["completed"] == 2
    assert (fixture["coverage"] / "report.md").is_file()


def test_merge_failure_cannot_publish_reports_from_a_previous_run(
    coverage_fixture: dict[str, Any],
) -> None:
    coverage = coverage_fixture["coverage"]
    stale_names = (
        "coverage.profdata",
        "summary.txt",
        "harness-summary.txt",
        "curl-coverage.json",
        "harness-coverage.json",
        "report.md",
        "gaps.json",
    )
    for name in stale_names:
        (coverage / name).write_text("stale 100% report", encoding="utf-8")
    merge_tool = coverage_fixture["build"] / "failed-profdata"
    merge_tool.write_text('#!/bin/sh\nprintf "merge failed\\n" >&2\nexit 7\n')
    merge_tool.chmod(0o755)

    result = _replay(coverage_fixture, LLVM_PROFDATA=str(merge_tool))

    assert result.returncode == 7
    assert "merge failed" in result.stderr
    assert all(not (coverage / name).exists() for name in stale_names)
    assert (coverage / "replay-status.json").exists()
    assert not (coverage / "coverage.profdata.tmp").exists()
