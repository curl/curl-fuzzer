"""Exercise the coverage target's one-shot and ordinary-build lifecycle."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("profiling", [False, True])
def test_target_exits_or_runs_probes_once(tmp_path: Path, profiling: bool) -> None:
    """An ordinary engine stops; profiling runs probes once per process."""
    compiler = shutil.which("clang++") or shutil.which("g++")
    if compiler is None:
        pytest.skip("a C++ compiler is required")

    driver = tmp_path / "driver.cc"
    driver.write_text(
        """
#include <cstddef>
#include <cstdint>
#include <cstdio>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
extern "C" int LLVMFuzzerInitialize(int *, char ***);
namespace full_coverage {
void ExercisePublicApiCoverage() { std::puts("public API probe"); }
void ExerciseUtilityApiCoverage() { std::puts("utility API probe"); }
void ExerciseDynamicFormattingCoverage() { std::puts("dynamic format probe"); }
void ExerciseLegacyMutatorCoverage() { std::puts("mutator probe"); }
}
int main() {
  int argc = 1;
  char program[] = "coverage-target";
  char *argv[] = {program, nullptr};
  char **argvp = argv;
  LLVMFuzzerInitialize(&argc, &argvp);
  std::puts("engine initialized");
  const uint8_t seed[] = {1};
  LLVMFuzzerTestOneInput(seed, sizeof(seed));
  LLVMFuzzerTestOneInput(seed, sizeof(seed));
  std::puts("engine continued");
}
""",
        encoding="utf-8",
    )
    binary = tmp_path / "coverage-target"
    command = [
        compiler,
        "-std=c++11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(REPO_ROOT),
        str(REPO_ROOT / "fuzzer_entrypoints" / "curl_fuzzer_full_coverage.cc"),
        str(driver),
        "-o",
        str(binary),
    ]
    if profiling:
        command.append("-DCURL_FUZZER_COVERAGE_ONLY")
    subprocess.run(command, check=True, capture_output=True, text=True)
    environment = os.environ.copy()
    # A runtime profile path alone must not turn an ordinary fuzzer into a
    # profiling target. Selection belongs to the build configuration.
    environment["LLVM_PROFILE_FILE"] = str(tmp_path / "unused.profraw")
    result = subprocess.run(
        [str(binary)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )
    assert result.stdout.splitlines() == (
        [
            "public API probe",
            "utility API probe",
            "dynamic format probe",
            "engine initialized",
            "mutator probe",
            "engine continued",
        ]
        if profiling
        else []
    )


def test_ordinary_libfuzzer_stops_without_a_failure_artifact(tmp_path: Path) -> None:
    """Clean process termination must not trigger libFuzzer's exit handler."""
    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("libFuzzer integration requires clang++")
    binary = tmp_path / "libfuzzer-target"
    subprocess.run(
        [
            compiler,
            "-std=c++11",
            "-fsanitize=fuzzer",
            str(REPO_ROOT / "fuzzer_entrypoints" / "curl_fuzzer_full_coverage.cc"),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    result = subprocess.run(
        [str(binary), "-runs=10000", f"-artifact_prefix={tmp_path}/"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert "ERROR:" not in result.stderr
    assert "Done 10000 runs" not in result.stderr
    assert not list(tmp_path.glob("crash-*"))


def test_profiling_libfuzzer_runs_probes_with_empty_merge_corpus(
    tmp_path: Path,
) -> None:
    """The OSS-Fuzz merge invocation needs no retained corpus input."""
    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("libFuzzer integration requires clang++")

    probes = tmp_path / "probes.cc"
    probes.write_text(
        """
#include <cstdio>
namespace full_coverage {
void ExercisePublicApiCoverage() { std::puts("public API probe"); }
void ExerciseUtilityApiCoverage() { std::puts("utility API probe"); }
void ExerciseDynamicFormattingCoverage() { std::puts("dynamic format probe"); }
void ExerciseLegacyMutatorCoverage() { std::puts("mutator probe"); }
}
""",
        encoding="utf-8",
    )
    binary = tmp_path / "libfuzzer-coverage-target"
    subprocess.run(
        [
            compiler,
            "-std=c++11",
            "-fsanitize=fuzzer",
            "-DCURL_FUZZER_COVERAGE_ONLY",
            "-I",
            str(REPO_ROOT),
            str(REPO_ROOT / "fuzzer_entrypoints" / "curl_fuzzer_full_coverage.cc"),
            str(probes),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    merge_output = tmp_path / "merge-output"
    empty_corpus = tmp_path / "empty-corpus"
    merge_output.mkdir()
    empty_corpus.mkdir()
    result = subprocess.run(
        [
            str(binary),
            "-merge=1",
            str(merge_output),
            str(empty_corpus),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.stdout.splitlines() == [
        "public API probe",
        "utility API probe",
        "dynamic format probe",
    ]
