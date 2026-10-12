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
namespace full_coverage {
void ExercisePublicApiCoverage() { std::puts("public API probe"); }
}
int main() {
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
        ["public API probe", "engine continued"] if profiling else []
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
