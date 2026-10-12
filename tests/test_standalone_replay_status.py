"""Check optional replay accounting without changing the standalone engine."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FAILURE_VARIABLES = (
    "REPLAY_FAIL_OPEN",
    "REPLAY_FAIL_READ",
    "REPLAY_FAIL_ALLOCATE",
    "REPLAY_FAIL_SEEK",
)


@pytest.fixture(scope="module")
def runner(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("clang++") or shutil.which("g++")
    if compiler is None:
        pytest.skip("a C++ compiler is required")
    build = tmp_path_factory.mktemp("standalone-replay")
    driver = build / "driver.cc"
    driver.write_text(
        """
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if(size && data[0] == 'e')
    std::exit(0);
  if(size && data[0] == 't')
    std::raise(SIGALRM);
  std::puts("callback returned");
  return 0;
}

extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
  if(std::getenv("REPLAY_FAIL_OPEN") && std::strcmp(mode, "rb") == 0)
    return nullptr;
  return __real_fopen(path, mode);
}

extern "C" size_t __real_fread(void*, size_t, size_t, FILE*);
extern "C" size_t __wrap_fread(void* data, size_t size, size_t count, FILE* file) {
  if(std::getenv("REPLAY_FAIL_READ"))
    return 0;
  return __real_fread(data, size, count, file);
}

extern "C" void* __real_calloc(size_t, size_t);
extern "C" void* __wrap_calloc(size_t count, size_t size) {
  if(std::getenv("REPLAY_FAIL_ALLOCATE"))
    return nullptr;
  return __real_calloc(count, size);
}

extern "C" int __real_fseek(FILE*, long, int);
extern "C" int __wrap_fseek(FILE* file, long offset, int whence) {
  if(std::getenv("REPLAY_FAIL_SEEK"))
    return -1;
  return __real_fseek(file, offset, whence);
}
""",
        encoding="utf-8",
    )
    binary = build / "runner"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(REPO_ROOT / "standalone_fuzz_target_runner.cc"),
            str(driver),
            "-Wl,--wrap=fopen,--wrap=fread,--wrap=calloc,--wrap=fseek",
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return binary


def _run(
    runner: Path,
    paths: list[Path],
    status: Path | None,
    updates: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for name in (*FAILURE_VARIABLES, "FUZZ_REPLAY_STATUS_FILE"):
        environment.pop(name, None)
    environment["FUZZ_TIMEOUT_SECS"] = "25"
    if status is not None:
        environment["FUZZ_REPLAY_STATUS_FILE"] = str(status)
    if updates is not None:
        environment.update(updates)
    return subprocess.run(
        [str(runner), *map(str, paths)],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
    )


def _counts(status: Path, **overrides: int) -> dict[str, int]:
    counts = json.loads(status.read_text(encoding="utf-8"))
    expected = {
        "attempted": 0,
        "completed": 0,
        "timed_out": 0,
        "input_errors": 0,
        "path_errors": 0,
    }
    expected.update(overrides)
    assert counts == expected
    assert all(type(value) is int for value in counts.values())
    return counts


@pytest.mark.parametrize("timeout_seconds", ["0", "25"])
def test_successful_directory_replay_reports_two_completed_inputs(
    runner: Path, tmp_path: Path, timeout_seconds: str
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "one").write_bytes(b"one")
    (corpus / "two").write_bytes(b"second")
    status = tmp_path / "status.json"
    # A fresh normal completion replaces any previous counters.
    status.write_text("stale status", encoding="utf-8")

    result = _run(runner, [corpus], status, {"FUZZ_TIMEOUT_SECS": timeout_seconds})

    _counts(status, attempted=2, completed=2)
    assert result.stdout.count("callback returned") == 2


def test_early_process_exit_does_not_emit_a_normal_completion_status(
    runner: Path, tmp_path: Path
) -> None:
    early_exit = tmp_path / "early-exit"
    early_exit.write_bytes(b"exit")
    status = tmp_path / "status.json"

    _run(runner, [early_exit], status)

    assert not status.exists()


def test_timeout_is_recorded_and_the_next_input_still_completes(
    runner: Path, tmp_path: Path
) -> None:
    timeout_input = tmp_path / "timeout"
    timeout_input.write_bytes(b"timeout")
    normal_input = tmp_path / "normal"
    normal_input.write_bytes(b"normal")
    status = tmp_path / "status.json"

    result = _run(runner, [timeout_input, normal_input], status)

    _counts(status, attempted=2, completed=1, timed_out=1)
    assert "TIMEOUT after 25s, skipping" in result.stderr
    assert result.stdout.count("callback returned") == 1


def test_missing_path_is_recorded_and_other_inputs_still_run(
    runner: Path, tmp_path: Path
) -> None:
    normal_input = tmp_path / "normal"
    normal_input.write_bytes(b"normal")
    status = tmp_path / "status.json"

    result = _run(runner, [tmp_path / "missing", normal_input], status)

    _counts(status, attempted=1, completed=1, path_errors=1)
    assert "stat failed" in result.stderr
    assert result.stdout.count("callback returned") == 1


@pytest.mark.parametrize(
    "failure,callback_returns",
    [
        ("REPLAY_FAIL_OPEN", False),
        ("REPLAY_FAIL_READ", True),
        ("REPLAY_FAIL_ALLOCATE", False),
        ("REPLAY_FAIL_SEEK", True),
    ],
)
def test_file_preparation_errors_do_not_claim_completed_inputs(
    runner: Path, tmp_path: Path, failure: str, callback_returns: bool
) -> None:
    normal_input = tmp_path / "normal"
    normal_input.write_bytes(b"normal")
    status = tmp_path / "status.json"

    result = _run(runner, [normal_input], status, {failure: "1"})

    _counts(status, attempted=1, input_errors=1)
    # Preserve the old callback behavior even after an incomplete read/seek.
    assert ("callback returned" in result.stdout) == callback_returns


@pytest.mark.parametrize("link_kind", ["dangling", "loop"])
def test_directory_metadata_errors_are_counted_in_both_passes(
    runner: Path, tmp_path: Path, link_kind: str
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "normal").write_bytes(b"normal")
    link = corpus / "invalid-link"
    link.symlink_to(link if link_kind == "loop" else tmp_path / "missing")
    status = tmp_path / "status.json"

    _run(runner, [corpus], status)

    _counts(status, attempted=1, completed=1, path_errors=2)


@pytest.mark.parametrize("setting", [None, ""])
def test_status_output_is_optional(
    runner: Path, tmp_path: Path, setting: str | None
) -> None:
    normal_input = tmp_path / "normal"
    normal_input.write_bytes(b"normal")
    updates = {"FUZZ_REPLAY_STATUS_FILE": setting} if setting is not None else None

    result = _run(runner, [normal_input], None, updates)

    assert result.stdout.count("callback returned") == 1
    assert "Replay status" not in result.stderr
    assert list(tmp_path.iterdir()) == [normal_input]


def test_status_open_failure_keeps_the_existing_success_exit_code(
    runner: Path, tmp_path: Path
) -> None:
    normal_input = tmp_path / "normal"
    normal_input.write_bytes(b"normal")
    status = tmp_path / "missing-directory" / "status.json"

    result = _run(runner, [normal_input], status)

    assert result.stdout.count("callback returned") == 1
    assert "Replay status open failed" in result.stderr
    assert not status.exists()


def test_status_flush_failure_is_reported_without_changing_exit_code(
    runner: Path, tmp_path: Path
) -> None:
    full_device = Path("/dev/full")
    if not full_device.exists():
        pytest.skip("/dev/full is required for deterministic write failure")
    normal_input = tmp_path / "normal"
    normal_input.write_bytes(b"normal")

    result = _run(runner, [normal_input], full_device)

    assert result.stdout.count("callback returned") == 1
    assert "Replay status write failed" in result.stderr
