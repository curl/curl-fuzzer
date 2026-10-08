"""Tests for the reproducible perf sampling helper."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import zipfile
from contextlib import suppress
from pathlib import Path

import pytest

from curl_fuzzer_tools import profile_fuzzer

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(
    arguments: list[str],
    *,
    environment_updates: dict[str, str] | None = None,
    working_directory: Path | None = None,
    simulate_installed: bool = False,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    python_path = str(REPO_ROOT / "src")
    if environment.get("PYTHONPATH"):
        python_path += os.pathsep + environment["PYTHONPATH"]
    environment["PYTHONPATH"] = python_path
    if environment_updates:
        environment.update(environment_updates)
    entry_point = "from curl_fuzzer_tools.profile_fuzzer import main"
    if simulate_installed:
        entry_point = (
            "import curl_fuzzer_tools.profile_fuzzer as profiler; "
            "profiler.SOURCE_CHECKOUT = None; "
            "profiler.DEFAULT_CORPUS_ROOT = None; "
            "main = profiler.main"
        )
    return subprocess.run(
        [
            sys.executable,
            "-c",
            f"{entry_point}; raise SystemExit(main())",
            *arguments,
        ],
        env=environment,
        cwd=working_directory,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_pyproject_exposes_profile_fuzzer_entry_point() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'profile_fuzzer = "curl_fuzzer_tools.profile_fuzzer:main"' in pyproject


def test_perf_environment_ignores_user_configuration(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("PERF_CONFIG", "/untrusted/config")
    monkeypatch.setenv("PERF_PAGER", "less")

    environment = profile_fuzzer._run_environment()

    assert environment["LC_ALL"] == "C"
    assert environment["PERF_CONFIG"] == "/dev/null"
    assert environment["PERF_PAGER"] == "cat"


@pytest.mark.parametrize("signum", (signal.SIGTERM, signal.SIGHUP))
def test_termination_signal_handlers_exit_and_are_restored(
    signum: signal.Signals,
) -> None:
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_hup = signal.getsignal(signal.SIGHUP)

    with (
        pytest.raises(SystemExit) as caught,
        profile_fuzzer._exit_on_termination_signals(),
    ):
        handler = signal.getsignal(signum)
        assert callable(handler)
        handler(signum, None)

    assert caught.value.code == 128 + signum
    assert signal.getsignal(signal.SIGTERM) == previous_term
    assert signal.getsignal(signal.SIGHUP) == previous_hup


def _write_fake_fuzzer(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if "-help=1" in sys.argv:
    print("Flags: max_total_time print_final_stats seed timeout")
    raise SystemExit(0)

if os.environ.get("FAKE_FUZZER_HANG"):
    time.sleep(60)

arguments = sys.argv[1:]
corpus = Path(next(argument for argument in arguments if not argument.startswith("-")))
print("FUZZER_ARGS=" + json.dumps(arguments), flush=True)
print(
    "SEED_FILES=" + ",".join(sorted(item.name for item in corpus.iterdir())),
    flush=True,
)
(corpus / "new-discovery").write_bytes(b"new")
print("#123 DONE cov: 10 ft: 20 corp: 2/7b exec/s: 41 rss: 2Mb", flush=True)
print("stat::number_of_executed_units: 123", flush=True)
print("stat::average_exec_per_sec: 41", flush=True)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_fake_perf(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

arguments = sys.argv[1:]
if arguments == ["--version"]:
    expected_environment = {
        "LC_ALL": "C",
        "PERF_CONFIG": "/dev/null",
        "PERF_PAGER": "cat",
    }
    if any(os.environ.get(key) != value for key, value in expected_environment.items()):
        raise SystemExit("perf environment was not normalized")
    print("perf version fake-1.0")
    if os.environ.get("FAKE_PERF_REMOVE_AFTER_VERSION"):
        Path(sys.argv[0]).unlink()
    raise SystemExit(0)

if arguments[0] == "record":
    output = Path(arguments[arguments.index("--output") + 1])
    output.write_bytes(b"PERFILE2 fake samples")
    print("PERF_ARGS=" + json.dumps(arguments), flush=True)
    print(
        "PERF_ENV="
        + json.dumps(
            {key: os.environ.get(key) for key in ("LC_ALL", "PERF_CONFIG", "PERF_PAGER")}
        ),
        flush=True,
    )
    command = arguments[arguments.index("--") + 1 :]
    raise SystemExit(subprocess.run(command, check=False).returncode)

if arguments[0] == "report":
    print("# Samples: 40 of event 'cpu-clock:u'")
    print("# Overhead  Samples  Command  Shared Object  Symbol")
    if not os.environ.get("FAKE_PERF_EMPTY_REPORT"):
        print("  62.50%       25  fuzzer   fuzzer         [.] Curl_easy_perform")
        print("  20.00%        8  fuzzer   fuzzer         [.] ParseMessage")
    raise SystemExit(0)

raise SystemExit("unexpected fake perf arguments: " + repr(arguments))
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _fixture(tmp_path: Path) -> dict[str, Path | str]:
    target = "test_fuzzer"
    binary_dir = tmp_path / "out"
    binary_dir.mkdir()
    fuzzer = binary_dir / target
    perf = tmp_path / "perf"
    _write_fake_fuzzer(fuzzer)
    _write_fake_perf(perf)

    dictionary = binary_dir / "tokens.dict"
    dictionary.write_text('"token"\n', encoding="utf-8")
    (binary_dir / f"{target}.options").write_text(
        """[libfuzzer]
max_len = 32768
timeout = 5
dict = tokens.dict
""",
        encoding="utf-8",
    )

    corpus_root = tmp_path / "corpora"
    target_corpus = corpus_root / target
    target_corpus.mkdir(parents=True)
    (target_corpus / "seed").write_bytes(b"seed")
    return {
        "target": target,
        "binary_dir": binary_dir,
        "fuzzer": fuzzer,
        "perf": perf,
        "dictionary": dictionary,
        "corpus_root": corpus_root,
    }


def _arguments(fixture: dict[str, Path | str], output_dir: Path) -> list[str]:
    return [
        "--binary-dir",
        str(fixture["binary_dir"]),
        "--target",
        str(fixture["target"]),
        "--corpus-root",
        str(fixture["corpus_root"]),
        "--seconds",
        "1",
        "--frequency",
        "17",
        "--perf",
        str(fixture["perf"]),
        "--output-dir",
        str(output_dir),
        "--provenance",
        "curl_revision=abc123",
    ]


def test_cli_collects_profile_with_exact_workload_metadata(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "profile"

    result = _run_cli(_arguments(fixture, output_dir))

    assert result.returncode == 0, result.stderr
    assert (output_dir / "perf.data").read_bytes() == b"PERFILE2 fake samples"
    assert "Curl_easy_perform" in (output_dir / "perf-report.txt").read_text(
        encoding="utf-8"
    )
    assert (output_dir / "artifacts").is_dir()
    corpus_archive = output_dir / "corpus.zip"
    seed_digest = hashlib.sha256(b"seed").hexdigest()
    with zipfile.ZipFile(corpus_archive) as archive:
        assert archive.namelist() == [seed_digest]
        assert archive.read(seed_digest) == b"seed"

    log = (output_dir / "fuzzer.log").read_text(encoding="utf-8")
    perf_arguments = json.loads(
        next(
            line.removeprefix("PERF_ARGS=")
            for line in log.splitlines()
            if line.startswith("PERF_ARGS=")
        )
    )
    perf_environment = json.loads(
        next(
            line.removeprefix("PERF_ENV=")
            for line in log.splitlines()
            if line.startswith("PERF_ENV=")
        )
    )
    fuzzer_arguments = json.loads(
        next(
            line.removeprefix("FUZZER_ARGS=")
            for line in log.splitlines()
            if line.startswith("FUZZER_ARGS=")
        )
    )
    assert perf_arguments[:8] == [
        "record",
        "--event",
        "cpu-clock:u",
        "--freq",
        "17",
        "--call-graph",
        "fp",
        "--output",
    ]
    assert perf_environment == {
        "LC_ALL": "C",
        "PERF_CONFIG": "/dev/null",
        "PERF_PAGER": "cat",
    }
    assert "-seed=101" in fuzzer_arguments
    assert "-max_total_time=1" in fuzzer_arguments
    assert "-timeout=5" in fuzzer_arguments
    assert "-max_len=32768" in fuzzer_arguments
    assert f"-dict={fixture['dictionary']}" in fuzzer_arguments

    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "ok"
    assert metadata["measurement"] == "perf_cpu_sampling"
    assert metadata["configuration"]["timeout"] == 5
    assert metadata["corpus"]["count"] == 1
    assert metadata["corpus"]["bytes"] == 4
    assert metadata["corpus"]["archive"] == {
        "bytes": corpus_archive.stat().st_size,
        "path": "corpus.zip",
        "sha256": hashlib.sha256(corpus_archive.read_bytes()).hexdigest(),
    }
    assert metadata["execution"] == {
        "average_exec_per_second": 41,
        "executed_units": 123,
    }
    assert metadata["provenance"] == {"curl_revision": "abc123"}
    assert metadata["options"]["values"]["dict"] == str(fixture["dictionary"])
    assert metadata["options"]["dictionary"] == {
        "bytes": 8,
        "path": str(fixture["dictionary"]),
        "sha256": hashlib.sha256(b'"token"\n').hexdigest(),
    }
    assert "<corpus>" in metadata["perf"]["command"]
    assert not any(
        "curl-fuzzer-profile-" in item for item in metadata["perf"]["command"]
    )
    assert "--stdio-color=never" in metadata["perf"]["report_command"]
    report_call_graph = metadata["perf"]["report_command"].index("--call-graph")
    assert metadata["perf"]["report_command"][report_call_graph + 1] == "none"
    percent_limit = metadata["perf"]["report_command"].index("--percent-limit")
    assert metadata["perf"]["report_command"][percent_limit + 1] == "0"

    summary = (output_dir / "summary.md").read_text(encoding="utf-8")
    assert "Status: **ok**" in summary
    assert "Curl_easy_perform" in summary
    assert "123" in summary


def test_cli_rejects_arguments_that_change_the_measurement(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "must-not-exist"
    command = _arguments(fixture, output_dir)
    command.extend(("--fuzzer-arg=-seed=7",))

    result = _run_cli(command)

    assert result.returncode == 2
    assert "managed by this tool" in result.stderr
    assert not output_dir.exists()


@pytest.mark.parametrize(
    "argument",
    (
        "--max_len=1",
        "-max_len",
        "-max_len=",
        "max_len=1",
    ),
)
def test_invalid_fuzzer_override_cannot_suppress_an_options_file_value(
    tmp_path: Path, argument: str
) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "invalid-override"
    command = _arguments(fixture, output_dir)
    command.append(f"--fuzzer-arg={argument}")

    result = _run_cli(command)

    assert result.returncode == 2
    assert "-name=value" in result.stderr
    assert not output_dir.exists()


@pytest.mark.parametrize(
    "option",
    (
        "ignore_remaining_args",
        "exact_artifact_path",
        "error_exitcode",
        "timeout_exitcode",
        "oom_exitcode",
        "interrupt_exitcode",
        "merge_inner",
        "minimize_crash_internal_step",
        "set_cover_merge",
        "stop_file",
        "exit_on_src_pos",
        "collect_data_flow",
        "close_fd_mask",
    ),
)
def test_cli_rejects_libfuzzer_control_and_internal_options(
    tmp_path: Path, option: str
) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "managed-option"
    command = _arguments(fixture, output_dir)
    command.append(f"--fuzzer-arg=-{option}=1")

    result = _run_cli(command)

    assert result.returncode == 2
    assert "managed by this tool" in result.stderr
    assert not output_dir.exists()


def test_fuzzer_argument_dictionary_is_normalized_and_hashed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "profile-dictionary"
    dictionary = tmp_path / "replacement.dict"
    dictionary.write_bytes(b'"replacement"\n')
    arguments = _arguments(fixture, output_dir)
    arguments.append(f"--fuzzer-arg=-dict={dictionary}")

    result = _run_cli(arguments)

    assert result.returncode == 0, result.stderr
    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["options"]["dictionary"] == {
        "bytes": dictionary.stat().st_size,
        "path": str(dictionary),
        "sha256": hashlib.sha256(dictionary.read_bytes()).hexdigest(),
    }
    command = metadata["perf"]["command"]
    assert f"-dict={dictionary}" in command
    assert f"-dict={fixture['dictionary']}" not in command


def test_explicit_corpus_works_outside_checkout_without_default_roots(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "profile-explicit"
    explicit_corpus = tmp_path / "only-this-corpus"
    explicit_corpus.mkdir()
    (explicit_corpus / "input").write_bytes(b"explicit")
    working_directory = tmp_path / "elsewhere"
    working_directory.mkdir()
    arguments = _arguments(fixture, output_dir)
    corpus_root_index = arguments.index("--corpus-root")
    del arguments[corpus_root_index : corpus_root_index + 2]
    arguments.extend(
        (
            "--corpus",
            str(explicit_corpus),
            "--public-corpus-root",
            str(tmp_path / "does-not-exist"),
        )
    )

    result = _run_cli(
        arguments,
        working_directory=working_directory,
        simulate_installed=True,
    )

    assert result.returncode == 0, result.stderr
    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["repository_revision"] is None
    assert metadata["corpus"]["sources"] == [str(explicit_corpus)]


def test_cli_does_not_accept_an_empty_sample_report(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "empty-report"
    result = _run_cli(
        _arguments(fixture, output_dir),
        environment_updates={"FAKE_PERF_EMPTY_REPORT": "1"},
    )

    assert result.returncode == 1
    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "failed"
    assert metadata["failure"] == "perf report contained no sampled symbols"
    assert "No sampled symbols were available" in (output_dir / "summary.md").read_text(
        encoding="utf-8"
    )


def test_cli_stops_a_timed_out_process_tree_and_keeps_diagnostics(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "timed-out"
    command = _arguments(fixture, output_dir)
    command.extend(("--wall-timeout", "1"))
    result = _run_cli(
        command,
        environment_updates={"FAKE_FUZZER_HANG": "1"},
        timeout=10,
    )

    assert result.returncode == 1
    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "failed"
    assert metadata["perf"]["timed_out"] is True
    assert "wall timeout" in metadata["failure"]
    assert (output_dir / "fuzzer.log").is_file()
    assert (output_dir / "summary.md").is_file()


def test_timeout_kills_descendants_after_the_process_group_leader_exits(
    monkeypatch, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    child_script = tmp_path / "child.py"
    child_script.write_text(
        """import os
import signal
import sys
import time
from pathlib import Path

signal.signal(signal.SIGINT, signal.SIG_IGN)
Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    leader_script = tmp_path / "leader.py"
    leader_script.write_text(
        """import signal
import subprocess
import sys
import time

subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    child_pid_path = tmp_path / "child.pid"
    monkeypatch.setattr(profile_fuzzer, "INTERRUPT_GRACE_SECONDS", 0.1)

    result = profile_fuzzer._run_process_tree(
        (sys.executable, str(leader_script), str(child_script), str(child_pid_path)),
        tmp_path / "process.log",
        1,
        os.environ.copy(),
    )

    assert result.timed_out is True
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    child_status = Path(f"/proc/{child_pid}/stat")
    for _ in range(50):
        if not child_status.exists() or child_status.read_text().split()[2] == "Z":
            break
        time.sleep(0.01)
    assert not child_status.exists() or child_status.read_text().split()[2] == "Z"


def test_sigterm_cleans_up_the_profiled_process_group(tmp_path: Path) -> None:
    child_script = tmp_path / "signal-child.py"
    child_script.write_text(
        """import os
import signal
import sys
import time
from pathlib import Path

signal.signal(signal.SIGINT, signal.SIG_IGN)
Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    runner_script = tmp_path / "signal-runner.py"
    runner_script.write_text(
        """import os
import sys
from pathlib import Path
from curl_fuzzer_tools import profile_fuzzer

profile_fuzzer.INTERRUPT_GRACE_SECONDS = 0.1
profile_fuzzer._run_process_tree(
    (sys.executable, sys.argv[1], sys.argv[2]),
    Path(sys.argv[3]),
    60,
    os.environ.copy(),
)
""",
        encoding="utf-8",
    )
    child_pid_path = tmp_path / "signal-child.pid"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    runner = subprocess.Popen(
        (
            sys.executable,
            str(runner_script),
            str(child_script),
            str(child_pid_path),
            str(tmp_path / "signal.log"),
        ),
        env=environment,
    )
    child_pid: int | None = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not child_pid_path.is_file():
            assert runner.poll() is None
            time.sleep(0.01)
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        time.sleep(0.05)

        runner.send_signal(signal.SIGTERM)

        assert runner.wait(timeout=5) == 128 + signal.SIGTERM
        child_status = Path(f"/proc/{child_pid}/stat")
        for _ in range(50):
            if not child_status.exists() or child_status.read_text().split()[2] == "Z":
                break
            time.sleep(0.01)
        assert not child_status.exists() or child_status.read_text().split()[2] == "Z"
    finally:
        if runner.poll() is None:
            runner.kill()
            runner.wait()
        if child_pid is not None:
            with suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


def test_cli_preserves_metadata_when_perf_cannot_start(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    output_dir = tmp_path / "start-failed"
    result = _run_cli(
        _arguments(fixture, output_dir),
        environment_updates={"FAKE_PERF_REMOVE_AFTER_VERSION": "1"},
    )

    assert result.returncode == 1
    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "failed"
    assert metadata["perf"]["returncode"] is None
    assert "could not start perf" in metadata["failure"]
    assert (output_dir / "corpus.zip").is_file()
    assert metadata["corpus"]["archive"]["path"] == "corpus.zip"
    assert (output_dir / "fuzzer.log").is_file()
