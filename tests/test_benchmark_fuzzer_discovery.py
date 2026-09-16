"""Tests for the libFuzzer discovery benchmark."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "benchmark_fuzzer_discovery.py"


def _load_module():  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location(
        "benchmark_fuzzer_discovery", SCRIPT
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _write_dummy_fuzzer(
    path: Path, *, crash: bool = False, timeout_finding: bool = False
) -> None:
    artifact_body = ""
    failure_body = ""
    exit_status = 0
    if crash:
        artifact_body = "Path(artifact_prefix, 'crash-deadbeef').write_bytes(b'boom')"
        failure_body = "print('ERROR: AddressSanitizer: heap-use-after-free')"
        exit_status = 77
    if timeout_finding:
        artifact_body = "Path(artifact_prefix, 'timeout-deadbeef').write_bytes(b'slow')"
        failure_body = "print('ERROR: libFuzzer: timeout after 25 seconds')"
        exit_status = 70
    path.write_text(
        f"""#!/usr/bin/env python3
import sys
from pathlib import Path

corpus = next(argument for argument in sys.argv[1:] if not argument.startswith('-'))
artifact_prefix = next(
    argument.split('=', 1)[1]
    for argument in sys.argv[1:]
    if argument.startswith('-artifact_prefix=')
)
print('ARGS=' + json.dumps(sys.argv[1:]))
print('SEED_FILES=' + ','.join(sorted(path.name for path in Path(corpus).iterdir())))
print('#17 DONE cov: 1 ft: 2 corp: 1/4b exec/s: 17 rss: 1Mb')
print('stat::number_of_executed_units: 17')
print('stat::average_exec_per_sec: 17')
{artifact_body}
{failure_body}
raise SystemExit({exit_status})
""".replace("import sys\n", "import json\nimport sys\n"),
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_parse_execution_evidence_prefers_fork_summary() -> None:
    module = _load_module()
    evidence = module.parse_execution_evidence(
        """#17 pulse cov: 1 ft: 2 corp: 1/4b exec/s: 17 rss: 1Mb
stat::number_of_executed_units: 19
stat::average_exec_per_sec: 18
INFO: fuzzed for 10 seconds, executed 123 units, 0 crashes found
"""
    )

    assert evidence.executed_units == 123
    assert evidence.average_exec_per_second == 18
    assert evidence.line == (
        "INFO: fuzzed for 10 seconds, executed 123 units, 0 crashes found"
    )
    assert (
        module.FAILURE_RE.search("ERROR: libFuzzer: timeout after 25 seconds") is None
    )


def test_cli_runs_independent_trials_and_writes_json(tmp_path: Path) -> None:
    fuzzer = tmp_path / "dummy fuzzer"
    seed = tmp_path / "private-seed.scenario"
    output_dir = tmp_path / "results"
    _write_dummy_fuzzer(fuzzer)
    seed.write_bytes(b"seed")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--fuzzer",
            str(fuzzer),
            "--seed",
            str(seed),
            "--trials",
            "2",
            "--timeout",
            "1",
            "--workers",
            "3",
            "--max-len",
            "64",
            "--unit-timeout",
            "2",
            "--base-seed",
            "41",
            "--output-dir",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    document = json.loads((output_dir / "results.json").read_text(encoding="utf-8"))
    assert document["measurement"] == "libfuzzer_time_to_crash"
    assert document["configuration"]["seed_sha256"] == (
        "19b25856e1c150ca834cffc8b59b23adbd0ec0389e58eb22b3b64768098d002b"
    )
    assert [run["libfuzzer_seed"] for run in document["runs"]] == [41, 42]
    assert [run["executed_units"] for run in document["runs"]] == [17, 17]
    assert [run["outcome"] for run in document["runs"]] == [
        "completed_without_crash",
        "completed_without_crash",
    ]
    assert document["summary"]["total_executed_units"] == 34

    corpus_dirs = [Path(run["corpus_dir"]) for run in document["runs"]]
    assert corpus_dirs[0] != corpus_dirs[1]
    assert all(
        (corpus_dir / "seed").read_bytes() == b"seed" for corpus_dir in corpus_dirs
    )
    for run in document["runs"]:
        log = Path(run["log_path"]).read_text(encoding="utf-8")
        assert "SEED_FILES=seed" in log
        assert "-max_total_time=1" in log
        assert "-fork=3" in log
        assert "-max_len=64" in log
        assert "-timeout=2" in log


def test_cli_identifies_crash_artifact(tmp_path: Path) -> None:
    fuzzer = tmp_path / "crashing-fuzzer"
    seed = tmp_path / "seed"
    output_dir = tmp_path / "results"
    _write_dummy_fuzzer(fuzzer, crash=True)
    seed.write_bytes(b"seed")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--fuzzer",
            str(fuzzer),
            "--seed",
            str(seed),
            "--trials",
            "1",
            "--timeout",
            "1",
            "--output-dir",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    document = json.loads((output_dir / "results.json").read_text(encoding="utf-8"))
    run = document["runs"][0]
    assert run["return_code"] == 77
    assert run["crash_detected"] is True
    assert run["outcome"] == "crash"
    assert len(run["crash_artifacts"]) == 1
    assert run["crash_artifacts"][0]["relative_path"] == "crash-deadbeef"
    assert run["crash_artifacts"][0]["sha256"] == (
        "81f52337ebb4cb1669bb802c708807dde0519d15cb102a6313d26ad5cd821713"
    )


def test_cli_classifies_timeout_artifact_separately(tmp_path: Path) -> None:
    fuzzer = tmp_path / "timeout-fuzzer"
    seed = tmp_path / "seed"
    output_dir = tmp_path / "results"
    _write_dummy_fuzzer(fuzzer, timeout_finding=True)
    seed.write_bytes(b"seed")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--fuzzer",
            str(fuzzer),
            "--seed",
            str(seed),
            "--trials",
            "1",
            "--timeout",
            "1",
            "--output-dir",
            str(output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    document = json.loads((output_dir / "results.json").read_text(encoding="utf-8"))
    run = document["runs"][0]
    assert run["outcome"] == "libfuzzer_timeout"
    assert run["libfuzzer_timeout_detected"] is True
    assert run["crash_detected"] is False
    assert run["crash_artifacts"] == []
    assert document["summary"]["crashes"] == 0
    assert document["summary"]["libfuzzer_timeouts"] == 1


def test_cli_rejects_max_len_smaller_than_seed(tmp_path: Path) -> None:
    fuzzer = tmp_path / "fuzzer"
    seed = tmp_path / "seed"
    _write_dummy_fuzzer(fuzzer)
    seed.write_bytes(b"large seed")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--fuzzer",
            str(fuzzer),
            "--seed",
            str(seed),
            "--max-len",
            "2",
            "--output-dir",
            str(tmp_path / "must-not-exist"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "smaller than the seed" in result.stderr
    assert not (tmp_path / "must-not-exist").exists()
