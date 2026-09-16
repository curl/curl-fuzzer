#!/usr/bin/env python3
"""
Measure libFuzzer time to a crash from one supplied seed.

Every trial starts with the same seed in a new corpus and uses a separate
artifact directory. The resulting JSON is intended for comparing discovery
between fuzzer builds; it does not measure code coverage.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

HARD_DEADLINE_SLACK_SECONDS = 3
INTERRUPT_GRACE_SECONDS = 3

STAT_EXEC_RE = re.compile(r"^stat::number_of_executed_units:\s*(\d+)\s*$")
STAT_RATE_RE = re.compile(r"^stat::average_exec_per_sec:\s*(\d+)\s*$")
FORK_EXEC_RE = re.compile(r"\bexecuted\s+(\d+)\s+units?\b", re.IGNORECASE)
PROGRESS_RE = re.compile(r"^#(\d+)\b")
PROGRESS_RATE_RE = re.compile(r"\bexec/s:\s*(\d+)\b")
FAILURE_RE = re.compile(
    r"(?:ERROR|SUMMARY):\s*(?:AddressSanitizer|HWAddressSanitizer|"
    r"MemorySanitizer|LeakSanitizer)|"
    r"assert(?:ion)?\b.*\bfailed\b|"
    r"deadly signal",
    re.IGNORECASE,
)
TIMEOUT_RE = re.compile(r"ERROR:\s*libFuzzer:\s*timeout\b", re.IGNORECASE)
OOM_RE = re.compile(
    r"ERROR:\s*libFuzzer:\s*(?:out[- ]of[- ]memory|oom)\b|"
    r"(?:AddressSanitizer|HWAddressSanitizer):.*(?:out of memory|"
    r"allocation-size-too-big)",
    re.IGNORECASE,
)


class BenchmarkError(RuntimeError):
    """Raised when the benchmark configuration is invalid."""


@dataclass(frozen=True)
class ExecutionEvidence:
    """Execution count and rate extracted from a libFuzzer log."""

    executed_units: int | None
    average_exec_per_second: int | None
    line: str | None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_execution_evidence(log_text: str) -> ExecutionEvidence:
    """Extract the strongest available execution evidence from a log."""
    stat_units: tuple[int, str] | None = None
    fork_units: tuple[int, str] | None = None
    progress_units: tuple[int, str] | None = None
    stat_rate: int | None = None
    progress_rate: int | None = None

    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        stat_exec_match = STAT_EXEC_RE.match(line)
        if stat_exec_match:
            stat_units = (int(stat_exec_match.group(1)), line)

        stat_rate_match = STAT_RATE_RE.match(line)
        if stat_rate_match:
            stat_rate = int(stat_rate_match.group(1))

        fork_match = FORK_EXEC_RE.search(line)
        if fork_match:
            fork_units = (int(fork_match.group(1)), line)

        progress_match = PROGRESS_RE.match(line)
        if progress_match:
            progress_units = (int(progress_match.group(1)), line)
            progress_rate_match = PROGRESS_RATE_RE.search(line)
            if progress_rate_match:
                progress_rate = int(progress_rate_match.group(1))

    units = fork_units or stat_units or progress_units
    return ExecutionEvidence(
        executed_units=units[0] if units else None,
        average_exec_per_second=(stat_rate if stat_rate is not None else progress_rate),
        line=units[1] if units else None,
    )


def _artifact_kind(name: str) -> str:
    for prefix in ("crash-", "leak-", "timeout-", "oom-", "slow-unit-"):
        if name.startswith(prefix):
            return prefix.removesuffix("-")
    return "unknown"


def describe_artifacts(artifact_dir: Path) -> list[dict[str, object]]:
    """Return stable metadata for regular files produced as artifacts."""
    artifacts: list[dict[str, object]] = []
    for path in sorted(artifact_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        artifacts.append(
            {
                "path": str(path.resolve()),
                "relative_path": path.relative_to(artifact_dir).as_posix(),
                "kind": _artifact_kind(path.name),
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return artifacts


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=INTERRUPT_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait()


def _trial_command(
    fuzzer: Path,
    corpus_dir: Path,
    artifact_dir: Path,
    timeout_seconds: int,
    workers: int,
    max_len: int | None,
    unit_timeout_seconds: int | None,
    libfuzzer_seed: int,
) -> list[str]:
    command = [
        str(fuzzer),
        str(corpus_dir),
        f"-artifact_prefix={artifact_dir}{os.sep}",
        f"-max_total_time={timeout_seconds}",
        "-keep_seed=1",
        "-print_final_stats=1",
        "-reload=0",
        f"-seed={libfuzzer_seed}",
    ]
    if workers > 1:
        command.append(f"-fork={workers}")
    if max_len is not None:
        command.append(f"-max_len={max_len}")
    if unit_timeout_seconds is not None:
        command.append(f"-timeout={unit_timeout_seconds}")
    return command


def run_trial(
    *,
    trial_number: int,
    trial_dir: Path,
    fuzzer: Path,
    seed: Path,
    timeout_seconds: int,
    workers: int,
    max_len: int | None,
    unit_timeout_seconds: int | None,
    libfuzzer_seed: int,
) -> dict[str, object]:
    """Run one trial and preserve its corpus, artifacts, and combined log."""
    corpus_dir = trial_dir / "corpus"
    artifact_dir = trial_dir / "artifacts"
    corpus_dir.mkdir(parents=True)
    artifact_dir.mkdir()
    shutil.copyfile(seed, corpus_dir / "seed")

    log_path = trial_dir / "fuzzer.log"
    command = _trial_command(
        fuzzer,
        corpus_dir,
        artifact_dir,
        timeout_seconds,
        workers,
        max_len,
        unit_timeout_seconds,
        libfuzzer_seed,
    )
    started = time.monotonic()
    hard_deadline_exceeded = False

    with log_path.open("wb") as log_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout_seconds + HARD_DEADLINE_SLACK_SECONDS)
        except subprocess.TimeoutExpired:
            hard_deadline_exceeded = True
            _stop_process_group(process)
        except BaseException:
            _stop_process_group(process)
            raise

    elapsed_seconds = time.monotonic() - started
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    evidence = parse_execution_evidence(log_text)
    artifacts = describe_artifacts(artifact_dir)
    artifact_kinds = {cast(str, artifact["kind"]) for artifact in artifacts}
    crash_artifacts = [
        artifact
        for artifact in artifacts
        if cast(str, artifact["kind"]) in ("crash", "leak")
    ]
    libfuzzer_timeout_detected = (
        "timeout" in artifact_kinds or TIMEOUT_RE.search(log_text) is not None
    )
    out_of_memory_detected = (
        "oom" in artifact_kinds or OOM_RE.search(log_text) is not None
    )
    slow_unit_detected = "slow-unit" in artifact_kinds
    failure_signature_detected = (
        FAILURE_RE.search(log_text) is not None and not out_of_memory_detected
    )
    crash_detected = bool(crash_artifacts) or failure_signature_detected

    return_code = process.returncode
    if hard_deadline_exceeded:
        outcome = "hard_timeout"
    elif crash_detected:
        outcome = "crash"
    elif libfuzzer_timeout_detected:
        outcome = "libfuzzer_timeout"
    elif out_of_memory_detected:
        outcome = "out_of_memory"
    elif slow_unit_detected:
        outcome = "slow_unit"
    elif artifacts:
        outcome = "other_artifact"
    elif return_code == 0:
        outcome = "completed_without_crash"
    else:
        outcome = "fuzzer_error"

    return {
        "trial": trial_number,
        "libfuzzer_seed": libfuzzer_seed,
        "command": command,
        "corpus_dir": str(corpus_dir.resolve()),
        "artifact_dir": str(artifact_dir.resolve()),
        "log_path": str(log_path.resolve()),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "return_code": return_code,
        "exit_status": return_code
        if return_code is not None and return_code >= 0
        else None,
        "termination_signal": -return_code
        if return_code is not None and return_code < 0
        else None,
        "hard_deadline_exceeded": hard_deadline_exceeded,
        "executed_units": evidence.executed_units,
        "average_exec_per_second": evidence.average_exec_per_second,
        "execution_evidence": evidence.line,
        "failure_signature_detected": failure_signature_detected,
        "libfuzzer_timeout_detected": libfuzzer_timeout_detected,
        "out_of_memory_detected": out_of_memory_detected,
        "slow_unit_detected": slow_unit_detected,
        "crash_detected": crash_detected,
        "artifacts": artifacts,
        "crash_artifacts": crash_artifacts,
        "outcome": outcome,
    }


def summarize(runs: Sequence[dict[str, object]]) -> dict[str, object]:
    """Summarize crash discovery and execution counts across trials."""
    crashes = [run for run in runs if run["crash_detected"]]
    crash_times = [cast(float, run["elapsed_seconds"]) for run in crashes]
    execution_counts = [
        cast(int, run["executed_units"])
        for run in runs
        if run["executed_units"] is not None
    ]
    return {
        "trials": len(runs),
        "crashes": len(crashes),
        "crash_rate": len(crashes) / len(runs) if runs else 0.0,
        "completed_without_crash": sum(
            run["outcome"] == "completed_without_crash" for run in runs
        ),
        "hard_timeouts": sum(run["outcome"] == "hard_timeout" for run in runs),
        "libfuzzer_timeouts": sum(
            run["outcome"] == "libfuzzer_timeout" for run in runs
        ),
        "out_of_memory": sum(run["outcome"] == "out_of_memory" for run in runs),
        "slow_units": sum(run["outcome"] == "slow_unit" for run in runs),
        "other_artifacts": sum(run["outcome"] == "other_artifact" for run in runs),
        "fuzzer_errors": sum(run["outcome"] == "fuzzer_error" for run in runs),
        "median_time_to_crash_seconds": (
            round(statistics.median(crash_times), 6) if crash_times else None
        ),
        "min_time_to_crash_seconds": round(min(crash_times), 6)
        if crash_times
        else None,
        "total_executed_units": sum(execution_counts) if execution_counts else None,
    }


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _create_output_dir(requested: Path | None) -> Path:
    if requested is None:
        return Path(tempfile.mkdtemp(prefix="fuzzer-discovery-"))
    output_dir = requested.expanduser().resolve()
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise BenchmarkError(
            f"output directory already exists: {output_dir}"
        ) from error
    return output_dir


def _validated_file(path: Path, description: str, executable: bool = False) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except FileNotFoundError as error:
        raise BenchmarkError(f"{description} does not exist: {path}") from error
    if not resolved.is_file():
        raise BenchmarkError(f"{description} is not a regular file: {resolved}")
    if executable and not os.access(resolved, os.X_OK):
        raise BenchmarkError(f"{description} is not executable: {resolved}")
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuzzer", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=Path)
    parser.add_argument("--trials", type=_positive_int, default=10)
    parser.add_argument(
        "--timeout",
        type=_positive_int,
        default=300,
        help="fuzzing seconds per trial (default: 300)",
    )
    parser.add_argument(
        "--workers",
        type=_positive_int,
        default=1,
        help="parallel libFuzzer fork workers per trial (default: 1)",
    )
    parser.add_argument(
        "--max-len",
        type=_positive_int,
        help="maximum generated input length; omitted by default",
    )
    parser.add_argument(
        "--unit-timeout",
        type=_positive_int,
        help="libFuzzer timeout for one input in seconds",
    )
    parser.add_argument("--base-seed", type=_positive_int, default=1)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="new directory for JSON, logs, corpora, and artifacts",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        fuzzer = _validated_file(args.fuzzer, "fuzzer", executable=True)
        seed = _validated_file(args.seed, "seed")
        if args.max_len is not None and args.max_len < seed.stat().st_size:
            raise BenchmarkError(
                f"--max-len ({args.max_len}) is smaller than the seed "
                f"({seed.stat().st_size} bytes)"
            )
        output_dir = _create_output_dir(args.output_dir)
    except BenchmarkError as error:
        parser.error(str(error))

    started_at = dt.datetime.now(dt.timezone.utc)
    runs: list[dict[str, object]] = []
    for index in range(args.trials):
        trial_number = index + 1
        trial_dir = output_dir / f"trial-{trial_number:03d}"
        run = run_trial(
            trial_number=trial_number,
            trial_dir=trial_dir,
            fuzzer=fuzzer,
            seed=seed,
            timeout_seconds=args.timeout,
            workers=args.workers,
            max_len=args.max_len,
            unit_timeout_seconds=args.unit_timeout,
            libfuzzer_seed=args.base_seed + index,
        )
        runs.append(run)
        units = run["executed_units"]
        units_text = f", {units} units" if units is not None else ""
        print(
            f"trial {trial_number}/{args.trials}: {run['outcome']} after "
            f"{run['elapsed_seconds']:.2f}s{units_text}"
        )

    summary = summarize(runs)
    document = {
        "schema_version": 1,
        "measurement": "libfuzzer_time_to_crash",
        "started_at": started_at.isoformat(),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "configuration": {
            "fuzzer": str(fuzzer),
            "seed": str(seed),
            "seed_size": seed.stat().st_size,
            "seed_sha256": _sha256(seed),
            "trials": args.trials,
            "timeout_seconds": args.timeout,
            "workers": args.workers,
            "max_len": args.max_len,
            "unit_timeout_seconds": args.unit_timeout,
            "base_seed": args.base_seed,
            "output_dir": str(output_dir.resolve()),
        },
        "runs": runs,
        "summary": summary,
    }
    json_path = output_dir / "results.json"
    with json_path.open("x", encoding="utf-8") as output:
        json.dump(document, output, indent=2, sort_keys=True)
        output.write("\n")

    print(
        f"summary: {summary['crashes']}/{summary['trials']} trials found a crash; "
        f"results: {json_path.resolve()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
