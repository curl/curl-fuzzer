"""Collect a reproducible Linux perf profile from one libFuzzer target."""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from types import FrameType

from .fuzzer_corpus import (
    CorpusError,
    CorpusSnapshotBuilder,
    resolve_corpus_sources,
    sha256_file,
)
from .source_checkout import find_source_checkout

INTERRUPT_GRACE_SECONDS = 3
DEFAULT_INPUT_TIMEOUT_SECONDS = 10
DEFAULT_REPORT_TIMEOUT_SECONDS = 120
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
PROVENANCE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
FUZZER_ARGUMENT_RE = re.compile(r"^-(?P<key>[A-Za-z0-9_]+)=(?P<value>.+)$")
STAT_EXEC_RE = re.compile(r"^stat::number_of_executed_units:\s*(\d+)\s*$")
STAT_RATE_RE = re.compile(r"^stat::average_exec_per_sec:\s*(\d+)\s*$")
REPORT_ROW_RE = re.compile(r"^\s*\d+(?:\.\d+)?%\s+", re.MULTILINE)


SOURCE_CHECKOUT = find_source_checkout()
DEFAULT_CORPUS_ROOT = SOURCE_CHECKOUT / "corpora" if SOURCE_CHECKOUT else None

# These options define the measurement itself or switch libFuzzer into another
# operating mode. Accepting them through --fuzzer-arg would make the recorded
# configuration disagree with the process that actually ran.
MANAGED_FUZZER_OPTIONS = frozenset(
    {
        "artifact_prefix",
        "analyze_dict",
        "cleanse_crash",
        "close_fd_mask",
        "collect_data_flow",
        "error_exitcode",
        "exact_artifact_path",
        "exit_on_item",
        "exit_on_src_pos",
        "fork",
        "help",
        "ignore_remaining_args",
        "interrupt_exitcode",
        "jobs",
        "max_total_time",
        "merge",
        "merge_control_file",
        "merge_inner",
        "minimize_crash",
        "minimize_crash_internal_step",
        "oom_exitcode",
        "print_final_stats",
        "reload",
        "runs",
        "seed",
        "set_cover_merge",
        "stop_file",
        "timeout",
        "timeout_exitcode",
        "workers",
    }
)


class ProfileError(RuntimeError):
    """Raised for an invalid profiling configuration."""


@dataclass(frozen=True)
class FuzzerOptions:
    """Effective settings loaded from an OSS-Fuzz options file."""

    path: Path | None
    sha256: str | None
    values: dict[str, str]
    arguments: tuple[str, ...]
    timeout: int
    dictionary: FileIdentity | None


@dataclass(frozen=True)
class FileIdentity:
    """Stable identity for a file that affects the measured workload."""

    path: Path
    bytes: int
    sha256: str


@dataclass(frozen=True)
class ExecutionEvidence:
    """Final execution metrics emitted by libFuzzer."""

    executed_units: int | None
    average_exec_per_second: int | None


@dataclass(frozen=True)
class ProcessResult:
    """Outcome of the perf record process tree."""

    returncode: int | None
    elapsed_seconds: float
    timed_out: bool


@dataclass(frozen=True)
class ProfileResult:
    """Files and status produced by one sampling run."""

    status: str
    failure: str | None
    process: ProcessResult
    evidence: ExecutionEvidence
    command: tuple[str, ...]
    report_command: tuple[str, ...] | None
    report_returncode: int | None
    top_rows: tuple[str, ...]


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--binary-dir",
        required=True,
        type=Path,
        help="directory containing the libFuzzer binary and packaged options",
    )
    parser.add_argument("--target", required=True, help="fuzzer binary name")
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="new directory for perf data, reports, logs, and metadata",
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=DEFAULT_CORPUS_ROOT,
        help="root containing checked-in per-target corpora",
    )
    parser.add_argument(
        "--public-corpus-root",
        type=Path,
        help="optional root containing downloaded OSS-Fuzz corpora",
    )
    parser.add_argument(
        "--corpus",
        action="append",
        default=[],
        type=Path,
        help="replace the default corpus sources; repeat to combine sources",
    )
    parser.add_argument(
        "--options-file",
        type=Path,
        help=(
            "libFuzzer options file; defaults to TARGET.options beside the "
            "binary or under ossconfig/"
        ),
    )
    parser.add_argument("--seconds", type=_positive_int, default=60)
    parser.add_argument("--seed", type=_positive_int, default=101)
    parser.add_argument(
        "--timeout",
        type=_positive_int,
        help="per-input timeout; defaults to the options file or 10 seconds",
    )
    parser.add_argument(
        "--wall-timeout",
        type=_positive_int,
        help="outer timeout; defaults to max(60, 4 * seconds + 30)",
    )
    parser.add_argument("--frequency", type=_positive_int, default=99)
    parser.add_argument(
        "--event",
        default="cpu-clock:u",
        help="perf sampling event",
    )
    parser.add_argument(
        "--call-graph",
        choices=("fp", "dwarf"),
        default="fp",
        help="perf stack-unwinding method",
    )
    parser.add_argument(
        "--cpu",
        type=_nonnegative_int,
        help="pin the fuzzer to this logical CPU with taskset",
    )
    parser.add_argument(
        "--fuzzer-arg",
        action="append",
        default=[],
        help="extra libFuzzer argument (use --fuzzer-arg=-max_len=...)",
    )
    parser.add_argument(
        "--perf",
        default="perf",
        help="perf executable name or path",
    )
    parser.add_argument(
        "--provenance",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="record build or CI provenance; repeat for multiple values",
    )
    return parser


def _resolve_directory(path: Path, description: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except FileNotFoundError as error:
        raise ProfileError(f"{description} does not exist: {path}") from error
    if not resolved.is_dir():
        raise ProfileError(f"{description} is not a directory: {resolved}")
    return resolved


def _resolve_file(path: Path, description: str, *, executable: bool = False) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except FileNotFoundError as error:
        raise ProfileError(f"{description} does not exist: {path}") from error
    if not resolved.is_file():
        raise ProfileError(f"{description} is not a regular file: {resolved}")
    if executable and not os.access(resolved, os.X_OK):
        raise ProfileError(f"{description} is not executable: {resolved}")
    return resolved


def _resolve_tool(command: str) -> Path:
    candidate = Path(command).expanduser()
    if candidate.is_absolute() or candidate.parent != Path("."):
        return _resolve_file(candidate, "perf", executable=True)
    found = shutil.which(command)
    if found is None:
        raise ProfileError(f"perf executable was not found: {command!r}")
    return Path(found).resolve()


def _tool_version(tool: Path, environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            [str(tool), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProfileError(f"could not inspect perf: {error}") from error
    version = next((line.strip() for line in result.stdout.splitlines() if line), "")
    if result.returncode != 0 or not version:
        raise ProfileError(f"perf version check exited with status {result.returncode}")
    return version


def _run_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    environment["PERF_CONFIG"] = "/dev/null"
    environment["PERF_PAGER"] = "cat"
    return environment


def _validate_fuzzer(binary: Path, environment: dict[str, str]) -> None:
    try:
        result = subprocess.run(
            [str(binary), "-help=1"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProfileError(
            f"could not inspect fuzzer binary {binary}: {error}"
        ) from error
    if result.returncode != 0 or "max_total_time" not in result.stdout:
        raise ProfileError(
            f"{binary} does not appear to be a production libFuzzer binary"
        )


def _argument_parts(argument: str) -> tuple[str, str]:
    match = FUZZER_ARGUMENT_RE.fullmatch(argument)
    if match is None:
        raise ProfileError(
            "fuzzer argument must have exactly one leading '-' and a non-empty "
            f"value (-name=value): {argument!r}"
        )
    return match.group("key"), match.group("value")


def _file_identity(path: Path, description: str) -> FileIdentity:
    resolved = _resolve_file(path, description)
    return FileIdentity(
        path=resolved,
        bytes=resolved.stat().st_size,
        sha256=sha256_file(resolved),
    )


def _validate_extra_arguments(
    arguments: Sequence[str],
) -> tuple[tuple[str, ...], FileIdentity | None]:
    validated: list[str] = []
    dictionary: FileIdentity | None = None
    for argument in arguments:
        key, value = _argument_parts(argument)
        if key in MANAGED_FUZZER_OPTIONS:
            raise ProfileError(f"fuzzer argument is managed by this tool: {argument}")
        if key == "dict":
            dictionary = _file_identity(
                Path(value).expanduser(), "libFuzzer dictionary"
            )
            argument = f"-dict={dictionary.path}"
        validated.append(argument)
    return tuple(validated), dictionary


def _discover_options_file(
    explicit: Path | None, binary_dir: Path, target: str
) -> Path | None:
    if explicit is not None:
        return _resolve_file(explicit, "options file")
    candidates = [binary_dir / f"{target}.options"]
    if SOURCE_CHECKOUT is not None:
        candidates.append(SOURCE_CHECKOUT / "ossconfig" / f"{target}.options")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def _load_fuzzer_options(
    path: Path | None,
    explicit_timeout: int | None,
    extra_arguments: Sequence[str],
    extra_dictionary: FileIdentity | None,
) -> FuzzerOptions:
    values: dict[str, str] = {}
    if path is not None:
        parser = configparser.ConfigParser(interpolation=None)
        try:
            with path.open(encoding="utf-8") as stream:
                parser.read_file(stream)
        except (OSError, configparser.Error) as error:
            raise ProfileError(
                f"could not parse options file {path}: {error}"
            ) from error
        if not parser.has_section("libfuzzer"):
            raise ProfileError(f"options file has no [libfuzzer] section: {path}")
        values = dict(parser.items("libfuzzer"))

    raw_timeout = values.pop("timeout", None)
    options_timeout: int | None = None
    if raw_timeout is not None:
        try:
            options_timeout = int(raw_timeout)
        except ValueError as error:
            raise ProfileError(
                f"invalid timeout in options file {path}: {raw_timeout!r}"
            ) from error
        if options_timeout <= 0:
            raise ProfileError(f"timeout in options file must be positive: {path}")
    timeout = explicit_timeout or options_timeout or DEFAULT_INPUT_TIMEOUT_SECONDS

    extra_keys = {_argument_parts(argument)[0] for argument in extra_arguments}
    arguments: list[str] = []
    normalized_values: dict[str, str] = {}
    options_dictionary: FileIdentity | None = None
    for key, value in values.items():
        if not re.fullmatch(r"[A-Za-z0-9_]+", key):
            raise ProfileError(f"invalid libFuzzer option name in {path}: {key!r}")
        if key in MANAGED_FUZZER_OPTIONS:
            raise ProfileError(
                f"options file requests unsupported mode {key!r}: {path}"
            )
        normalized = value
        if key == "dict" and key not in extra_keys:
            dictionary_path = Path(value).expanduser()
            if not dictionary_path.is_absolute():
                if path is None:
                    raise ProfileError("relative dictionary requires an options file")
                dictionary_path = path.parent / dictionary_path
            options_dictionary = _file_identity(dictionary_path, "libFuzzer dictionary")
            normalized = str(options_dictionary.path)
        normalized_values[key] = normalized
        if key not in extra_keys:
            arguments.append(f"-{key}={normalized}")

    return FuzzerOptions(
        path=path,
        sha256=sha256_file(path) if path is not None else None,
        values={**normalized_values, "timeout": str(timeout)},
        arguments=tuple(arguments),
        timeout=timeout,
        dictionary=extra_dictionary or options_dictionary,
    )


def _parse_provenance(values: Sequence[str]) -> dict[str, str]:
    provenance: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ProfileError(f"invalid --provenance {value!r}; expected KEY=VALUE")
        key, raw_value = value.split("=", 1)
        if not PROVENANCE_KEY_RE.fullmatch(key) or not raw_value:
            raise ProfileError(
                f"invalid --provenance {value!r}; expected non-empty KEY=VALUE"
            )
        if key in provenance:
            raise ProfileError(f"duplicate provenance key: {key}")
        provenance[key] = raw_value
    return provenance


def _create_output_dir(path: Path) -> Path:
    output_dir = path.expanduser().resolve()
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise ProfileError(f"output directory already exists: {output_dir}") from error
    return output_dir


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        process.poll()
        return

    deadline = time.monotonic() + INTERRUPT_GRACE_SECONDS
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)

    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        process.wait()


@contextmanager
def _exit_on_termination_signals() -> Iterator[None]:
    def exit_for_signal(signum: int, _frame: FrameType | None) -> None:
        raise SystemExit(128 + signum)

    handled_signals = (signal.SIGTERM, signal.SIGHUP)
    previous_handlers = {signum: signal.getsignal(signum) for signum in handled_signals}
    for signum in handled_signals:
        signal.signal(signum, exit_for_signal)
    try:
        yield
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def _run_process_tree(
    command: Sequence[str],
    log_path: Path,
    wall_timeout: int,
    environment: dict[str, str],
) -> ProcessResult:
    started = time.monotonic()
    timed_out = False
    with log_path.open("wb") as log_file:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=environment,
            )
        except OSError as error:
            raise ProfileError(f"could not start perf: {error}") from error
        with _exit_on_termination_signals():
            try:
                process.wait(timeout=wall_timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _stop_process_group(process)
            except BaseException:
                _stop_process_group(process)
                raise
    return ProcessResult(
        returncode=process.returncode,
        elapsed_seconds=round(time.monotonic() - started, 6),
        timed_out=timed_out,
    )


def _execution_evidence(log_text: str) -> ExecutionEvidence:
    executed_units: int | None = None
    average_exec_per_second: int | None = None
    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        executed_match = STAT_EXEC_RE.match(line)
        if executed_match:
            executed_units = int(executed_match.group(1))
        rate_match = STAT_RATE_RE.match(line)
        if rate_match:
            average_exec_per_second = int(rate_match.group(1))
    return ExecutionEvidence(executed_units, average_exec_per_second)


def _record_command(
    *,
    perf: Path,
    perf_data: Path,
    event: str,
    frequency: int,
    call_graph: str,
    cpu: int | None,
    binary: Path,
    corpus: Path,
    artifacts: Path,
    seconds: int,
    seed: int,
    timeout: int,
    options_arguments: Sequence[str],
    extra_arguments: Sequence[str],
) -> tuple[str, ...]:
    unwind = "dwarf,16384" if call_graph == "dwarf" else "fp"
    workload: list[str] = []
    if cpu is not None:
        taskset = shutil.which("taskset")
        if taskset is None:
            raise ProfileError("--cpu requires the taskset command")
        workload.extend((taskset, "-c", str(cpu)))
    workload.extend(
        (
            str(binary),
            f"-seed={seed}",
            f"-max_total_time={seconds}",
            f"-timeout={timeout}",
            "-reload=0",
            "-print_final_stats=1",
            f"-artifact_prefix={artifacts}{os.sep}",
            *options_arguments,
            *extra_arguments,
            str(corpus),
        )
    )
    return (
        str(perf),
        "record",
        "--event",
        event,
        "--freq",
        str(frequency),
        "--call-graph",
        unwind,
        "--output",
        str(perf_data),
        "--",
        *workload,
    )


def _profile(
    *,
    command: tuple[str, ...],
    perf: Path,
    perf_data: Path,
    report_path: Path,
    log_path: Path,
    wall_timeout: int,
    environment: dict[str, str],
) -> ProfileResult:
    try:
        process = _run_process_tree(command, log_path, wall_timeout, environment)
    except ProfileError as error:
        return ProfileResult(
            status="failed",
            failure=str(error),
            process=ProcessResult(
                returncode=None,
                elapsed_seconds=0.0,
                timed_out=False,
            ),
            evidence=ExecutionEvidence(None, None),
            command=command,
            report_command=None,
            report_returncode=None,
            top_rows=(),
        )
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    evidence = _execution_evidence(log_text)
    failures: list[str] = []
    if process.timed_out:
        failures.append(f"profile exceeded the {wall_timeout}s wall timeout")
    elif process.returncode != 0:
        failures.append(f"perf record exited with status {process.returncode}")
    if evidence.executed_units is None or evidence.executed_units <= 0:
        failures.append("libFuzzer did not report any executed units")

    report_command: tuple[str, ...] | None = None
    report_returncode: int | None = None
    top_rows: tuple[str, ...] = ()
    if not perf_data.is_file() or perf_data.stat().st_size == 0:
        failures.append("perf record produced no sampling data")
    else:
        report_command = (
            str(perf),
            "report",
            "--stdio",
            "--call-graph",
            "none",
            "--stdio-color=never",
            "--input",
            str(perf_data),
            "--header",
            "--show-nr-samples",
            "--no-children",
            "--percent-limit",
            "0",
            "--sort",
            "comm,dso,symbol",
        )
        try:
            with report_path.open("wb") as report_file:
                report = subprocess.run(
                    report_command,
                    check=False,
                    stdout=report_file,
                    stderr=subprocess.STDOUT,
                    timeout=DEFAULT_REPORT_TIMEOUT_SECONDS,
                    env=environment,
                )
            report_returncode = report.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            failures.append(f"could not render perf report: {error}")
        else:
            if report.returncode != 0:
                failures.append(f"perf report exited with status {report.returncode}")
            report_text = report_path.read_text(encoding="utf-8", errors="replace")
            top_rows = tuple(
                line.rstrip()
                for line in report_text.splitlines()
                if REPORT_ROW_RE.match(line)
            )
            if not top_rows:
                failures.append("perf report contained no sampled symbols")

    failure = "; ".join(failures) if failures else None
    return ProfileResult(
        status="failed" if failure else "ok",
        failure=failure,
        process=process,
        evidence=evidence,
        command=command,
        report_command=report_command,
        report_returncode=report_returncode,
        top_rows=top_rows,
    )


def _git_revision() -> str | None:
    if SOURCE_CHECKOUT is None:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(SOURCE_CHECKOUT), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _optional_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _describe_artifacts(artifact_dir: Path) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for path in sorted(artifact_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        artifacts.append(
            {
                "path": path.relative_to(artifact_dir).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return artifacts


def _display_command(command: Sequence[str], corpus: Path) -> list[str]:
    return ["<corpus>" if item == str(corpus) else item for item in command]


def _metadata_document(
    *,
    started_at: dt.datetime,
    target: str,
    binary: Path,
    corpus: Path,
    corpus_metadata: dict[str, object],
    fuzzer_options: FuzzerOptions,
    extra_arguments: Sequence[str],
    perf: Path,
    perf_version: str,
    event: str,
    frequency: int,
    call_graph: str,
    seconds: int,
    seed: int,
    wall_timeout: int,
    cpu: int | None,
    provenance: dict[str, str],
    result: ProfileResult,
    artifact_dir: Path,
) -> dict[str, object]:
    affinity = (
        sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    )
    return {
        "schema_version": 1,
        "measurement": "perf_cpu_sampling",
        "started_at": started_at.isoformat(),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": result.status,
        "failure": result.failure,
        "repository_revision": _git_revision(),
        "provenance": provenance,
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "affinity": affinity,
            "perf_event_paranoid": _optional_text(
                Path("/proc/sys/kernel/perf_event_paranoid")
            ),
            "kptr_restrict": _optional_text(Path("/proc/sys/kernel/kptr_restrict")),
        },
        "configuration": {
            "target": target,
            "seconds": seconds,
            "seed": seed,
            "timeout": fuzzer_options.timeout,
            "wall_timeout": wall_timeout,
            "cpu": cpu,
            "event": event,
            "frequency": frequency,
            "call_graph": call_graph,
            "fuzzer_arguments": [
                *fuzzer_options.arguments,
                *extra_arguments,
            ],
        },
        "binary": {
            "path": str(binary),
            "bytes": binary.stat().st_size,
            "sha256": sha256_file(binary),
        },
        "corpus": corpus_metadata,
        "options": {
            "path": str(fuzzer_options.path) if fuzzer_options.path else None,
            "sha256": fuzzer_options.sha256,
            "values": fuzzer_options.values,
            "dictionary": (
                {
                    "path": str(fuzzer_options.dictionary.path),
                    "bytes": fuzzer_options.dictionary.bytes,
                    "sha256": fuzzer_options.dictionary.sha256,
                }
                if fuzzer_options.dictionary is not None
                else None
            ),
        },
        "perf": {
            "path": str(perf),
            "version": perf_version,
            "command": _display_command(result.command, corpus),
            "report_command": list(result.report_command)
            if result.report_command is not None
            else None,
            "returncode": result.process.returncode,
            "report_returncode": result.report_returncode,
            "timed_out": result.process.timed_out,
            "elapsed_seconds": result.process.elapsed_seconds,
        },
        "execution": {
            "executed_units": result.evidence.executed_units,
            "average_exec_per_second": result.evidence.average_exec_per_second,
        },
        "artifacts": _describe_artifacts(artifact_dir),
    }


def _summary_text(
    target: str,
    metadata: dict[str, object],
    result: ProfileResult,
) -> str:
    binary = metadata["binary"]
    corpus = metadata["corpus"]
    execution = metadata["execution"]
    configuration = metadata["configuration"]
    if not isinstance(binary, dict):
        raise ProfileError("internal binary metadata is invalid")
    if not isinstance(corpus, dict):
        raise ProfileError("internal corpus metadata is invalid")
    if not isinstance(execution, dict):
        raise ProfileError("internal execution metadata is invalid")
    if not isinstance(configuration, dict):
        raise ProfileError("internal metadata structure is invalid")
    lines = [
        f"# Fuzzer CPU profile: `{target}`",
        "",
        f"Status: **{result.status}**",
        "",
    ]
    if result.failure is not None:
        lines.extend((f"Failure: {result.failure}", ""))
    lines.extend(
        (
            f"- Duration: {configuration['seconds']} seconds",
            (f"- Event: `{configuration['event']}` at {configuration['frequency']} Hz"),
            f"- Executed units: {execution['executed_units']}",
            (f"- Average executions/second: {execution['average_exec_per_second']}"),
            f"- Binary SHA-256: `{binary['sha256']}`",
            (
                f"- Corpus: {corpus['count']} inputs, {corpus['bytes']} bytes, "
                f"SHA-256 `{corpus['sha256']}`"
            ),
            "",
            "## Top sampled symbols",
            "",
        )
    )
    if result.top_rows:
        lines.append("```text")
        lines.extend(result.top_rows[:15])
        lines.append("```")
    else:
        lines.append("No sampled symbols were available.")
    lines.extend(
        (
            "",
            (
                "The profile identifies where CPU time was sampled. Use the "
                "repeatable benchmark to confirm whether a change improves throughput."
            ),
            "",
        )
    )
    return "\n".join(lines)


def _validate_cpu(cpu: int | None) -> None:
    if cpu is None or not hasattr(os, "sched_getaffinity"):
        return
    affinity = os.sched_getaffinity(0)
    if cpu not in affinity:
        allowed = ", ".join(str(value) for value in sorted(affinity))
        raise ProfileError(f"CPU {cpu} is outside this process's affinity: {allowed}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if not TARGET_RE.fullmatch(args.target):
            raise ProfileError(f"invalid target name: {args.target!r}")
        if not args.event:
            raise ProfileError("--event must not be empty")
        _validate_cpu(args.cpu)
        binary_dir = _resolve_directory(args.binary_dir, "binary directory")
        binary = _resolve_file(
            binary_dir / args.target, "fuzzer binary", executable=True
        )
        perf = _resolve_tool(args.perf)
        environment = _run_environment()
        perf_version = _tool_version(perf, environment)
        _validate_fuzzer(binary, environment)
        extra_arguments, extra_dictionary = _validate_extra_arguments(args.fuzzer_arg)
        options_path = _discover_options_file(
            args.options_file, binary_dir, args.target
        )
        fuzzer_options = _load_fuzzer_options(
            options_path,
            args.timeout,
            extra_arguments,
            extra_dictionary,
        )
        provenance = _parse_provenance(args.provenance)
        if args.corpus:
            sources = list(args.corpus)
        else:
            corpus_root = (
                _resolve_directory(args.corpus_root, "corpus root")
                if args.corpus_root is not None
                else None
            )
            public_corpus_root = (
                _resolve_directory(args.public_corpus_root, "public corpus root")
                if args.public_corpus_root is not None
                else None
            )
            sources = resolve_corpus_sources(
                args.target,
                binary_dir,
                corpus_root,
                public_corpus_root,
                {},
            )
        wall_timeout = args.wall_timeout or max(60, args.seconds * 4 + 30)

        with tempfile.TemporaryDirectory(prefix="curl-fuzzer-profile-") as raw_temp:
            corpus = Path(raw_temp) / "corpus"
            builder = CorpusSnapshotBuilder(corpus)
            for source in sources:
                builder.add(source)
            corpus_metadata = builder.metadata()
            if corpus_metadata["count"] == 0:
                raise ProfileError(f"corpus for {args.target} is empty")

            output_dir = _create_output_dir(args.output_dir)
            corpus_archive = output_dir / "corpus.zip"
            builder.write_zip(corpus_archive)
            corpus_metadata["archive"] = {
                "path": corpus_archive.name,
                "bytes": corpus_archive.stat().st_size,
                "sha256": sha256_file(corpus_archive),
            }
            artifact_dir = output_dir / "artifacts"
            artifact_dir.mkdir()
            perf_data = output_dir / "perf.data"
            report_path = output_dir / "perf-report.txt"
            log_path = output_dir / "fuzzer.log"
            command = _record_command(
                perf=perf,
                perf_data=perf_data,
                event=args.event,
                frequency=args.frequency,
                call_graph=args.call_graph,
                cpu=args.cpu,
                binary=binary,
                corpus=corpus,
                artifacts=artifact_dir,
                seconds=args.seconds,
                seed=args.seed,
                timeout=fuzzer_options.timeout,
                options_arguments=fuzzer_options.arguments,
                extra_arguments=extra_arguments,
            )
            started_at = dt.datetime.now(dt.timezone.utc)
            result = _profile(
                command=command,
                perf=perf,
                perf_data=perf_data,
                report_path=report_path,
                log_path=log_path,
                wall_timeout=wall_timeout,
                environment=environment,
            )
            metadata = _metadata_document(
                started_at=started_at,
                target=args.target,
                binary=binary,
                corpus=corpus,
                corpus_metadata=corpus_metadata,
                fuzzer_options=fuzzer_options,
                extra_arguments=extra_arguments,
                perf=perf,
                perf_version=perf_version,
                event=args.event,
                frequency=args.frequency,
                call_graph=args.call_graph,
                seconds=args.seconds,
                seed=args.seed,
                wall_timeout=wall_timeout,
                cpu=args.cpu,
                provenance=provenance,
                result=result,
                artifact_dir=artifact_dir,
            )
            (output_dir / "metadata.json").write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (output_dir / "summary.md").write_text(
                _summary_text(args.target, metadata, result), encoding="utf-8"
            )

        print(f"Profile: {output_dir}")
        if result.status != "ok":
            print(f"profile failed: {result.failure}", file=sys.stderr)
            return 1
        return 0
    except (CorpusError, ProfileError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
