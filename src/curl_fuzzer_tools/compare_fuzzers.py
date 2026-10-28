"""
Benchmark and compare production-style libFuzzer binaries.

The helper keeps seeds and fuzzer arguments fixed between variants. Each run
receives a fresh content-addressed corpus snapshot, so discoveries or
reductions cannot influence later runs. Same-name targets share one snapshot;
explicit legacy-to-proto target pairs use their respective native formats.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar

from .coverage_parity import (
    TARGET_NAME_RE,
    CoverageParityError,
    CoverageUniverse,
    DuplicateJsonKeyError,
    ParityManifest,
    evaluate_parity,
    load_parity_manifest,
    strict_json_loads,
    validate_baseline_corpora,
    validate_live_inventory,
    validate_manifest_progression,
    validate_source_identity,
)
from .fuzzer_corpus import (
    CorpusError,
    CorpusSnapshotBuilder,
    parse_corpus_mappings,
    resolve_corpus_sources,
    sha256_file,
)
from .source_checkout import find_source_checkout

SOURCE_CHECKOUT = find_source_checkout()
REPO_ROOT = SOURCE_CHECKOUT or Path.cwd()
DEFAULT_TARGETS = (
    "curl_fuzzer_ftp",
    "curl_fuzzer_http",
    "curl_fuzzer_tftp",
    "curl_fuzzer_proto_http",
    "curl_fuzzer_proto_http_deep",
    "curl_fuzzer_proto_http2",
    "curl_fuzzer_proto_https",
    "curl_fuzzer_proto_https_h2",
    "curl_fuzzer_proto_https_gnutls",
    "curl_fuzzer_proto_https_mbedtls",
    "curl_fuzzer_proto_http3",
    "curl_fuzzer_proto_h2_proxy",
    "curl_fuzzer_proto_socks4",
    "curl_fuzzer_proto_resolver",
    "curl_fuzzer_proto_ws",
    "curl_fuzzer_proto_wss",
    "curl_fuzzer_proto_telnet",
    "curl_fuzzer_proto_ftp",
    "curl_fuzzer_proto_tftp",
    "curl_fuzzer_proto_smtp",
    "curl_fuzzer_proto_imap",
    "curl_fuzzer_proto_pop3",
    "curl_fuzzer_proto_mqtt",
    "curl_fuzzer_proto_dict",
    "curl_fuzzer_proto_file",
    "curl_fuzzer_proto_ldap",
    "curl_fuzzer_proto_rtsp",
    "curl_fuzzer_proto_ipfs",
    "curl_fuzzer_proto_api",
    "curl_fuzzer_proto_multi",
    "curl_fuzzer_proto_timing",
)
MANAGED_FUZZER_ARGS = (
    "-artifact_prefix=",
    "-max_total_time=",
    "-print_final_stats=",
    "-reload=",
    "-seed=",
    "-timeout=",
)
REPLAY_COUNTER_NAMES = (
    "attempted",
    "completed",
    "timed_out",
    "input_errors",
    "path_errors",
)
DEFAULT_COVERAGE_WALL_TIMEOUT = 300
DEFAULT_COVERAGE_INPUT_TIMEOUT = 25
PARITY_COVERAGE_WALL_TIMEOUT = 7200
LLVM_COVERAGE_COUNTER_SATURATION = (1 << 63) - 1
COVERAGE_REPLAY_SANITIZER_ENVIRONMENT: dict[str, str | None] = {
    "ASAN_OPTIONS": "detect_leaks=0",
    "LSAN_OPTIONS": None,
}

EVENT_RE = re.compile(
    r"^#(?P<units>\d+)\s+"
    r"(?P<event>INITED|DONE|pulse|NEW|REDUCE|RELOAD)\s+"
    r"cov:\s*(?P<cov>\d+)\s+ft:\s*(?P<ft>\d+)\s+"
    r"corp:\s*(?P<corpus_count>\d+)/(?P<corpus_size>\S+)"
    r"(?:.*?exec/s:\s*(?P<exec_per_second>\d+))?"
)
STAT_RE = re.compile(r"^stat::(?P<name>[a-z_]+):\s*(?P<value>\d+)\s*$")


class MeasurementError(RuntimeError):
    """Raised for invalid configuration or unavailable measurement inputs."""


@dataclass(frozen=True)
class Variant:
    """A named directory containing libFuzzer binaries."""

    name: str
    binary_dir: Path


@dataclass(frozen=True)
class TargetPair:
    """Baseline and candidate binary names participating in one comparison."""

    baseline_target: str
    candidate_target: str

    @property
    def label(self) -> str:
        if self.baseline_target == self.candidate_target:
            return self.baseline_target
        return f"{self.baseline_target}=>{self.candidate_target}"

    def target_for(self, variant: str) -> str:
        return self.baseline_target if variant == "baseline" else self.candidate_target


@dataclass(frozen=True)
class ParsedOutput:
    """Metrics parsed from one libFuzzer log."""

    initial: dict[str, object] | None
    final: dict[str, object] | None
    stats: dict[str, int]


FunctionKey = tuple[str, str]
RegionKey = tuple[str, str, int, int, int, int]
CoverageKey = TypeVar("CoverageKey", FunctionKey, RegionKey)


@dataclass(frozen=True)
class SourceCoverageIndex:
    """Stable curl-relative identities extracted from one llvm-cov export."""

    functions: frozenset[FunctionKey]
    covered_functions: frozenset[FunctionKey]
    regions: frozenset[RegionKey]
    covered_regions: frozenset[RegionKey]


def _event_to_dict(match: re.Match[str]) -> dict[str, object]:
    """Convert one libFuzzer progress line to JSON-friendly values."""
    values: dict[str, object] = {
        "event": match.group("event"),
        "executed_units": int(match.group("units")),
        "cov": int(match.group("cov")),
        "ft": int(match.group("ft")),
        "corpus_count": int(match.group("corpus_count")),
        "corpus_size": match.group("corpus_size"),
    }
    exec_per_second = match.group("exec_per_second")
    if exec_per_second is not None:
        values["exec_per_second"] = int(exec_per_second)
    return values


def parse_libfuzzer_output(text: str) -> ParsedOutput:
    """Parse initialization, final coverage, and final statistics."""
    initial: dict[str, object] | None = None
    final: dict[str, object] | None = None
    latest: dict[str, object] | None = None
    stats: dict[str, int] = {}

    for line in text.splitlines():
        event_match = EVENT_RE.match(line.strip())
        if event_match:
            event = _event_to_dict(event_match)
            latest = event
            if event["event"] == "INITED":
                initial = event
            if event["event"] == "DONE":
                final = event

        stat_match = STAT_RE.match(line.strip())
        if stat_match:
            stats[stat_match.group("name")] = int(stat_match.group("value"))

    return ParsedOutput(initial=initial, final=final or latest, stats=stats)


def _curl_relative_path(filename: str, source_root: Path) -> str | None:
    """Normalize one llvm-cov filename to a curl-root-relative path."""
    path = Path(filename)
    if not path.is_absolute():
        path = source_root / path
    try:
        relative = path.resolve().relative_to(source_root.resolve())
    except ValueError:
        return None
    if not relative.parts or relative.parts[0] not in ("lib", "src"):
        return None
    return relative.as_posix()


def _validated_coverage_count(value: object, *, subject: str) -> int:
    """Validate one llvm-cov execution count without coercion."""
    if type(value) is not int:
        raise MeasurementError(
            f"llvm-cov export contained a non-integer {subject}: {value!r}"
        )
    if value < 0:
        raise MeasurementError(
            f"llvm-cov export contained a negative {subject}: {value}"
        )
    if value >= LLVM_COVERAGE_COUNTER_SATURATION:
        raise MeasurementError(
            "llvm-cov export contained a saturated or out-of-range "
            f"{subject}: {value}; "
            f"expected less than INT64_MAX "
            f"({LLVM_COVERAGE_COUNTER_SATURATION})"
        )
    return value


def parse_source_coverage_export(
    document: object, source_root: Path
) -> SourceCoverageIndex:
    """Extract covered curl functions and code regions from llvm-cov JSON."""
    if not isinstance(document, dict):
        raise MeasurementError("llvm-cov export was not a JSON object")
    raw_data = document.get("data")
    if not isinstance(raw_data, list) or not raw_data:
        raise MeasurementError("llvm-cov export did not contain coverage data")

    functions: set[FunctionKey] = set()
    covered_functions: set[FunctionKey] = set()
    regions: set[RegionKey] = set()
    covered_regions: set[RegionKey] = set()

    for data_entry in raw_data:
        if not isinstance(data_entry, dict):
            continue
        raw_functions = data_entry.get("functions")
        if not isinstance(raw_functions, list):
            continue
        for raw_function in raw_functions:
            if not isinstance(raw_function, dict):
                continue
            name = raw_function.get("name")
            raw_filenames = raw_function.get("filenames")
            if not isinstance(name, str) or not isinstance(raw_filenames, list):
                continue
            normalized_filenames = [
                _curl_relative_path(filename, source_root)
                if isinstance(filename, str)
                else None
                for filename in raw_filenames
            ]
            anchor = next(
                (filename for filename in normalized_filenames if filename is not None),
                None,
            )
            if anchor is None:
                continue

            function_key = (anchor, name)
            functions.add(function_key)
            function_count = _validated_coverage_count(
                raw_function.get("count"),
                subject=f"function count for {name!r} at {anchor}",
            )
            if function_count > 0:
                covered_functions.add(function_key)

            raw_regions = raw_function.get("regions")
            if not isinstance(raw_regions, list):
                continue
            for raw_region in raw_regions:
                if not isinstance(raw_region, list) or len(raw_region) < 6:
                    continue
                coordinates = raw_region[:4]
                raw_count = raw_region[4]
                file_id = raw_region[5]
                if (
                    not all(isinstance(value, int) for value in coordinates)
                    or not isinstance(file_id, int)
                    or file_id < 0
                    or file_id >= len(normalized_filenames)
                ):
                    continue
                # Region kind 0 is an ordinary code region. Expansion, skipped,
                # gap, and branch records have different counting semantics and
                # are intentionally excluded from the parity metric.
                kind = raw_region[7] if len(raw_region) >= 8 else 0
                if kind != 0:
                    continue
                region_file = normalized_filenames[file_id]
                if region_file is None:
                    continue
                start_line, start_column, end_line, end_column = coordinates
                location = (
                    f"{region_file}:{start_line}:{start_column}-{end_line}:{end_column}"
                )
                count = _validated_coverage_count(
                    raw_count,
                    subject=f"ordinary region count for {name!r} at {location}",
                )
                region_key = (
                    region_file,
                    name,
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                )
                regions.add(region_key)
                if count > 0:
                    covered_regions.add(region_key)

    if not functions:
        raise MeasurementError(
            "llvm-cov export contained no functions under the supplied curl "
            f"source root: {source_root}"
        )
    return SourceCoverageIndex(
        functions=frozenset(functions),
        covered_functions=frozenset(covered_functions),
        regions=frozenset(regions),
        covered_regions=frozenset(covered_regions),
    )


def _coverage_percent(covered: int, total: int) -> float:
    return round(100.0 * covered / total, 3) if total else 100.0


def _source_coverage_summary(index: SourceCoverageIndex) -> dict[str, object]:
    """Return compact totals for one source coverage index."""
    return {
        "functions": {
            "count": len(index.functions),
            "covered": len(index.covered_functions),
            "percent": _coverage_percent(
                len(index.covered_functions), len(index.functions)
            ),
        },
        "regions": {
            "count": len(index.regions),
            "covered": len(index.covered_regions),
            "percent": _coverage_percent(
                len(index.covered_regions), len(index.regions)
            ),
        },
    }


def _function_detail(key: FunctionKey) -> dict[str, object]:
    return {"file": key[0], "name": key[1]}


def _region_detail(key: RegionKey) -> dict[str, object]:
    return {
        "file": key[0],
        "function": key[1],
        "start": {"line": key[2], "column": key[3]},
        "end": {"line": key[4], "column": key[5]},
    }


def _covered_set_comparison(
    baseline: frozenset[CoverageKey],
    candidate: frozenset[CoverageKey],
    detail: Callable[[CoverageKey], dict[str, object]],
) -> dict[str, object]:
    """Compare two covered-identity sets and retain inspectable gap lists."""
    baseline_only = sorted(baseline - candidate)
    candidate_only = sorted(candidate - baseline)
    common = baseline & candidate
    return {
        "baseline_covered": len(baseline),
        "candidate_covered": len(candidate),
        "covered_by_both": len(common),
        "baseline_only_count": len(baseline_only),
        "candidate_only_count": len(candidate_only),
        "baseline_retention_percent": _coverage_percent(len(common), len(baseline)),
        "baseline_only": [detail(key) for key in baseline_only],
        "candidate_only": [detail(key) for key in candidate_only],
    }


def compare_source_coverage(
    baseline: SourceCoverageIndex, candidate: SourceCoverageIndex
) -> dict[str, object]:
    """Compare curl source coverage while ignoring harness counter numbering."""
    return {
        "functions": _covered_set_comparison(
            baseline.covered_functions,
            candidate.covered_functions,
            _function_detail,
        ),
        "regions": _covered_set_comparison(
            baseline.covered_regions,
            candidate.covered_regions,
            _region_detail,
        ),
        "instrumented_universe": {
            "baseline_only_functions": len(baseline.functions - candidate.functions),
            "candidate_only_functions": len(candidate.functions - baseline.functions),
            "baseline_only_regions": len(baseline.regions - candidate.regions),
            "candidate_only_regions": len(candidate.regions - baseline.regions),
        },
    }


def _merge_source_coverage(
    indexes: Iterable[SourceCoverageIndex],
) -> SourceCoverageIndex:
    functions: set[FunctionKey] = set()
    covered_functions: set[FunctionKey] = set()
    regions: set[RegionKey] = set()
    covered_regions: set[RegionKey] = set()
    for index in indexes:
        functions.update(index.functions)
        covered_functions.update(index.covered_functions)
        regions.update(index.regions)
        covered_regions.update(index.covered_regions)
    return SourceCoverageIndex(
        functions=frozenset(functions),
        covered_functions=frozenset(covered_functions),
        regions=frozenset(regions),
        covered_regions=frozenset(covered_regions),
    )


def _target_pairs(
    targets: Sequence[str] | None, pair_values: Sequence[str]
) -> tuple[TargetPair, ...]:
    """Combine backward-compatible same-name targets with mapped pairs."""
    pairs = [TargetPair(target, target) for target in (targets or ())]
    for value in pair_values:
        if value.count("=") != 1:
            raise MeasurementError(
                f"invalid --target-pair {value!r}; expected BASELINE=CANDIDATE"
            )
        baseline, candidate = value.split("=", 1)
        if not baseline or not candidate:
            raise MeasurementError(
                f"invalid --target-pair {value!r}; expected BASELINE=CANDIDATE"
            )
        pairs.append(TargetPair(baseline, candidate))
    if not pairs:
        pairs = [TargetPair(target, target) for target in DEFAULT_TARGETS]
    for pair in pairs:
        for target in (pair.baseline_target, pair.candidate_target):
            if TARGET_NAME_RE.fullmatch(target) is None:
                raise MeasurementError(
                    f"invalid target name {target!r}; expected only letters, "
                    "digits, and underscores"
                )
    labels = [pair.label for pair in pairs]
    if len(labels) != len(set(labels)):
        raise MeasurementError("selected targets produce duplicate comparison labels")
    return tuple(pairs)


def _binary_path(binary_dir: Path, target: str) -> Path:
    """Resolve a validated binary name as a direct child of its build directory."""
    if TARGET_NAME_RE.fullmatch(target) is None:
        raise MeasurementError(f"invalid target name: {target!r}")
    directory = binary_dir.resolve()
    binary = (directory / target).resolve()
    if binary.parent != directory:
        raise MeasurementError(
            f"fuzzer binary must be a direct child of {directory}: {binary}"
        )
    return binary


def _run_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    return environment


def _validate_fuzzer(binary: Path, environment: dict[str, str]) -> None:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise MeasurementError(f"fuzzer binary is not executable: {binary}")
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
        raise MeasurementError(f"could not inspect {binary}: {error}") from error
    if result.returncode != 0 or "max_total_time" not in result.stdout:
        raise MeasurementError(
            f"{binary} does not appear to be a production-style libFuzzer binary"
        )


def _resource_usage() -> tuple[float, float]:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime, usage.ru_stime


def _count_corpus(path: Path) -> tuple[int, int]:
    sizes = [item.stat().st_size for item in path.iterdir() if item.is_file()]
    return len(sizes), sum(sizes)


def _persist_snapshot(
    builder: CorpusSnapshotBuilder,
    metadata: dict[str, object],
    destination_root: Path,
    variant: str,
    target: str,
) -> dict[str, object]:
    """Retain one deterministic, native-format corpus snapshot."""
    corpus_sha = metadata.get("sha256")
    if not isinstance(corpus_sha, str):
        raise MeasurementError(f"corpus metadata for {variant}/{target} has no hash")
    destination_root.mkdir(parents=True, exist_ok=True)
    archive = destination_root / f"{variant}-{target}-{corpus_sha}.zip"
    pending = archive.with_suffix(".zip.tmp")
    if pending.exists():
        pending.unlink()
    builder.write_zip(pending)
    os.replace(pending, archive)
    artifact = _artifact_metadata(archive, "corpus snapshot")
    artifact.update(
        {
            "content_sha256": corpus_sha,
            "input_count": metadata.get("count"),
            "content_bytes": metadata.get("bytes"),
        }
    )
    return artifact


def _build_snapshot(
    *,
    target: str,
    binary_dir: Path,
    destination: Path,
    corpus_root: Path,
    public_corpus_root: Path | None,
    overrides: dict[str, list[Path]],
) -> tuple[CorpusSnapshotBuilder, dict[str, object]]:
    builder = CorpusSnapshotBuilder(destination)
    sources = resolve_corpus_sources(
        target,
        binary_dir,
        corpus_root,
        public_corpus_root,
        overrides,
    )
    for source in sources:
        builder.add(source)
    metadata = builder.metadata()
    if metadata["count"] == 0:
        raise MeasurementError(f"corpus for {target} is empty")
    return builder, metadata


def _managed_command(
    binary: Path,
    corpus: Path,
    artifacts: Path,
    seed: int,
    seconds: int,
    timeout: int,
    cpu: int | None,
    extra_args: Sequence[str],
) -> list[str]:
    command: list[str] = []
    if cpu is not None:
        taskset = shutil.which("taskset")
        if taskset is None:
            raise MeasurementError("--cpu requires the taskset command")
        command.extend((taskset, "-c", str(cpu)))
    command.extend(
        (
            str(binary),
            f"-seed={seed}",
            f"-max_total_time={seconds}",
            f"-timeout={timeout}",
            "-reload=0",
            "-print_final_stats=1",
            f"-artifact_prefix={artifacts}/",
            *extra_args,
            str(corpus),
        )
    )
    return command


def _run_once(
    *,
    variant: Variant,
    target_label: str,
    binary_target: str,
    snapshot: Path,
    run_root: Path,
    log_root: Path,
    seed: int,
    repeat: int,
    seconds: int,
    timeout: int,
    wall_timeout: int,
    cpu: int | None,
    extra_args: Sequence[str],
    environment: dict[str, str],
) -> dict[str, object]:
    safe_label = target_label.replace("=>", "-vs-")
    run_name = f"{variant.name}-{safe_label}-r{repeat + 1}-seed{seed}"
    corpus = run_root / run_name / "corpus"
    artifacts = log_root / "artifacts" / run_name
    log_path = log_root / f"{run_name}.log"
    corpus.parent.mkdir(parents=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    shutil.copytree(snapshot, corpus)
    initial_count, initial_bytes = _count_corpus(corpus)

    binary = _binary_path(variant.binary_dir, binary_target)
    command = _managed_command(
        binary,
        corpus,
        artifacts,
        seed,
        seconds,
        timeout,
        cpu,
        extra_args,
    )
    display_command = ["<corpus>" if item == str(corpus) else item for item in command]

    user_before, system_before = _resource_usage()
    start = time.monotonic()
    returncode: int | None = None
    failure: str | None = None
    with log_path.open("w", encoding="utf-8") as log_file:
        try:
            result = subprocess.run(
                command,
                check=False,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=wall_timeout,
                env=environment,
            )
            returncode = result.returncode
            if returncode != 0:
                failure = f"libFuzzer exited with status {returncode}"
        except subprocess.TimeoutExpired:
            failure = f"process exceeded the {wall_timeout}s wall timeout"
        except OSError as error:
            failure = f"could not execute fuzzer: {error}"
    wall_seconds = time.monotonic() - start
    user_after, system_after = _resource_usage()

    output = log_path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_libfuzzer_output(output)
    exec_per_second = parsed.stats.get("average_exec_per_sec")
    if exec_per_second is None and parsed.final is not None:
        raw_exec_per_second = parsed.final.get("exec_per_second")
        if isinstance(raw_exec_per_second, int):
            exec_per_second = raw_exec_per_second

    if failure is None and (
        parsed.initial is None or parsed.final is None or exec_per_second is None
    ):
        failure = "required libFuzzer metrics were not present in the log"

    final_count, final_bytes = _count_corpus(corpus)
    return {
        "variant": variant.name,
        "target": target_label,
        "binary_target": binary_target,
        "repeat": repeat + 1,
        "seed": seed,
        "status": "failed" if failure else "ok",
        "failure": failure,
        "returncode": returncode,
        "command": display_command,
        "log": str(log_path),
        "timing": {
            "wall_seconds": round(wall_seconds, 6),
            "user_seconds": round(user_after - user_before, 6),
            "system_seconds": round(system_after - system_before, 6),
        },
        "corpus_before": {"count": initial_count, "bytes": initial_bytes},
        "corpus_after": {"count": final_count, "bytes": final_bytes},
        "initial": parsed.initial,
        "final": parsed.final,
        "stats": parsed.stats,
        "exec_per_second": exec_per_second,
    }


def _median(values: Iterable[float | int]) -> float | None:
    materialized = list(values)
    return statistics.median(materialized) if materialized else None


def _summaries(
    runs: Sequence[dict[str, object]],
    variants: Sequence[Variant],
    targets: Sequence[str],
) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for target in targets:
        for variant in variants:
            selected = [
                run
                for run in runs
                if run["target"] == target
                and run["variant"] == variant.name
                and run["status"] == "ok"
            ]
            timings = [run["timing"] for run in selected]
            initial = [run["initial"] for run in selected]
            final = [run["final"] for run in selected]
            summaries.append(
                {
                    "target": target,
                    "variant": variant.name,
                    "successful_runs": len(selected),
                    "median_exec_per_second": _median(
                        int(run["exec_per_second"])
                        for run in selected
                        if isinstance(run["exec_per_second"], int)
                    ),
                    "median_wall_seconds": _median(
                        float(timing["wall_seconds"])
                        for timing in timings
                        if isinstance(timing, dict)
                    ),
                    "median_user_seconds": _median(
                        float(timing["user_seconds"])
                        for timing in timings
                        if isinstance(timing, dict)
                    ),
                    "median_system_seconds": _median(
                        float(timing["system_seconds"])
                        for timing in timings
                        if isinstance(timing, dict)
                    ),
                    "median_initial_cov": _median(
                        int(event["cov"])
                        for event in initial
                        if isinstance(event, dict)
                    ),
                    "median_initial_ft": _median(
                        int(event["ft"]) for event in initial if isinstance(event, dict)
                    ),
                    "median_final_cov": _median(
                        int(event["cov"]) for event in final if isinstance(event, dict)
                    ),
                    "median_final_ft": _median(
                        int(event["ft"]) for event in final if isinstance(event, dict)
                    ),
                }
            )
    return summaries


def _format_number(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def _percentage_delta(baseline: object, candidate: object) -> float | None:
    if not isinstance(baseline, (float, int)) or not isinstance(
        candidate, (float, int)
    ):
        return None
    if baseline == 0:
        return None
    return round(100.0 * (candidate - baseline) / baseline, 3)


def _comparisons(
    summaries: Sequence[dict[str, object]],
    targets: Sequence[str],
    counter_comparable: set[str],
) -> list[dict[str, object]]:
    by_key = {(summary["target"], summary["variant"]): summary for summary in summaries}
    comparisons: list[dict[str, object]] = []
    for target in targets:
        baseline = by_key.get((target, "baseline"))
        candidate = by_key.get((target, "candidate"))
        if baseline is None or candidate is None:
            continue
        compare_counters = target in counter_comparable
        comparisons.append(
            {
                "target": target,
                "libfuzzer_counters_comparable": compare_counters,
                "exec_per_second_percent": _percentage_delta(
                    baseline["median_exec_per_second"],
                    candidate["median_exec_per_second"],
                ),
                "wall_seconds_percent": _percentage_delta(
                    baseline["median_wall_seconds"],
                    candidate["median_wall_seconds"],
                ),
                "initial_cov_delta": _numeric_delta(
                    baseline["median_initial_cov"], candidate["median_initial_cov"]
                )
                if compare_counters
                else None,
                "initial_ft_delta": _numeric_delta(
                    baseline["median_initial_ft"], candidate["median_initial_ft"]
                )
                if compare_counters
                else None,
                "final_cov_delta": _numeric_delta(
                    baseline["median_final_cov"], candidate["median_final_cov"]
                )
                if compare_counters
                else None,
                "final_ft_delta": _numeric_delta(
                    baseline["median_final_ft"], candidate["median_final_ft"]
                )
                if compare_counters
                else None,
            }
        )
    return comparisons


def _numeric_delta(baseline: object, candidate: object) -> float | None:
    if not isinstance(baseline, (float, int)) or not isinstance(
        candidate, (float, int)
    ):
        return None
    return candidate - baseline


def _print_summary(summaries: Sequence[dict[str, object]], repeats: int) -> None:
    columns = (
        ("target", 22),
        ("variant", 10),
        ("ok", 5),
        ("exec/s", 10),
        ("wall", 8),
        ("user", 8),
        ("sys", 8),
        ("init cov/ft", 16),
        ("final cov/ft", 16),
    )
    print(" ".join(label.ljust(width) for label, width in columns))
    for summary in summaries:
        initial = (
            f"{_format_number(summary['median_initial_cov'])}/"
            f"{_format_number(summary['median_initial_ft'])}"
        )
        final = (
            f"{_format_number(summary['median_final_cov'])}/"
            f"{_format_number(summary['median_final_ft'])}"
        )
        values = (
            str(summary["target"]),
            str(summary["variant"]),
            f"{summary['successful_runs']}/{repeats}",
            _format_number(summary["median_exec_per_second"]),
            _format_number(summary["median_wall_seconds"]),
            _format_number(summary["median_user_seconds"]),
            _format_number(summary["median_system_seconds"]),
            initial,
            final,
        )
        print(
            " ".join(value.ljust(width) for value, (_, width) in zip(values, columns))
        )


def _format_delta(value: object, suffix: str = "") -> str:
    if not isinstance(value, (float, int)):
        return "-"
    return f"{value:+.2f}{suffix}"


def _print_comparisons(comparisons: Sequence[dict[str, object]]) -> None:
    if not comparisons:
        return
    print("\nCandidate relative to baseline (median values):")
    print(
        f"{'target':22} {'exec/s':>10} {'wall':>10} "
        f"{'init cov/ft':>16} {'final cov/ft':>16}"
    )
    for comparison in comparisons:
        initial = (
            f"{_format_delta(comparison['initial_cov_delta'])}/"
            f"{_format_delta(comparison['initial_ft_delta'])}"
        )
        final = (
            f"{_format_delta(comparison['final_cov_delta'])}/"
            f"{_format_delta(comparison['final_ft_delta'])}"
        )
        print(
            f"{comparison['target']!s:22} "
            f"{_format_delta(comparison['exec_per_second_percent'], '%'):>10} "
            f"{_format_delta(comparison['wall_seconds_percent'], '%'):>10} "
            f"{initial:>16} {final:>16}"
        )


def _git_revision() -> str | None:
    if SOURCE_CHECKOUT is None:
        return None
    result = subprocess.run(
        ["git", "-C", str(SOURCE_CHECKOUT), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _resolve_curl_source_dir(
    coverage_dir: Path, explicit: Path | None, option_name: str
) -> Path:
    """Find the curl checkout whose paths are embedded in a coverage build."""
    candidates = (
        [explicit]
        if explicit is not None
        else [
            coverage_dir / "curl" / "src" / "curl_external",
            coverage_dir / "curl_external-prefix" / "src" / "curl_external",
        ]
    )
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "lib").is_dir() and (resolved / "src").is_dir():
            return resolved
    if explicit is not None:
        raise MeasurementError(
            f"{option_name} must contain curl's lib/ and src/ directories: "
            f"{explicit.resolve()}"
        )
    raise MeasurementError(
        f"could not infer curl's source tree from {coverage_dir}; pass {option_name}"
    )


def _source_tree_identity(source_root: Path) -> dict[str, object]:
    """Hash source files whose line coordinates define coverage identities."""
    source_suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc"}
    files = sorted(
        path
        for directory in (source_root / "lib", source_root / "src")
        for path in directory.rglob("*")
        if path.is_file() and path.suffix.lower() in source_suffixes
    )
    if not files:
        raise MeasurementError(
            f"curl source tree contains no source files: {source_root}"
        )
    digest = hashlib.sha256()
    for source_file in files:
        relative = source_file.relative_to(source_root).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        with source_file.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return {"sha256": digest.hexdigest(), "source_files": len(files)}


def _resolve_tool(command: str, label: str) -> Path:
    """Resolve an LLVM utility and fail before starting expensive runs."""
    candidate = Path(command).expanduser()
    if candidate.parent != Path(".") or candidate.is_absolute():
        resolved = candidate.resolve()
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    found = shutil.which(command)
    if found is None:
        raise MeasurementError(f"required {label} tool was not found: {command!r}")
    return Path(found).resolve()


def _tool_version(tool: Path, label: str) -> str:
    try:
        result = subprocess.run(
            [str(tool), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MeasurementError(f"could not inspect {label}: {error}") from error
    if result.returncode != 0:
        raise MeasurementError(
            f"could not inspect {label}; {tool} exited with status {result.returncode}"
        )
    version = next((line.strip() for line in result.stdout.splitlines() if line), "")
    if not version:
        raise MeasurementError(f"{label} did not report a version: {tool}")
    return version


def _validate_coverage_binary(binary: Path) -> None:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise MeasurementError(f"coverage replay binary is not executable: {binary}")


def _command_failure(label: str, result: subprocess.CompletedProcess[str]) -> str:
    output = result.stdout.strip()
    if len(output) > 4000:
        output = output[-4000:]
    suffix = f":\n{output}" if output else ""
    return f"{label} exited with status {result.returncode}{suffix}"


def _artifact_metadata(
    path: Path, label: str, *, require_nonempty: bool = True
) -> dict[str, object]:
    """Require an artifact and return its durable identity."""
    try:
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as error:
        raise MeasurementError(f"could not read {label} {path}: {error}") from error
    if require_nonempty and size <= 0:
        raise MeasurementError(f"{label} is empty: {path}")
    return {"path": str(path), "bytes": size, "sha256": digest}


def _require_nonempty_artifact(path: Path, label: str) -> None:
    """Check artifact existence and size without hashing a pending file."""
    try:
        size = path.stat().st_size
    except OSError as error:
        raise MeasurementError(f"could not read {label} {path}: {error}") from error
    if size <= 0:
        raise MeasurementError(f"{label} is empty: {path}")


def _coverage_target_root(
    artifact_root: Path, variant_name: str, target_name: str
) -> Path:
    """Create a contained replay directory without following child symlinks."""
    if any(
        not part or Path(part).name != part or part in {".", ".."}
        for part in (variant_name, target_name)
    ):
        raise MeasurementError("unsafe source coverage artifact path")
    if artifact_root.is_symlink():
        raise MeasurementError(
            f"source coverage artifact root must not be a symlink: {artifact_root}"
        )
    artifact_root.mkdir(parents=True, exist_ok=True)
    resolved_root = artifact_root.resolve()
    variant_root = resolved_root / variant_name
    if variant_root.is_symlink():
        raise MeasurementError(
            f"source coverage variant directory must not be a symlink: {variant_root}"
        )
    variant_root.mkdir(exist_ok=True)
    resolved_variant = variant_root.resolve()
    if resolved_variant.parent != resolved_root:
        raise MeasurementError("source coverage variant directory escaped its root")
    target_root = resolved_variant / target_name
    if target_root.is_symlink():
        raise MeasurementError(
            f"source coverage target directory must not be a symlink: {target_root}"
        )
    target_root.mkdir(exist_ok=True)
    resolved_target = target_root.resolve()
    if resolved_target.parent != resolved_variant:
        raise MeasurementError("source coverage target directory escaped its root")
    return resolved_target


def _source_coverage_artifact_roots(log_root: Path) -> tuple[Path, Path]:
    """Create contained non-symlink roots before retaining coverage artifacts."""
    if log_root.is_symlink():
        raise MeasurementError(f"log directory must not be a symlink: {log_root}")
    log_root.mkdir(parents=True, exist_ok=True)
    resolved_log_root = log_root.resolve()
    source_root = resolved_log_root / "source-coverage"
    if source_root.is_symlink():
        raise MeasurementError(
            f"source coverage artifact root must not be a symlink: {source_root}"
        )
    source_root.mkdir(exist_ok=True)
    resolved_source_root = source_root.resolve()
    if resolved_source_root.parent != resolved_log_root:
        raise MeasurementError(
            "source coverage artifact root escaped the log directory"
        )
    corpus_root = resolved_source_root / "corpora"
    if corpus_root.is_symlink():
        raise MeasurementError(
            f"source coverage corpus directory must not be a symlink: {corpus_root}"
        )
    corpus_root.mkdir(exist_ok=True)
    resolved_corpus_root = corpus_root.resolve()
    if resolved_corpus_root.parent != resolved_source_root:
        raise MeasurementError("source coverage corpus directory escaped its root")
    return resolved_source_root, resolved_corpus_root


def _clear_coverage_artifacts(target_root: Path) -> None:
    """Remove prior replay outputs without following symlinked leaves."""
    for pattern in (
        "*.profraw",
        "*.profdata",
        "*.export.json",
        "*.tmp",
        "replay-status.json",
        "replay.log",
    ):
        for stale in target_root.glob(pattern):
            if stale.is_file() or stale.is_symlink():
                stale.unlink()


def _read_replay_status(path: Path, expected_inputs: int) -> dict[str, int]:
    """Validate exact standalone-runner completion counters."""
    if expected_inputs <= 0:
        raise MeasurementError("coverage replay requires a nonempty corpus")
    try:
        document = strict_json_loads(path.read_text(encoding="utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as error:
        raise MeasurementError(
            f"could not read replay status {path}: {error}"
        ) from error
    if not isinstance(document, dict) or set(document) != set(REPLAY_COUNTER_NAMES):
        raise MeasurementError(
            f"replay status {path} must contain exactly: "
            + ", ".join(REPLAY_COUNTER_NAMES)
        )
    counters: dict[str, int] = {}
    for name in REPLAY_COUNTER_NAMES:
        value = document.get(name)
        if type(value) is not int or value < 0:
            raise MeasurementError(
                f"replay status {path} field {name} must be a nonnegative integer"
            )
        counters[name] = value
    if (
        counters["attempted"] != expected_inputs
        or counters["completed"] != expected_inputs
        or any(counters[name] for name in ("timed_out", "input_errors", "path_errors"))
    ):
        raise MeasurementError(
            f"incomplete coverage replay for {path}: expected {expected_inputs}, "
            f"got {counters}"
        )
    return counters


def _measure_coverage_target(
    *,
    variant: Variant,
    target_label: str,
    binary_target: str,
    source_root: Path,
    snapshot: Path,
    snapshot_artifact: dict[str, object],
    expected_inputs: int,
    artifact_root: Path,
    environment: dict[str, str],
    wall_timeout: int,
    input_timeout: int,
    expected_binary_sha256: str,
    llvm_profdata: Path,
    llvm_cov: Path,
) -> tuple[dict[str, object], SourceCoverageIndex]:
    """Replay one fixed corpus and export curl-only source coverage."""
    binary = _binary_path(variant.binary_dir, binary_target)
    _validate_coverage_binary(binary)
    safe_label = target_label.replace("=>", "-vs-")
    target_root = _coverage_target_root(artifact_root, variant.name, safe_label)
    _clear_coverage_artifacts(target_root)

    log_path = target_root / "replay.log"
    status_path = target_root / "replay-status.json"
    profile_pattern = target_root / f"{binary_target}-%p.profraw"
    replay_environment = environment.copy()
    for name in (
        "LLVM_PROFILE_FILE",
        "FUZZ_REPLAY_STATUS_FILE",
        "FUZZ_TIMEOUT_SECS",
        *COVERAGE_REPLAY_SANITIZER_ENVIRONMENT,
    ):
        replay_environment.pop(name, None)
    replay_environment["LLVM_PROFILE_FILE"] = str(profile_pattern)
    replay_environment["FUZZ_REPLAY_STATUS_FILE"] = str(status_path)
    replay_environment["FUZZ_TIMEOUT_SECS"] = str(input_timeout)
    replay_environment.update(
        {
            name: value
            for name, value in COVERAGE_REPLAY_SANITIZER_ENVIRONMENT.items()
            if value is not None
        }
    )
    command = [str(binary), str(snapshot)]
    with log_path.open("w", encoding="utf-8") as log_file:
        try:
            replay = subprocess.run(
                command,
                check=False,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=wall_timeout,
                env=replay_environment,
            )
        except subprocess.TimeoutExpired as error:
            raise MeasurementError(
                f"coverage replay for {variant.name}/{binary_target} exceeded "
                f"{wall_timeout}s; see {log_path}"
            ) from error
        except OSError as error:
            raise MeasurementError(
                f"could not run coverage replay binary {binary}: {error}"
            ) from error
    if replay.returncode != 0:
        raise MeasurementError(
            f"coverage replay for {variant.name}/{binary_target} exited with status "
            f"{replay.returncode}; see {log_path}"
        )

    counters = _read_replay_status(status_path, expected_inputs)
    status_artifact = _artifact_metadata(status_path, "coverage replay status")

    raw_profiles = sorted(target_root.glob("*.profraw"))
    if not raw_profiles:
        raise MeasurementError(
            f"coverage replay for {variant.name}/{binary_target} produced no .profraw "
            "file; rebuild it with -fprofile-instr-generate and "
            "-fcoverage-mapping"
        )
    raw_profile_artifacts = [
        _artifact_metadata(path, "raw coverage profile") for path in raw_profiles
    ]

    profile = target_root / f"{binary_target}.profdata"
    merge_command = [
        str(llvm_profdata),
        "merge",
        "-sparse",
        "-o",
        str(profile),
        *(str(path) for path in raw_profiles),
    ]
    try:
        merge = subprocess.run(
            merge_command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=wall_timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MeasurementError(
            f"could not merge coverage for {variant.name}/{binary_target}: {error}"
        ) from error
    if merge.returncode != 0:
        raise MeasurementError(
            _command_failure(
                f"llvm-profdata merge for {variant.name}/{binary_target}", merge
            )
        )
    profile_artifact = _artifact_metadata(profile, "merged coverage profile")

    export_path = target_root / f"{binary_target}.export.json"
    pending_export = target_root / f"{binary_target}.export.json.tmp"
    export_command = [
        str(llvm_cov),
        "export",
        str(binary),
        f"-instr-profile={profile}",
        str(source_root / "lib"),
        str(source_root / "src"),
    ]
    try:
        with pending_export.open("w", encoding="utf-8") as output_stream:
            export = subprocess.run(
                export_command,
                check=False,
                stdout=output_stream,
                stderr=subprocess.PIPE,
                text=True,
                timeout=wall_timeout,
                env=environment,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MeasurementError(
            f"could not export coverage for {variant.name}/{binary_target}: {error}"
        ) from error
    if export.returncode != 0:
        error_result = subprocess.CompletedProcess(
            export.args, export.returncode, export.stderr
        )
        raise MeasurementError(
            _command_failure(
                f"llvm-cov export for {variant.name}/{binary_target}", error_result
            )
        )
    _require_nonempty_artifact(pending_export, "LLVM coverage export")
    try:
        os.replace(pending_export, export_path)
    except OSError as error:
        raise MeasurementError(
            f"could not retain LLVM coverage export {export_path}: {error}"
        ) from error
    export_artifact = _artifact_metadata(export_path, "LLVM coverage export")
    try:
        export_document = json.loads(export_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MeasurementError(
            f"could not parse llvm-cov export for {variant.name}/{binary_target}: "
            f"{error}"
        ) from error
    index = parse_source_coverage_export(export_document, source_root)
    binary_artifact = _artifact_metadata(binary, "coverage replay binary")
    if binary_artifact["sha256"] != expected_binary_sha256:
        raise MeasurementError(
            f"coverage replay binary changed during measurement: {binary}"
        )
    metadata: dict[str, object] = {
        "binary": binary_artifact,
        "binary_target": binary_target,
        "replay_command": [str(binary), "<corpus>"],
        "input_timeout_seconds": input_timeout,
        "expected_inputs": expected_inputs,
        "replay_counters": counters,
        "replay_status": status_artifact,
        "replay_log": _artifact_metadata(
            log_path, "coverage replay log", require_nonempty=False
        ),
        "corpus": snapshot_artifact,
        "raw_profiles": raw_profile_artifacts,
        "profile": profile_artifact,
        "export": export_artifact,
        "summary": _source_coverage_summary(index),
    }
    return metadata, index


def _measure_source_coverage(
    *,
    variants: Sequence[Variant],
    source_roots: dict[str, Path],
    source_identities: dict[str, dict[str, object]],
    target_pairs: Sequence[TargetPair],
    snapshots: dict[tuple[str, str], Path],
    snapshot_metadata: dict[tuple[str, str], dict[str, object]],
    snapshot_artifacts: dict[tuple[str, str], dict[str, object]],
    artifact_root: Path,
    environment: dict[str, str],
    wall_timeout: int,
    input_timeout: int,
    llvm_profdata: Path,
    llvm_cov: Path,
    tool_versions: dict[str, str],
) -> tuple[dict[str, object], SourceCoverageIndex, SourceCoverageIndex]:
    """Measure and compare fixed-corpus curl source coverage per target."""
    variant_documents: dict[str, object] = {}
    indexes: dict[str, dict[str, SourceCoverageIndex]] = {}
    measurement_cache: dict[
        tuple[str, str, str, str, str],
        tuple[str, dict[str, object], SourceCoverageIndex],
    ] = {}
    expected_unique_measurements = sum(
        len({pair.target_for(variant.name) for pair in target_pairs})
        for variant in variants
    )
    total_expected = 0
    total_attempted = 0
    total_completed = 0
    for variant in variants:
        target_documents: dict[str, object] = {}
        measurement_documents: dict[str, object] = {}
        target_indexes: dict[str, SourceCoverageIndex] = {}
        ordered_targets = tuple(
            dict.fromkeys(pair.target_for(variant.name) for pair in target_pairs)
        )
        target_measurements: dict[str, str] = {}
        for binary_target in ordered_targets:
            binary = _binary_path(variant.binary_dir, binary_target)
            binary_sha_value = _artifact_metadata(binary, "coverage replay binary").get(
                "sha256"
            )
            if not isinstance(binary_sha_value, str):
                raise MeasurementError(
                    f"missing binary SHA-256 for {variant.name}/{binary_target}"
                )
            binary_sha = binary_sha_value
            corpus = snapshot_metadata[(variant.name, binary_target)]
            corpus_sha = corpus.get("sha256")
            if not isinstance(corpus_sha, str):
                raise MeasurementError(
                    f"missing corpus SHA-256 for {variant.name}/{binary_target}"
                )
            source_sha = source_identities[variant.name].get("sha256")
            if not isinstance(source_sha, str):
                raise MeasurementError(
                    f"missing source SHA-256 for {variant.name}/{binary_target}"
                )
            cache_key = (
                variant.name,
                binary_target,
                binary_sha,
                corpus_sha,
                source_sha,
            )
            cached = measurement_cache.get(cache_key)
            if cached is not None:
                measurement_id, metadata, index = cached
                target_measurements[binary_target] = measurement_id
                target_indexes[binary_target] = index
                continue

            identity = json.dumps(cache_key, separators=(",", ":"))
            measurement_id = hashlib.sha256(identity.encode()).hexdigest()
            print(
                f"==> {variant.name}/{binary_target} fixed-corpus source coverage",
                flush=True,
            )
            expected = corpus.get("count")
            if type(expected) is not int or expected <= 0:
                raise MeasurementError(
                    f"invalid corpus count for {variant.name}/{binary_target}"
                )
            metadata, index = _measure_coverage_target(
                variant=variant,
                target_label=f"{binary_target}-{measurement_id[:16]}",
                binary_target=binary_target,
                source_root=source_roots[variant.name],
                snapshot=snapshots[(variant.name, binary_target)],
                snapshot_artifact=snapshot_artifacts[(variant.name, binary_target)],
                expected_inputs=expected,
                artifact_root=artifact_root,
                environment=environment,
                wall_timeout=wall_timeout,
                input_timeout=input_timeout,
                expected_binary_sha256=binary_sha,
                llvm_profdata=llvm_profdata,
                llvm_cov=llvm_cov,
            )
            metadata["measurement_id"] = measurement_id
            measurement_cache[cache_key] = (measurement_id, metadata, index)
            measurement_documents[measurement_id] = metadata
            target_measurements[binary_target] = measurement_id
            target_indexes[binary_target] = index
            counters = metadata["replay_counters"]
            if not isinstance(counters, dict):
                raise MeasurementError("internal replay counter metadata is invalid")
            total_expected += expected
            total_attempted += int(counters["attempted"])
            total_completed += int(counters["completed"])

        for target_pair in target_pairs:
            binary_target = target_pair.target_for(variant.name)
            measurement_id = target_measurements[binary_target]
            target_documents[target_pair.label] = {
                "binary_target": binary_target,
                "measurement_id": measurement_id,
            }
        aggregate = _merge_source_coverage(target_indexes.values())
        indexes[variant.name] = target_indexes
        variant_documents[variant.name] = {
            "binary_dir": str(variant.binary_dir),
            "curl_source_dir": str(source_roots[variant.name]),
            "source_identity": source_identities[variant.name],
            "targets": target_documents,
            "measurements": measurement_documents,
            "aggregate": _source_coverage_summary(aggregate),
        }

    if len(measurement_cache) != expected_unique_measurements:
        raise MeasurementError(
            "internal source replay accounting mismatch: expected "
            f"{expected_unique_measurements} unique target executions, got "
            f"{len(measurement_cache)}"
        )

    baseline_indexes = indexes["baseline"]
    candidate_indexes = indexes["candidate"]
    target_comparisons = {
        target_pair.label: compare_source_coverage(
            baseline_indexes[target_pair.baseline_target],
            candidate_indexes[target_pair.candidate_target],
        )
        for target_pair in target_pairs
    }
    baseline_aggregate = _merge_source_coverage(baseline_indexes.values())
    candidate_aggregate = _merge_source_coverage(candidate_indexes.values())
    document: dict[str, object] = {
        "method": "fixed-corpus llvm-cov export over curl lib/ and src/",
        "tools": {
            "llvm_profdata": {
                "path": str(llvm_profdata),
                "version": tool_versions["llvm_profdata"],
            },
            "llvm_cov": {
                "path": str(llvm_cov),
                "version": tool_versions["llvm_cov"],
            },
        },
        "variants": variant_documents,
        "replay_totals": {
            "unique_measurements": len(measurement_cache),
            "expected_inputs": total_expected,
            "attempted": total_attempted,
            "completed": total_completed,
        },
        "comparison": {
            "targets": target_comparisons,
            "aggregate": compare_source_coverage(
                baseline_aggregate, candidate_aggregate
            ),
        },
    }
    return document, baseline_aggregate, candidate_aggregate


def _print_source_coverage(document: dict[str, object]) -> None:
    comparison = document.get("comparison")
    if not isinstance(comparison, dict):
        return
    targets = comparison.get("targets")
    if not isinstance(targets, dict):
        return
    print("\nCurl source coverage retained by candidate (fixed corpus replay):")
    print(f"{'target':22} {'functions':>12} {'regions':>12} {'missing f/r':>14}")
    for target, raw_comparison in targets.items():
        if not isinstance(raw_comparison, dict):
            continue
        functions = raw_comparison.get("functions")
        regions = raw_comparison.get("regions")
        if not isinstance(functions, dict) or not isinstance(regions, dict):
            continue
        print(
            f"{target!s:22} "
            f"{_format_number(functions.get('baseline_retention_percent')) + '%':>12} "
            f"{_format_number(regions.get('baseline_retention_percent')) + '%':>12} "
            f"{functions.get('baseline_only_count', '-')}"
            f"/{regions.get('baseline_only_count', '-'):>12}"
        )


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--baseline-dir",
        type=Path,
        help="directory containing the baseline production libFuzzer binaries",
    )
    parser.add_argument(
        "--candidate-dir",
        type=Path,
        help="optional directory containing candidate libFuzzer binaries",
    )
    parser.add_argument(
        "--target",
        dest="targets",
        action="append",
        help="target to measure; repeat to select multiple targets",
    )
    parser.add_argument(
        "--target-pair",
        action="append",
        default=[],
        metavar="BASELINE=CANDIDATE",
        help=(
            "compare differently named targets using each target's native "
            "corpus; repeat to select multiple pairs"
        ),
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=REPO_ROOT / "corpora",
        help="root containing checked-in per-target corpus directories",
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
        metavar="TARGET=PATH",
        help="replace a target's default corpus sources; repeat to combine sources",
    )
    parser.add_argument("--seconds", type=int, default=10, help="fuzzing time per run")
    parser.add_argument("--timeout", type=int, default=10, help="per-input timeout")
    parser.add_argument(
        "--wall-timeout",
        type=int,
        help="outer process timeout; defaults to max(60, 4 * seconds + 30)",
    )
    parser.add_argument("--repeats", type=int, default=3, help="runs per variant")
    parser.add_argument(
        "--seed-base",
        type=int,
        default=101,
        help="repeat N uses seed-base + N - 1",
    )
    parser.add_argument("--cpu", type=int, help="pin each run to this logical CPU")
    parser.add_argument(
        "--fuzzer-arg",
        action="append",
        default=[],
        help="extra libFuzzer argument (use --fuzzer-arg=-max_len=...)",
    )
    parser.add_argument(
        "--compare-libfuzzer-counters",
        action="store_true",
        help=(
            "report cov/ft deltas for same-name targets; the caller must "
            "guarantee identical SanitizerCoverage sites and feature semantics"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "build" / "measurements" / "comparison.json",
        help="JSON result path",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        help="directory for complete run logs and crash artifacts",
    )
    parser.add_argument(
        "--coverage-baseline-dir",
        type=Path,
        help=(
            "optional baseline build directory containing standalone, "
            "LLVM source-coverage-instrumented binaries"
        ),
    )
    parser.add_argument(
        "--coverage-candidate-dir",
        type=Path,
        help=(
            "candidate build directory containing matching standalone, "
            "LLVM source-coverage-instrumented binaries"
        ),
    )
    parser.add_argument(
        "--baseline-curl-source-dir",
        type=Path,
        help="curl source root used by the baseline coverage build",
    )
    parser.add_argument(
        "--candidate-curl-source-dir",
        type=Path,
        help="curl source root used by the candidate coverage build",
    )
    parser.add_argument(
        "--coverage-wall-timeout",
        type=int,
        default=argparse.SUPPRESS,
        help=(
            "outer timeout for each fixed-corpus coverage replay; defaults to "
            "300s, or 7200s in parity-manifest mode"
        ),
    )
    parser.add_argument(
        "--coverage-input-timeout",
        type=int,
        default=argparse.SUPPRESS,
        help=(
            "per-input timeout exported to standalone coverage runners; "
            "defaults to 25s, or the immutable manifest value in parity mode"
        ),
    )
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="run deterministic source replay without timed libFuzzer benchmarks",
    )
    parser.add_argument(
        "--parity-manifest",
        type=Path,
        help="immutable function-parity manifest to bind and ratchet",
    )
    parser.add_argument(
        "--previous-parity-manifest",
        type=Path,
        help=(
            "trusted prior manifest used to reject immutable baseline changes "
            "and resolved-gap removals"
        ),
    )
    parser.add_argument(
        "--target-inventory",
        type=Path,
        default=REPO_ROOT / "scripts" / "fuzz_targets",
        help="repository target inventory validated in parity-manifest mode",
    )
    parser.add_argument(
        "--llvm-profdata",
        default="llvm-profdata",
        help="llvm-profdata executable name or path",
    )
    parser.add_argument(
        "--llvm-cov",
        default="llvm-cov",
        help="llvm-cov executable name or path",
    )
    args = parser.parse_args(argv)
    if not hasattr(args, "coverage_wall_timeout"):
        args.coverage_wall_timeout = None
    if not hasattr(args, "coverage_input_timeout"):
        args.coverage_input_timeout = None
    return args


def _validate_args(args: argparse.Namespace) -> None:
    if args.seconds <= 0 or args.timeout <= 0 or args.repeats <= 0:
        raise MeasurementError("--seconds, --timeout, and --repeats must be positive")
    if args.wall_timeout is not None and args.wall_timeout <= 0:
        raise MeasurementError("--wall-timeout must be positive")
    if args.coverage_wall_timeout is not None and args.coverage_wall_timeout <= 0:
        raise MeasurementError("--coverage-wall-timeout must be positive")
    if args.coverage_input_timeout is not None and args.coverage_input_timeout <= 0:
        raise MeasurementError("--coverage-input-timeout must be positive")
    if args.cpu is not None and args.cpu < 0:
        raise MeasurementError("--cpu must not be negative")
    if args.source_only and args.compare_libfuzzer_counters:
        raise MeasurementError(
            "--source-only is incompatible with --compare-libfuzzer-counters"
        )
    if not args.source_only and args.baseline_dir is None:
        raise MeasurementError(
            "--baseline-dir is required unless --source-only is used"
        )
    if args.target_pair and not args.source_only and args.candidate_dir is None:
        raise MeasurementError("--target-pair requires --candidate-dir")
    if args.compare_libfuzzer_counters and args.candidate_dir is None:
        raise MeasurementError("--compare-libfuzzer-counters requires --candidate-dir")
    coverage_inputs = (
        args.coverage_baseline_dir,
        args.coverage_candidate_dir,
        args.baseline_curl_source_dir,
        args.candidate_curl_source_dir,
    )
    if any(value is not None for value in coverage_inputs):
        if args.coverage_baseline_dir is None or args.coverage_candidate_dir is None:
            raise MeasurementError(
                "source coverage comparison requires both "
                "--coverage-baseline-dir and --coverage-candidate-dir"
            )
        if not args.source_only and args.candidate_dir is None:
            raise MeasurementError(
                "source coverage comparison requires --candidate-dir"
            )
    if args.source_only and (
        args.coverage_baseline_dir is None or args.coverage_candidate_dir is None
    ):
        raise MeasurementError(
            "--source-only requires --coverage-baseline-dir and "
            "--coverage-candidate-dir"
        )
    if args.parity_manifest is not None and (
        args.coverage_baseline_dir is None or args.coverage_candidate_dir is None
    ):
        raise MeasurementError(
            "--parity-manifest requires both coverage build directories"
        )
    if args.previous_parity_manifest is not None and args.parity_manifest is None:
        raise MeasurementError("--previous-parity-manifest requires --parity-manifest")
    if args.parity_manifest is not None and args.previous_parity_manifest is None:
        raise MeasurementError(
            "--parity-manifest requires a trusted --previous-parity-manifest"
        )
    if args.parity_manifest is not None:
        baseline_coverage = args.coverage_baseline_dir.resolve()
        candidate_coverage = args.coverage_candidate_dir.resolve()
        if baseline_coverage != candidate_coverage:
            raise MeasurementError(
                "--parity-manifest requires baseline and candidate coverage "
                "targets from the same build directory"
            )
    for argument in args.fuzzer_arg:
        if not argument.startswith("-"):
            raise MeasurementError(f"fuzzer argument must begin with '-': {argument}")
        if argument.startswith(MANAGED_FUZZER_ARGS):
            raise MeasurementError(
                f"fuzzer argument is managed by this tool: {argument}"
            )


def _resolve_coverage_replay_settings(
    args: argparse.Namespace, parity_manifest: ParityManifest | None
) -> None:
    """Apply generic defaults or bind parity replay settings to the manifest."""
    if parity_manifest is None:
        if args.coverage_wall_timeout is None:
            args.coverage_wall_timeout = DEFAULT_COVERAGE_WALL_TIMEOUT
        if args.coverage_input_timeout is None:
            args.coverage_input_timeout = DEFAULT_COVERAGE_INPUT_TIMEOUT
        return

    expected_input_timeout = parity_manifest.replay_input_timeout_seconds
    if args.coverage_input_timeout is None:
        args.coverage_input_timeout = expected_input_timeout
    elif args.coverage_input_timeout != expected_input_timeout:
        raise MeasurementError(
            "--coverage-input-timeout does not match the parity manifest: "
            f"expected {expected_input_timeout}"
        )
    if (
        COVERAGE_REPLAY_SANITIZER_ENVIRONMENT
        != parity_manifest.replay_sanitizer_environment
    ):
        raise MeasurementError(
            "coverage replay sanitizer environment does not match the parity manifest"
        )
    if args.coverage_wall_timeout is None:
        args.coverage_wall_timeout = PARITY_COVERAGE_WALL_TIMEOUT


def _validate_parity_socket_capability(
    socketpair_factory: Callable[
        [int, int], tuple[socket.socket, socket.socket]
    ] = socket.socketpair,
) -> None:
    """Fail before replay when local protocol peers cannot exchange bytes."""
    payload = b"curl-fuzzer-parity-preflight"
    try:
        sender, receiver = socketpair_factory(socket.AF_UNIX, socket.SOCK_STREAM)
        with sender, receiver:
            sender.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = receiver.recv(len(payload) - len(received))
                if not chunk:
                    break
                received.extend(chunk)
    except OSError as error:
        raise MeasurementError(
            "parity source replay requires local AF_UNIX socket send/receive "
            f"capability; the preflight failed: {error}. Run the comparison in "
            "an execution environment that permits local socket I/O; completed "
            "callback counts alone do not prove protocol execution"
        ) from error
    if bytes(received) != payload:
        raise MeasurementError(
            "parity source replay local AF_UNIX socket preflight returned "
            f"{len(received)} of {len(payload)} bytes; completed callback counts "
            "alone do not prove protocol execution"
        )


def _validate_output_separation(
    args: argparse.Namespace,
    output: Path,
    log_root: Path,
    corpus_sources: Iterable[Path],
) -> None:
    """Keep result and retained-artifact writes disjoint from all inputs."""
    raw_corpus_sources = tuple(corpus_sources)
    directory_inputs = (
        args.corpus_root,
        args.public_corpus_root,
        args.baseline_curl_source_dir,
        args.candidate_curl_source_dir,
    )
    for raw_directory in directory_inputs:
        if raw_directory is None:
            continue
        directory = raw_directory.resolve()
        if output == directory or output.is_relative_to(directory):
            raise MeasurementError(
                f"--output must not be inside an input directory: {directory}"
            )

    coverage_directories = (
        args.coverage_baseline_dir,
        args.coverage_candidate_dir,
    )
    inferred_source_paths: set[Path] = set()
    for raw_coverage_directory in coverage_directories:
        if raw_coverage_directory is None:
            continue
        coverage_directory = raw_coverage_directory.resolve()
        inferred_sources = (
            (coverage_directory / "curl" / "src" / "curl_external").resolve(),
            (
                coverage_directory / "curl_external-prefix" / "src" / "curl_external"
            ).resolve(),
        )
        inferred_source_paths.update(inferred_sources)
        if any(output.is_relative_to(source) for source in inferred_sources):
            raise MeasurementError(
                "--output must not be inside an inferred curl source directory"
            )

    file_inputs = (
        args.parity_manifest,
        args.previous_parity_manifest,
        args.target_inventory,
    )
    for raw_file in file_inputs:
        if raw_file is not None and output == raw_file.resolve():
            raise MeasurementError(
                f"--output must not overwrite an input file: {raw_file.resolve()}"
            )

    for raw_source in raw_corpus_sources:
        source = raw_source.resolve()
        if output == source or (source.is_dir() and output.is_relative_to(source)):
            raise MeasurementError(
                f"--output must not overwrite a corpus input: {source}"
            )

    resolved_tools: list[Path] = []
    for command in (args.llvm_profdata, args.llvm_cov):
        tool = Path(command).expanduser()
        found = shutil.which(command)
        resolved_tool = (
            Path(found).resolve()
            if found is not None
            else tool.resolve()
            if tool.is_absolute() or "/" in command or "\\" in command
            else None
        )
        if resolved_tool is not None:
            resolved_tools.append(resolved_tool)
            if output == resolved_tool:
                raise MeasurementError(
                    f"--output must not overwrite an LLVM tool: {resolved_tool}"
                )

    build_directories = (
        args.baseline_dir,
        args.candidate_dir,
        args.coverage_baseline_dir,
        args.coverage_candidate_dir,
    )
    for raw_directory in build_directories:
        if raw_directory is None:
            continue
        directory = raw_directory.resolve()
        if output.parent == directory:
            raise MeasurementError(
                f"--output must not be a direct child of a build directory: {directory}"
            )

    resolved_build_directories = {
        raw_path.resolve() for raw_path in build_directories if raw_path is not None
    }
    protected_paths = {
        output,
        *(
            raw_path.resolve()
            for raw_path in (*directory_inputs, *file_inputs)
            if raw_path is not None
        ),
        *(raw_source.resolve() for raw_source in raw_corpus_sources),
        *inferred_source_paths,
        *resolved_tools,
    }
    artifact_roots = {
        log_root,
        (log_root / "source-coverage").resolve(),
    }
    for artifact_root in artifact_roots:
        for protected in protected_paths:
            if (
                artifact_root == protected
                or artifact_root.is_relative_to(protected)
                or protected.is_relative_to(artifact_root)
            ):
                raise MeasurementError(
                    "--log-dir and its artifact roots must not overlap an "
                    f"input, output, build, or tool path: {artifact_root} and "
                    f"{protected}"
                )
        for build_directory in resolved_build_directories:
            overlaps_build = (
                artifact_root == build_directory
                or artifact_root.is_relative_to(build_directory)
                or build_directory.is_relative_to(artifact_root)
            )
            implicit_sibling_inside_build = (
                args.log_dir is None
                and artifact_root.is_relative_to(build_directory)
                and output.is_relative_to(build_directory)
            )
            if overlaps_build and not implicit_sibling_inside_build:
                raise MeasurementError(
                    "--log-dir and its artifact roots must not overlap an "
                    f"input, output, build, or tool path: {artifact_root} and "
                    f"{build_directory}"
                )


def _raw_corpus_input_paths(values: Iterable[str]) -> list[Path]:
    """Extract possible corpus paths before validating mapping syntax."""
    paths: list[Path] = []
    for value in values:
        _, separator, raw_path = value.partition("=")
        if separator and raw_path:
            paths.append(Path(raw_path))
    return paths


def _remove_stale_output(output: Path) -> None:
    try:
        output.unlink(missing_ok=True)
    except OSError as error:
        raise MeasurementError(
            f"could not remove stale result {output}: {error}"
        ) from error


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested measurements and return a process status."""
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    try:
        raw_output = args.output
        if raw_output.is_symlink():
            raise MeasurementError(f"output must not be a symlink: {raw_output}")
        output = raw_output.resolve()
        raw_log_root = (
            args.log_dir
            if args.log_dir is not None
            else output.parent / f"{output.stem}-logs"
        )
        if raw_log_root.is_symlink():
            raise MeasurementError(
                f"log directory must not be a symlink: {raw_log_root}"
            )
        log_root = raw_log_root.resolve()
        _validate_output_separation(
            args,
            output,
            log_root,
            _raw_corpus_input_paths(args.corpus),
        )
        _remove_stale_output(output)
        _validate_args(args)
        overrides = parse_corpus_mappings(args.corpus)
        parity_manifest: ParityManifest | None = None
        previous_parity_manifest: ParityManifest | None = None
        if args.parity_manifest is not None:
            parity_manifest = load_parity_manifest(args.parity_manifest)
        _resolve_coverage_replay_settings(args, parity_manifest)
        if parity_manifest is not None:
            validate_live_inventory(parity_manifest, args.target_inventory)
            if args.previous_parity_manifest is not None:
                previous_parity_manifest = load_parity_manifest(
                    args.previous_parity_manifest
                )
                validate_manifest_progression(previous_parity_manifest, parity_manifest)
            _validate_parity_socket_capability()
        if parity_manifest is not None and not args.targets and not args.target_pair:
            target_pairs = tuple(
                TargetPair(baseline, candidate)
                for baseline, candidate in parity_manifest.target_pairs
            )
        else:
            target_pairs = _target_pairs(args.targets, args.target_pair)
        if (
            parity_manifest is not None
            and tuple(
                (pair.baseline_target, pair.candidate_target) for pair in target_pairs
            )
            != parity_manifest.target_pairs
        ):
            raise MeasurementError(
                "selected target mapping does not match --parity-manifest"
            )
        target_labels = tuple(pair.label for pair in target_pairs)
        variants: list[Variant] = []
        if not args.source_only:
            if args.baseline_dir is None:
                raise MeasurementError("missing --baseline-dir")
            variants.append(Variant("baseline", args.baseline_dir.resolve()))
            if args.candidate_dir is not None:
                variants.append(Variant("candidate", args.candidate_dir.resolve()))
        selected_binary_targets = {
            target
            for pair in target_pairs
            for target in (pair.baseline_target, pair.candidate_target)
        }
        unknown_overrides = set(overrides).difference(selected_binary_targets)
        if unknown_overrides:
            raise MeasurementError(
                "--corpus provided for unselected target(s): "
                + ", ".join(sorted(unknown_overrides))
            )

        output.parent.mkdir(parents=True, exist_ok=True)
        log_root.mkdir(parents=True, exist_ok=True)
        environment = _run_environment()

        for variant in variants:
            for binary_target in dict.fromkeys(
                pair.target_for(variant.name) for pair in target_pairs
            ):
                _validate_fuzzer(
                    _binary_path(variant.binary_dir, binary_target), environment
                )

        source_coverage_enabled = args.coverage_baseline_dir is not None
        source_coverage_root: Path | None = None
        source_corpus_artifact_root: Path | None = None
        if source_coverage_enabled:
            (
                source_coverage_root,
                source_corpus_artifact_root,
            ) = _source_coverage_artifact_roots(log_root)
        coverage_variants: list[Variant] = []
        source_roots: dict[str, Path] = {}
        source_identities: dict[str, dict[str, object]] = {}
        llvm_profdata: Path | None = None
        llvm_cov: Path | None = None
        tool_versions: dict[str, str] = {}
        if source_coverage_enabled:
            if args.coverage_candidate_dir is None:
                raise MeasurementError("missing --coverage-candidate-dir")
            coverage_variants = [
                Variant("baseline", args.coverage_baseline_dir.resolve()),
                Variant("candidate", args.coverage_candidate_dir.resolve()),
            ]
            source_roots = {
                "baseline": _resolve_curl_source_dir(
                    coverage_variants[0].binary_dir,
                    args.baseline_curl_source_dir,
                    "--baseline-curl-source-dir",
                ),
                "candidate": _resolve_curl_source_dir(
                    coverage_variants[1].binary_dir,
                    args.candidate_curl_source_dir,
                    "--candidate-curl-source-dir",
                ),
            }
            source_identities = {
                name: _source_tree_identity(source_root)
                for name, source_root in source_roots.items()
            }
            if (
                source_identities["baseline"]["sha256"]
                != source_identities["candidate"]["sha256"]
            ):
                raise MeasurementError(
                    "baseline and candidate curl source trees differ; function "
                    "and region coordinates are comparable only for identical "
                    "curl sources"
                )
            if parity_manifest is not None:
                validate_source_identity(parity_manifest, source_identities["baseline"])
            llvm_profdata = _resolve_tool(args.llvm_profdata, "llvm-profdata")
            llvm_cov = _resolve_tool(args.llvm_cov, "llvm-cov")
            tool_versions = {
                "llvm_profdata": _tool_version(llvm_profdata, "llvm-profdata"),
                "llvm_cov": _tool_version(llvm_cov, "llvm-cov"),
            }
            for coverage_variant in coverage_variants:
                for binary_target in dict.fromkeys(
                    pair.target_for(coverage_variant.name) for pair in target_pairs
                ):
                    _validate_coverage_binary(
                        _binary_path(coverage_variant.binary_dir, binary_target)
                    )

        runs: list[dict[str, object]] = []
        corpus_metadata: dict[str, dict[str, object]] = {}
        source_coverage_document: dict[str, object] | None = None
        parity_result: dict[str, object] | None = None
        parity_binding_failed = False
        wall_timeout = args.wall_timeout or max(60, args.seconds * 4 + 30)

        with tempfile.TemporaryDirectory(prefix="curl-fuzzer-measure-") as raw_temp:
            temporary_root = Path(raw_temp)
            snapshot_root = temporary_root / "snapshots"
            run_root = temporary_root / "runs"
            corpus_root = args.corpus_root.resolve()
            public_corpus_root = (
                args.public_corpus_root.resolve()
                if args.public_corpus_root is not None
                else None
            )

            timed_snapshots: dict[tuple[str, str], Path] = {}
            if not args.source_only:
                for target_pair in target_pairs:
                    target_label = target_pair.label
                    safe_label = target_label.replace("=>", "-vs-")
                    if target_pair.baseline_target == target_pair.candidate_target:
                        binary_target = target_pair.baseline_target
                        snapshot = snapshot_root / "timed" / safe_label / "shared"
                        _, metadata = _build_snapshot(
                            target=binary_target,
                            binary_dir=variants[0].binary_dir,
                            destination=snapshot,
                            corpus_root=corpus_root,
                            public_corpus_root=public_corpus_root,
                            overrides=overrides,
                        )
                        corpus_metadata[target_label] = metadata
                        for variant in variants:
                            timed_snapshots[(target_label, variant.name)] = snapshot
                    else:
                        pair_metadata: dict[str, object] = {
                            "baseline_target": target_pair.baseline_target,
                            "candidate_target": target_pair.candidate_target,
                        }
                        for variant in variants:
                            binary_target = target_pair.target_for(variant.name)
                            snapshot = (
                                snapshot_root / "timed" / safe_label / variant.name
                            )
                            _, metadata = _build_snapshot(
                                target=binary_target,
                                binary_dir=variant.binary_dir,
                                destination=snapshot,
                                corpus_root=corpus_root,
                                public_corpus_root=public_corpus_root,
                                overrides=overrides,
                            )
                            pair_metadata[variant.name] = metadata
                            timed_snapshots[(target_label, variant.name)] = snapshot
                        corpus_metadata[target_label] = pair_metadata

                    for repeat in range(args.repeats):
                        seed = args.seed_base + repeat
                        ordered_variants = (
                            variants if repeat % 2 == 0 else list(reversed(variants))
                        )
                        for variant in ordered_variants:
                            binary_target = target_pair.target_for(variant.name)
                            print(
                                f"==> {target_label} {variant.name} "
                                f"({binary_target}) repeat {repeat + 1}/"
                                f"{args.repeats}, seed {seed}",
                                flush=True,
                            )
                            run = _run_once(
                                variant=variant,
                                target_label=target_label,
                                binary_target=binary_target,
                                snapshot=timed_snapshots[(target_label, variant.name)],
                                run_root=run_root,
                                log_root=log_root,
                                seed=seed,
                                repeat=repeat,
                                seconds=args.seconds,
                                timeout=args.timeout,
                                wall_timeout=wall_timeout,
                                cpu=args.cpu,
                                extra_args=args.fuzzer_arg,
                                environment=environment,
                            )
                            runs.append(run)
                            if run["status"] != "ok":
                                print(f"    FAILED: {run['failure']}", file=sys.stderr)

            if source_coverage_enabled:
                if llvm_profdata is None or llvm_cov is None:
                    raise MeasurementError("LLVM coverage tools were not initialized")
                if source_coverage_root is None or source_corpus_artifact_root is None:
                    raise MeasurementError(
                        "source coverage artifact roots were not initialized"
                    )
                coverage_snapshots: dict[tuple[str, str], Path] = {}
                coverage_metadata: dict[tuple[str, str], dict[str, object]] = {}
                coverage_artifacts: dict[tuple[str, str], dict[str, object]] = {}
                for coverage_variant in coverage_variants:
                    ordered_targets = tuple(
                        dict.fromkeys(
                            pair.target_for(coverage_variant.name)
                            for pair in target_pairs
                        )
                    )
                    for binary_target in ordered_targets:
                        key = (coverage_variant.name, binary_target)
                        shared_source_corpus = any(
                            pair.baseline_target == pair.candidate_target
                            and pair.baseline_target == binary_target
                            for pair in target_pairs
                        )
                        if (
                            coverage_variant.name == "candidate"
                            and shared_source_corpus
                        ):
                            baseline_key = ("baseline", binary_target)
                            coverage_snapshots[key] = coverage_snapshots[baseline_key]
                            coverage_metadata[key] = coverage_metadata[baseline_key]
                            coverage_artifacts[key] = coverage_artifacts[baseline_key]
                            continue
                        snapshot = (
                            snapshot_root
                            / "coverage"
                            / coverage_variant.name
                            / binary_target
                        )
                        corpus_binary_dir = coverage_variant.binary_dir
                        if not args.source_only:
                            speed_variant = next(
                                variant
                                for variant in variants
                                if variant.name == coverage_variant.name
                            )
                            corpus_binary_dir = speed_variant.binary_dir
                            if shared_source_corpus:
                                corpus_binary_dir = variants[0].binary_dir
                        builder, metadata = _build_snapshot(
                            target=binary_target,
                            binary_dir=corpus_binary_dir,
                            destination=snapshot,
                            corpus_root=corpus_root,
                            public_corpus_root=public_corpus_root,
                            overrides=overrides,
                        )
                        coverage_snapshots[key] = snapshot
                        coverage_metadata[key] = metadata
                        coverage_artifacts[key] = _persist_snapshot(
                            builder,
                            metadata,
                            source_corpus_artifact_root,
                            coverage_variant.name,
                            binary_target,
                        )

                if args.source_only:
                    for target_pair in target_pairs:
                        corpus_metadata[target_pair.label] = {
                            "baseline_target": target_pair.baseline_target,
                            "candidate_target": target_pair.candidate_target,
                            "baseline": coverage_metadata[
                                ("baseline", target_pair.baseline_target)
                            ],
                            "candidate": coverage_metadata[
                                ("candidate", target_pair.candidate_target)
                            ],
                        }

                baseline_corpora: dict[str, dict[str, object]] | None = None
                if parity_manifest is not None:
                    baseline_corpora = {
                        target: coverage_metadata[("baseline", target)]
                        for target in parity_manifest.baseline_inventory
                    }
                    validate_baseline_corpora(parity_manifest, baseline_corpora)

                (
                    source_coverage_document,
                    baseline_aggregate,
                    candidate_aggregate,
                ) = _measure_source_coverage(
                    variants=coverage_variants,
                    source_roots=source_roots,
                    source_identities=source_identities,
                    target_pairs=target_pairs,
                    snapshots=coverage_snapshots,
                    snapshot_metadata=coverage_metadata,
                    snapshot_artifacts=coverage_artifacts,
                    artifact_root=source_coverage_root,
                    environment=environment,
                    wall_timeout=args.coverage_wall_timeout,
                    input_timeout=args.coverage_input_timeout,
                    llvm_profdata=llvm_profdata,
                    llvm_cov=llvm_cov,
                    tool_versions=tool_versions,
                )
                if parity_manifest is not None:
                    if baseline_corpora is None:
                        raise MeasurementError(
                            "baseline corpus identities were not initialized"
                        )
                    try:
                        parity_result = evaluate_parity(
                            parity_manifest,
                            source_identity=source_identities["baseline"],
                            target_pairs=tuple(
                                (pair.baseline_target, pair.candidate_target)
                                for pair in target_pairs
                            ),
                            baseline_corpora=baseline_corpora,
                            baseline=CoverageUniverse(
                                functions=baseline_aggregate.covered_functions,
                                regions=baseline_aggregate.covered_regions,
                            ),
                            candidate=CoverageUniverse(
                                functions=candidate_aggregate.covered_functions,
                                regions=candidate_aggregate.covered_regions,
                            ),
                        )
                    except CoverageParityError as error:
                        parity_binding_failed = True
                        parity_result = {
                            "manifest": str(parity_manifest.path),
                            "manifest_sha256": parity_manifest.sha256,
                            "immutable_baseline_sha256": (
                                parity_manifest.immutable_baseline_sha256
                            ),
                            "gate_scope": parity_manifest.gate_scope,
                            "retirement_eligible": (
                                parity_manifest.retirement_eligible
                            ),
                            "status": "invalid",
                            "error": {
                                "kind": "binding",
                                "message": str(error),
                            },
                        }

        summaries = _summaries(runs, variants, target_labels)
        comparable_counter_labels = (
            {
                target_pair.label
                for target_pair in target_pairs
                if target_pair.baseline_target == target_pair.candidate_target
            }
            if args.compare_libfuzzer_counters
            else set()
        )
        comparisons = _comparisons(summaries, target_labels, comparable_counter_labels)
        binary_metadata = {
            variant.name: {
                target_pair.label: {
                    "target": target_pair.target_for(variant.name),
                    **_artifact_metadata(
                        _binary_path(
                            variant.binary_dir,
                            target_pair.target_for(variant.name),
                        ),
                        "libFuzzer binary",
                    ),
                }
                for target_pair in target_pairs
            }
            for variant in variants
        }
        affinity = (
            sorted(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else None
        )
        if args.source_only:
            measurement_scope = "source-only"
        elif source_coverage_enabled:
            measurement_scope = "benchmark-and-source"
        else:
            measurement_scope = "benchmark"
        result_document = {
            "schema_version": 4,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "repository_revision": _git_revision(),
            "measurement_scope": measurement_scope,
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "cpu_count": os.cpu_count(),
                "affinity": affinity,
            },
            "config": {
                "targets": target_labels,
                "target_pairs": [
                    {
                        "label": target_pair.label,
                        "baseline": target_pair.baseline_target,
                        "candidate": target_pair.candidate_target,
                        "shared_corpus": (
                            target_pair.baseline_target == target_pair.candidate_target
                        ),
                    }
                    for target_pair in target_pairs
                ],
                "seconds": args.seconds,
                "timeout": args.timeout,
                "wall_timeout": wall_timeout,
                "repeats": args.repeats,
                "seed_base": args.seed_base,
                "cpu": args.cpu,
                "fuzzer_args": args.fuzzer_arg,
                "compare_libfuzzer_counters": args.compare_libfuzzer_counters,
                "source_only": args.source_only,
                "source_coverage": source_coverage_enabled,
                "coverage_wall_timeout": args.coverage_wall_timeout,
                "coverage_input_timeout": args.coverage_input_timeout,
                "coverage_replay_sanitizer_environment": dict(
                    COVERAGE_REPLAY_SANITIZER_ENVIRONMENT
                ),
                "parity_manifest": (
                    {
                        "path": str(parity_manifest.path),
                        "sha256": parity_manifest.sha256,
                        "baseline_id": parity_manifest.baseline_id,
                        "immutable_baseline_sha256": (
                            parity_manifest.immutable_baseline_sha256
                        ),
                        "gate_scope": parity_manifest.gate_scope,
                        "retirement_eligible": parity_manifest.retirement_eligible,
                    }
                    if parity_manifest is not None
                    else None
                ),
                "previous_parity_manifest": (
                    {
                        "path": str(previous_parity_manifest.path),
                        "sha256": previous_parity_manifest.sha256,
                        "baseline_id": previous_parity_manifest.baseline_id,
                    }
                    if previous_parity_manifest is not None
                    else None
                ),
            },
            "binaries": binary_metadata,
            "corpora": corpus_metadata,
            "runs": runs,
            "summary": summaries,
            "comparison": comparisons,
        }
        if source_coverage_document is not None:
            result_document["source_coverage"] = source_coverage_document
        if parity_result is not None:
            result_document["parity"] = parity_result
        output.write_text(
            json.dumps(result_document, indent=2) + "\n", encoding="utf-8"
        )

        if not args.source_only:
            print()
            _print_summary(summaries, args.repeats)
            _print_comparisons(comparisons)
        if source_coverage_document is not None:
            _print_source_coverage(source_coverage_document)
        print(f"\nJSON: {output}")
        print(f"Logs: {log_root}")

        if parity_binding_failed:
            print(
                "function-parity evidence did not bind to the manifest; "
                "see the JSON result",
                file=sys.stderr,
            )
            return 2
        failures = [run for run in runs if run["status"] != "ok"]
        if failures:
            print(
                f"{len(failures)} run(s) failed; see the preserved logs",
                file=sys.stderr,
            )
            return 1
        if parity_result is not None and parity_result.get("status") != "passed":
            print(
                "function-parity ratchet failed; see the JSON result",
                file=sys.stderr,
            )
            return 1
        return 0
    except (
        CorpusError,
        CoverageParityError,
        MeasurementError,
        OSError,
        UnicodeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
