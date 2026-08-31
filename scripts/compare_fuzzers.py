#!/usr/bin/env python3
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
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Callable, Iterable, Sequence, TypeVar


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGETS = (
    "curl_fuzzer_ftp",
    "curl_fuzzer_http",
    "curl_fuzzer_https",
    "curl_fuzzer_tftp",
    "curl_fuzzer_ws",
    "curl_fuzzer_proto_http",
    "curl_fuzzer_proto_http_deep",
    "curl_fuzzer_proto_https",
    "curl_fuzzer_proto_ws",
    "curl_fuzzer_proto_wss",
    "curl_fuzzer_proto_telnet",
    "curl_fuzzer_proto_ftp",
    "curl_fuzzer_proto_tftp",
    "curl_fuzzer_proto_api",
    "curl_fuzzer_proto_timing",
)
HISTORICAL_PROTO_CORPUS_TARGETS = frozenset(
    {
        "curl_fuzzer_proto_http",
        "curl_fuzzer_proto_http_deep",
        "curl_fuzzer_proto_https",
        "curl_fuzzer_proto_ws",
        "curl_fuzzer_proto_wss",
        "curl_fuzzer_proto_telnet",
        "curl_fuzzer_proto_ftp",
        "curl_fuzzer_proto_tftp",
        "curl_fuzzer_proto_api",
        "curl_fuzzer_proto_timing",
    }
)
MANAGED_FUZZER_ARGS = (
    "-artifact_prefix=",
    "-max_total_time=",
    "-print_final_stats=",
    "-reload=",
    "-seed=",
    "-timeout=",
)

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
            function_count = raw_function.get("count")
            if isinstance(function_count, (int, float)) and function_count > 0:
                covered_functions.add(function_key)

            raw_regions = raw_function.get("regions")
            if not isinstance(raw_regions, list):
                continue
            for raw_region in raw_regions:
                if not isinstance(raw_region, list) or len(raw_region) < 6:
                    continue
                coordinates = raw_region[:5]
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
                start_line, start_column, end_line, end_column, count = coordinates
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CorpusSnapshotBuilder:
    """Build a deduplicated, content-addressed corpus directory."""

    def __init__(self, destination: Path) -> None:
        self.destination = destination
        self.destination.mkdir(parents=True)
        self.hashes: dict[str, int] = {}
        self.sources: list[str] = []

    def _record_file(self, source: Path) -> None:
        digest = _sha256_file(source)
        if digest in self.hashes:
            return
        destination = self.destination / digest
        shutil.copy2(source, destination)
        self.hashes[digest] = destination.stat().st_size

    def _record_stream(self, source: IO[bytes]) -> None:
        digest = hashlib.sha256()
        with tempfile.NamedTemporaryFile(
            dir=self.destination, prefix=".incoming-", delete=False
        ) as pending:
            pending_path = Path(pending.name)
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                pending.write(chunk)

        content_hash = digest.hexdigest()
        if content_hash in self.hashes:
            pending_path.unlink()
            return
        destination = self.destination / content_hash
        os.replace(pending_path, destination)
        self.hashes[content_hash] = destination.stat().st_size

    def add(self, source: Path) -> None:
        """Add a directory tree, a zip archive, or one corpus file."""
        source = source.resolve()
        if not source.exists():
            raise MeasurementError(f"corpus source does not exist: {source}")
        self.sources.append(str(source))

        if source.is_dir():
            for corpus_file in sorted(
                path for path in source.rglob("*") if path.is_file()
            ):
                self._record_file(corpus_file)
            return

        if zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                for member in sorted(
                    archive.infolist(), key=lambda item: item.filename
                ):
                    if member.is_dir():
                        continue
                    with archive.open(member) as archived_file:
                        self._record_stream(archived_file)
            return

        self._record_file(source)

    def metadata(self) -> dict[str, object]:
        """Return stable corpus identity and size metadata."""
        identity = hashlib.sha256()
        for digest, size in sorted(self.hashes.items()):
            identity.update(f"{digest}:{size}\n".encode())
        return {
            "count": len(self.hashes),
            "bytes": sum(self.hashes.values()),
            "sha256": identity.hexdigest(),
            "sources": self.sources,
        }


def _parse_target_mapping(values: Iterable[str]) -> dict[str, list[Path]]:
    mappings: dict[str, list[Path]] = {}
    for value in values:
        if "=" not in value:
            raise MeasurementError(f"invalid --corpus {value!r}; expected TARGET=PATH")
        target, raw_path = value.split("=", 1)
        if not target or not raw_path:
            raise MeasurementError(f"invalid --corpus {value!r}; expected TARGET=PATH")
        mappings.setdefault(target, []).append(Path(raw_path))
    return mappings


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
    labels = [pair.label for pair in pairs]
    if len(labels) != len(set(labels)):
        raise MeasurementError("selected targets produce duplicate comparison labels")
    return tuple(pairs)


def _corpus_sources(
    target: str,
    baseline_dir: Path,
    corpus_root: Path,
    public_corpus_root: Path | None,
    overrides: dict[str, list[Path]],
) -> list[Path]:
    if target in overrides:
        return overrides[target]

    sources: list[Path] = []
    checked_in = corpus_root / target
    if checked_in.is_dir() and any(path.is_file() for path in checked_in.rglob("*")):
        sources.append(checked_in)

    seed_archive = baseline_dir / f"{target}_seed_corpus.zip"
    if seed_archive.is_file():
        sources.append(seed_archive)

    if public_corpus_root is not None:
        public_targets = [target]
        if target in HISTORICAL_PROTO_CORPUS_TARGETS:
            public_targets.append("curl_fuzzer_proto")
        for public_target in public_targets:
            public = public_corpus_root / public_target
            if public.is_dir() and any(path.is_file() for path in public.rglob("*")):
                sources.append(public)

    if not sources:
        raise MeasurementError(
            f"no corpus found for {target}; checked {checked_in} and {seed_archive}"
        )
    return sources


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

    binary = (variant.binary_dir / binary_target).resolve()
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
    counter_comparable: set[str] | None = None,
) -> list[dict[str, object]]:
    by_key = {(summary["target"], summary["variant"]): summary for summary in summaries}
    comparisons: list[dict[str, object]] = []
    for target in targets:
        baseline = by_key.get((target, "baseline"))
        candidate = by_key.get((target, "candidate"))
        if baseline is None or candidate is None:
            continue
        compare_counters = counter_comparable is None or target in counter_comparable
        comparisons.append(
            {
                "target": target,
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
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
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


def _measure_coverage_target(
    *,
    variant: Variant,
    target_label: str,
    binary_target: str,
    source_root: Path,
    snapshot: Path,
    artifact_root: Path,
    environment: dict[str, str],
    wall_timeout: int,
    llvm_profdata: Path,
    llvm_cov: Path,
) -> tuple[dict[str, object], SourceCoverageIndex]:
    """Replay one fixed corpus and export curl-only source coverage."""
    binary = (variant.binary_dir / binary_target).resolve()
    _validate_coverage_binary(binary)
    safe_label = target_label.replace("=>", "-vs-")
    target_root = artifact_root / variant.name / safe_label
    target_root.mkdir(parents=True, exist_ok=True)
    for pattern in ("*.profraw", "*.profdata", "*.export.json", "*.tmp"):
        for stale in target_root.glob(pattern):
            if stale.is_file():
                stale.unlink()

    log_path = target_root / "replay.log"
    profile_pattern = target_root / f"{binary_target}-%p.profraw"
    replay_environment = environment.copy()
    replay_environment["LLVM_PROFILE_FILE"] = str(profile_pattern)
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

    raw_profiles = sorted(target_root.glob("*.profraw"))
    if not raw_profiles:
        raise MeasurementError(
            f"coverage replay for {variant.name}/{binary_target} produced no .profraw "
            "file; rebuild it with -fprofile-instr-generate and "
            "-fcoverage-mapping"
        )

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
    os.replace(pending_export, export_path)
    try:
        export_document = json.loads(export_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MeasurementError(
            f"could not parse llvm-cov export for {variant.name}/{binary_target}: "
            f"{error}"
        ) from error
    index = parse_source_coverage_export(export_document, source_root)
    metadata: dict[str, object] = {
        "binary": str(binary),
        "binary_target": binary_target,
        "binary_sha256": _sha256_file(binary),
        "replay_command": [str(binary), "<corpus>"],
        "replay_log": str(log_path),
        "raw_profiles": [str(path) for path in raw_profiles],
        "profile": str(profile),
        "export": str(export_path),
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
    artifact_root: Path,
    environment: dict[str, str],
    wall_timeout: int,
    llvm_profdata: Path,
    llvm_cov: Path,
    tool_versions: dict[str, str],
) -> dict[str, object]:
    """Measure and compare fixed-corpus curl source coverage per target."""
    variant_documents: dict[str, object] = {}
    indexes: dict[str, dict[str, SourceCoverageIndex]] = {}
    for variant in variants:
        target_documents: dict[str, object] = {}
        target_indexes: dict[str, SourceCoverageIndex] = {}
        for target_pair in target_pairs:
            target_label = target_pair.label
            binary_target = target_pair.target_for(variant.name)
            print(
                f"==> {target_label} {variant.name} ({binary_target}) "
                "fixed-corpus source coverage",
                flush=True,
            )
            metadata, index = _measure_coverage_target(
                variant=variant,
                target_label=target_label,
                binary_target=binary_target,
                source_root=source_roots[variant.name],
                snapshot=snapshots[(target_label, variant.name)],
                artifact_root=artifact_root,
                environment=environment,
                wall_timeout=wall_timeout,
                llvm_profdata=llvm_profdata,
                llvm_cov=llvm_cov,
            )
            target_documents[target_label] = metadata
            target_indexes[target_label] = index
        aggregate = _merge_source_coverage(target_indexes.values())
        indexes[variant.name] = target_indexes
        variant_documents[variant.name] = {
            "binary_dir": str(variant.binary_dir),
            "curl_source_dir": str(source_roots[variant.name]),
            "source_identity": source_identities[variant.name],
            "targets": target_documents,
            "aggregate": _source_coverage_summary(aggregate),
        }

    baseline_indexes = indexes["baseline"]
    candidate_indexes = indexes["candidate"]
    target_comparisons = {
        target_pair.label: compare_source_coverage(
            baseline_indexes[target_pair.label],
            candidate_indexes[target_pair.label],
        )
        for target_pair in target_pairs
    }
    baseline_aggregate = _merge_source_coverage(baseline_indexes.values())
    candidate_aggregate = _merge_source_coverage(candidate_indexes.values())
    return {
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
        "comparison": {
            "targets": target_comparisons,
            "aggregate": compare_source_coverage(
                baseline_aggregate, candidate_aggregate
            ),
        },
    }


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
        required=True,
        type=Path,
        help="directory containing the baseline libFuzzer binaries",
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
        default=300,
        help="outer timeout for each fixed-corpus coverage replay",
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
    return parser.parse_args(argv)


def _validate_args(args: argparse.Namespace) -> None:
    if args.seconds <= 0 or args.timeout <= 0 or args.repeats <= 0:
        raise MeasurementError("--seconds, --timeout, and --repeats must be positive")
    if args.wall_timeout is not None and args.wall_timeout <= 0:
        raise MeasurementError("--wall-timeout must be positive")
    if args.coverage_wall_timeout <= 0:
        raise MeasurementError("--coverage-wall-timeout must be positive")
    if args.cpu is not None and args.cpu < 0:
        raise MeasurementError("--cpu must not be negative")
    if args.target_pair and args.candidate_dir is None:
        raise MeasurementError("--target-pair requires --candidate-dir")
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
        if args.candidate_dir is None:
            raise MeasurementError(
                "source coverage comparison requires --candidate-dir"
            )
    for argument in args.fuzzer_arg:
        if not argument.startswith("-"):
            raise MeasurementError(f"fuzzer argument must begin with '-': {argument}")
        if argument.startswith(MANAGED_FUZZER_ARGS):
            raise MeasurementError(
                f"fuzzer argument is managed by this tool: {argument}"
            )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested measurements and return a process status."""
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    try:
        _validate_args(args)
        target_pairs = _target_pairs(args.targets, args.target_pair)
        target_labels = tuple(pair.label for pair in target_pairs)
        variants = [Variant("baseline", args.baseline_dir.resolve())]
        if args.candidate_dir is not None:
            variants.append(Variant("candidate", args.candidate_dir.resolve()))
        overrides = _parse_target_mapping(args.corpus)
        selected_binary_targets = {
            pair.target_for(variant.name)
            for pair in target_pairs
            for variant in variants
        }
        unknown_overrides = set(overrides).difference(selected_binary_targets)
        if unknown_overrides:
            raise MeasurementError(
                "--corpus provided for unselected target(s): "
                + ", ".join(sorted(unknown_overrides))
            )

        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        log_root = (
            args.log_dir.resolve()
            if args.log_dir is not None
            else output.parent / f"{output.stem}-logs"
        )
        log_root.mkdir(parents=True, exist_ok=True)
        environment = _run_environment()

        for variant in variants:
            for target_pair in target_pairs:
                binary_target = target_pair.target_for(variant.name)
                _validate_fuzzer(
                    (variant.binary_dir / binary_target).resolve(), environment
                )

        source_coverage_enabled = args.coverage_baseline_dir is not None
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
            llvm_profdata = _resolve_tool(args.llvm_profdata, "llvm-profdata")
            llvm_cov = _resolve_tool(args.llvm_cov, "llvm-cov")
            tool_versions = {
                "llvm_profdata": _tool_version(llvm_profdata, "llvm-profdata"),
                "llvm_cov": _tool_version(llvm_cov, "llvm-cov"),
            }
            for coverage_variant in coverage_variants:
                for target_pair in target_pairs:
                    binary_target = target_pair.target_for(coverage_variant.name)
                    _validate_coverage_binary(
                        (coverage_variant.binary_dir / binary_target).resolve()
                    )

        runs: list[dict[str, object]] = []
        corpus_metadata: dict[str, dict[str, object]] = {}
        source_coverage_document: dict[str, object] | None = None
        wall_timeout = args.wall_timeout or max(60, args.seconds * 4 + 30)

        with tempfile.TemporaryDirectory(prefix="curl-fuzzer-measure-") as raw_temp:
            temporary_root = Path(raw_temp)
            snapshot_root = temporary_root / "snapshots"
            run_root = temporary_root / "runs"
            snapshots: dict[tuple[str, str], Path] = {}
            for target_pair in target_pairs:
                target_label = target_pair.label
                safe_label = target_label.replace("=>", "-vs-")
                if target_pair.baseline_target == target_pair.candidate_target:
                    binary_target = target_pair.baseline_target
                    snapshot = snapshot_root / safe_label / "shared"
                    builder = CorpusSnapshotBuilder(snapshot)
                    sources = _corpus_sources(
                        binary_target,
                        variants[0].binary_dir,
                        args.corpus_root.resolve(),
                        args.public_corpus_root.resolve()
                        if args.public_corpus_root is not None
                        else None,
                        overrides,
                    )
                    for source in sources:
                        builder.add(source)
                    metadata = builder.metadata()
                    if metadata["count"] == 0:
                        raise MeasurementError(f"corpus for {binary_target} is empty")
                    corpus_metadata[target_label] = metadata
                    for variant in variants:
                        snapshots[(target_label, variant.name)] = snapshot
                else:
                    pair_metadata: dict[str, object] = {
                        "baseline_target": target_pair.baseline_target,
                        "candidate_target": target_pair.candidate_target,
                    }
                    for variant in variants:
                        binary_target = target_pair.target_for(variant.name)
                        snapshot = snapshot_root / safe_label / variant.name
                        builder = CorpusSnapshotBuilder(snapshot)
                        sources = _corpus_sources(
                            binary_target,
                            variant.binary_dir,
                            args.corpus_root.resolve(),
                            args.public_corpus_root.resolve()
                            if args.public_corpus_root is not None
                            else None,
                            overrides,
                        )
                        for source in sources:
                            builder.add(source)
                        metadata = builder.metadata()
                        if metadata["count"] == 0:
                            raise MeasurementError(
                                f"corpus for {binary_target} is empty"
                            )
                        pair_metadata[variant.name] = metadata
                        snapshots[(target_label, variant.name)] = snapshot
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
                            f"({binary_target}) "
                            f"repeat {repeat + 1}/{args.repeats}, seed {seed}",
                            flush=True,
                        )
                        run = _run_once(
                            variant=variant,
                            target_label=target_label,
                            binary_target=binary_target,
                            snapshot=snapshots[(target_label, variant.name)],
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
                source_coverage_document = _measure_source_coverage(
                    variants=coverage_variants,
                    source_roots=source_roots,
                    source_identities=source_identities,
                    target_pairs=target_pairs,
                    snapshots=snapshots,
                    artifact_root=log_root / "source-coverage",
                    environment=environment,
                    wall_timeout=args.coverage_wall_timeout,
                    llvm_profdata=llvm_profdata,
                    llvm_cov=llvm_cov,
                    tool_versions=tool_versions,
                )

        summaries = _summaries(runs, variants, target_labels)
        comparable_counter_labels = {
            target_pair.label
            for target_pair in target_pairs
            if target_pair.baseline_target == target_pair.candidate_target
        }
        comparisons = _comparisons(summaries, target_labels, comparable_counter_labels)
        binary_metadata = {
            variant.name: {
                target_pair.label: {
                    "target": target_pair.target_for(variant.name),
                    "path": str(
                        (
                            variant.binary_dir / target_pair.target_for(variant.name)
                        ).resolve()
                    ),
                    "sha256": _sha256_file(
                        (
                            variant.binary_dir / target_pair.target_for(variant.name)
                        ).resolve()
                    ),
                    "bytes": (variant.binary_dir / target_pair.target_for(variant.name))
                    .stat()
                    .st_size,
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
        result_document = {
            "schema_version": 2,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "repository_revision": _git_revision(),
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
                "source_coverage": source_coverage_enabled,
                "coverage_wall_timeout": args.coverage_wall_timeout,
            },
            "binaries": binary_metadata,
            "corpora": corpus_metadata,
            "runs": runs,
            "summary": summaries,
            "comparison": comparisons,
        }
        if source_coverage_document is not None:
            result_document["source_coverage"] = source_coverage_document
        output.write_text(
            json.dumps(result_document, indent=2) + "\n", encoding="utf-8"
        )

        print()
        _print_summary(summaries, args.repeats)
        _print_comparisons(comparisons)
        if source_coverage_document is not None:
            _print_source_coverage(source_coverage_document)
        print(f"\nJSON: {output}")
        print(f"Logs: {log_root}")

        failures = [run for run in runs if run["status"] != "ok"]
        if failures:
            print(
                f"{len(failures)} run(s) failed; see the preserved logs",
                file=sys.stderr,
            )
            return 1
        return 0
    except MeasurementError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
