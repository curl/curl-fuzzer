#!/usr/bin/env python3
"""Report separate libcurl and harness gaps from scoped llvm-cov JSON exports."""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

METRICS = ("lines", "functions", "regions", "branches")
EXPORT_TYPE = "llvm.coverage.json.export"


class CoverageReportError(ValueError):
    """Raised when an export cannot provide trustworthy coverage counts."""


@dataclass(frozen=True)
class CoverageCount:
    """Exact counters; an empty denominator has no coverage percentage."""

    covered: int
    count: int

    @property
    def missed(self) -> int:
        """Return the number of unexecuted mapped counters."""
        return self.count - self.covered

    @property
    def percent(self) -> float | None:
        """Return a percentage only when LLVM supplied measurable counters."""
        return 100 * self.covered / self.count if self.count else None

    def to_json(self) -> dict[str, int | float | None]:
        """Preserve exact denominators alongside their derived percentage."""
        return {
            "covered": self.covered,
            "count": self.count,
            "missed": self.missed,
            "percent": self.percent,
        }


@dataclass(frozen=True)
class FunctionGap:
    """A wholly unexecuted source definition, grouping its instantiations."""

    filename: str
    line: int
    column: int
    names: tuple[str, ...]
    instantiations: int
    code_regions: int


def _object(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CoverageReportError(f"{location}: expected an object")
    return value


def _list(value: object, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise CoverageReportError(f"{location}: expected an array")
    return value


def _count(value: object, location: str) -> int:
    if type(value) is not int or value < 0:
        raise CoverageReportError(f"{location}: expected a nonnegative integer")
    return value


def _runner_counters(document: object) -> dict[str, int]:
    record = _object(document, "runner status")
    counters = {
        name: _count(record.get(name), f"runner status.{name}")
        for name in (
            "attempted",
            "completed",
            "timed_out",
            "input_errors",
            "path_errors",
        )
    }
    if (
        counters["completed"] + counters["timed_out"] > counters["attempted"]
        or counters["input_errors"] > counters["attempted"]
    ):
        raise CoverageReportError("runner status: outcomes exceed attempted inputs")
    return counters


def record_replay_result(
    status_file: Path,
    target: str,
    outcome: str,
    exit_code: int | None,
    expected_inputs: int,
    count_errors: int,
    counter_file: Path,
    log_file: Path,
    profile_pattern: str,
) -> None:
    """Persist one target result while allowing subsequent targets to replay."""
    counters = None
    counter_error = None
    profiles_written = 0
    if outcome == "executed":
        try:
            counters = _runner_counters(json.loads(counter_file.read_text()))
        except (OSError, UnicodeError, ValueError) as error:
            counter_error = str(error)
        profiles_written = sum(
            Path(filename).is_file() and Path(filename).stat().st_size > 0
            for filename in glob.glob(profile_pattern)
        )
        if (
            exit_code != 0
            or count_errors
            or (
                counters
                and any(
                    counters[name]
                    for name in ("timed_out", "input_errors", "path_errors")
                )
            )
        ):
            outcome = "failed"
        elif (
            counters is not None
            and expected_inputs > 0
            and counters["attempted"] == counters["completed"] == expected_inputs
            and profiles_written > 0
        ):
            outcome = "complete"
        else:
            outcome = "incomplete"
    result = {
        "target": target,
        "outcome": outcome,
        "exit_code": exit_code,
        "expected_inputs": expected_inputs,
        "count_errors": count_errors,
        "counters": counters,
        "counter_error": counter_error,
        "profiles_written": profiles_written,
        "log": str(log_file),
    }
    status = json.loads(status_file.read_text())
    for index, row in enumerate(status["targets"]):
        if row["target"] == target:
            status["targets"][index] = result
            break
    status["complete"] = bool(status["targets"]) and all(
        row["outcome"] == "complete" for row in status["targets"]
    )
    status_file.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")


def _replay_status(document: object) -> dict[str, Any]:
    status = _object(document, "replay status")
    rows = _list(status.get("targets"), "replay status.targets")
    for raw in rows:
        row = _object(raw, "replay target")
        if not isinstance(row.get("target"), str) or row.get("outcome") not in {
            "complete",
            "failed",
            "incomplete",
            "missing_binary",
            "no_corpus",
            "empty_corpus",
        }:
            raise CoverageReportError("replay target: invalid identity or outcome")
        if row["outcome"] == "complete":
            counters = _runner_counters(row.get("counters"))
            expected = _count(
                row.get("expected_inputs"), "replay target.expected_inputs"
            )
            if (
                _count(row.get("exit_code"), "replay target.exit_code") != 0
                or _count(row.get("count_errors"), "replay target.count_errors")
                or not _count(
                    row.get("profiles_written"), "replay target.profiles_written"
                )
                or expected == 0
                or counters["attempted"] != expected
                or counters["completed"] != expected
                or any(
                    counters[name]
                    for name in ("timed_out", "input_errors", "path_errors")
                )
            ):
                raise CoverageReportError(
                    "replay target: incomplete replay marked complete"
                )
    complete = bool(rows) and all(row["outcome"] == "complete" for row in rows)
    if type(status.get("complete")) is not bool or status["complete"] != complete:
        raise CoverageReportError("replay status: inconsistent completeness flag")
    return status


def _metric(summary: dict[str, Any], name: str, location: str) -> CoverageCount | None:
    if name not in summary:
        return None
    record = _object(summary[name], f"{location}.{name}")
    covered = _count(record.get("covered"), f"{location}.{name}.covered")
    count = _count(record.get("count"), f"{location}.{name}.count")
    if covered > count:
        raise CoverageReportError(f"{location}.{name}: covered exceeds count")
    return CoverageCount(covered, count)


def _function_gaps(
    records: list[Any], filenames: set[str], location: str
) -> tuple[list[FunctionGap], int]:
    groups: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
    excluded = 0
    for index, raw in enumerate(records):
        record_location = f"{location}.functions[{index}]"
        record = _object(raw, record_location)
        names = _list(record.get("filenames"), f"{record_location}.filenames")
        regions = _list(record.get("regions"), f"{record_location}.regions")
        if not names or not all(isinstance(name, str) for name in names):
            raise CoverageReportError(f"{record_location}: invalid filenames")
        if not isinstance(record.get("name"), str):
            raise CoverageReportError(f"{record_location}: invalid function name")
        _count(record.get("count"), f"{record_location}.count")
        for region in regions:
            if not isinstance(region, list) or len(region) < 8:
                raise CoverageReportError(f"{record_location}: invalid region mapping")
            for value in region[:8]:
                _count(value, f"{record_location}.region")
            if region[5] >= len(names) or region[6] >= len(names):
                raise CoverageReportError(f"{record_location}: invalid region file ID")

        # Mirror LLVM's findMainViewFileID and instantiation grouping. Expanded
        # macro files are not the function definition; the first remaining file
        # ID owns it. LLVM groups definitions by their first region's start.
        expanded_ids = {region[6] for region in regions if region[7] == 1}
        main_id = next((i for i in range(len(names)) if i not in expanded_ids), None)
        if main_id is None or names[main_id] not in filenames:
            excluded += 1
            continue
        first_region = next((r for r in regions if r[5] == main_id), None)
        if first_region is None:
            raise CoverageReportError(f"{record_location}: no definition region")
        key = (names[main_id], first_region[0], first_region[1])
        groups.setdefault(key, []).append(record)

    gaps = []
    for (filename, line, column), instances in groups.items():
        if any(instance["count"] for instance in instances):
            continue
        gaps.append(
            FunctionGap(
                filename=filename,
                line=line,
                column=column,
                names=tuple(sorted({instance["name"] for instance in instances})),
                instantiations=len(instances),
                code_regions=max(
                    sum(region[7] == 0 for region in instance["regions"])
                    for instance in instances
                ),
            )
        )
    gaps.sort(key=lambda gap: (-gap.code_regions, gap.filename, gap.line, gap.column))
    return gaps, excluded


def summarize_export(document: object, label: str, source: str) -> dict[str, Any]:
    """Summarize one source-scoped export without recounting macro expansions."""
    root = _object(document, source)
    if root.get("type") != EXPORT_TYPE:
        raise CoverageReportError(f"{source}: expected {EXPORT_TYPE}")
    version = root.get("version")
    if not isinstance(version, str) or version.split(".")[0] != "2":
        raise CoverageReportError(
            f"{source}: unsupported LLVM export version {version!r}"
        )
    units = _list(root.get("data"), f"{source}.data")
    if len(units) != 1:
        raise CoverageReportError(
            f"{source}: expected one merged export unit; merge profiles and objects "
            "before exporting instead of adding overlapping architectures"
        )
    unit = _object(units[0], f"{source}.data[0]")
    files: list[dict[str, Any]] = []
    filenames: set[str] = set()
    totals: dict[str, CoverageCount | None] = {
        name: CoverageCount(0, 0) for name in METRICS
    }
    missing_metrics: dict[str, list[str]] = {name: [] for name in METRICS}
    for index, raw in enumerate(_list(unit.get("files"), f"{source}.files")):
        location = f"{source}.files[{index}]"
        record = _object(raw, location)
        filename = record.get("filename")
        if not isinstance(filename, str) or not filename:
            raise CoverageReportError(f"{location}: missing filename")
        if filename in filenames:
            raise CoverageReportError(f"{source}: duplicate file {filename!r}")
        filenames.add(filename)
        summary = _object(record.get("summary"), f"{location}.summary")
        metrics = {}
        for name in METRICS:
            metric = _metric(summary, name, location)
            metrics[name] = metric.to_json() if metric else None
            if metric is None:
                missing_metrics[name].append(filename)
                totals[name] = None
            elif totals[name] is not None:
                current = totals[name]
                assert current is not None
                totals[name] = CoverageCount(
                    current.covered + metric.covered, current.count + metric.count
                )
        files.append({"filename": filename, "metrics": metrics})

    # LLVM's function array can include records outside the requested file list
    # even when files and totals are scoped. Never use those for gap rankings.
    function_details_available = "functions" in unit
    gaps, excluded = _function_gaps(
        _list(unit.get("functions", []), f"{source}.functions"), filenames, source
    )
    files.sort(
        key=lambda file: (
            -(file["metrics"]["lines"] or {}).get("missed", 0),
            -(file["metrics"]["regions"] or {}).get("missed", 0),
            file["filename"],
        )
    )
    return {
        "label": label,
        "source": source,
        "llvm_export_version": version,
        "file_count": len(files),
        "metrics": {
            name: metric.to_json() if metric else None
            for name, metric in totals.items()
        },
        "missing_metrics": missing_metrics,
        "files": files,
        "function_details_available": function_details_available,
        "excluded_function_mappings": excluded,
        "uncovered_functions": [asdict(gap) for gap in gaps],
    }


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("`", "\\`").replace("\n", " ")


def render_markdown(
    reports: Sequence[dict[str, Any]], limit: int, replay: dict[str, Any] | None = None
) -> str:
    """Render counts and prioritized gaps with their measurement limitations."""
    lines = [
        "# Coverage gaps",
        "",
        (
            "Each source group uses the explicit filenames in its LLVM export. "
            "Counts come from LLVM file summaries; percentages are calculated from "
            "covered/count, never averaged across files. Empty denominators are N/A."
        ),
        "",
    ]
    if replay is not None:
        rows = replay["targets"]
        completed = sum(row["outcome"] == "complete" for row in rows)
        state = "complete" if replay["complete"] else "partial"
        lines += [
            "## Selected corpus replay",
            "",
            f"Replay is **{state}**: {completed} / {len(rows)} selected targets completed.",
            "Completeness describes this selected replay, independently of coverage percentages.",
            "",
            "| Target | Outcome | Exit | Completed / declared inputs | Count errors | Profiles | Log |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- |",
        ]
        for row in rows:
            counters = row.get("counters") or {}
            lines.append(
                f"| {_cell(row['target'])} | {_cell(row['outcome'])} | "
                f"{row.get('exit_code')} | {counters.get('completed', 'unavailable')} / "
                f"{row.get('expected_inputs', 'unavailable')} | {row.get('count_errors', 0)} | "
                f"{row.get('profiles_written', 0)} | {_cell(row.get('log', 'unavailable'))} |"
            )
        lines.append("")
    for report in reports:
        lines += [
            f"## {_cell(report['label'])}",
            "",
            (
                f"Export: `{_cell(report['source'])}`; "
                f"{report['file_count']} mapped files; "
                f"LLVM JSON version {_cell(report['llvm_export_version'])}."
            ),
            "",
            "| Metric | Covered / total | Missed | Coverage |",
            "| --- | ---: | ---: | ---: |",
        ]
        for name in METRICS:
            metric = report["metrics"][name]
            if metric is None:
                lines.append(f"| {name} | unavailable | unavailable | unavailable |")
            else:
                percentage = (
                    f"{metric['percent']:.2f}%"
                    if metric["percent"] is not None
                    else "N/A"
                )
                lines.append(
                    f"| {name} | {metric['covered']} / {metric['count']} | "
                    f"{metric['missed']} | {percentage} |"
                )
        lines += [
            "",
            "### Files with missed counters",
            "",
            "Ranked by missed lines, then missed regions. Cells show missed / total.",
            "",
            "| File | Lines | Functions | Regions | Branches |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        missed_files = [
            file
            for file in report["files"]
            if any(metric and metric["missed"] for metric in file["metrics"].values())
        ]
        for file in missed_files[:limit]:
            cells = []
            for name in METRICS:
                metric = file["metrics"][name]
                cells.append(
                    f"{metric['missed']} / {metric['count']}"
                    if metric is not None
                    else "unavailable"
                )
            lines.append(f"| {_cell(file['filename'])} | {' | '.join(cells)} |")
        if not missed_files:
            lines.append("| No missed counters in the exported scope | — | — | — | — |")
        lines += [
            "",
            "### Wholly uncovered functions",
            "",
            (
                "Definitions are grouped by source file, line, and column, as LLVM "
                "groups instantiations. A definition is covered when any "
                "instantiation executes. Rankings use the largest instantiation's "
                "code-region count for size, without changing the summary denominators."
            ),
            "",
            "| Definition | Symbols | Code regions | Instantiations |",
            "| --- | --- | ---: | ---: |",
        ]
        for gap in report["uncovered_functions"][:limit]:
            lines.append(
                f"| {_cell(gap['filename'])}:{gap['line']}:{gap['column']} | "
                f"{_cell(', '.join(gap['names']))} | {gap['code_regions']} | "
                f"{gap['instantiations']} |"
            )
        if not report["function_details_available"]:
            lines.append(
                "| Function mappings unavailable; export without -summary-only | — | — | — |"
            )
        elif not report["uncovered_functions"]:
            lines.append("| No wholly uncovered mapped definitions | — | — | — |")
        lines += [
            "",
            (
                f"{report['excluded_function_mappings']} function mappings whose "
                "definitions are outside the exported file list were excluded from "
                "the function ranking."
            ),
            "",
        ]
        for name, filenames in report["missing_metrics"].items():
            if filenames:
                lines += [
                    (
                        f"{name} is unavailable: {len(filenames)} file summaries "
                        "omit that metric; partial counts are not reported as a total."
                    ),
                    "",
                ]
    lines += [
        "## Scope and blockers",
        "",
        (
            "The JSON file lists preserve the exact measured scope. Uninstrumented "
            "dependencies, disabled backends, platform-specific code, and source files "
            "omitted by the build or export do not contribute counters. Compiler-skipped "
            "regions do not establish executable line coverage. This report does not "
            "treat any of those cases as covered."
        ),
        "",
        (
            "Allocation failures, operating-system failures, and terminating assertions "
            "may need controlled fault injection or separate replay processes. A missed "
            "counter does not establish whether its path is reachable. Skipped targets, "
            "incomplete corpus replay, and stale binary/profile combinations must be "
            "resolved before claiming complete coverage. Compare runs using matching "
            "source revisions, build features, toolchains, and corpora."
        ),
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Read the two scoped exports and write Markdown and optional JSON reports."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libcurl", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="Markdown output; default: stdout")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--replay-status", type=Path)
    parser.add_argument(
        "--limit", type=int, default=20, help="Rows per ranking (default: 20)"
    )
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("--limit must be positive")
    try:
        reports = [
            summarize_export(
                json.loads(path.read_text(encoding="utf-8")), label, str(path)
            )
            for label, path in (
                ("libcurl", args.libcurl),
                ("curl-fuzzer", args.harness),
            )
        ]
        replay = (
            _replay_status(json.loads(args.replay_status.read_text(encoding="utf-8")))
            if args.replay_status
            else None
        )
        markdown = render_markdown(reports, args.limit, replay)
        if args.output:
            args.output.write_text(markdown, encoding="utf-8")
        else:
            sys.stdout.write(markdown)
        if args.json_output:
            result: dict[str, Any] = {"reports": reports}
            if replay is not None:
                result["replay"] = replay
            args.json_output.write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
    except (OSError, UnicodeError, json.JSONDecodeError, CoverageReportError) as error:
        print(f"coverage summary: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
