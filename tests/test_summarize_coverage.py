"""Exercise scoped LLVM coverage counts and definition-level gap reporting."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "summarize_coverage.py"


@pytest.fixture
def module() -> Any:
    specification = importlib.util.spec_from_file_location("summarize_coverage", SCRIPT)
    assert specification is not None and specification.loader is not None
    loaded = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = loaded
    specification.loader.exec_module(loaded)
    return loaded


def _file(filename: str, covered: int = 0, count: int = 10) -> dict[str, Any]:
    return {
        "filename": filename,
        "summary": {
            metric: {"covered": covered, "count": count, "percent": 99.99}
            for metric in ("lines", "functions", "regions", "branches")
        },
    }


def _function(
    filename: str, name: str, line: int, count: int = 0, code_regions: int = 1
) -> dict[str, Any]:
    return {
        "name": name,
        "filenames": [filename],
        "count": count,
        "regions": [
            [line + index, 1, line + index, 20, count, 0, 0, 0]
            for index in range(code_regions)
        ],
    }


def _export(
    files: list[dict[str, Any]], functions: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    unit: dict[str, Any] = {"files": files}
    if functions is not None:
        unit["functions"] = functions
    return {"type": "llvm.coverage.json.export", "version": "2.0.1", "data": [unit]}


def test_totals_use_exact_file_counts_not_exported_percentages(module: Any) -> None:
    report = module.summarize_export(
        _export([_file("/src/curl/lib/large.c", 1, 100), _file("small.c", 1, 1)]),
        "libcurl",
        "coverage.json",
    )

    for metric in report["metrics"].values():
        assert metric["covered"] == 2
        assert metric["count"] == 101
        assert metric["missed"] == 99
        assert metric["percent"] == pytest.approx(200 / 101)
    assert report["files"][0]["filename"] == "/src/curl/lib/large.c"


def test_empty_denominator_is_unmeasured_not_complete(module: Any) -> None:
    report = module.summarize_export(
        _export([_file("empty.h", 0, 0)], []), "harness", "x"
    )

    assert report["metrics"]["branches"]["percent"] is None
    assert report["metrics"]["branches"]["count"] == 0
    text = module.render_markdown([report], 20)
    assert "| branches | 0 / 0 | 0 | N/A |" in text
    assert "100.00%" not in text


def test_missing_metric_does_not_publish_partial_total(module: Any) -> None:
    missing = _file("old-export.c", 1, 2)
    del missing["summary"]["branches"]
    report = module.summarize_export(
        _export([_file("complete.c", 2, 3), missing]), "harness", "x"
    )

    assert report["metrics"]["branches"] is None
    assert report["metrics"]["lines"]["count"] == 5
    assert report["missing_metrics"]["branches"] == ["old-export.c"]
    assert (
        "| branches | unavailable | unavailable | unavailable |"
        in module.render_markdown([report], 20)
    )


def test_gap_rankings_exclude_function_mappings_outside_scoped_files(
    module: Any,
) -> None:
    small = _function("/src/curl_fuzzer/small.cc", "small", 3, code_regions=1)
    large = _function("/src/curl_fuzzer/large.cc", "large", 7, code_regions=4)
    dependency = _function("/src/dependency/other.cc", "other", 1, code_regions=100)
    # The harness header appears only as an expansion of a dependency function.
    dependency["filenames"].append("/src/curl_fuzzer/small.cc")
    dependency["regions"].append([1, 1, 1, 2, 0, 0, 1, 1])
    report = module.summarize_export(
        _export(
            [_file(small["filenames"][0]), _file(large["filenames"][0])],
            [small, large, dependency],
        ),
        "harness",
        "x",
    )

    assert [gap["names"] for gap in report["uncovered_functions"]] == [
        ("large",),
        ("small",),
    ]
    assert report["excluded_function_mappings"] == 1


def test_executed_instantiation_covers_definition_and_symbols_do_not_collide(
    module: Any,
) -> None:
    report = module.summarize_export(
        _export(
            [_file("a.cc"), _file("b.cc")],
            [
                _function("a.cc", "template<int>", 10),
                _function("a.cc", "template<double>", 10, count=1),
                _function("a.cc", "static_helper", 30),
                _function("b.cc", "static_helper", 30),
            ],
        ),
        "harness",
        "x",
    )

    assert len(report["uncovered_functions"]) == 2
    assert {gap["filename"] for gap in report["uncovered_functions"]} == {
        "a.cc",
        "b.cc",
    }
    assert all(
        gap["names"] == ("static_helper",) for gap in report["uncovered_functions"]
    )


def test_multiple_missed_instantiations_report_one_definition(module: Any) -> None:
    report = module.summarize_export(
        _export(
            [_file("template.h")],
            [
                _function("template.h", "helper<int>", 20, code_regions=2),
                _function("template.h", "helper<long>", 20, code_regions=3),
            ],
        ),
        "harness",
        "x",
    )

    (gap,) = report["uncovered_functions"]
    assert gap["instantiations"] == 2
    assert gap["names"] == ("helper<int>", "helper<long>")
    assert gap["code_regions"] == 3


def test_main_definition_can_have_nonzero_file_id(module: Any) -> None:
    function = {
        "name": "macro_function",
        "filenames": ["macro.h", "definition.cc"],
        "count": 0,
        "regions": [
            [99, 1, 99, 2, 0, 0, 0, 0],
            [10, 1, 15, 1, 0, 1, 0, 0],
            [12, 1, 12, 2, 0, 1, 0, 1],
        ],
    }
    report = module.summarize_export(
        _export([_file("definition.cc")], [function]), "harness", "x"
    )

    assert report["uncovered_functions"][0]["filename"] == "definition.cc"
    assert report["uncovered_functions"][0]["line"] == 10


def test_summary_only_export_explicitly_marks_function_details_unavailable(
    module: Any,
) -> None:
    report = module.summarize_export(_export([_file("a.cc")]), "harness", "x")

    assert not report["function_details_available"]
    assert "export without -summary-only" in module.render_markdown([report], 20)


@pytest.mark.parametrize("covered,count", [(3, 2), (-1, 2), (True, 2), (1, 1.5)])
def test_invalid_metric_counts_are_rejected(
    module: Any, covered: object, count: object
) -> None:
    file = _file("broken.c")
    file["summary"]["lines"].update(covered=covered, count=count)

    with pytest.raises(module.CoverageReportError):
        module.summarize_export(_export([file]), "libcurl", "broken.json")


def test_duplicate_files_and_overlapping_export_units_are_rejected(module: Any) -> None:
    with pytest.raises(module.CoverageReportError, match="duplicate file"):
        module.summarize_export(
            _export([_file("same.c"), _file("same.c")]), "harness", "x"
        )
    document = _export([_file("a.c")])
    document["data"].append(document["data"][0])
    with pytest.raises(module.CoverageReportError, match="one merged export unit"):
        module.summarize_export(document, "harness", "x")


def test_malformed_function_file_ids_are_rejected(module: Any) -> None:
    function = _function("a.c", "broken", 1)
    function["regions"][0][5] = 9
    with pytest.raises(module.CoverageReportError, match="invalid region file ID"):
        module.summarize_export(_export([_file("a.c")], [function]), "harness", "x")


def test_cli_writes_separate_counts_and_limits_only_markdown_rankings(
    tmp_path: Path,
) -> None:
    curl = tmp_path / "curl-coverage.json"
    harness = tmp_path / "harness-coverage.json"
    markdown = tmp_path / "report.md"
    machine = tmp_path / "gaps.json"
    curl.write_text(json.dumps(_export([_file("lib.c", 3, 4)], [])), encoding="utf-8")
    harness.write_text(
        json.dumps(_export([_file("a.cc", 1, 2), _file("b.cc", 1, 2)], [])),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--libcurl",
            str(curl),
            "--harness",
            str(harness),
            "--output",
            str(markdown),
            "--json-output",
            str(machine),
            "--limit",
            "1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    reports = json.loads(machine.read_text())["reports"]
    assert reports[0]["metrics"]["lines"]["percent"] == 75
    assert reports[1]["metrics"]["lines"]["percent"] == 50
    assert len(reports[1]["files"]) == 2
    text = markdown.read_text()
    assert "## libcurl" in text and "## curl-fuzzer" in text
    assert "| a.cc |" in text and "| b.cc |" not in text


def test_cli_reports_bad_json_without_a_traceback(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("not json", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--libcurl",
            str(broken),
            "--harness",
            str(broken),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "coverage summary:" in result.stderr
    assert "Traceback" not in result.stderr
