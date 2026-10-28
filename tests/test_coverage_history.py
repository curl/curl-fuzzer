"""Tests for the OSS-Fuzz coverage-history command."""

from __future__ import annotations

import datetime as dt
import io
import json
from pathlib import Path
from typing import Any

import pytest

from curl_fuzzer_tools import coverage_history


def _summary(*, line_covered: int = 15) -> dict[str, Any]:
    return {
        "data": [
            {
                "files": [
                    {
                        "filename": "/src/curl/lib/a.c",
                        "summary": {
                            "lines": {"covered": line_covered, "count": 20},
                            "functions": {"covered": 3, "count": 4},
                            "regions": {"covered": 11, "count": 22},
                        },
                    },
                    {
                        "filename": "/src/curl/lib/vtls/b.c",
                        "summary": {
                            "lines": {"covered": 5, "count": 5},
                            "functions": {"covered": 2, "count": 2},
                            "regions": {"covered": 7, "count": 8},
                        },
                    },
                    {
                        "filename": "/src/curl_fuzzer/proto_fuzzer.cc",
                        "summary": {
                            "lines": {"covered": 999, "count": 999},
                            "functions": {"covered": 999, "count": 999},
                            "regions": {"covered": 999, "count": 999},
                        },
                    },
                ]
            }
        ]
    }


def _point(date: dt.date, line_covered: int) -> coverage_history.CoveragePoint:
    return coverage_history.parse_summary(
        _summary(line_covered=line_covered),
        date=date,
        url=coverage_history.report_url(date),
    )


def test_pyproject_exposes_coverage_history_entry_point() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'coverage_history = "curl_fuzzer_tools.coverage_history:main"' in pyproject


def test_report_urls_cover_aggregate_and_per_target_layouts() -> None:
    date = dt.date(2026, 10, 28)
    assert coverage_history.report_url(date) == (
        "https://storage.googleapis.com/oss-fuzz-coverage/curl/reports/"
        "20261028/linux/summary.json"
    )
    assert coverage_history.report_url(date, "curl_fuzzer_proto_ldap") == (
        "https://storage.googleapis.com/oss-fuzz-coverage/curl/reports-by-target/"
        "20261028/curl_fuzzer_proto_ldap/linux/summary.json"
    )
    with pytest.raises(coverage_history.CoverageHistoryError, match="target name"):
        coverage_history.report_url(date, "../escape")
    for target in (".", ".."):
        with pytest.raises(coverage_history.CoverageHistoryError, match="target name"):
            coverage_history.report_url(date, target)


def test_summary_sums_only_curl_lib_files() -> None:
    point = _point(dt.date(2026, 10, 28), 15)
    assert point.metrics["lines"] == coverage_history.CoverageCount(20, 25)
    assert point.metrics["functions"] == coverage_history.CoverageCount(5, 6)
    assert point.metrics["regions"] == coverage_history.CoverageCount(18, 30)
    assert point.metrics["lines"].percent == 80.0


def test_summary_rejects_invalid_counts() -> None:
    document = _summary()
    document["data"][0]["files"][0]["summary"]["lines"]["covered"] = 21  # type: ignore[index]
    with pytest.raises(coverage_history.CoverageHistoryError, match="exceeds"):
        coverage_history.parse_summary(
            document,
            date=dt.date(2026, 10, 28),
            url="https://example.invalid/summary.json",
        )


def test_collect_history_keeps_source_urls_and_missing_dates() -> None:
    missing_date = dt.date(2026, 10, 27)

    def fetcher(url: str, timeout: float) -> object:
        assert timeout == 4.0
        if "20261027" in url:
            raise coverage_history.MissingReportError(url)
        return _summary()

    points, missing = coverage_history.collect_history(
        dt.date(2026, 10, 26),
        dt.date(2026, 10, 28),
        target="curl_fuzzer_proto_ldap",
        timeout=4.0,
        fetcher=fetcher,
    )
    assert [point.date for point in points] == [
        dt.date(2026, 10, 26),
        dt.date(2026, 10, 28),
    ]
    assert missing == [missing_date]
    assert all("reports-by-target" in point.url for point in points)


def test_machine_readable_outputs_retain_counts_and_urls() -> None:
    points = [_point(dt.date(2026, 10, 27), 14), _point(dt.date(2026, 10, 28), 15)]
    document = coverage_history.history_document(points, [], target=None)
    assert document["scope"] == {"kind": "aggregate"}
    assert document["points"][1]["lines"] == {  # type: ignore[index]
        "covered": 20,
        "count": 25,
        "percent": 80.0,
    }
    assert document["points"][1]["url"].endswith(  # type: ignore[index,union-attr]
        "/20261028/linux/summary.json"
    )

    csv_rows = coverage_history.render_csv(points).splitlines()
    assert csv_rows[0].startswith("date,lines_covered,lines_count,lines_percent")
    assert "2026-10-28,20,25,80.000000" in csv_rows[2]
    assert csv_rows[2].endswith("/20261028/linux/summary.json")


def test_svg_is_standalone_and_contains_series_metadata() -> None:
    points = [_point(dt.date(2026, 10, 27), 14), _point(dt.date(2026, 10, 28), 15)]
    svg = coverage_history.render_svg(points, metric="lines", target=None)
    assert svg.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    assert "curl/lib lines coverage: aggregate" in svg
    assert '<polyline class="series"' in svg
    assert "2026-10-27: 76.000000%" in svg
    assert "2026-10-28: 80.000000%" in svg


def test_svg_positions_points_by_elapsed_date() -> None:
    points = [
        _point(dt.date(2026, 10, 1), 13),
        _point(dt.date(2026, 10, 2), 14),
        _point(dt.date(2026, 10, 20), 15),
    ]
    svg = coverage_history.render_svg(points, metric="lines", target=None)
    assert 'cx="72.00"' in svg
    assert 'cx="114.32"' in svg
    assert 'cx="876.00"' in svg


def test_main_uses_entry_point_output_formats(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        coverage_history,
        "fetch_summary",
        lambda url, timeout: _summary(),
    )
    stream = io.StringIO()
    result = coverage_history.main(
        [
            "--start",
            "20261028",
            "--end",
            "2026-10-28",
            "--format",
            "json",
        ],
        stdout=stream,
    )
    assert result == 0
    assert json.loads(stream.getvalue())["points"][0]["date"] == "2026-10-28"
