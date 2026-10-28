"""Fetch and graph dated OSS-Fuzz coverage summaries for curl's lib/ tree."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TextIO
from xml.sax.saxutils import escape

AGGREGATE_URL_TEMPLATE = (
    "https://storage.googleapis.com/oss-fuzz-coverage/curl/reports/"
    "{date}/linux/summary.json"
)
TARGET_URL_TEMPLATE = (
    "https://storage.googleapis.com/oss-fuzz-coverage/curl/reports-by-target/"
    "{date}/{target}/linux/summary.json"
)
CURL_LIB_MARKER = "/src/curl/lib/"
METRICS = ("lines", "functions", "regions")
TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class CoverageHistoryError(RuntimeError):
    """Raised when coverage history cannot be fetched or interpreted."""


class MissingReportError(CoverageHistoryError):
    """Raised when OSS-Fuzz has no report for one requested date."""


@dataclass(frozen=True)
class CoverageCount:
    """Covered and instrumented totals for one LLVM coverage metric."""

    covered: int
    count: int

    @property
    def percent(self) -> float:
        """Return the coverage percentage, treating an empty total as complete."""
        return 100.0 * self.covered / self.count if self.count else 100.0


@dataclass(frozen=True)
class CoveragePoint:
    """One dated curl/lib coverage observation and its source URL."""

    date: dt.date
    url: str
    metrics: dict[str, CoverageCount]


def parse_date(value: str) -> dt.date:
    """Parse an ISO date or the compact date used in OSS-Fuzz URLs."""
    try:
        if re.fullmatch(r"\d{8}", value):
            return dt.datetime.strptime(value, "%Y%m%d").date()
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid date {value!r}; expected YYYY-MM-DD or YYYYMMDD"
        ) from error


def report_url(date: dt.date, target: str | None = None) -> str:
    """Return the public OSS-Fuzz summary URL for one date and scope."""
    compact_date = date.strftime("%Y%m%d")
    if target is None:
        return AGGREGATE_URL_TEMPLATE.format(date=compact_date)
    if TARGET_RE.fullmatch(target) is None:
        raise CoverageHistoryError(f"invalid OSS-Fuzz target name: {target!r}")
    return TARGET_URL_TEMPLATE.format(date=compact_date, target=target)


def _coverage_value(value: object, *, metric: str, field: str, filename: str) -> int:
    if type(value) is not int or value < 0:
        raise CoverageHistoryError(
            f"invalid {metric}.{field} for {filename!r}: {value!r}"
        )
    return value


def parse_summary(document: object, *, date: dt.date, url: str) -> CoveragePoint:
    """Sum per-file LLVM metrics for files under the public curl/lib path."""
    if not isinstance(document, dict):
        raise CoverageHistoryError(f"coverage summary is not an object: {url}")
    data = document.get("data")
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        raise CoverageHistoryError(f"coverage summary has no data: {url}")
    files = data[0].get("files")
    if not isinstance(files, list):
        raise CoverageHistoryError(f"coverage summary has no file list: {url}")

    totals = {metric: [0, 0] for metric in METRICS}
    matched_files = 0
    for file_record in files:
        if not isinstance(file_record, dict):
            continue
        filename = file_record.get("filename")
        if not isinstance(filename, str) or CURL_LIB_MARKER not in filename:
            continue
        summary = file_record.get("summary")
        if not isinstance(summary, dict):
            raise CoverageHistoryError(f"missing summary for {filename!r}: {url}")
        matched_files += 1
        for metric in METRICS:
            metric_summary = summary.get(metric)
            if not isinstance(metric_summary, dict):
                raise CoverageHistoryError(
                    f"missing {metric} summary for {filename!r}: {url}"
                )
            covered = _coverage_value(
                metric_summary.get("covered"),
                metric=metric,
                field="covered",
                filename=filename,
            )
            count = _coverage_value(
                metric_summary.get("count"),
                metric=metric,
                field="count",
                filename=filename,
            )
            if covered > count:
                raise CoverageHistoryError(
                    f"{metric}.covered exceeds count for {filename!r}: {url}"
                )
            totals[metric][0] += covered
            totals[metric][1] += count

    if not matched_files:
        raise CoverageHistoryError(
            f"coverage summary contains no curl/lib files: {url}"
        )
    return CoveragePoint(
        date=date,
        url=url,
        metrics={
            metric: CoverageCount(covered=values[0], count=values[1])
            for metric, values in totals.items()
        },
    )


def fetch_summary(url: str, timeout: float) -> object:
    """Fetch one public OSS-Fuzz JSON summary."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "curl-fuzzer-coverage-history/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise MissingReportError(f"coverage report not found: {url}") from error
        raise CoverageHistoryError(
            f"coverage request failed with HTTP {error.code}: {url}"
        ) from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise CoverageHistoryError(
            f"coverage request failed for {url}: {error}"
        ) from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CoverageHistoryError(
            f"invalid coverage JSON at {url}: {error}"
        ) from error


def _date_range(start: dt.date, end: dt.date) -> list[dt.date]:
    if end < start:
        raise CoverageHistoryError("--end must not be earlier than --start")
    days = (end - start).days
    return [start + dt.timedelta(days=offset) for offset in range(days + 1)]


def collect_history(
    start: dt.date,
    end: dt.date,
    *,
    target: str | None,
    timeout: float,
    fetcher: Callable[[str, float], object] | None = None,
) -> tuple[list[CoveragePoint], list[dt.date]]:
    """Fetch an inclusive history, retaining dates whose report is absent."""
    active_fetcher = fetch_summary if fetcher is None else fetcher
    points: list[CoveragePoint] = []
    missing: list[dt.date] = []
    for date in _date_range(start, end):
        url = report_url(date, target)
        try:
            document = active_fetcher(url, timeout)
        except MissingReportError:
            missing.append(date)
            continue
        points.append(parse_summary(document, date=date, url=url))
    return points, missing


def _point_record(point: CoveragePoint) -> dict[str, object]:
    return {
        "date": point.date.isoformat(),
        "url": point.url,
        **{
            metric: {
                "covered": point.metrics[metric].covered,
                "count": point.metrics[metric].count,
                "percent": round(point.metrics[metric].percent, 6),
            }
            for metric in METRICS
        },
    }


def history_document(
    points: Sequence[CoveragePoint],
    missing: Sequence[dt.date],
    *,
    target: str | None,
) -> dict[str, object]:
    """Build the stable machine-readable history document."""
    scope: dict[str, str] = {"kind": "aggregate"}
    if target is not None:
        scope = {"kind": "target", "target": target}
    return {
        "schema_version": 1,
        "project": "curl",
        "source_tree": "curl/lib",
        "scope": scope,
        "points": [_point_record(point) for point in points],
        "missing_dates": [date.isoformat() for date in missing],
    }


def render_csv(points: Sequence[CoveragePoint]) -> str:
    """Render coverage points as stable CSV."""
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    header = ["date"]
    for metric in METRICS:
        header.extend((f"{metric}_covered", f"{metric}_count", f"{metric}_percent"))
    header.append("url")
    writer.writerow(header)
    for point in points:
        row: list[object] = [point.date.isoformat()]
        for metric in METRICS:
            value = point.metrics[metric]
            row.extend((value.covered, value.count, f"{value.percent:.6f}"))
        row.append(point.url)
        writer.writerow(row)
    return stream.getvalue()


def render_table(points: Sequence[CoveragePoint]) -> str:
    """Render a compact human-readable table with source URLs."""
    rows = [
        ("date", "lines", "functions", "regions", "source"),
        *(
            (
                point.date.isoformat(),
                f"{point.metrics['lines'].percent:.2f}%",
                f"{point.metrics['functions'].percent:.2f}%",
                f"{point.metrics['regions'].percent:.2f}%",
                point.url,
            )
            for point in points
        ),
    ]
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    return "\n".join(
        "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        for row in rows
    )


def render_svg(
    points: Sequence[CoveragePoint], *, metric: str, target: str | None
) -> str:
    """Render one coverage percentage series as a standalone SVG."""
    if not points:
        raise CoverageHistoryError("cannot graph an empty coverage history")
    width, height = 900, 440
    left, right, top, bottom = 72, 24, 56, 72
    graph_width = width - left - right
    graph_height = height - top - bottom
    values = [point.metrics[metric].percent for point in points]
    low = min(values)
    high = max(values)
    padding = max(0.25, (high - low) * 0.12)
    y_min = max(0.0, low - padding)
    y_max = min(100.0, high + padding)
    if y_max - y_min < 0.5:
        center = (y_min + y_max) / 2
        y_min = max(0.0, center - 0.25)
        y_max = min(100.0, center + 0.25)

    first_date = points[0].date
    date_span = (points[-1].date - first_date).days

    def x_position(index: int) -> float:
        if date_span == 0:
            return left + graph_width / 2
        elapsed_days = (points[index].date - first_date).days
        return left + graph_width * elapsed_days / date_span

    def y_position(value: float) -> float:
        return top + graph_height * (y_max - value) / (y_max - y_min)

    polyline = " ".join(
        f"{x_position(index):.2f},{y_position(value):.2f}"
        for index, value in enumerate(values)
    )
    scope = "aggregate" if target is None else target
    title = escape(f"curl/lib {metric} coverage: {scope}")
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {width} {height}" role="img">'
        ),
        f"<title>{title}</title>",
        (
            "<style>text{font:13px sans-serif;fill:#30343b}"
            ".grid{stroke:#d9dde3;stroke-width:1}"
            ".axis{stroke:#59636e;stroke-width:1.5}"
            ".series{fill:none;stroke:#0868ac;stroke-width:3}"
            ".point{fill:#0868ac}</style>"
        ),
        f'<text x="{left}" y="30" font-size="20">{title}</text>',
    ]
    for tick in range(5):
        fraction = tick / 4
        value = y_max - fraction * (y_max - y_min)
        y = top + fraction * graph_height
        parts.append(
            f'<line class="grid" x1="{left}" y1="{y:.2f}" '
            f'x2="{width - right}" y2="{y:.2f}"/>'
        )
        parts.append(
            f'<text x="{left - 10}" y="{y + 4:.2f}" text-anchor="end">'
            f"{value:.2f}%</text>"
        )
    parts.extend(
        (
            (
                f'<line class="axis" x1="{left}" y1="{top}" '
                f'x2="{left}" y2="{height - bottom}"/>'
            ),
            (
                f'<line class="axis" x1="{left}" y1="{height - bottom}" '
                f'x2="{width - right}" y2="{height - bottom}"/>'
            ),
            f'<polyline class="series" points="{polyline}"/>',
        )
    )
    label_indexes = (
        sorted(
            {
                round(index * (len(points) - 1) / min(5, len(points) - 1))
                for index in range(min(5, len(points) - 1) + 1)
            }
        )
        if len(points) > 1
        else [0]
    )
    for index in label_indexes:
        x = x_position(index)
        parts.append(
            f'<text x="{x:.2f}" y="{height - bottom + 24}" '
            f'text-anchor="middle">{points[index].date.isoformat()}</text>'
        )
    for index, point in enumerate(points):
        x = x_position(index)
        y = y_position(values[index])
        tooltip = escape(
            f"{point.date.isoformat()}: {values[index]:.6f}% ({point.url})"
        )
        parts.append(
            f'<circle class="point" cx="{x:.2f}" cy="{y:.2f}" r="4">'
            f"<title>{tooltip}</title></circle>"
        )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch and graph dated OSS-Fuzz coverage for curl/lib."
    )
    parser.add_argument("--start", required=True, type=parse_date)
    parser.add_argument("--end", type=parse_date, default=dt.date.today())
    parser.add_argument(
        "--target",
        help="use reports-by-target data for one fuzzer instead of aggregate data",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "csv", "svg"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "--metric",
        choices=METRICS,
        default="lines",
        help="metric graphed by --format svg (default: lines)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="per-request timeout in seconds (default: 30)",
    )
    return parser


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    """Run the coverage-history command."""
    parser = _parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    output = sys.stdout if stdout is None else stdout
    try:
        points, missing = collect_history(
            args.start,
            args.end,
            target=args.target,
            timeout=args.timeout,
        )
    except CoverageHistoryError as error:
        print(f"coverage_history: {error}", file=sys.stderr)
        return 1
    if not points:
        print(
            "coverage_history: no reports were found in the requested range",
            file=sys.stderr,
        )
        return 1
    if missing:
        dates = ", ".join(date.isoformat() for date in missing)
        print(f"coverage_history: skipped missing reports: {dates}", file=sys.stderr)

    if args.format == "json":
        rendered = json.dumps(
            history_document(points, missing, target=args.target),
            indent=2,
            sort_keys=True,
        )
    elif args.format == "csv":
        rendered = render_csv(points).rstrip("\n")
    elif args.format == "svg":
        rendered = render_svg(points, metric=args.metric, target=args.target).rstrip(
            "\n"
        )
    else:
        rendered = render_table(points)
    print(rendered, file=output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
