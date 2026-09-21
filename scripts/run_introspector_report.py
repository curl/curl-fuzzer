#!/usr/bin/env python3
"""Generate a local static Introspector report with the project exclusions."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "fuzz_introspector_exclusion.config"
# Match the pinned frontend's C/C++ source extensions, including headers.
SOURCE_EXTENSIONS = {".c", ".cpp", ".cc", ".c++", ".cxx", ".h", ".hpp", ".hh", ".hxx"}


class IntrospectorReportError(RuntimeError):
    """A local report could not be generated reliably."""


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    """Parse the local report command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_directory",
        type=Path,
        help="new or empty directory for all report files",
    )
    parser.add_argument(
        "--curl-source",
        type=Path,
        required=True,
        help="root of a local curl Git checkout",
    )
    parser.add_argument(
        "--no-exclusions",
        action="store_true",
        help="include tests, examples and tools for a static baseline comparison",
    )
    return parser.parse_args(arguments)


def read_exclusions(config_path: Path) -> list[re.Pattern[str]]:
    """Read the checked-in file rules without silently ignoring other rules."""
    patterns = []
    in_file_rules = False
    for line in config_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "FILES_TO_AVOID":
            in_file_rules = True
            continue
        if line == "FUNCS_TO_AVOID" or not in_file_rules:
            raise IntrospectorReportError(
                f"{config_path}: this source runner supports FILES_TO_AVOID rules only"
            )
        patterns.append(re.compile(line))
    if not in_file_rules:
        raise IntrospectorReportError(f"{config_path}: missing FILES_TO_AVOID header")
    return patterns


def collect_source_files(
    root: Path, canonical_root: str, exclusions: Sequence[re.Pattern[str]]
) -> tuple[list[str], list[str]]:
    """Select tracked and unignored local sources using OSS-Fuzz path rules."""
    root = root.resolve()
    repository = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    )
    if Path(repository.stdout.strip()).resolve() != root:
        raise IntrospectorReportError(f"Expected a Git checkout root: {root}")
    files = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=True,
        capture_output=True,
    )
    included = []
    excluded = []
    for relative in sorted(
        {os.fsdecode(name) for name in files.stdout.split(b"\0") if name}
    ):
        path = root / relative
        if path.suffix not in SOURCE_EXTENSIONS or not path.is_file():
            continue
        canonical_path = f"{canonical_root}/{Path(relative).as_posix()}"
        if any(pattern.search(canonical_path) for pattern in exclusions):
            excluded.append(canonical_path)
        else:
            included.append(str(path))
    return included, excluded


def normalize_static_report_assets(output_directory: Path) -> None:
    """Fix optional-table assumptions in the pinned upstream HTML assets."""
    report = output_directory / "fuzz_report.html"
    html = report.read_text(encoding="utf-8")
    if not (output_directory / "analysis_1.js").is_file():
        html = re.sub(
            r"\s*<script\b[^>]*\bsrc=['\"]analysis_1\.js['\"][^>]*>\s*</script>",
            "",
            html,
        )

    custom_script = output_directory / "custom.js"
    if custom_script.is_file():
        javascript = custom_script.read_text(encoding="utf-8")
        marker = "// curl-fuzzer: handle absent optional and runtime coverage tables."
        if marker not in javascript:
            optional_table = "function populateFuzzersOverviewTable(value) {\n"
            empty_coverage = (
                "    table.rows.add(fuzzer_table_data[key]);\n  }\n  table.draw();"
            )
            if (
                javascript.count(optional_table) != 1
                or javascript.count(empty_coverage) != 1
            ):
                raise IntrospectorReportError(
                    "Introspector's JavaScript changed; review the static report "
                    "compatibility fixes before using this upstream revision"
                )
            javascript = javascript.replace(
                optional_table,
                optional_table
                + f"  {marker}\n"
                + "  if (!document.getElementById(value)) {\n"
                + "    return;\n"
                + "  }\n",
            ).replace(
                empty_coverage,
                "    table.rows.add(fuzzer_table_data[key]);\n    table.draw();\n  }",
            )
            custom_script.write_text(javascript, encoding="utf-8")
    elif re.search(r"\bsrc=['\"]custom\.js['\"]", html):
        raise IntrospectorReportError("The HTML report is missing custom.js")

    report.write_text(html, encoding="utf-8")


def generate_report(
    output_directory: Path,
    source_files: Sequence[str],
    analyse_folder: Callable[..., object],
    run_analysis_on_dir: Callable[..., tuple[int, object]],
) -> Path:
    """Run the frontend and HTML backend without scanning either checkout."""
    output_directory = output_directory.resolve()
    original_directory = Path.cwd()
    try:
        # Some upstream analyses use relative output paths despite out_dir.
        os.chdir(output_directory)
        with tempfile.TemporaryDirectory(
            prefix=".empty-source-", dir=output_directory
        ) as empty_source_directory:
            analyse_folder(
                language="c++",
                directory=empty_source_directory,
                entrypoint="LLVMFuzzerTestOneInput",
                out=str(output_directory),
                files_to_include=list(source_files),
            )
        if not list(output_directory.glob("fuzzerLogFile-*.data")):
            raise IntrospectorReportError("The source frontend produced no call trees")
        print("Generating static reachability HTML (no runtime coverage)", flush=True)
        exit_code, _ = run_analysis_on_dir(
            target_folder=str(output_directory),
            coverage_url="",
            analyses_to_run=["MetadataAnalysis", "FilePathAnalyser"],
            correlation_file="",
            enable_all_analyses=False,
            report_name="curl: local static reachability (no runtime coverage)",
            language="c-cpp",
            parallelise=False,
            out_dir=str(output_directory),
        )
        report = output_directory / "fuzz_report.html"
        if exit_code != 0 or not report.is_file():
            raise IntrospectorReportError(
                f"Introspector did not generate an HTML report (exit {exit_code})"
            )
        normalize_static_report_assets(output_directory)
        return report
    finally:
        os.chdir(original_directory)


def main(arguments: Sequence[str] | None = None) -> int:
    """Generate a static report using the documented pinned environment."""
    parsed = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    sys.setrecursionlimit(10000)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        output_directory = parsed.output_directory.resolve()
        if output_directory.exists() and (
            not output_directory.is_dir() or any(output_directory.iterdir())
        ):
            raise IntrospectorReportError(
                f"Choose a new or empty output directory to avoid stale metadata: "
                f"{output_directory}"
            )
        exclusions = [] if parsed.no_exclusions else read_exclusions(CONFIG_PATH)
        source_files = []
        excluded_files = []
        revisions = {}
        roots = {
            "/src/curl": str(parsed.curl_source.resolve()),
            "/src/curl_fuzzer": str(REPO_ROOT),
        }
        for canonical_root, root in roots.items():
            included, excluded = collect_source_files(
                Path(root), canonical_root, exclusions
            )
            source_files.extend(included)
            excluded_files.extend(excluded)
            revisions[canonical_root] = subprocess.run(
                ["git", "-C", root, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        if not source_files:
            raise IntrospectorReportError("No C/C++ sources were selected")

        output_directory.mkdir(parents=True, exist_ok=True)
        # Keep matplotlib's first-run font cache with the report artifacts.
        os.environ["MPLCONFIGDIR"] = str(output_directory / ".matplotlib")
        from generate_introspector_calltree import _install_tree_sitter_compatibility

        _install_tree_sitter_compatibility()
        from fuzz_introspector import commands
        from fuzz_introspector.exceptions import FuzzIntrospectorError
        from fuzz_introspector.frontends import oss_fuzz

        manifest = {
            "analysis": "Static source reachability; no corpus execution or runtime coverage",
            "source_roots": roots,
            "source_revisions": revisions,
            "exclusion_config": None if parsed.no_exclusions else str(CONFIG_PATH),
            "exclusion_patterns": [pattern.pattern for pattern in exclusions],
            "included_sources": source_files,
            "excluded_sources": excluded_files,
        }
        (output_directory / "source-selection.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        print(
            f"Analysing {len(source_files)} source files; "
            f"excluded {len(excluded_files)} using project rules",
            flush=True,
        )
        try:
            report = generate_report(
                output_directory,
                source_files,
                oss_fuzz.analyse_folder,
                commands.run_analysis_on_dir,
            )
        except FuzzIntrospectorError as error:
            raise IntrospectorReportError(str(error)) from error
    except ImportError as error:
        print(
            f"Introspector dependency missing: {error}. "
            "See docs/coverage.md for the pinned environment.",
            file=sys.stderr,
        )
        return 2
    except subprocess.CalledProcessError as error:
        details = error.stderr
        if isinstance(details, bytes):
            details = details.decode(errors="replace")
        print(f"Cannot read source checkout: {details or error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, re.error, IntrospectorReportError) as error:
        print(f"Could not generate Introspector report: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
