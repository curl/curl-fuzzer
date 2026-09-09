#!/usr/bin/env python3
"""Check that Fuzz Introspector sees every proto-target orchestration chain."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

PROTO_TARGET_PREFIX = "curl_fuzzer_proto"
MULTI_TARGET = "curl_fuzzer_proto_multi"
# The introspector build is x86_64 and not MemorySanitizer, so it must emit the
# complete proto target set declared by scripts/fuzz_targets.
EXPECTED_PROTO_TARGETS = frozenset(
    {
        "curl_fuzzer_proto",
        "curl_fuzzer_proto_api",
        "curl_fuzzer_proto_ftp",
        "curl_fuzzer_proto_gopher",
        "curl_fuzzer_proto_h2_proxy",
        "curl_fuzzer_proto_socks4",
        "curl_fuzzer_proto_resolver",
        "curl_fuzzer_proto_http",
        "curl_fuzzer_proto_http3",
        "curl_fuzzer_proto_http_deep",
        "curl_fuzzer_proto_https",
        "curl_fuzzer_proto_https_h2",
        "curl_fuzzer_proto_https_gnutls",
        "curl_fuzzer_proto_https_mbedtls",
        "curl_fuzzer_proto_multi",
        "curl_fuzzer_proto_telnet",
        "curl_fuzzer_proto_tftp",
        "curl_fuzzer_proto_timing",
        "curl_fuzzer_proto_ws",
        "curl_fuzzer_proto_wss",
    }
)
CALLTREE_BASENAME = f"fuzzerLogFile-{MULTI_TARGET}.data"
CALLTREE_FILENAME = re.compile(
    rf"^fuzzerLogFile-(?P<target>{PROTO_TARGET_PREFIX}[A-Za-z0-9_-]*)\.data$"
)
REQUIRED_CHAIN = (
    "LLVMFuzzerTestOneInput",
    "proto_fuzzer::ProtoFuzzerTestOneInput",
    "proto_fuzzer::RunScenario",
    "proto_fuzzer::RunMultiTransferScenario",
)
CALLTREE_LINE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>\S.*?)\s+"
    r"(?P<source>\S+)\s+(?:linenumber=)?(?P<source_line>-?\d+)\s*$"
)
CALLTREE_DELIMITER = re.compile(r"^={20,}$")


class IntrospectorCheckError(RuntimeError):
    """Raised when an Introspector artifact is missing or structurally wrong."""


@dataclass(frozen=True)
class CallTreeNode:
    """One function and its parent in an indentation-based call tree."""

    name: str
    source: str
    source_line: int
    report_line: int
    indent: int
    parent: int | None


def parse_calltree(text: str, source: str = "<calltree>") -> list[CallTreeNode]:
    """Parse a Fuzz Introspector ``Call tree`` text artifact."""
    lines = text.splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if line.strip()), None
    )
    if (
        header_index is None
        or lines[header_index].lstrip("\ufeff").strip() != "Call tree"
    ):
        raise IntrospectorCheckError(
            f"{source}: expected a 'Call tree' header before the first node"
        )

    nodes: list[CallTreeNode] = []
    stack: list[int] = []
    for index, line in enumerate(lines[header_index + 1 :], header_index + 2):
        stripped = line.strip()
        if not stripped:
            continue
        if CALLTREE_DELIMITER.fullmatch(stripped):
            break
        match = CALLTREE_LINE.fullmatch(line)
        if match is None:
            excerpt = line if len(line) <= 120 else f"{line[:117]}..."
            raise IntrospectorCheckError(
                f"{source}:{index}: malformed call-tree node: {excerpt!r}"
            )

        # Fuzz Introspector currently emits spaces, but expand tabs so mixed
        # indentation cannot accidentally turn a sibling into a descendant.
        indent = len(match.group("indent").expandtabs(8))
        while stack and nodes[stack[-1]].indent >= indent:
            stack.pop()
        parent = stack[-1] if stack else None
        nodes.append(
            CallTreeNode(
                name=match.group("name"),
                source=match.group("source"),
                source_line=int(match.group("source_line")),
                report_line=index,
                indent=indent,
                parent=parent,
            )
        )
        stack.append(len(nodes) - 1)

    if not nodes:
        raise IntrospectorCheckError(f"{source}: call tree contains no nodes")
    return nodes


def _summary_calltree_references(
    document: object, summary_path: Path
) -> dict[str, str]:
    if not isinstance(document, dict):
        raise IntrospectorCheckError(f"{summary_path}: summary is not a JSON object")
    targets = sorted(
        key
        for key in document
        if isinstance(key, str) and key.startswith(PROTO_TARGET_PREFIX)
    )
    if not targets:
        raise IntrospectorCheckError(
            f"{summary_path}: summary has no {PROTO_TARGET_PREFIX}* target metadata"
        )

    references: dict[str, str] = {}
    failures: list[str] = []
    for target_name in targets:
        target = document[target_name]
        if not isinstance(target, dict):
            failures.append(f"{target_name} metadata is not an object")
            continue
        metadata = target.get("metadata-files")
        if not isinstance(metadata, dict):
            failures.append(f"{target_name} has no 'metadata-files' object")
            continue
        calltree = metadata.get("calltree")
        if not isinstance(calltree, str) or not calltree:
            failures.append(f"{target_name} metadata has no call-tree filename")
            continue
        references[target_name] = calltree

    if failures:
        raise IntrospectorCheckError(
            f"{summary_path}: invalid proto-target metadata: {'; '.join(failures)}"
        )
    return references


def _read_summary_document(summary_path: Path) -> object:
    try:
        return json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise IntrospectorCheckError(
            f"could not read Introspector summary {summary_path}: {error}"
        ) from error


def _unique_paths(paths: Sequence[Path]) -> list[Path]:
    return sorted({path.resolve() for path in paths}, key=lambda path: str(path))


def _resolve_summary_calltrees(
    summary_path: Path, search_root: Path, document: object | None = None
) -> dict[str, Path]:
    if document is None:
        document = _read_summary_document(summary_path)
    references = _summary_calltree_references(document, summary_path)
    resolved: dict[str, Path] = {}
    failures: list[str] = []
    for target, raw_reference in references.items():
        reference = Path(raw_reference)
        candidate = (
            reference if reference.is_absolute() else summary_path.parent / reference
        )
        if candidate.is_file():
            resolved[target] = candidate.resolve()
            continue

        # CI artifact downloads can flatten or wrap the inspector directory.
        # The basename recorded in summary.json remains authoritative.
        matches = _unique_paths(
            [
                path
                for path in search_root.rglob(reference.name)
                if path.is_file() and path.name == reference.name
            ]
        )
        if len(matches) == 1:
            resolved[target] = matches[0]
        elif not matches:
            failures.append(f"{target} points to missing {raw_reference!r}")
        else:
            rendered = ", ".join(str(path) for path in matches)
            failures.append(f"{target} points to ambiguous files: {rendered}")

    if failures:
        raise IntrospectorCheckError(
            f"{summary_path}: could not resolve every proto call tree: "
            + "; ".join(failures)
        )
    return resolved


def _target_from_calltree_path(path: Path) -> str:
    match = CALLTREE_FILENAME.fullmatch(path.name)
    return match.group("target") if match else MULTI_TARGET


def _raw_calltrees(report: Path) -> dict[str, Path]:
    grouped: dict[str, list[Path]] = {}
    for path in report.rglob(f"fuzzerLogFile-{PROTO_TARGET_PREFIX}*.data"):
        match = CALLTREE_FILENAME.fullmatch(path.name)
        if path.is_file() and match is not None:
            grouped.setdefault(match.group("target"), []).append(path.resolve())

    if not grouped:
        raise IntrospectorCheckError(
            f"could not find fuzzerLogFile-{PROTO_TARGET_PREFIX}*.data below {report}"
        )
    unique = {target: _unique_paths(paths) for target, paths in grouped.items()}
    duplicates = {target: paths for target, paths in unique.items() if len(paths) > 1}
    if duplicates:
        rendered = "; ".join(
            f"{target}: {', '.join(str(path) for path in paths)}"
            for target, paths in sorted(duplicates.items())
        )
        raise IntrospectorCheckError(
            "multiple call trees found for the same proto target; "
            f"pass one file explicitly: {rendered}"
        )
    return {target: paths[0] for target, paths in sorted(unique.items())}


def locate_calltrees(report: Path) -> dict[str, Path]:
    """Locate all applicable proto call trees from a report path."""
    report = report.resolve()
    if not report.exists():
        raise IntrospectorCheckError(
            f"Introspector report path does not exist: {report}"
        )

    if report.is_file():
        if report.suffix == ".json":
            return _resolve_summary_calltrees(report, report.parent)
        return {_target_from_calltree_path(report): report}

    proto_summaries: list[tuple[Path, object]] = []
    for summary in sorted(report.rglob("summary.json")):
        try:
            document = _read_summary_document(summary)
        except IntrospectorCheckError:
            continue
        if isinstance(document, dict) and any(
            isinstance(key, str) and key.startswith(PROTO_TARGET_PREFIX)
            for key in document
        ):
            proto_summaries.append((summary, document))

    if len(proto_summaries) == 1:
        summary, document = proto_summaries[0]
        return _resolve_summary_calltrees(summary, report, document)
    if len(proto_summaries) > 1:
        rendered = "\n  ".join(str(summary) for summary, _ in proto_summaries)
        raise IntrospectorCheckError(
            "multiple Introspector summaries contain proto-target metadata; "
            f"pass one summary explicitly:\n  {rendered}"
        )
    return _raw_calltrees(report)


def locate_calltree(report: Path) -> Path:
    """Locate the multi-target call tree for compatibility with older callers."""
    calltrees = locate_calltrees(report)
    if MULTI_TARGET in calltrees:
        return calltrees[MULTI_TARGET]
    if len(calltrees) == 1:
        return next(iter(calltrees.values()))
    rendered = ", ".join(sorted(calltrees))
    raise IntrospectorCheckError(
        f"no {MULTI_TARGET} call tree found; available proto targets: {rendered}"
    )


def _children(nodes: Sequence[CallTreeNode]) -> dict[int | None, list[int]]:
    children: dict[int | None, list[int]] = {}
    for index, node in enumerate(nodes):
        children.setdefault(node.parent, []).append(index)
    return children


def _descendants(nodes: Sequence[CallTreeNode], root: int) -> set[int]:
    result: set[int] = set()
    for index, node in enumerate(nodes):
        parent = node.parent
        while parent is not None:
            if parent == root:
                result.add(index)
                break
            parent = nodes[parent].parent
    return result


def _format_children(
    nodes: Sequence[CallTreeNode],
    children: dict[int | None, list[int]],
    parents: list[int],
) -> str:
    names = sorted(
        {nodes[index].name for parent in parents for index in children.get(parent, [])}
    )
    if not names:
        return "<none>"
    limit = 12
    rendered = ", ".join(names[:limit])
    if len(names) > limit:
        rendered += f", ... ({len(names) - limit} more)"
    return rendered


def verify_calltree(
    nodes: Sequence[CallTreeNode], *, require_multi: bool = True
) -> None:
    """Verify the shared chain and, when requested, the multi-specific subtree."""
    children = _children(nodes)
    roots = [
        index
        for index in children.get(None, [])
        if nodes[index].name == REQUIRED_CHAIN[0]
    ]
    if not roots:
        occurrences = sum(node.name == REQUIRED_CHAIN[0] for node in nodes)
        raise IntrospectorCheckError(
            f"missing root {REQUIRED_CHAIN[0]!r}; found {occurrences} occurrence(s) "
            "below another node"
        )

    required_chain = REQUIRED_CHAIN if require_multi else REQUIRED_CHAIN[:3]
    chains: list[tuple[int, ...]] = [(root,) for root in roots]
    for expected in required_chain[1:]:
        extended = [
            (*chain, child)
            for chain in chains
            for child in children.get(chain[-1], [])
            if nodes[child].name == expected
        ]
        if not extended:
            parent_name = nodes[chains[0][-1]].name
            direct_children = _format_children(
                nodes, children, [chain[-1] for chain in chains]
            )
            occurrences = sum(node.name == expected for node in nodes)
            raise IntrospectorCheckError(
                f"missing direct call-tree edge {parent_name!r} -> {expected!r}; "
                f"direct children seen: {direct_children}; {expected!r} occurs "
                f"{occurrences} time(s) elsewhere"
            )
        chains = extended

    if not require_multi:
        return

    problems: list[str] = []
    for chain in chains:
        run_scenario = chain[2]
        run_multi = chain[3]
        scenario_names = {
            nodes[index].name for index in _descendants(nodes, run_scenario)
        }
        multi_names = {nodes[index].name for index in _descendants(nodes, run_multi)}
        missing = []
        if "curl_easy_reset" not in scenario_names:
            missing.append("curl_easy_reset below proto_fuzzer::RunScenario")
        if "curl_multi_perform" not in multi_names:
            missing.append(
                "curl_multi_perform below proto_fuzzer::RunMultiTransferScenario"
            )
        if not missing:
            return
        location = nodes[run_scenario].report_line
        problems.append(
            f"chain beginning at report line {location}: missing {', '.join(missing)}"
        )

    api_counts = {
        name: sum(node.name == name for node in nodes)
        for name in ("curl_easy_reset", "curl_multi_perform")
    }
    raise IntrospectorCheckError(
        "the required orchestration chain exists, but its subtree is incomplete; "
        + "; ".join(problems)
        + "; occurrences anywhere in the report: "
        + ", ".join(f"{name}={count}" for name, count in api_counts.items())
    )


def check_report(report: Path) -> dict[str, Path]:
    """Locate, parse, and verify every applicable proto-target call tree."""
    calltrees = locate_calltrees(report)
    if report.is_dir() or report.suffix == ".json":
        actual_targets = set(calltrees)
        missing = sorted(EXPECTED_PROTO_TARGETS - actual_targets)
        unexpected = sorted(actual_targets - EXPECTED_PROTO_TARGETS)
        if missing or unexpected:
            details = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected: {', '.join(unexpected)}")
            raise IntrospectorCheckError(
                "proto target set does not match scripts/fuzz_targets; "
                + "; ".join(details)
            )

    failures: list[str] = []
    for target, calltree in sorted(calltrees.items()):
        try:
            text = calltree.read_text(encoding="utf-8")
            nodes = parse_calltree(text, str(calltree))
            verify_calltree(nodes, require_multi=target == MULTI_TARGET)
        except (OSError, UnicodeError) as error:
            failures.append(f"{target}: could not read {calltree}: {error}")
        except IntrospectorCheckError as error:
            failures.append(f"{target}: {error}")

    if failures:
        rendered = "\n  ".join(failures)
        raise IntrospectorCheckError(
            f"{len(failures)} proto target call-tree check(s) failed:\n  {rendered}"
        )
    return calltrees


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report",
        type=Path,
        help="Introspector output directory, summary.json, or call-tree .data file",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line checker."""
    arguments = _parse_args(argv)
    try:
        calltrees = check_report(arguments.report)
    except IntrospectorCheckError as error:
        print(f"Introspector call-tree check failed: {error}", file=sys.stderr)
        return 1
    targets = ", ".join(sorted(calltrees))
    print(
        f"Introspector call-tree check passed for {len(calltrees)} proto target(s): "
        f"{targets}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
