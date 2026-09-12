#!/usr/bin/env python3
"""Generate the focused source-level call tree used by Introspector CI."""

from __future__ import annotations

import argparse
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CALLTREE_BASENAME = "fuzzerLogFile-curl_fuzzer_proto_multi.data"

# Put the unrelated helpers first so the check also catches regressions where
# Introspector resolves RunScenario by its unqualified name.
SOURCE_PATHS = (
    "tests/http3_mock_server_test.cc",
    "tests/tftp_mock_server_test.cc",
    "tests/ftp_mock_server_test.cc",
    "fuzzer_entrypoints/curl_fuzzer_proto_multi.cc",
    "proto_fuzzer/fuzzer_main.cc",
    "proto_fuzzer/scenario_runner.cc",
    "proto_fuzzer/multi_transfer_runner.cc",
)


class IntrospectorGenerationError(RuntimeError):
    """Raised when focused Introspector metadata cannot be generated."""


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_directory",
        type=Path,
        help="directory in which Fuzz Introspector should write its metadata",
    )
    return parser.parse_args(arguments)


def _install_tree_sitter_compatibility() -> None:
    """Provide the tree-sitter behavior expected by Introspector."""
    import tree_sitter
    from tree_sitter import Language, Point, Query

    # tree-sitter 0.26.0's Point accessors return borrowed references. Values
    # outside CPython's immortal-integer range can then be freed while still
    # in use, corrupting the heap during traversal. Tuple indexing has the
    # correct ownership semantics and is equivalent to the two accessors.
    # https://github.com/tree-sitter/py-tree-sitter/issues/472
    if getattr(tree_sitter, "__version__", "") == "0.26.0":
        Point.row = property(lambda point: point[0])
        Point.column = property(lambda point: point[1])

    if hasattr(Language, "query") and hasattr(Query, "captures"):
        return

    from tree_sitter import Node, QueryCursor

    class QueryAdapter:
        def __init__(self, language: Language, source: str) -> None:
            self._query = Query(language, source)

        def captures(self, node: Node) -> dict[str, list[Node]]:
            return QueryCursor(self._query).captures(node)

    def query(language: Language, source: str) -> QueryAdapter:
        return QueryAdapter(language, source)

    # tree-sitter 0.25 moved Query.captures(), and 0.26 removed
    # Language.query(). Fuzz Introspector still uses that convenient pair
    # throughout its source frontends, so adapt it at our integration edge.
    Language.query = query


def generate_calltree(
    output_directory: Path, analyse_folder: Callable[..., object]
) -> Path:
    """Generate one call tree in a clean staging directory."""
    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)

    sources = [REPO_ROOT / source for source in SOURCE_PATHS]
    missing = [str(source) for source in sources if not source.is_file()]
    if missing:
        raise IntrospectorGenerationError(
            f"Introspector input files are missing: {', '.join(missing)}"
        )

    destination = output_directory / CALLTREE_BASENAME
    destination.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".curl-fuzzer-introspector-", dir=output_directory
    ) as temporary:
        temporary_directory = Path(temporary)
        empty_source_directory = temporary_directory / "source"
        staged_output_directory = temporary_directory / "output"
        empty_source_directory.mkdir()
        staged_output_directory.mkdir()

        # analyse_folder scans directory recursively in addition to
        # files_to_include. Give it an empty directory so this check remains
        # focused and deterministic.
        analyse_folder(
            language="c++",
            directory=str(empty_source_directory),
            entrypoint="LLVMFuzzerTestOneInput",
            out=str(staged_output_directory),
            files_to_include=[str(source) for source in sources],
        )

        generated = staged_output_directory / CALLTREE_BASENAME
        if not generated.is_file():
            raise IntrospectorGenerationError(
                f"Fuzz Introspector did not generate {CALLTREE_BASENAME}"
            )
        generated.replace(destination)

    return destination


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the pinned Fuzz Introspector source frontend."""
    parsed = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        _install_tree_sitter_compatibility()
        from fuzz_introspector.frontends import oss_fuzz
    except ImportError as error:
        print(
            f"Could not import Fuzz Introspector dependencies: {error}",
            file=sys.stderr,
        )
        return 2

    try:
        calltree = generate_calltree(parsed.output_directory, oss_fuzz.analyse_folder)
    except (IntrospectorGenerationError, OSError) as error:
        print(f"Could not generate Introspector call tree: {error}", file=sys.stderr)
        return 1

    print(calltree)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
