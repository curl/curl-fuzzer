#!/usr/bin/env python3
"""Generate focused source-level call trees for every proto fuzzer."""

from __future__ import annotations

import argparse
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT_PATHS = tuple(
    str(path.relative_to(REPO_ROOT))
    for path in sorted(
        (REPO_ROOT / "fuzzer_entrypoints").glob("curl_fuzzer_proto*.cc")
    )
)

# Put the unrelated helpers first so the check also catches regressions where
# Introspector resolves RunScenario by its unqualified name.
DISTRACTOR_SOURCE_PATHS = (
    "tests/http3_mock_server_test.cc",
    "tests/tftp_mock_server_test.cc",
    "tests/ftp_mock_server_test.cc",
    "tests/ftps_mock_server_test.cc",
    "tests/smtp_mock_server_test.cc",
    "tests/imap_mock_server_test.cc",
    "tests/pop3_mock_server_test.cc",
    "tests/mqtt_mock_server_test.cc",
    "tests/dict_mock_server_test.cc",
    "tests/ldap_mock_server_test.cc",
    "tests/ldaps_mock_server_test.cc",
    "tests/rtsp_mock_server_test.cc",
    "tests/smtps_mock_server_test.cc",
    "tests/imaps_mock_server_test.cc",
    "tests/pop3s_mock_server_test.cc",
    "tests/mqtts_mock_server_test.cc",
)
SHARED_SOURCE_PATHS = (
    "proto_fuzzer/fuzzer_main.cc",
    "proto_fuzzer/scenario_runner.cc",
    "proto_fuzzer/transfer_session.cc",
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


def _calltree_basename(entrypoint_path: str) -> str:
    return f"fuzzerLogFile-{Path(entrypoint_path).stem}.data"


def generate_calltrees(
    output_directory: Path, analyse_folder: Callable[..., object]
) -> tuple[Path, ...]:
    """Generate one isolated call tree for every proto fuzzer entrypoint."""
    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)

    if not ENTRYPOINT_PATHS:
        raise IntrospectorGenerationError("no proto fuzzer entrypoints were found")

    source_paths = (
        *DISTRACTOR_SOURCE_PATHS,
        *ENTRYPOINT_PATHS,
        *SHARED_SOURCE_PATHS,
    )
    sources = [REPO_ROOT / source for source in source_paths]
    missing = [str(source) for source in sources if not source.is_file()]
    if missing:
        raise IntrospectorGenerationError(
            f"Introspector input files are missing: {', '.join(missing)}"
        )

    # Never let output from an earlier run satisfy the completeness check.
    for stale in output_directory.glob("fuzzerLogFile-curl_fuzzer_proto*.data"):
        stale.unlink()

    destinations = tuple(
        output_directory / _calltree_basename(entrypoint)
        for entrypoint in ENTRYPOINT_PATHS
    )
    with tempfile.TemporaryDirectory(
        prefix=".curl-fuzzer-introspector-", dir=output_directory
    ) as temporary:
        temporary_directory = Path(temporary)
        generated_calltrees: list[Path] = []
        for entrypoint in ENTRYPOINT_PATHS:
            target = Path(entrypoint).stem
            target_directory = temporary_directory / target
            empty_source_directory = target_directory / "source"
            staged_output_directory = target_directory / "output"
            empty_source_directory.mkdir(parents=True)
            staged_output_directory.mkdir()

            # Every wrapper exports the same LLVMFuzzerTestOneInput symbol.
            # Analyse them separately so Introspector cannot attach one
            # target's root to another target's source file.
            selected_paths = (
                *DISTRACTOR_SOURCE_PATHS,
                entrypoint,
                *SHARED_SOURCE_PATHS,
            )
            analyse_folder(
                language="c++",
                directory=str(empty_source_directory),
                entrypoint="LLVMFuzzerTestOneInput",
                out=str(staged_output_directory),
                files_to_include=[
                    str(REPO_ROOT / source) for source in selected_paths
                ],
            )

            basename = _calltree_basename(entrypoint)
            generated = staged_output_directory / basename
            if not generated.is_file():
                raise IntrospectorGenerationError(
                    f"Fuzz Introspector did not generate {basename}"
                )
            generated_calltrees.append(generated)

        for generated, destination in zip(
            generated_calltrees, destinations, strict=True
        ):
            generated.replace(destination)

    return destinations


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
        calltrees = generate_calltrees(
            parsed.output_directory, oss_fuzz.analyse_folder
        )
    except (IntrospectorGenerationError, OSError) as error:
        print(f"Could not generate Introspector call tree: {error}", file=sys.stderr)
        return 1

    for calltree in calltrees:
        print(calltree)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
