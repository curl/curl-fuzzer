"""Tests for the focused Fuzz Introspector source runner."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "generate_introspector_calltree.py"


def _load_module():  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location(
        "generate_introspector_calltree", SCRIPT
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_generate_calltree_uses_only_the_curated_sources(tmp_path: Path) -> None:
    module = _load_module()
    observed = {}

    def analyse_folder(**arguments):  # type: ignore[no-untyped-def]
        observed.update(arguments)
        source_directory = Path(arguments["directory"])
        assert source_directory.is_dir()
        assert not list(source_directory.iterdir())
        output_directory = Path(arguments["out"])
        (output_directory / module.CALLTREE_BASENAME).write_text(
            "Call tree\n", encoding="utf-8"
        )

    calltree = module.generate_calltree(tmp_path / "result", analyse_folder)

    assert calltree == (tmp_path / "result" / module.CALLTREE_BASENAME).resolve()
    assert calltree.read_text(encoding="utf-8") == "Call tree\n"
    assert observed["language"] == "c++"
    assert observed["entrypoint"] == "LLVMFuzzerTestOneInput"
    assert observed["files_to_include"] == [
        str(REPO_ROOT / source) for source in module.SOURCE_PATHS
    ]
    assert module.SOURCE_PATHS == (
        "tests/http3_mock_server_test.cc",
        "tests/tftp_mock_server_test.cc",
        "tests/ftp_mock_server_test.cc",
        "fuzzer_entrypoints/curl_fuzzer_proto_multi.cc",
        "proto_fuzzer/fuzzer_main.cc",
        "proto_fuzzer/scenario_runner.cc",
        "proto_fuzzer/multi_transfer_runner.cc",
    )


def test_tree_sitter_compatibility_uses_current_apis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    tree_sitter = ModuleType("tree_sitter")
    tree_sitter.__version__ = "0.26.0"

    class Language:
        pass

    class Point(tuple):
        row = property(lambda _point: None)
        column = property(lambda _point: None)

    created_queries = []

    class Query:
        def __init__(self, language, source):  # type: ignore[no-untyped-def]
            self.language = language
            self.source = source
            created_queries.append(self)

    class QueryCursor:
        def __init__(self, query):  # type: ignore[no-untyped-def]
            self.query = query

        def captures(self, node):  # type: ignore[no-untyped-def]
            return {"capture": [node]}

    tree_sitter.Language = Language
    tree_sitter.Node = object
    tree_sitter.Point = Point
    tree_sitter.Query = Query
    tree_sitter.QueryCursor = QueryCursor
    monkeypatch.setitem(sys.modules, "tree_sitter", tree_sitter)

    module._install_tree_sitter_compatibility()

    language = Language()
    node = object()
    query = language.query("(call_expression) @call")
    assert created_queries[0].source == "(call_expression) @call"
    assert created_queries[0].language is language
    assert query.captures(node) == {"capture": [node]}

    point = Point((300, 400))
    assert point.row == 300
    assert point.column == 400


def test_generate_calltree_rejects_missing_output_and_removes_stale_file(
    tmp_path: Path,
) -> None:
    module = _load_module()
    output_directory = tmp_path / "result"
    output_directory.mkdir()
    stale = output_directory / module.CALLTREE_BASENAME
    stale.write_text("stale", encoding="utf-8")

    with pytest.raises(module.IntrospectorGenerationError):
        module.generate_calltree(output_directory, lambda **_arguments: None)

    assert not stale.exists()


def test_help_does_not_require_fuzz_introspector(capsys) -> None:  # type: ignore[no-untyped-def]
    module = _load_module()

    with pytest.raises(SystemExit) as raised:
        module.main(["--help"])

    assert raised.value.code == 0
    assert "output_directory" in capsys.readouterr().out
