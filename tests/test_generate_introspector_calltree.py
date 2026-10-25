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


def test_generate_calltrees_isolates_every_proto_entrypoint(tmp_path: Path) -> None:
    module = _load_module()
    observed: list[dict[str, object]] = []

    def analyse_folder(**arguments):  # type: ignore[no-untyped-def]
        observed.append(arguments)
        source_directory = Path(arguments["directory"])
        assert source_directory.is_dir()
        assert not list(source_directory.iterdir())
        output_directory = Path(arguments["out"])
        entrypoints = [
            Path(source)
            for source in arguments["files_to_include"]
            if Path(source).parent.name == "fuzzer_entrypoints"
        ]
        assert len(entrypoints) == 1
        basename = f"fuzzerLogFile-{entrypoints[0].stem}.data"
        (output_directory / basename).write_text(
            "Call tree\n", encoding="utf-8"
        )

    calltrees = module.generate_calltrees(tmp_path / "result", analyse_folder)

    expected_entrypoints = tuple(
        str(path.relative_to(REPO_ROOT))
        for path in sorted(
            (REPO_ROOT / "fuzzer_entrypoints").glob("curl_fuzzer_proto*.cc")
        )
    )
    assert module.ENTRYPOINT_PATHS == expected_entrypoints
    assert len(module.ENTRYPOINT_PATHS) == 30
    assert calltrees == tuple(
        (tmp_path / "result" / f"fuzzerLogFile-{Path(source).stem}.data").resolve()
        for source in expected_entrypoints
    )
    assert all(
        calltree.read_text(encoding="utf-8") == "Call tree\n"
        for calltree in calltrees
    )
    assert len(observed) == len(expected_entrypoints)

    for arguments, entrypoint in zip(observed, expected_entrypoints, strict=True):
        assert arguments["language"] == "c++"
        assert arguments["entrypoint"] == "LLVMFuzzerTestOneInput"
        assert arguments["files_to_include"] == [
            str(REPO_ROOT / source)
            for source in (
                *module.DISTRACTOR_SOURCE_PATHS,
                entrypoint,
                *module.SHARED_SOURCE_PATHS,
            )
        ]

    assert module.DISTRACTOR_SOURCE_PATHS == (
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
    assert module.SHARED_SOURCE_PATHS == (
        "proto_fuzzer/fuzzer_main.cc",
        "proto_fuzzer/scenario_runner.cc",
        "proto_fuzzer/transfer_session.cc",
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


def test_generate_calltrees_rejects_missing_output_and_removes_stale_files(
    tmp_path: Path,
) -> None:
    module = _load_module()
    output_directory = tmp_path / "result"
    output_directory.mkdir()
    stale = output_directory / "fuzzerLogFile-curl_fuzzer_proto_multi.data"
    removed_target = (
        output_directory / "fuzzerLogFile-curl_fuzzer_proto_removed.data"
    )
    for path in (stale, removed_target):
        path.write_text("stale", encoding="utf-8")

    with pytest.raises(module.IntrospectorGenerationError):
        module.generate_calltrees(output_directory, lambda **_arguments: None)

    assert not stale.exists()
    assert not removed_target.exists()


def test_help_does_not_require_fuzz_introspector(capsys) -> None:  # type: ignore[no-untyped-def]
    module = _load_module()

    with pytest.raises(SystemExit) as raised:
        module.main(["--help"])

    assert raised.value.code == 0
    assert "output_directory" in capsys.readouterr().out
