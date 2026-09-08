"""Tests for the generated Fuzz Introspector call-tree checker."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_introspector_report.py"


def _load_module():  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location(
        "check_introspector_report", SCRIPT
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _valid_calltree() -> str:
    # Deliberately mix tabs and nonuniform spaces. Depth, rather than a fixed
    # two-space prefix, defines ancestry in Introspector's text format. Both
    # source-line suffix forms occur in generated reports.
    return """Call tree
LLVMFuzzerTestOneInput /src/entry.cc linenumber=-1
\tproto_fuzzer::ProtoFuzzerTestOneInput /src/entry.cc 20
\t  proto_fuzzer::RunScenario /src/scenario_runner.cc 30
\t    curl_easy_reset /src/curl/lib/easy.c 40
\t    proto_fuzzer::RunMultiTransferScenario /src/multi_transfer_runner.cc 50
\t      curl_multi_perform /src/curl/lib/multi.c 60
====================================
This trailing report section is not part of the call tree.
"""


def _base_calltree() -> str:
    return """Call tree
LLVMFuzzerTestOneInput /src/http.cc -1
  proto_fuzzer::ProtoFuzzerTestOneInput /src/http.cc 20
    proto_fuzzer::RunScenario /src/scenario_runner.cc 30
"""


def _summary(calltrees: dict[str, str]) -> dict[str, object]:
    document: dict[str, object] = {"analyses": {}}
    for target, calltree in calltrees.items():
        document[target] = {
            "metadata-files": {
                "calltree": calltree,
                "program-data": f"fuzzerLogFile-{target}.data.yaml",
            }
        }
    return document


def _complete_calltrees(module, tmp_path: Path) -> dict[str, Path]:  # type: ignore[no-untyped-def]
    calltrees = {}
    for target in sorted(module.EXPECTED_PROTO_TARGETS):
        path = tmp_path / f"{target}.data"
        text = _valid_calltree() if target == module.MULTI_TARGET else _base_calltree()
        path.write_text(text, encoding="utf-8")
        calltrees[target] = path
    return calltrees


def test_parse_and_verify_variable_width_indentation() -> None:
    module = _load_module()

    nodes = module.parse_calltree(_valid_calltree())

    module.verify_calltree(nodes)
    assert [node.indent for node in nodes] == [0, 8, 10, 12, 12, 14]
    assert nodes[0].source_line == -1
    assert nodes[4].parent == 2


def test_verify_rejects_a_required_function_on_the_wrong_branch() -> None:
    module = _load_module()
    calltree = _valid_calltree().replace(
        "\t      curl_multi_perform /src/curl/lib/multi.c 60",
        "unrelated /src/other.cc 1\n  curl_multi_perform /src/curl/lib/multi.c 60",
    )

    with pytest.raises(module.IntrospectorCheckError) as raised:
        module.verify_calltree(module.parse_calltree(calltree))

    message = str(raised.value)
    assert "curl_multi_perform below proto_fuzzer::RunMultiTransferScenario" in message
    assert "curl_multi_perform=1" in message


def test_verify_reports_the_missing_direct_edge_and_seen_children() -> None:
    module = _load_module()
    calltree = _valid_calltree().replace(
        "\t  proto_fuzzer::RunScenario /src/scenario_runner.cc 30",
        "\t  ScenarioRunner /src/scenario_runner.cc 30",
    )

    with pytest.raises(module.IntrospectorCheckError) as raised:
        module.verify_calltree(module.parse_calltree(calltree))

    message = str(raised.value)
    assert "missing direct call-tree edge" in message
    assert "proto_fuzzer::ProtoFuzzerTestOneInput" in message
    assert "proto_fuzzer::RunScenario" in message
    assert "direct children seen: ScenarioRunner" in message


def test_parse_rejects_malformed_nodes_with_a_report_line() -> None:
    module = _load_module()

    with pytest.raises(module.IntrospectorCheckError) as raised:
        module.parse_calltree(
            "Call tree\nLLVMFuzzerTestOneInput has-no-source-line\n",
            "broken.data",
        )

    assert "broken.data:2: malformed call-tree node" in str(raised.value)


def test_locate_calltree_uses_summary_metadata(tmp_path: Path) -> None:
    module = _load_module()
    report = tmp_path / "inspector-report"
    report.mkdir()
    calltree = report / "renamed-calltree.data"
    calltree.write_text(_valid_calltree(), encoding="utf-8")
    (report / "summary.json").write_text(
        json.dumps(_summary({"curl_fuzzer_proto_multi": calltree.name})),
        encoding="utf-8",
    )
    # This conventional filename must not override summary.json metadata.
    (report / module.CALLTREE_BASENAME).write_text("wrong", encoding="utf-8")

    assert module.locate_calltree(report) == calltree.resolve()


def test_summary_checks_every_proto_target_calltree(tmp_path: Path) -> None:
    module = _load_module()
    calltrees = _complete_calltrees(module, tmp_path)
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(_summary({target: path.name for target, path in calltrees.items()})),
        encoding="utf-8",
    )

    assert module.check_report(summary) == {
        target: path.resolve() for target, path in calltrees.items()
    }


def test_summary_reports_a_broken_non_multi_proto_target(tmp_path: Path) -> None:
    module = _load_module()
    calltrees = _complete_calltrees(module, tmp_path)
    http = calltrees["curl_fuzzer_proto_http"]
    http.write_text(
        "Call tree\nLLVMFuzzerTestOneInput /src/http.cc -1\n",
        encoding="utf-8",
    )
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(_summary({target: path.name for target, path in calltrees.items()})),
        encoding="utf-8",
    )

    with pytest.raises(module.IntrospectorCheckError) as raised:
        module.check_report(summary)

    message = str(raised.value)
    assert "1 proto target call-tree check(s) failed" in message
    assert "curl_fuzzer_proto_http" in message
    assert "proto_fuzzer::ProtoFuzzerTestOneInput" in message


def test_summary_rejects_a_missing_proto_target(tmp_path: Path) -> None:
    module = _load_module()
    calltrees = _complete_calltrees(module, tmp_path)
    missing = "curl_fuzzer_proto_https_mbedtls"
    del calltrees[missing]
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(_summary({target: path.name for target, path in calltrees.items()})),
        encoding="utf-8",
    )

    with pytest.raises(module.IntrospectorCheckError) as raised:
        module.check_report(summary)

    assert "proto target set does not match scripts/fuzz_targets" in str(raised.value)
    assert f"missing: {missing}" in str(raised.value)


def test_direct_data_file_infers_a_non_multi_target(tmp_path: Path) -> None:
    module = _load_module()
    calltree = tmp_path / "fuzzerLogFile-curl_fuzzer_proto_http.data"
    calltree.write_text(_base_calltree(), encoding="utf-8")

    assert module.check_report(calltree) == {
        "curl_fuzzer_proto_http": calltree.resolve()
    }


def test_locate_calltree_falls_back_to_a_nested_data_file(tmp_path: Path) -> None:
    module = _load_module()
    calltree = tmp_path / "wrapped" / "report" / module.CALLTREE_BASENAME
    calltree.parent.mkdir(parents=True)
    calltree.write_text(_valid_calltree(), encoding="utf-8")

    assert module.locate_calltree(tmp_path) == calltree.resolve()


def test_summary_reports_missing_target_metadata(tmp_path: Path) -> None:
    module = _load_module()
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps({"another_fuzzer": {}}), encoding="utf-8")

    with pytest.raises(module.IntrospectorCheckError) as raised:
        module.locate_calltree(summary)

    assert "summary has no curl_fuzzer_proto* target metadata" in str(raised.value)


def test_cli_returns_nonzero_with_actionable_failure(tmp_path: Path) -> None:
    calltree = tmp_path / "fuzzerLogFile-curl_fuzzer_proto_multi.data"
    calltree.write_text(
        "Call tree\nLLVMFuzzerTestOneInput /src/entry.cc -1\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(calltree)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Introspector call-tree check failed" in result.stderr
    assert "proto_fuzzer::ProtoFuzzerTestOneInput" in result.stderr
