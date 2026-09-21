"""Check local Introspector source selection and isolation."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "run_introspector_report.py"


def _load_module():  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location(
        "run_introspector_report", SCRIPT
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _checkout(root: Path, tracked: list[str], untracked: list[str]) -> None:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    (root / ".gitignore").write_text("build/\nvendor/\n.oss-fuzz/\n", encoding="utf-8")
    for relative in tracked + untracked:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("void example(void) {}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", ".gitignore", *tracked], check=True)


def test_selection_maps_local_checkouts_to_config_paths(tmp_path: Path) -> None:
    module = _load_module()
    curl = tmp_path / "arbitrary-curl-checkout"
    fuzzer = tmp_path / "arbitrary-fuzzer-checkout"
    curl_sources = ["lib/http.c", "lib/vtls/schannel.c", "include/curl/curl.h"]
    curl_excluded = [
        "tests/unit/unit1300.c",
        "src/tool_operate.c",
        "docs/examples/example.c",
        "CMake/CurlTests.c",
        "projects/Windows/example.c",
    ]
    fuzzer_sources = ["fuzzer_entrypoints/curl_fuzzer_http.cc", "fuzz_netrc.cc"]
    fuzzer_excluded = ["tests/server_test.cc", "standalone_fuzz_target_runner.cc"]
    ignored = ["build/generated.cc", "vendor/dependency.cc", ".oss-fuzz/target.cc"]
    _checkout(curl, curl_sources + curl_excluded, ignored + ["lib/new file.c"])
    _checkout(
        fuzzer,
        fuzzer_sources + fuzzer_excluded,
        ignored + ["proto_fuzzer/new_runner.cc"],
    )

    rules = module.read_exclusions(module.CONFIG_PATH)
    curl_included, curl_removed = module.collect_source_files(curl, "/src/curl", rules)
    fuzz_included, fuzz_removed = module.collect_source_files(
        fuzzer, "/src/curl_fuzzer", rules
    )

    assert set(curl_included) == {
        str(curl / path) for path in curl_sources + ["lib/new file.c"]
    }
    assert set(fuzz_included) == {
        str(fuzzer / path) for path in fuzzer_sources + ["proto_fuzzer/new_runner.cc"]
    }
    assert set(curl_removed) == {f"/src/curl/{path}" for path in curl_excluded}
    assert set(fuzz_removed) == {f"/src/curl_fuzzer/{path}" for path in fuzzer_excluded}

    baseline, removed = module.collect_source_files(curl, "/src/curl", [])
    assert set(baseline) == {
        str(curl / path) for path in curl_sources + curl_excluded + ["lib/new file.c"]
    }
    assert removed == []
    assert all((curl / path).is_file() for path in curl_excluded + ignored)


def test_generation_scans_empty_directory_and_keeps_artifacts_in_output(
    tmp_path: Path,
) -> None:
    module = _load_module()
    output = tmp_path / "report"
    output.mkdir()
    source = tmp_path / "harness.cc"
    source.write_text("int LLVMFuzzerTestOneInput() {}\n", encoding="utf-8")
    original_directory = Path.cwd()
    scan_directories = []

    def analyse_folder(**arguments):  # type: ignore[no-untyped-def]
        scan = Path(arguments["directory"])
        scan_directories.append(scan)
        assert scan.is_dir() and not list(scan.iterdir())
        assert scan.parent == output
        assert Path.cwd() == output
        assert arguments["files_to_include"] == [str(source)]
        (Path(arguments["out"]) / "fuzzerLogFile-harness.data").write_text(
            "Call tree\n", encoding="utf-8"
        )

    def run_analysis_on_dir(**arguments):  # type: ignore[no-untyped-def]
        assert not scan_directories[0].exists()
        assert Path.cwd() == output
        assert arguments["target_folder"] == str(output)
        assert not arguments["enable_all_analyses"]
        assert not arguments["parallelise"]
        assert arguments["coverage_url"] == ""
        (Path(arguments["out_dir"]) / "fuzz_report.html").write_text(
            "report", encoding="utf-8"
        )
        return 0, {}

    result = module.generate_report(
        output, [str(source)], analyse_folder, run_analysis_on_dir
    )

    assert result == output / "fuzz_report.html"
    assert source.read_text(encoding="utf-8") == "int LLVMFuzzerTestOneInput() {}\n"
    assert Path.cwd() == original_directory


def test_generation_reports_missing_frontend_output_and_restores_cwd(
    tmp_path: Path,
) -> None:
    module = _load_module()
    original_directory = Path.cwd()

    def unexpected_backend(**_arguments):  # type: ignore[no-untyped-def]
        pytest.fail("Backend must not run without frontend output")

    with pytest.raises(module.IntrospectorReportError, match="no call trees"):
        module.generate_report(
            tmp_path, ["harness.cc"], lambda **_arguments: None, unexpected_backend
        )

    assert Path.cwd() == original_directory
    assert not list(tmp_path.iterdir())


def test_nonempty_output_is_rejected_without_touching_old_report(
    tmp_path: Path,
) -> None:
    module = _load_module()
    stale = tmp_path / "fuzz_report.html"
    stale.write_text("old report", encoding="utf-8")

    assert module.main([str(tmp_path), "--curl-source", "missing-checkout"]) == 1
    assert stale.read_text(encoding="utf-8") == "old report"


@pytest.mark.parametrize("contents", ["# No file rules\n", "FUNCS_TO_AVOID\nhelper\n"])
def test_unsupported_or_missing_config_header_fails(
    tmp_path: Path, contents: str
) -> None:
    module = _load_module()
    config = tmp_path / "exclusions.config"
    config.write_text(contents, encoding="utf-8")

    with pytest.raises(module.IntrospectorReportError):
        module.read_exclusions(config)


def test_help_does_not_require_fuzz_introspector(capsys) -> None:  # type: ignore[no-untyped-def]
    module = _load_module()

    with pytest.raises(SystemExit) as raised:
        module.main(["--help"])

    assert raised.value.code == 0
    assert "--curl-source" in capsys.readouterr().out


def test_static_report_assets_work_without_optional_analysis_or_coverage(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed to exercise generated report JavaScript")
    module = _load_module()
    report = tmp_path / "fuzz_report.html"
    report.write_text(
        "<p>Functions reached: 1286</p>\n"
        '<script src="custom.js" type="text/javascript"></script>\n'
        '<script src="analysis_1.js" type="text/javascript">\n</script>\n',
        encoding="utf-8",
    )
    custom_script = tmp_path / "custom.js"
    custom_script.write_text(
        """function populateFunctionsHitTable() {
  for (const [key, value] of Object.entries(fuzzer_table_data)) {
    var table = $('#'+key).DataTable();
    table.rows.add(fuzzer_table_data[key]);
  }
  table.draw();
}
function populateFuzzersOverviewTable(value) {
  var table = $('#'+value).DataTable();
  if (value === 'fuzzers_overview_table') {
    table.rows.add(all_functions_table_data);
  } else {
    table.rows.add(analysis_1_data);
  }
  table.draw();
}
""",
        encoding="utf-8",
    )
    data = tmp_path / "all_functions.js"
    data.write_text("var all_functions_table_data = [1, 2, 3];", encoding="utf-8")
    original_data = data.read_bytes()

    module.normalize_static_report_assets(tmp_path)
    normalized_html = report.read_text(encoding="utf-8")
    normalized_javascript = custom_script.read_bytes()
    assert "analysis_1.js" not in normalized_html
    assert "Functions reached: 1286" in normalized_html
    assert data.read_bytes() == original_data
    module.normalize_static_report_assets(tmp_path)
    assert report.read_text(encoding="utf-8") == normalized_html
    assert custom_script.read_bytes() == normalized_javascript

    # No optional-analysis global or table exists. Empty coverage must also
    # leave UI initialization running after the visible function table draws.
    subprocess.run(
        [
            node,
            "-e",
            """const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const visible = new Set(['fuzzers_overview_table']);
let rowsAdded = 0;
let draws = 0;
const context = {
  document: {getElementById: id => visible.has(id) ? {} : null},
  all_functions_table_data: [1, 2, 3],
  fuzzer_table_data: {},
  $: selector => {
    assert.ok(visible.has(selector.slice(1)), 'Absent table must not initialize');
    return {DataTable: () => ({
      rows: {add: rows => {rowsAdded += rows.length;}},
      draw: () => {draws += 1;}
    })};
  }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
context.populateFuzzersOverviewTable('fuzzers_overview_table');
context.populateFuzzersOverviewTable('all_functions_overview_table');
context.populateFunctionsHitTable();
assert.equal(rowsAdded, 3);
assert.equal(draws, 1);
visible.add('coverage_table');
context.fuzzer_table_data.coverage_table = [4, 5];
context.populateFunctionsHitTable();
assert.equal(rowsAdded, 5);
assert.equal(draws, 2);
""",
            str(custom_script),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_static_report_rejects_unexpected_upstream_javascript(tmp_path: Path) -> None:
    module = _load_module()
    report = tmp_path / "fuzz_report.html"
    report.write_text('<script src="custom.js"></script>', encoding="utf-8")
    custom_script = tmp_path / "custom.js"
    custom_script.write_text("changed upstream implementation", encoding="utf-8")

    with pytest.raises(module.IntrospectorReportError, match="JavaScript changed"):
        module.normalize_static_report_assets(tmp_path)

    assert (
        custom_script.read_text(encoding="utf-8") == "changed upstream implementation"
    )
