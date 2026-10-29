"""Tests for the reproducible libFuzzer comparison helper."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from curl_fuzzer_tools import compare_fuzzers

REPO_ROOT = Path(__file__).resolve().parent.parent


def _test_parity_manifest() -> compare_fuzzers.ParityManifest:
    return compare_fuzzers.ParityManifest(
        path=Path("external-parity-manifest.json"),
        sha256="0" * 64,
        baseline_id="test-parity-baseline",
        immutable_baseline_sha256="1" * 64,
        source_identity={},
        replay_input_timeout_seconds=10,
        replay_sanitizer_environment={
            "ASAN_OPTIONS": "detect_leaks=0",
            "LSAN_OPTIONS": None,
        },
        gate_scope="development_function_parity",
        retirement_eligible=False,
        region_status="indeterminate_nondeterministic",
        gate_rationale="test manifest",
        target_pairs=(("legacy", "proto"),),
        baseline_inventory=frozenset({"legacy"}),
        candidate_inventory=frozenset({"proto"}),
        excluded_inventory=frozenset(),
        baseline_corpora={"legacy": (1, "2" * 64)},
        baseline_function_count=1,
        baseline_function_sha256="3" * 64,
        baseline_region_count=1,
        baseline_region_sha256="4" * 64,
        initial_functions=frozenset({("lib/test.c", "test_function")}),
        initial_regions=frozenset({("lib/test.c", "test_function", 1, 1, 1, 2)}),
        resolved_functions=frozenset(),
        resolved_regions=frozenset(),
        identity_canonicalization={},
        provenance={},
    )


def _run_cli(
    arguments: list[str], extra_environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    python_path = str(REPO_ROOT / "src")
    if environment.get("PYTHONPATH"):
        python_path += os.pathsep + environment["PYTHONPATH"]
    environment["PYTHONPATH"] = python_path
    if extra_environment is not None:
        environment.update(extra_environment)
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from curl_fuzzer_tools.compare_fuzzers import main; raise SystemExit(main())",
            *arguments,
        ],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_pyproject_exposes_compare_fuzzers_entry_point() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'compare_fuzzers = "curl_fuzzer_tools.compare_fuzzers:main"' in pyproject


def test_git_revision_is_absent_without_a_verified_checkout(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(compare_fuzzers, "SOURCE_CHECKOUT", None)

    assert compare_fuzzers._git_revision() is None


def _write_dummy_fuzzer(path: Path, exit_status: int = 0) -> None:
    path.write_text(
        f"""#!/bin/sh
for argument in "$@"; do
  if [ "$argument" = "-help=1" ]; then
    echo "Flags: max_total_time print_final_stats"
    exit 0
  fi
done
corpus=""
seed=0
for argument in "$@"; do
  case "$argument" in
    -seed=*) seed=${{argument#-seed=}} ;;
    -*) ;;
    *) corpus=$argument ;;
  esac
done
count=$(find "$corpus" -maxdepth 1 -type f | wc -l)
echo "#2 INITED cov: 10 ft: 20 corp: $count/3b exec/s: 0 rss: 1Mb"
printf mutation > "$corpus/new-$seed"
echo "#100 DONE cov: 12 ft: 25 corp: $((count + 1))/11b exec/s: 50 rss: 2Mb"
echo "stat::number_of_executed_units: 100"
echo "stat::average_exec_per_sec: 50"
echo "stat::new_units_added: 1"
echo "stat::slowest_unit_time_sec: 0"
echo "stat::peak_rss_mb: 2"
exit {exit_status}
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_coverage_fuzzer(
    path: Path,
    *,
    expected_timeout: int = 25,
    invocation_log: Path | None = None,
    profile_contents: bytes = b"raw profile",
    write_status: bool = True,
) -> None:
    marker = ""
    if invocation_log is not None:
        marker = (
            f"with Path({str(invocation_log)!r}).open('a', encoding='utf-8') "
            "as stream:\n    stream.write('run\\n')"
        )
    status_block = ""
    if write_status:
        status_block = """status = os.environ.get("FUZZ_REPLAY_STATUS_FILE")
if not status:
    raise SystemExit("FUZZ_REPLAY_STATUS_FILE is not set")
if os.environ.get("FUZZ_TIMEOUT_SECS") != __EXPECTED_TIMEOUT__:
    raise SystemExit("FUZZ_TIMEOUT_SECS is not set to the requested value")
if os.environ.get("ASAN_OPTIONS") != "detect_leaks=0":
    raise SystemExit("ASAN_OPTIONS is not pinned for source replay")
if "LSAN_OPTIONS" in os.environ:
    raise SystemExit("ambient LSAN_OPTIONS reached source replay")
__MARKER__
input_count = sum(item.is_file() for item in Path(sys.argv[1]).iterdir())
Path(status).write_text(json.dumps({
    "attempted": input_count,
    "completed": input_count,
    "timed_out": 0,
    "input_errors": 0,
    "path_errors": 0,
}))
"""
    script = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

profile = os.environ.get("LLVM_PROFILE_FILE")
if not profile:
    raise SystemExit("LLVM_PROFILE_FILE is not set")
Path(profile.replace("%p", str(os.getpid()))).write_bytes(__PROFILE_CONTENTS__)
__STATUS_BLOCK__
"""
    script = (
        script.replace("__PROFILE_CONTENTS__", repr(profile_contents))
        .replace("__STATUS_BLOCK__", status_block)
        .replace("__EXPECTED_TIMEOUT__", repr(str(expected_timeout)))
        .replace("__MARKER__", marker)
    )
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _coverage_document(source_root: Path, counts: tuple[int, int, int]) -> dict:
    functions = []
    for line, (name, count) in enumerate(
        zip(("common", "baseline_only", "candidate_only"), counts), start=1
    ):
        functions.append(
            {
                "name": name,
                "filenames": [str(source_root / "lib" / "example.c")],
                "count": count,
                "regions": [[line, 1, line, 10, count, 0, 0, 0]],
            }
        )
    return {"data": [{"functions": functions}], "type": "llvm.coverage.json.export"}


def _write_fake_llvm_tools(
    directory: Path,
    baseline_document: dict,
    candidate_document: dict,
    *,
    merged_profile_contents: bytes = b"merged profile",
    empty_export: bool = False,
) -> tuple[Path, Path]:
    profdata = directory / "llvm-profdata"
    profdata.write_text(
        """#!/usr/bin/env python3
import pathlib
import sys

if "--version" in sys.argv:
    print("fake llvm-profdata 18")
    raise SystemExit(0)
output = pathlib.Path(sys.argv[sys.argv.index("-o") + 1])
output.write_bytes(__MERGED_PROFILE_CONTENTS__)
""".replace("__MERGED_PROFILE_CONTENTS__", repr(merged_profile_contents)),
        encoding="utf-8",
    )
    profdata.chmod(0o755)

    llvm_cov = directory / "llvm-cov"
    llvm_cov.write_text(
        f"""#!/usr/bin/env python3
import json
import sys

if "--version" in sys.argv:
    print("fake llvm-cov 18")
    raise SystemExit(0)
binary = sys.argv[2]
baseline = {json.dumps(baseline_document)!r}
candidate = {json.dumps(candidate_document)!r}
if {empty_export!r}:
    raise SystemExit(0)
print(baseline if "coverage-baseline" in binary else candidate)
""",
        encoding="utf-8",
    )
    llvm_cov.chmod(0o755)
    return profdata, llvm_cov


def _write_seed_archive(directory: Path, target: str, contents: bytes) -> None:
    with zipfile.ZipFile(directory / f"{target}_seed_corpus.zip", "w") as archive:
        archive.writestr("seed", contents)


def _write_matching_source_trees(tmp_path: Path) -> tuple[Path, Path]:
    baseline_source = tmp_path / "curl-baseline"
    candidate_source = tmp_path / "curl-candidate"
    for source_root in (baseline_source, candidate_source):
        (source_root / "lib").mkdir(parents=True)
        (source_root / "src").mkdir()
        (source_root / "lib" / "example.c").write_text(
            "void example(void) {}\n", encoding="utf-8"
        )
    return baseline_source, candidate_source


def test_parse_libfuzzer_output() -> None:
    parsed = compare_fuzzers.parse_libfuzzer_output(
        """#2 INITED cov: 10 ft: 20 corp: 1/3b exec/s: 0 rss: 1Mb
#100 DONE cov: 12 ft: 25 corp: 2/11b exec/s: 50 rss: 2Mb
stat::number_of_executed_units: 100
stat::average_exec_per_sec:     50
"""
    )

    assert parsed.initial["cov"] == 10
    assert parsed.initial["ft"] == 20
    assert parsed.final["cov"] == 12
    assert parsed.final["ft"] == 25
    assert parsed.stats["average_exec_per_sec"] == 50


def test_source_coverage_compares_stable_curl_relative_identities(
    tmp_path: Path,
) -> None:
    baseline_root = tmp_path / "baseline-curl"
    candidate_root = tmp_path / "candidate-curl"
    for source_root in (baseline_root, candidate_root):
        (source_root / "lib").mkdir(parents=True)
        (source_root / "src").mkdir()
        (source_root / "lib" / "example.c").write_text(
            "void example(void) {}\n", encoding="utf-8"
        )

    baseline = compare_fuzzers.parse_source_coverage_export(
        _coverage_document(baseline_root, (1, 1, 0)), baseline_root
    )
    candidate = compare_fuzzers.parse_source_coverage_export(
        _coverage_document(candidate_root, (1, 0, 1)), candidate_root
    )
    comparison = compare_fuzzers.compare_source_coverage(baseline, candidate)

    assert comparison["functions"]["baseline_retention_percent"] == 50.0
    assert comparison["functions"]["baseline_only"] == [
        {"file": "lib/example.c", "name": "baseline_only"}
    ]
    assert comparison["regions"]["candidate_only"][0]["function"] == ("candidate_only")


@pytest.mark.parametrize(
    ("metric", "location"),
    [
        pytest.param("function", "lib/example.c", id="function"),
        pytest.param("ordinary region", "lib/example.c:1:1-1:10", id="region"),
    ],
)
@pytest.mark.parametrize(
    ("count", "error"),
    [
        pytest.param(
            9223372036854775807,
            "saturated or out-of-range",
            id="int64-max-saturation",
        ),
        pytest.param(
            9223372036854775808,
            "saturated or out-of-range",
            id="above-int64-max",
        ),
        pytest.param(-1, "negative", id="negative"),
        pytest.param(1.5, "non-integer", id="float"),
        pytest.param(True, "non-integer", id="boolean"),
    ],
)
def test_source_coverage_rejects_invalid_counts(
    tmp_path: Path,
    metric: str,
    location: str,
    count: object,
    error: str,
) -> None:
    source_root = tmp_path / "curl"
    (source_root / "lib").mkdir(parents=True)
    document = _coverage_document(source_root, (1, 1, 1))
    function = document["data"][0]["functions"][0]
    if metric == "function":
        function["count"] = count
    else:
        function["regions"][0][4] = count

    with pytest.raises(
        compare_fuzzers.MeasurementError,
        match=rf"{error} {metric} count.*'common'.*{location}",
    ):
        compare_fuzzers.parse_source_coverage_export(document, source_root)


def test_source_coverage_accepts_largest_nonsaturated_counts(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "curl"
    (source_root / "lib").mkdir(parents=True)
    largest_count = 9223372036854775806
    document = _coverage_document(
        source_root, (largest_count, largest_count, largest_count)
    )

    coverage = compare_fuzzers.parse_source_coverage_export(document, source_root)

    assert coverage.covered_functions == coverage.functions
    assert coverage.covered_regions == coverage.regions


def test_cli_uses_a_fresh_corpus_for_every_run(tmp_path: Path) -> None:
    binary_dir = tmp_path / "bin"
    corpus_dir = tmp_path / "corpora" / "dummy_fuzzer"
    binary_dir.mkdir()
    corpus_dir.mkdir(parents=True)
    _write_dummy_fuzzer(binary_dir / "dummy_fuzzer")
    (corpus_dir / "seed").write_text("abc", encoding="utf-8")
    output = binary_dir / "measurements" / "result.json"

    result = _run_cli(
        [
            "--baseline-dir",
            str(binary_dir),
            "--candidate-dir",
            str(binary_dir),
            "--target",
            "dummy_fuzzer",
            "--corpus-root",
            str(tmp_path / "corpora"),
            "--seconds",
            "1",
            "--repeats",
            "2",
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == 4
    assert [run["corpus_before"]["count"] for run in document["runs"]] == [
        1,
        1,
        1,
        1,
    ]
    assert [run["seed"] for run in document["runs"]] == [101, 101, 102, 102]
    assert document["summary"][0]["median_exec_per_second"] == 50
    assert document["comparison"][0]["exec_per_second_percent"] == 0
    assert document["comparison"][0]["libfuzzer_counters_comparable"] is False
    assert document["comparison"][0]["initial_cov_delta"] is None
    assert document["comparison"][0]["final_ft_delta"] is None
    assert document["config"]["compare_libfuzzer_counters"] is False
    assert document["corpora"]["dummy_fuzzer"]["count"] == 1


def test_cli_compares_libfuzzer_counters_only_when_explicitly_enabled(
    tmp_path: Path,
) -> None:
    binary_dir = tmp_path / "bin"
    corpus_dir = tmp_path / "corpora" / "dummy_fuzzer"
    binary_dir.mkdir()
    corpus_dir.mkdir(parents=True)
    _write_dummy_fuzzer(binary_dir / "dummy_fuzzer")
    (corpus_dir / "seed").write_text("abc", encoding="utf-8")
    output = tmp_path / "result.json"

    result = _run_cli(
        [
            "--baseline-dir",
            str(binary_dir),
            "--candidate-dir",
            str(binary_dir),
            "--target",
            "dummy_fuzzer",
            "--corpus-root",
            str(tmp_path / "corpora"),
            "--seconds",
            "1",
            "--repeats",
            "1",
            "--compare-libfuzzer-counters",
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    comparison = document["comparison"][0]
    assert comparison["libfuzzer_counters_comparable"] is True
    assert comparison["initial_cov_delta"] == 0
    assert comparison["final_ft_delta"] == 0
    assert document["config"]["compare_libfuzzer_counters"] is True


def test_specialized_lanes_are_default_benchmark_targets() -> None:
    assert {
        "curl_fuzzer_proto_http_deep",
        "curl_fuzzer_proto_http2",
        "curl_fuzzer_proto_https_h2",
        "curl_fuzzer_proto_https_gnutls",
        "curl_fuzzer_proto_https_mbedtls",
        "curl_fuzzer_proto_http3",
        "curl_fuzzer_proto_h2_proxy",
        "curl_fuzzer_proto_socks4",
        "curl_fuzzer_proto_resolver",
        "curl_fuzzer_proto_telnet",
    }.issubset(compare_fuzzers.DEFAULT_TARGETS)


def test_ftp_and_tftp_lanes_are_default_benchmark_targets() -> None:
    assert "curl_fuzzer_proto_ftp" in compare_fuzzers.DEFAULT_TARGETS
    assert "curl_fuzzer_proto_tftp" in compare_fuzzers.DEFAULT_TARGETS


def test_cli_compares_native_corpora_and_source_coverage_for_target_pair(
    tmp_path: Path,
) -> None:
    baseline_bin = tmp_path / "speed-baseline"
    candidate_bin = tmp_path / "speed-candidate"
    coverage_baseline = tmp_path / "coverage-baseline"
    coverage_candidate = tmp_path / "coverage-candidate"
    for directory in (
        baseline_bin,
        candidate_bin,
        coverage_baseline,
        coverage_candidate,
    ):
        directory.mkdir()
    _write_dummy_fuzzer(baseline_bin / "legacy_http")
    _write_dummy_fuzzer(candidate_bin / "proto_http")
    _write_coverage_fuzzer(coverage_baseline / "legacy_http")
    _write_coverage_fuzzer(coverage_candidate / "proto_http")

    corpus_root = tmp_path / "corpora"
    (corpus_root / "legacy_http").mkdir(parents=True)
    (corpus_root / "proto_http").mkdir()
    (corpus_root / "legacy_http" / "tlv").write_bytes(b"legacy TLV")
    (corpus_root / "proto_http" / "scenario").write_bytes(b"protobuf")

    baseline_source = tmp_path / "curl-baseline"
    candidate_source = tmp_path / "curl-candidate"
    for source_root in (baseline_source, candidate_source):
        (source_root / "lib").mkdir(parents=True)
        (source_root / "src").mkdir()
        (source_root / "lib" / "example.c").write_text(
            "void example(void) {}\n", encoding="utf-8"
        )
    llvm_profdata, llvm_cov = _write_fake_llvm_tools(
        tmp_path,
        _coverage_document(baseline_source, (1, 1, 0)),
        _coverage_document(candidate_source, (1, 0, 1)),
    )
    output = tmp_path / "paired.json"

    result = _run_cli(
        [
            "--baseline-dir",
            str(baseline_bin),
            "--candidate-dir",
            str(candidate_bin),
            "--target-pair",
            "legacy_http=proto_http",
            "--corpus-root",
            str(corpus_root),
            "--seconds",
            "1",
            "--repeats",
            "1",
            "--coverage-baseline-dir",
            str(coverage_baseline),
            "--coverage-candidate-dir",
            str(coverage_candidate),
            "--baseline-curl-source-dir",
            str(baseline_source),
            "--candidate-curl-source-dir",
            str(candidate_source),
            "--llvm-profdata",
            str(llvm_profdata),
            "--llvm-cov",
            str(llvm_cov),
            "--compare-libfuzzer-counters",
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    label = "legacy_http=>proto_http"
    assert document["config"]["target_pairs"] == [
        {
            "label": label,
            "baseline": "legacy_http",
            "candidate": "proto_http",
            "shared_corpus": False,
        }
    ]
    assert [run["binary_target"] for run in document["runs"]] == [
        "legacy_http",
        "proto_http",
    ]
    comparison = document["comparison"][0]
    assert comparison["libfuzzer_counters_comparable"] is False
    assert comparison["initial_cov_delta"] is None
    assert comparison["final_ft_delta"] is None
    assert document["config"]["compare_libfuzzer_counters"] is True
    assert document["corpora"][label]["baseline"]["bytes"] == len(b"legacy TLV")
    assert document["corpora"][label]["candidate"]["bytes"] == len(b"protobuf")
    source_comparison = document["source_coverage"]["comparison"]["targets"][label]
    assert source_comparison["functions"]["baseline_only_count"] == 1
    assert source_comparison["regions"]["candidate_only_count"] == 1
    assert (
        document["source_coverage"]["variants"]["candidate"]["targets"][label][
            "binary_target"
        ]
        == "proto_http"
    )


def test_cli_preserves_log_and_fails_on_fuzzer_error(tmp_path: Path) -> None:
    binary_dir = tmp_path / "bin"
    corpus_dir = tmp_path / "corpora" / "dummy_fuzzer"
    binary_dir.mkdir()
    corpus_dir.mkdir(parents=True)
    _write_dummy_fuzzer(binary_dir / "dummy_fuzzer", exit_status=77)
    (corpus_dir / "seed").write_text("abc", encoding="utf-8")
    output = tmp_path / "result.json"

    result = _run_cli(
        [
            "--baseline-dir",
            str(binary_dir),
            "--target",
            "dummy_fuzzer",
            "--corpus-root",
            str(tmp_path / "corpora"),
            "--seconds",
            "1",
            "--repeats",
            "1",
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 1
    document = json.loads(output.read_text(encoding="utf-8"))
    run = document["runs"][0]
    assert run["status"] == "failed"
    assert run["returncode"] == 77
    assert "status 77" in run["failure"]
    assert Path(run["log"]).is_file()


def test_source_only_cli_uses_coverage_seed_archives_and_retains_evidence(
    tmp_path: Path,
) -> None:
    coverage_baseline = tmp_path / "coverage-baseline"
    coverage_candidate = tmp_path / "coverage-candidate"
    coverage_baseline.mkdir()
    coverage_candidate.mkdir()
    baseline_log = tmp_path / "baseline-invocations"
    candidate_log = tmp_path / "candidate-invocations"
    _write_coverage_fuzzer(
        coverage_baseline / "legacy_http",
        expected_timeout=7,
        invocation_log=baseline_log,
    )
    _write_coverage_fuzzer(
        coverage_candidate / "proto_http",
        expected_timeout=7,
        invocation_log=candidate_log,
    )
    _write_seed_archive(coverage_baseline, "legacy_http", b"legacy TLV")
    _write_seed_archive(coverage_candidate, "proto_http", b"protobuf")
    baseline_source, candidate_source = _write_matching_source_trees(tmp_path)
    llvm_profdata, llvm_cov = _write_fake_llvm_tools(
        tmp_path,
        _coverage_document(baseline_source, (1, 1, 0)),
        _coverage_document(candidate_source, (1, 0, 1)),
    )
    output = tmp_path / "source-only.json"
    log_root = tmp_path / "retained-logs"

    result = _run_cli(
        [
            "--source-only",
            "--target-pair",
            "legacy_http=proto_http",
            "--coverage-baseline-dir",
            str(coverage_baseline),
            "--coverage-candidate-dir",
            str(coverage_candidate),
            "--baseline-curl-source-dir",
            str(baseline_source),
            "--candidate-curl-source-dir",
            str(candidate_source),
            "--corpus-root",
            str(tmp_path / "no-checked-in-corpora"),
            "--coverage-input-timeout",
            "7",
            "--llvm-profdata",
            str(llvm_profdata),
            "--llvm-cov",
            str(llvm_cov),
            "--output",
            str(output),
            "--log-dir",
            str(log_root),
        ],
        {
            "LLVM_PROFILE_FILE": str(tmp_path / "ambient.profraw"),
            "FUZZ_REPLAY_STATUS_FILE": str(tmp_path / "ambient-status.json"),
            "FUZZ_TIMEOUT_SECS": "999",
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=0",
            "LSAN_OPTIONS": "exitcode=0",
        },
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == 4
    assert document["measurement_scope"] == "source-only"
    assert document["config"]["source_only"] is True
    assert document["config"]["coverage_input_timeout"] == 7
    assert document["config"]["coverage_replay_sanitizer_environment"] == {
        "ASAN_OPTIONS": "detect_leaks=0",
        "LSAN_OPTIONS": None,
    }
    assert document["binaries"] == {}
    assert document["runs"] == []
    assert document["summary"] == []
    assert document["comparison"] == []
    assert "variant" not in result.stdout.splitlines()[-1]
    assert baseline_log.read_text(encoding="utf-8") == "run\n"
    assert candidate_log.read_text(encoding="utf-8") == "run\n"
    source_coverage = document["source_coverage"]
    assert source_coverage["replay_totals"] == {
        "unique_measurements": 2,
        "expected_inputs": 2,
        "attempted": 2,
        "completed": 2,
    }
    for variant in ("baseline", "candidate"):
        measurement = next(
            iter(source_coverage["variants"][variant]["measurements"].values())
        )
        assert measurement["input_timeout_seconds"] == 7
        for name in ("binary", "corpus", "replay_status", "profile", "export"):
            artifact = measurement[name]
            assert artifact["bytes"] > 0
            assert len(artifact["sha256"]) == 64
            assert Path(artifact["path"]).is_file()
        assert (
            measurement["corpus"]["sha256"] != measurement["corpus"]["content_sha256"]
        )
        assert measurement["replay_log"]["bytes"] == 0
        assert len(measurement["replay_log"]["sha256"]) == 64
        assert Path(measurement["replay_log"]["path"]).is_file()
        assert len(measurement["raw_profiles"]) == 1
        raw_profile = measurement["raw_profiles"][0]
        assert raw_profile["bytes"] > 0
        assert len(raw_profile["sha256"]) == 64
        assert Path(raw_profile["path"]).is_file()
    assert (
        str(coverage_baseline)
        in document["corpora"]["legacy_http=>proto_http"]["baseline"]["sources"][0]
    )
    assert not (tmp_path / "ambient.profraw").exists()
    assert not (tmp_path / "ambient-status.json").exists()


def test_source_coverage_executes_each_variant_target_once_across_pairs(
    tmp_path: Path,
) -> None:
    coverage_baseline = tmp_path / "coverage-baseline"
    coverage_candidate = tmp_path / "coverage-candidate"
    coverage_baseline.mkdir()
    coverage_candidate.mkdir()
    invocation_logs = {
        "legacy_one": tmp_path / "legacy-one-runs",
        "legacy_two": tmp_path / "legacy-two-runs",
        "proto": tmp_path / "proto-runs",
    }
    for target in ("legacy_one", "legacy_two"):
        _write_coverage_fuzzer(
            coverage_baseline / target,
            invocation_log=invocation_logs[target],
        )
        _write_seed_archive(coverage_baseline, target, target.encode())
    _write_coverage_fuzzer(
        coverage_candidate / "proto", invocation_log=invocation_logs["proto"]
    )
    _write_seed_archive(coverage_candidate, "proto", b"proto")
    baseline_source, candidate_source = _write_matching_source_trees(tmp_path)
    llvm_profdata, llvm_cov = _write_fake_llvm_tools(
        tmp_path,
        _coverage_document(baseline_source, (1, 1, 0)),
        _coverage_document(candidate_source, (1, 0, 1)),
    )
    output = tmp_path / "deduplicated.json"

    result = _run_cli(
        [
            "--source-only",
            "--target-pair",
            "legacy_one=proto",
            "--target-pair",
            "legacy_two=proto",
            "--coverage-baseline-dir",
            str(coverage_baseline),
            "--coverage-candidate-dir",
            str(coverage_candidate),
            "--baseline-curl-source-dir",
            str(baseline_source),
            "--candidate-curl-source-dir",
            str(candidate_source),
            "--corpus-root",
            str(tmp_path / "no-corpora"),
            "--llvm-profdata",
            str(llvm_profdata),
            "--llvm-cov",
            str(llvm_cov),
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    source_coverage = document["source_coverage"]
    assert source_coverage["replay_totals"]["unique_measurements"] == 3
    assert invocation_logs["legacy_one"].read_text(encoding="utf-8") == "run\n"
    assert invocation_logs["legacy_two"].read_text(encoding="utf-8") == "run\n"
    assert invocation_logs["proto"].read_text(encoding="utf-8") == "run\n"
    candidate_targets = source_coverage["variants"]["candidate"]["targets"]
    assert (
        candidate_targets["legacy_one=>proto"]["measurement_id"]
        == (candidate_targets["legacy_two=>proto"]["measurement_id"])
    )


def test_source_only_same_name_pair_shares_the_baseline_snapshot(
    tmp_path: Path,
) -> None:
    coverage_baseline = tmp_path / "coverage-baseline"
    coverage_candidate = tmp_path / "coverage-candidate"
    coverage_baseline.mkdir()
    coverage_candidate.mkdir()
    _write_coverage_fuzzer(coverage_baseline / "shared")
    _write_coverage_fuzzer(coverage_candidate / "shared")
    _write_seed_archive(coverage_baseline, "shared", b"baseline seed")
    _write_seed_archive(coverage_candidate, "shared", b"different candidate seed")
    baseline_source, candidate_source = _write_matching_source_trees(tmp_path)
    llvm_profdata, llvm_cov = _write_fake_llvm_tools(
        tmp_path,
        _coverage_document(baseline_source, (1, 1, 0)),
        _coverage_document(candidate_source, (1, 0, 1)),
    )
    output = tmp_path / "shared.json"

    result = _run_cli(
        [
            "--source-only",
            "--target",
            "shared",
            "--coverage-baseline-dir",
            str(coverage_baseline),
            "--coverage-candidate-dir",
            str(coverage_candidate),
            "--baseline-curl-source-dir",
            str(baseline_source),
            "--candidate-curl-source-dir",
            str(candidate_source),
            "--corpus-root",
            str(tmp_path / "no-corpora"),
            "--llvm-profdata",
            str(llvm_profdata),
            "--llvm-cov",
            str(llvm_cov),
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    corpus = document["corpora"]["shared"]
    assert corpus["baseline"]["sha256"] == corpus["candidate"]["sha256"]
    variants = document["source_coverage"]["variants"]
    baseline_measurement = next(iter(variants["baseline"]["measurements"].values()))
    candidate_measurement = next(iter(variants["candidate"]["measurements"].values()))
    assert (
        baseline_measurement["corpus"]["path"]
        == candidate_measurement["corpus"]["path"]
    )
    assert str(coverage_baseline) in corpus["candidate"]["sources"][0]


@pytest.mark.parametrize(
    "failure_mode",
    ["missing_status", "empty_raw_profile", "empty_merged_profile", "empty_export"],
)
def test_source_only_incomplete_evidence_is_a_controlled_exit_two(
    tmp_path: Path, failure_mode: str
) -> None:
    coverage_baseline = tmp_path / "coverage-baseline"
    coverage_candidate = tmp_path / "coverage-candidate"
    coverage_baseline.mkdir()
    coverage_candidate.mkdir()
    _write_coverage_fuzzer(
        coverage_baseline / "legacy",
        profile_contents=b"" if failure_mode == "empty_raw_profile" else b"raw",
        write_status=failure_mode != "missing_status",
    )
    _write_coverage_fuzzer(coverage_candidate / "proto")
    _write_seed_archive(coverage_baseline, "legacy", b"legacy")
    _write_seed_archive(coverage_candidate, "proto", b"proto")
    baseline_source, candidate_source = _write_matching_source_trees(tmp_path)
    llvm_profdata, llvm_cov = _write_fake_llvm_tools(
        tmp_path,
        _coverage_document(baseline_source, (1, 1, 0)),
        _coverage_document(candidate_source, (1, 0, 1)),
        merged_profile_contents=(
            b"" if failure_mode == "empty_merged_profile" else b"merged"
        ),
        empty_export=failure_mode == "empty_export",
    )
    output = tmp_path / "stale-result.json"
    output.write_text('{"status":"passed"}\n', encoding="utf-8")

    result = _run_cli(
        [
            "--source-only",
            "--target-pair",
            "legacy=proto",
            "--coverage-baseline-dir",
            str(coverage_baseline),
            "--coverage-candidate-dir",
            str(coverage_candidate),
            "--baseline-curl-source-dir",
            str(baseline_source),
            "--candidate-curl-source-dir",
            str(candidate_source),
            "--corpus-root",
            str(tmp_path / "no-corpora"),
            "--llvm-profdata",
            str(llvm_profdata),
            "--llvm-cov",
            str(llvm_cov),
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_read_replay_status_accepts_only_exact_complete_counters(
    tmp_path: Path,
) -> None:
    status = tmp_path / "status.json"
    status.write_text(
        json.dumps(
            {
                "attempted": 2,
                "completed": 2,
                "timed_out": 0,
                "input_errors": 0,
                "path_errors": 0,
            }
        ),
        encoding="utf-8",
    )

    assert compare_fuzzers._read_replay_status(status, 2) == {
        "attempted": 2,
        "completed": 2,
        "timed_out": 0,
        "input_errors": 0,
        "path_errors": 0,
    }


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "{}",
        '{"attempted":2,"completed":2,"timed_out":0,"input_errors":0}',
        (
            '{"attempted":2,"completed":2,"timed_out":0,'
            '"input_errors":0,"path_errors":0,"extra":0}'
        ),
        (
            '{"attempted":true,"completed":2,"timed_out":0,'
            '"input_errors":0,"path_errors":0}'
        ),
        (
            '{"attempted":-1,"completed":2,"timed_out":0,'
            '"input_errors":0,"path_errors":0}'
        ),
        (
            '{"attempted":1,"completed":1,"timed_out":0,'
            '"input_errors":0,"path_errors":0}'
        ),
        (
            '{"attempted":2,"completed":2,"timed_out":1,'
            '"input_errors":0,"path_errors":0}'
        ),
        (
            '{"attempted":2,"attempted":2,"completed":2,"timed_out":0,'
            '"input_errors":0,"path_errors":0}'
        ),
    ],
)
def test_read_replay_status_rejects_incomplete_or_ambiguous_evidence(
    tmp_path: Path, payload: str
) -> None:
    status = tmp_path / "status.json"
    status.write_text(payload, encoding="utf-8")

    with pytest.raises(compare_fuzzers.MeasurementError):
        compare_fuzzers._read_replay_status(status, 2)


def test_read_replay_status_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(compare_fuzzers.MeasurementError, match="could not read"):
        compare_fuzzers._read_replay_status(tmp_path / "missing.json", 1)


def test_artifact_metadata_allows_only_empty_logs(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"")

    with pytest.raises(compare_fuzzers.MeasurementError, match="is empty"):
        compare_fuzzers._artifact_metadata(artifact, "profile")
    metadata = compare_fuzzers._artifact_metadata(
        artifact, "log", require_nonempty=False
    )
    assert metadata["bytes"] == 0
    assert len(metadata["sha256"]) == 64


def test_coverage_cleanup_rejects_symlinked_target_directory(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    variant_root = artifact_root / "baseline"
    variant_root.mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep.profraw"
    sentinel.write_text("keep", encoding="utf-8")
    (variant_root / "target-id").symlink_to(external, target_is_directory=True)

    with pytest.raises(compare_fuzzers.MeasurementError, match="must not be a symlink"):
        compare_fuzzers._coverage_target_root(artifact_root, "baseline", "target-id")

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_coverage_cleanup_rejects_symlinked_artifact_root(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep.profraw"
    sentinel.write_text("keep", encoding="utf-8")
    artifact_root = tmp_path / "artifacts"
    artifact_root.symlink_to(external, target_is_directory=True)

    with pytest.raises(compare_fuzzers.MeasurementError, match="root must not"):
        compare_fuzzers._coverage_target_root(artifact_root, "baseline", "target-id")

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_source_coverage_setup_rejects_symlinked_artifact_root(
    tmp_path: Path,
) -> None:
    log_root = tmp_path / "logs"
    log_root.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep"
    sentinel.write_text("keep", encoding="utf-8")
    (log_root / "source-coverage").symlink_to(external, target_is_directory=True)

    with pytest.raises(compare_fuzzers.MeasurementError, match="root must not"):
        compare_fuzzers._source_coverage_artifact_roots(log_root)

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_source_coverage_setup_rejects_symlinked_corpus_root(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "logs" / "source-coverage"
    source_root.mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep"
    sentinel.write_text("keep", encoding="utf-8")
    (source_root / "corpora").symlink_to(external, target_is_directory=True)

    with pytest.raises(compare_fuzzers.MeasurementError, match="corpus directory"):
        compare_fuzzers._source_coverage_artifact_roots(tmp_path / "logs")

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_coverage_cleanup_unlinks_replay_log_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    target_root = compare_fuzzers._coverage_target_root(
        tmp_path / "artifacts", "baseline", "target-id"
    )
    sentinel = tmp_path / "external.log"
    sentinel.write_text("keep", encoding="utf-8")
    replay_log = target_root / "replay.log"
    replay_log.symlink_to(sentinel)

    compare_fuzzers._clear_coverage_artifacts(target_root)

    assert not replay_log.exists()
    assert not replay_log.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cli_rejects_symlinked_output_without_unlinking_target(tmp_path: Path) -> None:
    sentinel = tmp_path / "external.json"
    sentinel.write_text("keep", encoding="utf-8")
    output = tmp_path / "result.json"
    output.symlink_to(sentinel)

    result = _run_cli(
        [
            "--baseline-dir",
            str(tmp_path / "missing-bin"),
            "--target",
            "missing",
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 2
    assert "output must not be a symlink" in result.stderr
    assert output.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cli_removes_stale_result_before_measurement_setup_failure(
    tmp_path: Path,
) -> None:
    output = tmp_path / "stale.json"
    output.write_text('{"status":"passed"}\n', encoding="utf-8")

    result = _run_cli(
        [
            "--baseline-dir",
            str(tmp_path / "missing-bin"),
            "--target",
            "missing",
            "--output",
            str(output),
        ]
    )

    assert result.returncode == 2
    assert not output.exists()


def test_cli_removes_stale_result_before_configuration_failure(
    tmp_path: Path,
) -> None:
    output = tmp_path / "stale.json"
    output.write_text('{"status":"passed"}\n', encoding="utf-8")

    result = _run_cli(["--source-only", "--output", str(output)])

    assert result.returncode == 2
    assert not output.exists()


def test_cli_rejects_partial_source_coverage_configuration(tmp_path: Path) -> None:
    result = _run_cli(
        [
            "--baseline-dir",
            str(tmp_path / "baseline"),
            "--candidate-dir",
            str(tmp_path / "candidate"),
            "--coverage-baseline-dir",
            str(tmp_path / "coverage-baseline"),
        ]
    )

    assert result.returncode == 2
    assert "requires both --coverage-baseline-dir" in result.stderr


def test_cli_rejects_counter_comparison_without_candidate(tmp_path: Path) -> None:
    result = _run_cli(
        [
            "--baseline-dir",
            str(tmp_path / "baseline"),
            "--compare-libfuzzer-counters",
        ]
    )

    assert result.returncode == 2
    assert "requires --candidate-dir" in result.stderr


def test_generic_and_parity_coverage_replay_defaults_are_distinct() -> None:
    generic = compare_fuzzers._parse_args([])
    compare_fuzzers._resolve_coverage_replay_settings(generic, None)

    assert generic.coverage_input_timeout == 25
    assert generic.coverage_wall_timeout == 300

    parity = compare_fuzzers._parse_args([])
    manifest = _test_parity_manifest()
    compare_fuzzers._resolve_coverage_replay_settings(parity, manifest)

    assert parity.coverage_input_timeout == 10
    assert parity.coverage_wall_timeout == 7200


def test_parity_coverage_replay_settings_allow_only_matching_input_timeout() -> None:
    manifest = _test_parity_manifest()
    matching = compare_fuzzers._parse_args(
        ["--coverage-input-timeout", "10", "--coverage-wall-timeout", "900"]
    )

    compare_fuzzers._resolve_coverage_replay_settings(matching, manifest)

    assert matching.coverage_input_timeout == 10
    assert matching.coverage_wall_timeout == 900

    mismatched = compare_fuzzers._parse_args(["--coverage-input-timeout", "11"])
    with pytest.raises(compare_fuzzers.MeasurementError, match="expected 10"):
        compare_fuzzers._resolve_coverage_replay_settings(mismatched, manifest)


def test_parity_coverage_replay_settings_reject_sanitizer_policy_drift(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    manifest = _test_parity_manifest()
    args = compare_fuzzers._parse_args([])
    monkeypatch.setattr(
        compare_fuzzers,
        "COVERAGE_REPLAY_SANITIZER_ENVIRONMENT",
        {"ASAN_OPTIONS": "detect_leaks=1", "LSAN_OPTIONS": None},
    )

    with pytest.raises(compare_fuzzers.MeasurementError, match="sanitizer environment"):
        compare_fuzzers._resolve_coverage_replay_settings(args, manifest)


def test_parity_socket_preflight_exchanges_complete_payload() -> None:
    sender = MagicMock()
    receiver = MagicMock()
    sender.__enter__.return_value = sender
    receiver.__enter__.return_value = receiver
    receiver.recv.side_effect = [b"curl-fuzzer-", b"parity-preflight"]
    socketpair_factory = MagicMock(return_value=(sender, receiver))

    compare_fuzzers._validate_parity_socket_capability(socketpair_factory)

    socketpair_factory.assert_called_once_with(
        compare_fuzzers.socket.AF_UNIX,
        compare_fuzzers.socket.SOCK_STREAM,
    )
    sender.sendall.assert_called_once_with(b"curl-fuzzer-parity-preflight")
    assert receiver.recv.call_count == 2


def test_parity_socket_preflight_reports_denied_local_io() -> None:
    def denied_socketpair(_family: int, _kind: int):  # type: ignore[no-untyped-def]
        raise PermissionError(1, "Operation not permitted")

    with pytest.raises(
        compare_fuzzers.MeasurementError,
        match=(
            "requires local AF_UNIX socket send/receive capability.*"
            "permits local socket I/O"
        ),
    ):
        compare_fuzzers._validate_parity_socket_capability(denied_socketpair)


def test_parity_socket_preflight_rejects_truncated_exchange() -> None:
    sender = MagicMock()
    receiver = MagicMock()
    sender.__enter__.return_value = sender
    receiver.__enter__.return_value = receiver
    receiver.recv.side_effect = [b"truncated", b""]

    with pytest.raises(
        compare_fuzzers.MeasurementError,
        match="preflight returned 9 of 28 bytes",
    ):
        compare_fuzzers._validate_parity_socket_capability(
            lambda _family, _kind: (sender, receiver)
        )


@pytest.mark.parametrize(
    "selection",
    [
        ["--target", "../escape"],
        ["--target-pair", "legacy=../escape"],
    ],
)
def test_cli_rejects_target_path_traversal_without_touching_sentinel(
    tmp_path: Path, selection: list[str]
) -> None:
    sentinel = tmp_path / "escape.profraw"
    sentinel.write_text("keep", encoding="utf-8")

    result = _run_cli(
        [
            "--baseline-dir",
            str(tmp_path / "bin"),
            "--candidate-dir",
            str(tmp_path / "candidate-bin"),
            *selection,
            "--log-dir",
            str(tmp_path / "logs"),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result.returncode == 2
    assert "invalid target name" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_binary_must_resolve_to_a_direct_build_directory_child(
    tmp_path: Path,
) -> None:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("binary", encoding="utf-8")
    (binary_dir / "target").symlink_to(outside)

    with pytest.raises(compare_fuzzers.MeasurementError, match="direct child"):
        compare_fuzzers._binary_path(binary_dir, "target")


def test_cli_requires_trusted_previous_manifest_for_every_parity_run(
    tmp_path: Path,
) -> None:
    coverage = tmp_path / "coverage"
    result = _run_cli(
        [
            "--source-only",
            "--coverage-baseline-dir",
            str(coverage),
            "--coverage-candidate-dir",
            str(coverage),
            "--parity-manifest",
            str(tmp_path / "external-manifest.json"),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result.returncode == 2
    assert "requires a trusted --previous-parity-manifest" in result.stderr


def test_cli_parity_requires_one_shared_coverage_build(tmp_path: Path) -> None:
    manifest = tmp_path / "external-manifest.json"
    result = _run_cli(
        [
            "--source-only",
            "--coverage-baseline-dir",
            str(tmp_path / "baseline"),
            "--coverage-candidate-dir",
            str(tmp_path / "candidate"),
            "--parity-manifest",
            str(manifest),
            "--previous-parity-manifest",
            str(manifest),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result.returncode == 2
    assert "same build directory" in result.stderr


def test_cli_parity_rejects_input_timeout_that_differs_from_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "external-manifest.json"
    coverage = tmp_path / "coverage"
    monkeypatch.setattr(
        compare_fuzzers,
        "load_parity_manifest",
        lambda _path: _test_parity_manifest(),
    )

    result = compare_fuzzers.main(
        [
            "--source-only",
            "--coverage-baseline-dir",
            str(coverage),
            "--coverage-candidate-dir",
            str(coverage),
            "--coverage-input-timeout",
            "11",
            "--parity-manifest",
            str(manifest),
            "--previous-parity-manifest",
            str(manifest),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result == 2
    assert "does not match the parity manifest: expected 10" in capsys.readouterr().err
    assert not (tmp_path / "result.json").exists()


def test_cli_never_unlinks_a_manifest_used_as_its_output(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"important":true}\n', encoding="utf-8")
    coverage = tmp_path / "coverage"

    result = _run_cli(
        [
            "--source-only",
            "--coverage-baseline-dir",
            str(coverage),
            "--coverage-candidate-dir",
            str(coverage),
            "--parity-manifest",
            str(manifest),
            "--previous-parity-manifest",
            str(manifest),
            "--output",
            str(manifest),
        ]
    )

    assert result.returncode == 2
    assert "must not overwrite" in result.stderr
    assert manifest.read_text(encoding="utf-8") == '{"important":true}\n'


def test_cli_never_unlinks_a_direct_build_directory_child(tmp_path: Path) -> None:
    build = tmp_path / "build"
    build.mkdir()
    sentinel = build / "result.json"
    sentinel.write_text("keep", encoding="utf-8")

    result = _run_cli(
        [
            "--baseline-dir",
            str(build),
            "--target",
            "dummy",
            "--output",
            str(sentinel),
        ]
    )

    assert result.returncode == 2
    assert "direct child of a build directory" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("directory_input", [False, True])
def test_cli_never_unlinks_a_corpus_input(
    tmp_path: Path, directory_input: bool
) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    sentinel = corpus_root / "seed"
    sentinel.write_text("keep", encoding="utf-8")
    corpus_arguments = (
        ["--corpus-root", str(corpus_root)]
        if directory_input
        else ["--corpus", f"dummy={sentinel}"]
    )

    result = _run_cli(
        [
            "--baseline-dir",
            str(tmp_path / "bin"),
            "--target",
            "dummy",
            *corpus_arguments,
            "--output",
            str(sentinel),
        ]
    )

    assert result.returncode == 2
    assert "--output must not" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cli_never_uses_corpus_root_as_log_directory(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    sentinel = corpus_root / "source-coverage" / "baseline" / "dummy" / "replay.log"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep", encoding="utf-8")
    coverage = tmp_path / "coverage"

    result = _run_cli(
        [
            "--source-only",
            "--target",
            "dummy",
            "--coverage-baseline-dir",
            str(coverage),
            "--coverage-candidate-dir",
            str(coverage),
            "--corpus-root",
            str(corpus_root),
            "--log-dir",
            str(corpus_root),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result.returncode == 2
    assert "--log-dir and its artifact roots must not overlap" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cli_never_uses_directory_inside_build_as_log_directory(
    tmp_path: Path,
) -> None:
    coverage = tmp_path / "coverage"
    log_root = coverage / "retained"
    sentinel = log_root / "source-coverage" / "baseline" / "dummy" / "replay.log"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep", encoding="utf-8")
    corpus = tmp_path / "seed"
    corpus.write_text("input", encoding="utf-8")

    result = _run_cli(
        [
            "--source-only",
            "--target",
            "dummy",
            "--coverage-baseline-dir",
            str(coverage),
            "--coverage-candidate-dir",
            str(coverage),
            "--corpus",
            f"dummy={corpus}",
            "--log-dir",
            str(log_root),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result.returncode == 2
    assert "--log-dir and its artifact roots must not overlap" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cli_never_uses_artifact_tree_containing_corpus_file(
    tmp_path: Path,
) -> None:
    log_root = tmp_path / "retained"
    sentinel = log_root / "source-coverage" / "baseline" / "dummy" / "replay.log"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep", encoding="utf-8")
    coverage = tmp_path / "coverage"

    result = _run_cli(
        [
            "--source-only",
            "--target",
            "dummy",
            "--coverage-baseline-dir",
            str(coverage),
            "--coverage-candidate-dir",
            str(coverage),
            "--corpus",
            f"dummy={sentinel}",
            "--log-dir",
            str(log_root),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result.returncode == 2
    assert "--log-dir and its artifact roots must not overlap" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cli_rejects_symlinked_log_directory_before_cleanup(tmp_path: Path) -> None:
    external = tmp_path / "external"
    sentinel = external / "source-coverage" / "baseline" / "dummy" / "replay.log"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep", encoding="utf-8")
    log_root = tmp_path / "logs"
    log_root.symlink_to(external, target_is_directory=True)
    coverage = tmp_path / "coverage"
    corpus = tmp_path / "seed"
    corpus.write_text("input", encoding="utf-8")

    result = _run_cli(
        [
            "--source-only",
            "--target",
            "dummy",
            "--coverage-baseline-dir",
            str(coverage),
            "--coverage-candidate-dir",
            str(coverage),
            "--corpus",
            f"dummy={corpus}",
            "--log-dir",
            str(log_root),
            "--output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result.returncode == 2
    assert "log directory must not be a symlink" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("invalid_input", ["manifest", "inventory"])
def test_cli_clears_stale_result_before_manifest_or_inventory_validation(
    tmp_path: Path,
    invalid_input: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "external-manifest.json"
    inventory = REPO_ROOT / "scripts" / "fuzz_targets"
    if invalid_input == "manifest":
        manifest = tmp_path / "bad-manifest.json"
        manifest.write_text("not json", encoding="utf-8")
    else:
        inventory = tmp_path / "bad-inventory"
        inventory.write_text(
            'FUZZ_TARGETS_LIST+=" curl_fuzzer_new"\n', encoding="utf-8"
        )
        monkeypatch.setattr(
            compare_fuzzers,
            "load_parity_manifest",
            lambda _path: _test_parity_manifest(),
        )

        def reject_inventory(
            _manifest: compare_fuzzers.ParityManifest, _path: Path
        ) -> None:
            raise compare_fuzzers.CoverageParityError("invalid test inventory")

        monkeypatch.setattr(
            compare_fuzzers, "validate_live_inventory", reject_inventory
        )
    output = tmp_path / "stale.json"
    output.write_text('{"status":"passed"}\n', encoding="utf-8")
    coverage = tmp_path / "coverage"

    arguments = [
        "--source-only",
        "--coverage-baseline-dir",
        str(coverage),
        "--coverage-candidate-dir",
        str(coverage),
        "--parity-manifest",
        str(manifest),
        "--previous-parity-manifest",
        str(manifest),
        "--target-inventory",
        str(inventory),
        "--output",
        str(output),
    ]
    if invalid_input == "manifest":
        status = _run_cli(arguments).returncode
    else:
        status = compare_fuzzers.main(arguments)

    assert status == 2
    assert not output.exists()
