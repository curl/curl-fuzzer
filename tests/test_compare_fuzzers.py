"""Tests for the reproducible libFuzzer comparison helper."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "compare_fuzzers.py"


def _load_module():  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location("compare_fuzzers", SCRIPT)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


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


def _write_coverage_fuzzer(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import os
from pathlib import Path

profile = os.environ.get("LLVM_PROFILE_FILE")
if not profile:
    raise SystemExit("LLVM_PROFILE_FILE is not set")
Path(profile.replace("%p", str(os.getpid()))).write_bytes(b"raw profile")
""",
        encoding="utf-8",
    )
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
output.write_bytes(b"merged profile")
""",
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
print(baseline if "coverage-baseline" in binary else candidate)
""",
        encoding="utf-8",
    )
    llvm_cov.chmod(0o755)
    return profdata, llvm_cov


def test_parse_libfuzzer_output() -> None:
    module = _load_module()
    parsed = module.parse_libfuzzer_output(
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
    module = _load_module()
    baseline_root = tmp_path / "baseline-curl"
    candidate_root = tmp_path / "candidate-curl"
    for source_root in (baseline_root, candidate_root):
        (source_root / "lib").mkdir(parents=True)
        (source_root / "src").mkdir()
        (source_root / "lib" / "example.c").write_text(
            "void example(void) {}\n", encoding="utf-8"
        )

    baseline = module.parse_source_coverage_export(
        _coverage_document(baseline_root, (1, 1, 0)), baseline_root
    )
    candidate = module.parse_source_coverage_export(
        _coverage_document(candidate_root, (1, 0, 1)), candidate_root
    )
    comparison = module.compare_source_coverage(baseline, candidate)

    assert comparison["functions"]["baseline_retention_percent"] == 50.0
    assert comparison["functions"]["baseline_only"] == [
        {"file": "lib/example.c", "name": "baseline_only"}
    ]
    assert comparison["regions"]["candidate_only"][0]["function"] == ("candidate_only")


def test_cli_uses_a_fresh_corpus_for_every_run(tmp_path: Path) -> None:
    binary_dir = tmp_path / "bin"
    corpus_dir = tmp_path / "corpora" / "dummy_fuzzer"
    binary_dir.mkdir()
    corpus_dir.mkdir(parents=True)
    _write_dummy_fuzzer(binary_dir / "dummy_fuzzer")
    (corpus_dir / "seed").write_text("abc", encoding="utf-8")
    output = tmp_path / "result.json"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
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
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    assert [run["corpus_before"]["count"] for run in document["runs"]] == [
        1,
        1,
        1,
        1,
    ]
    assert [run["seed"] for run in document["runs"]] == [101, 101, 102, 102]
    assert document["summary"][0]["median_exec_per_second"] == 50
    assert document["comparison"][0]["exec_per_second_percent"] == 0
    assert document["corpora"]["dummy_fuzzer"]["count"] == 1


def test_proto_http_binary_uses_matching_corpus_directory(
    tmp_path: Path,
) -> None:
    module = _load_module()
    corpus_root = tmp_path / "corpora"
    proto_http = corpus_root / "curl_fuzzer_proto_http"
    proto_http.mkdir(parents=True)
    (proto_http / "seed").write_bytes(b"proto")

    sources = module._corpus_sources(
        "curl_fuzzer_proto_http",
        tmp_path / "bin",
        corpus_root,
        None,
        {},
    )

    assert sources == [proto_http]


def test_fixed_proto_lane_includes_historical_public_corpus(tmp_path: Path) -> None:
    module = _load_module()
    corpus_root = tmp_path / "corpora"
    proto_http = corpus_root / "curl_fuzzer_proto_http"
    proto_http.mkdir(parents=True)
    (proto_http / "seed").write_bytes(b"proto")

    public_root = tmp_path / "public"
    current_public = public_root / "curl_fuzzer_proto_http"
    historical_public = public_root / "curl_fuzzer_proto"
    current_public.mkdir(parents=True)
    historical_public.mkdir()
    (current_public / "current").write_bytes(b"current")
    (historical_public / "historical").write_bytes(b"historical")

    sources = module._corpus_sources(
        "curl_fuzzer_proto_http",
        tmp_path / "bin",
        corpus_root,
        public_root,
        {},
    )

    assert sources == [proto_http, current_public, historical_public]


def test_deep_http_lane_is_a_default_fixed_proto_target() -> None:
    module = _load_module()

    assert "curl_fuzzer_proto_http_deep" in module.DEFAULT_TARGETS
    assert "curl_fuzzer_proto_http_deep" in module.HISTORICAL_PROTO_CORPUS_TARGETS


def test_telnet_lane_is_a_default_fixed_proto_target() -> None:
    module = _load_module()

    assert "curl_fuzzer_proto_telnet" in module.DEFAULT_TARGETS
    assert "curl_fuzzer_proto_telnet" in module.HISTORICAL_PROTO_CORPUS_TARGETS


def test_h2_proxy_lane_uses_only_its_frame_aware_corpus() -> None:
    module = _load_module()

    assert "curl_fuzzer_proto_h2_proxy" in module.DEFAULT_TARGETS
    assert "curl_fuzzer_proto_h2_proxy" not in module.HISTORICAL_PROTO_CORPUS_TARGETS


def test_gnutls_https_lane_reuses_compatible_https_corpora(tmp_path: Path) -> None:
    module = _load_module()
    corpus_root = tmp_path / "corpora"
    https_corpus = corpus_root / "curl_fuzzer_proto_https"
    https_corpus.mkdir(parents=True)
    (https_corpus / "seed").write_bytes(b"https")

    baseline_dir = tmp_path / "bin"
    baseline_dir.mkdir()
    https_seed_archive = baseline_dir / "curl_fuzzer_proto_https_seed_corpus.zip"
    https_seed_archive.write_bytes(b"seed archive")

    public_root = tmp_path / "public"
    gnutls_public = public_root / "curl_fuzzer_proto_https_gnutls"
    https_public = public_root / "curl_fuzzer_proto_https"
    historical_public = public_root / "curl_fuzzer_proto"
    for directory in (gnutls_public, https_public, historical_public):
        directory.mkdir(parents=True)
        (directory / "input").write_bytes(directory.name.encode())

    sources = module._corpus_sources(
        "curl_fuzzer_proto_https_gnutls",
        baseline_dir,
        corpus_root,
        public_root,
        {},
    )

    assert "curl_fuzzer_proto_https_gnutls" in module.DEFAULT_TARGETS
    assert sources == [
        https_corpus,
        https_seed_archive,
        gnutls_public,
        https_public,
        historical_public,
    ]


def test_mbedtls_https_lane_reuses_compatible_https_corpora(
    tmp_path: Path,
) -> None:
    module = _load_module()
    corpus_root = tmp_path / "corpora"
    https_corpus = corpus_root / "curl_fuzzer_proto_https"
    https_corpus.mkdir(parents=True)
    (https_corpus / "seed").write_bytes(b"https")

    baseline_dir = tmp_path / "bin"
    baseline_dir.mkdir()
    https_seed_archive = baseline_dir / "curl_fuzzer_proto_https_seed_corpus.zip"
    https_seed_archive.write_bytes(b"seed archive")

    public_root = tmp_path / "public"
    mbedtls_public = public_root / "curl_fuzzer_proto_https_mbedtls"
    https_public = public_root / "curl_fuzzer_proto_https"
    historical_public = public_root / "curl_fuzzer_proto"
    for directory in (mbedtls_public, https_public, historical_public):
        directory.mkdir(parents=True)
        (directory / "input").write_bytes(directory.name.encode())

    sources = module._corpus_sources(
        "curl_fuzzer_proto_https_mbedtls",
        baseline_dir,
        corpus_root,
        public_root,
        {},
    )

    assert "curl_fuzzer_proto_https_mbedtls" in module.DEFAULT_TARGETS
    assert sources == [
        https_corpus,
        https_seed_archive,
        mbedtls_public,
        https_public,
        historical_public,
    ]


def test_ftp_and_tftp_lanes_keep_legacy_speed_baselines() -> None:
    module = _load_module()

    assert "curl_fuzzer_ftp" in module.DEFAULT_TARGETS
    assert "curl_fuzzer_proto_ftp" in module.DEFAULT_TARGETS
    assert "curl_fuzzer_tftp" in module.DEFAULT_TARGETS
    assert "curl_fuzzer_proto_tftp" in module.DEFAULT_TARGETS


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

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
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
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
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
    assert document["comparison"][0]["initial_cov_delta"] is None
    assert document["comparison"][0]["final_ft_delta"] is None
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

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
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
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    document = json.loads(output.read_text(encoding="utf-8"))
    run = document["runs"][0]
    assert run["status"] == "failed"
    assert run["returncode"] == 77
    assert "status 77" in run["failure"]
    assert Path(run["log"]).is_file()


def test_cli_rejects_partial_source_coverage_configuration(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--baseline-dir",
            str(tmp_path / "baseline"),
            "--candidate-dir",
            str(tmp_path / "candidate"),
            "--coverage-baseline-dir",
            str(tmp_path / "coverage-baseline"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "requires both --coverage-baseline-dir" in result.stderr
