"""Tests for the proto-migration function-parity development ratchet."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from curl_fuzzer_tools import coverage_parity
from curl_fuzzer_tools.coverage_parity import (
    CoverageParityError,
    CoverageUniverse,
    ParityManifest,
    evaluate_parity,
    identity_sha256,
    load_parity_manifest,
    read_target_inventory,
    validate_baseline_corpora,
    validate_live_inventory,
    validate_manifest_progression,
    validate_source_identity,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_BASELINE_ID = "test-proto-migration-v1"
BASELINE_TARGET = "curl_fuzzer_legacy"
CANDIDATE_TARGET = "curl_fuzzer_proto_example"
FUNCTION_GAP = ("lib/example.c", "legacy_only")
COMMON_FUNCTION = ("lib/example.c", "common")
REGION_GAP = ("lib/example.c", "legacy_only", 1, 1, 1, 8)
COMMON_REGION = ("lib/example.c", "common", 2, 1, 2, 8)
ARTIFACT_SHA256 = "e" * 64
AUDIT_ARTIFACTS = {
    "pairs.json",
    "expected-full-inputs.json",
    "coverage-provenance.json",
    "assembly-completeness.json",
    "full-source-comparison.json",
    "gaps.json",
    "report.md",
    "public-corpus-manifest.json",
}
AUDITED_BASELINE_INVENTORY = frozenset(
    {
        "curl_fuzzer",
        "curl_fuzzer_ftp",
        "curl_fuzzer_full_coverage",
        "curl_fuzzer_mqtt",
        "curl_fuzzer_smtp",
    }
)
AUDITED_CANDIDATE_INVENTORY = frozenset(
    {
        "curl_fuzzer_proto",
        "curl_fuzzer_proto_api",
        "curl_fuzzer_proto_dict",
        "curl_fuzzer_proto_file",
        "curl_fuzzer_proto_ftp",
        "curl_fuzzer_proto_gopher",
        "curl_fuzzer_proto_h2_proxy",
        "curl_fuzzer_proto_http",
        "curl_fuzzer_proto_http2",
        "curl_fuzzer_proto_http3",
        "curl_fuzzer_proto_http_deep",
        "curl_fuzzer_proto_https",
        "curl_fuzzer_proto_https_gnutls",
        "curl_fuzzer_proto_https_h2",
        "curl_fuzzer_proto_https_mbedtls",
        "curl_fuzzer_proto_imap",
        "curl_fuzzer_proto_ipfs",
        "curl_fuzzer_proto_ldap",
        "curl_fuzzer_proto_mqtt",
        "curl_fuzzer_proto_multi",
        "curl_fuzzer_proto_pop3",
        "curl_fuzzer_proto_resolver",
        "curl_fuzzer_proto_rtsp",
        "curl_fuzzer_proto_smtp",
        "curl_fuzzer_proto_socks4",
        "curl_fuzzer_proto_telnet",
        "curl_fuzzer_proto_tftp",
        "curl_fuzzer_proto_timing",
        "curl_fuzzer_proto_ws",
        "curl_fuzzer_proto_wss",
    }
)
AUDITED_EXCLUDED_INVENTORY = frozenset(
    {"fuzz_url", "fuzz_bufq", "fuzz_doh", "fuzz_netrc"}
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _test_manifest_document() -> dict[str, Any]:
    baseline_functions = frozenset({FUNCTION_GAP, COMMON_FUNCTION})
    baseline_regions = frozenset({REGION_GAP, COMMON_REGION})
    document: dict[str, Any] = {
        "schema_version": 1,
        "baseline_id": TEST_BASELINE_ID,
        "immutable_baseline_sha256": "0" * 64,
        "curl_source_identity": {"sha256": "a" * 64, "source_files": 1},
        "coverage_replay_policy": {
            "input_timeout_seconds": 10,
            "sanitizer_environment": {
                "ASAN_OPTIONS": "detect_leaks=0",
                "LSAN_OPTIONS": None,
            },
        },
        "gate_policy": dict(coverage_parity._EXPECTED_GATE_POLICY),
        "target_inventory": {
            "baseline": [BASELINE_TARGET],
            "candidate": [CANDIDATE_TARGET],
            "excluded_standalone": ["fuzz_url", "fuzz_bufq", "fuzz_doh", "fuzz_netrc"],
        },
        "target_pairs": [{"baseline": BASELINE_TARGET, "candidate": CANDIDATE_TARGET}],
        "baseline_corpora": {BASELINE_TARGET: {"count": 1, "sha256": "b" * 64}},
        "baseline_universe": {
            "functions": {
                "count": len(baseline_functions),
                "sha256": identity_sha256(baseline_functions),
            },
            "regions": {
                "count": len(baseline_regions),
                "sha256": identity_sha256(baseline_regions),
            },
        },
        "initial_gaps": {
            "functions": {FUNCTION_GAP[0]: [FUNCTION_GAP[1]]},
            "regions": {REGION_GAP[0]: {REGION_GAP[1]: ["1:1-1:8"]}},
        },
        "resolved_gaps": {"functions": {}, "regions": {}},
        "identity_canonicalization": {
            "encoding": "UTF-8",
            "json": {
                "ensure_ascii": False,
                "separators": [",", ":"],
                "sort_keys": True,
            },
            "functions": (
                "lexicographically sorted arrays of [curl-relative file, function name]"
            ),
            "regions": (
                "lexicographically sorted arrays of [curl-relative file, function "
                "name, start line, start column, end line, end column]; LLVM region "
                "kind 0 only"
            ),
        },
        "provenance": {
            "curl_revision": "c" * 40,
            "curl_source_path_manifest_sha256": "d" * 64,
            "audit_fuzzer_revision": "f" * 40,
            "audit_artifacts": {
                name: {"bytes": 1, "sha256": ARTIFACT_SHA256}
                for name in AUDIT_ARTIFACTS
            },
            "corpus_boundary": {
                "public_archives_attempted": 1,
                "public_archives_available": 1,
                "public_archives_inaccessible": 0,
                "note": "Synthetic unit-test audit boundary.",
            },
        },
    }
    immutable_document = {
        key: value
        for key, value in document.items()
        if key not in {"immutable_baseline_sha256", "resolved_gaps"}
    }
    document["immutable_baseline_sha256"] = _canonical_sha256(immutable_document)
    return document


def _pin_test_manifest(
    monkeypatch: pytest.MonkeyPatch, document: dict[str, Any]
) -> None:
    initial_functions = frozenset({FUNCTION_GAP})
    initial_regions = frozenset({REGION_GAP})
    monkeypatch.setitem(
        coverage_parity._PINNED_BASELINES,
        TEST_BASELINE_ID,
        {
            "immutable_baseline_sha256": document["immutable_baseline_sha256"],
            "initial_function_count": len(initial_functions),
            "initial_function_sha256": identity_sha256(initial_functions),
            "initial_region_count": len(initial_regions),
            "initial_region_sha256": identity_sha256(initial_regions),
        },
    )


def _write_test_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, Any] | None = None,
    *,
    name: str = "manifest.json",
) -> Path:
    if document is None:
        document = _test_manifest_document()
    _pin_test_manifest(monkeypatch, _test_manifest_document())
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _small_manifest() -> tuple[ParityManifest, CoverageUniverse, CoverageUniverse]:
    baseline = CoverageUniverse(
        functions=frozenset({FUNCTION_GAP, COMMON_FUNCTION}),
        regions=frozenset({REGION_GAP, COMMON_REGION}),
    )
    candidate = CoverageUniverse(
        functions=frozenset({COMMON_FUNCTION}),
        regions=frozenset({COMMON_REGION}),
    )
    gate_policy = coverage_parity._EXPECTED_GATE_POLICY
    return (
        ParityManifest(
            path=Path("external-test-manifest.json"),
            sha256="f" * 64,
            baseline_id=TEST_BASELINE_ID,
            immutable_baseline_sha256="d" * 64,
            source_identity={"sha256": "a" * 64, "source_files": 1},
            replay_input_timeout_seconds=10,
            replay_sanitizer_environment={
                "ASAN_OPTIONS": "detect_leaks=0",
                "LSAN_OPTIONS": None,
            },
            gate_scope=str(gate_policy["scope"]),
            retirement_eligible=False,
            region_status=str(gate_policy["region_status"]),
            gate_rationale=str(gate_policy["rationale"]),
            target_pairs=((BASELINE_TARGET, CANDIDATE_TARGET),),
            baseline_inventory=frozenset({BASELINE_TARGET}),
            candidate_inventory=frozenset({CANDIDATE_TARGET}),
            excluded_inventory=frozenset(
                {"fuzz_url", "fuzz_bufq", "fuzz_doh", "fuzz_netrc"}
            ),
            baseline_corpora={BASELINE_TARGET: (1, "b" * 64)},
            baseline_function_count=len(baseline.functions),
            baseline_function_sha256=identity_sha256(baseline.functions),
            baseline_region_count=len(baseline.regions),
            baseline_region_sha256=identity_sha256(baseline.regions),
            initial_functions=frozenset({FUNCTION_GAP}),
            initial_regions=frozenset({REGION_GAP}),
            resolved_functions=frozenset(),
            resolved_regions=frozenset(),
            identity_canonicalization={},
            provenance={},
        ),
        baseline,
        candidate,
    )


def _evaluate(
    manifest: ParityManifest,
    baseline: CoverageUniverse,
    candidate: CoverageUniverse,
) -> dict[str, object]:
    return evaluate_parity(
        manifest,
        source_identity={"sha256": "a" * 64, "source_files": 1},
        target_pairs=((BASELINE_TARGET, CANDIDATE_TARGET),),
        baseline_corpora={BASELINE_TARGET: {"count": 1, "sha256": "b" * 64}},
        baseline=baseline,
        candidate=candidate,
    )


def _write_changed_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section: str,
    key: str,
    value: object,
) -> Path:
    document = _test_manifest_document()
    document[section][key] = value
    return _write_test_manifest(tmp_path, monkeypatch, document, name="changed.json")


def test_external_manifest_baseline_is_exactly_code_pinned() -> None:
    assert coverage_parity._PINNED_BASELINES["proto-migration-v1"] == {
        "immutable_baseline_sha256": (
            "97f3b974700a1c2075e311b805257390f39cda9ec0063a3b271484bfe37b08f1"
        ),
        "initial_function_count": 215,
        "initial_function_sha256": (
            "da37b0ff5442655adb94150e2ae1f2f59cbde2c2d8c3ffddbd5584d79668f538"
        ),
        "initial_region_count": 6470,
        "initial_region_sha256": (
            "90765eab0b68a4d8fe40e57b2eb24c68dc872493bd83e183213dc4c9155f2bf6"
        ),
    }


def test_synthetic_external_manifest_loads_with_code_pinned_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = load_parity_manifest(_write_test_manifest(tmp_path, monkeypatch))

    assert manifest.baseline_id == TEST_BASELINE_ID
    assert manifest.replay_input_timeout_seconds == 10
    assert manifest.replay_sanitizer_environment == {
        "ASAN_OPTIONS": "detect_leaks=0",
        "LSAN_OPTIONS": None,
    }
    assert manifest.gate_scope == "development_function_parity"
    assert manifest.retirement_eligible is False
    assert manifest.region_status == "indeterminate_nondeterministic"
    assert "Regions remain diagnostic" in manifest.gate_rationale
    assert manifest.initial_functions == frozenset({FUNCTION_GAP})
    assert manifest.initial_regions == frozenset({REGION_GAP})
    assert manifest.target_pairs == ((BASELINE_TARGET, CANDIDATE_TARGET),)
    assert manifest.baseline_inventory == frozenset({BASELINE_TARGET})
    assert manifest.candidate_inventory == frozenset({CANDIDATE_TARGET})
    assert manifest.baseline_corpora == {BASELINE_TARGET: (1, "b" * 64)}


@pytest.mark.parametrize(
    "section",
    [
        "curl_source_identity",
        "coverage_replay_policy",
        "gate_policy",
        "baseline_universe",
    ],
)
def test_manifest_rejects_unexpected_nested_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, section: str
) -> None:
    path = _write_changed_manifest(tmp_path, monkeypatch, section, "unexpected", True)

    with pytest.raises(CoverageParityError, match="expected"):
        load_parity_manifest(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("input_timeout_seconds", 0, "must be positive"),
        ("input_timeout_seconds", True, "nonnegative integer"),
        ("input_timeout_seconds", "10", "nonnegative integer"),
    ],
)
def test_manifest_strictly_validates_replay_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    message: str,
) -> None:
    path = _write_changed_manifest(
        tmp_path, monkeypatch, "coverage_replay_policy", field, value
    )

    with pytest.raises(CoverageParityError, match=message):
        load_parity_manifest(path)


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("EXTRA", None, "expected ASAN_OPTIONS and LSAN_OPTIONS"),
        ("ASAN_OPTIONS", "", "nonempty string or null"),
        ("LSAN_OPTIONS", 1, "nonempty string or null"),
    ],
)
def test_manifest_strictly_validates_replay_sanitizer_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: object,
    message: str,
) -> None:
    document = _test_manifest_document()
    document["coverage_replay_policy"]["sanitizer_environment"][name] = value
    path = _write_test_manifest(
        tmp_path,
        monkeypatch,
        document,
        name="bad-replay-environment.json",
    )

    with pytest.raises(CoverageParityError, match=message):
        load_parity_manifest(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope", "full_source_parity"),
        ("blocking_metrics", ["functions", "regions"]),
        ("diagnostic_metrics", []),
        ("retirement_eligible", True),
        ("retirement_eligible", 0),
        ("region_status", "passed"),
        ("rationale", "different"),
    ],
)
def test_manifest_strictly_validates_gate_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    document = _test_manifest_document()
    document["gate_policy"][field] = value
    path = _write_test_manifest(
        tmp_path, monkeypatch, document, name="bad-gate-policy.json"
    )

    with pytest.raises(CoverageParityError, match="code-pinned"):
        load_parity_manifest(path)


def test_manifest_rejects_region_resolutions_while_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _test_manifest_document()
    document["resolved_gaps"]["regions"] = {"lib/example.c": {"example": ["1:1-1:2"]}}
    path = _write_test_manifest(
        tmp_path, monkeypatch, document, name="resolved-region.json"
    )

    with pytest.raises(CoverageParityError, match="must remain empty"):
        load_parity_manifest(path)


def test_manifest_rejects_unexpected_root_and_provenance_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for location in ("root", "provenance"):
        document = _test_manifest_document()
        if location == "root":
            document["unexpected"] = True
        else:
            document["provenance"]["unexpected"] = True
        path = _write_test_manifest(
            tmp_path, monkeypatch, document, name=f"{location}.json"
        )

        with pytest.raises(CoverageParityError, match="unexpected|missing"):
            load_parity_manifest(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("bytes", 0, "must be positive"),
        ("bytes", True, "nonnegative integer"),
        ("sha256", "not-a-hash", "lowercase SHA-256"),
    ],
)
def test_manifest_strictly_validates_audit_artifact_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    message: str,
) -> None:
    document = _test_manifest_document()
    document["provenance"]["audit_artifacts"]["pairs.json"][field] = value
    path = _write_test_manifest(
        tmp_path, monkeypatch, document, name="bad-evidence.json"
    )

    with pytest.raises(CoverageParityError, match=message):
        load_parity_manifest(path)


@pytest.mark.parametrize("nested", [False, True])
def test_manifest_rejects_duplicate_json_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nested: bool
) -> None:
    document = _test_manifest_document()
    _pin_test_manifest(monkeypatch, document)
    text = json.dumps(document, indent=2)
    if nested:
        text = text.replace(
            f'        "sha256": "{ARTIFACT_SHA256}"',
            (
                f'        "sha256": "{ARTIFACT_SHA256}",\n'
                f'        "sha256": "{ARTIFACT_SHA256}"'
            ),
            1,
        )
    else:
        text = text.replace(
            '  "schema_version": 1,',
            '  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
    path = tmp_path / "duplicate.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(CoverageParityError, match="duplicate JSON object key"):
        load_parity_manifest(path)


def test_manifest_rejects_target_path_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = _test_manifest_document()
    document["target_pairs"][0]["baseline"] = "../escape"
    path = _write_test_manifest(tmp_path, monkeypatch, document, name="traversal.json")

    with pytest.raises(CoverageParityError, match="slash-free"):
        load_parity_manifest(path)


def test_live_inventory_matches_every_manifest_target(tmp_path: Path) -> None:
    manifest, _, _ = _small_manifest()
    inventory = tmp_path / "fuzz_targets"
    inventory.write_text(
        'FUZZ_TARGETS_LIST="curl_fuzzer_legacy curl_fuzzer_proto_example '
        'fuzz_url fuzz_bufq fuzz_doh fuzz_netrc"\n',
        encoding="utf-8",
    )

    validate_live_inventory(manifest, inventory)


def test_live_inventory_matches_every_audited_migration_target() -> None:
    manifest, _, _ = _small_manifest()
    manifest = replace(
        manifest,
        baseline_inventory=AUDITED_BASELINE_INVENTORY,
        candidate_inventory=AUDITED_CANDIDATE_INVENTORY,
        excluded_inventory=AUDITED_EXCLUDED_INVENTORY,
    )

    validate_live_inventory(manifest, REPO_ROOT / "scripts" / "fuzz_targets")


@pytest.mark.parametrize("kind", ["omitted", "extra"])
def test_live_inventory_rejects_omitted_and_extra_targets(
    tmp_path: Path, kind: str
) -> None:
    manifest, _, _ = _small_manifest()
    targets = set(
        manifest.baseline_inventory
        | manifest.candidate_inventory
        | manifest.excluded_inventory
    )
    if kind == "omitted":
        targets.remove(CANDIDATE_TARGET)
    else:
        targets.add("curl_fuzzer_proto_new_lane")
    inventory = tmp_path / "fuzz_targets"
    inventory.write_text(
        f'FUZZ_TARGETS_LIST="{" ".join(sorted(targets))}"\n', encoding="utf-8"
    )

    with pytest.raises(CoverageParityError, match="inventory"):
        validate_live_inventory(manifest, inventory)


@pytest.mark.parametrize(
    "unsupported",
    [
        'FUZZ_TARGETS_LIST+=" curl_fuzzer_new"',
        "FUZZ_TARGETS_LIST='curl_fuzzer_new'",
        'FUZZ_TARGETS_LIST="${HELPER_TARGETS}"',
        'FUZZ_TARGETS_LIST="curl_fuzzer_new \\\ncurl_fuzzer_other"',
    ],
)
def test_target_inventory_rejects_unsupported_mutations(
    tmp_path: Path, unsupported: str
) -> None:
    inventory = tmp_path / "fuzz_targets"
    inventory.write_text(
        f'FUZZ_TARGETS_LIST="fuzz_url fuzz_bufq fuzz_doh fuzz_netrc"\n{unsupported}\n',
        encoding="utf-8",
    )

    with pytest.raises(CoverageParityError, match="FUZZ_TARGETS_LIST"):
        read_target_inventory(inventory)


def test_exact_known_gaps_pass_and_report_no_resolution() -> None:
    manifest, baseline, candidate = _small_manifest()

    result = _evaluate(manifest, baseline, candidate)

    assert result["status"] == "passed"
    assert result["gate_scope"] == "development_function_parity"
    assert result["retirement_eligible"] is False
    assert result["functions"]["new_count"] == 0
    assert result["regions"]["status"] == "indeterminate_nondeterministic"
    assert result["regions"]["blocking"] is False
    assert result["regions"]["authoritative"] is False
    assert not {
        "new_count",
        "regression_count",
        "eligible_resolution_count",
    }.intersection(result["regions"])


def test_arbitrary_region_drift_is_diagnostic_and_does_not_change_status() -> None:
    manifest, baseline, candidate = _small_manifest()
    baseline_only = ("lib/drift.c", "baseline_path", 3, 1, 3, 8)
    candidate_only = ("lib/drift.c", "candidate_path", 4, 1, 4, 8)
    baseline = replace(baseline, regions=frozenset({baseline_only}))
    candidate = replace(candidate, regions=frozenset({candidate_only}))

    result = _evaluate(manifest, baseline, candidate)

    assert result["status"] == "passed"
    regions = result["regions"]
    assert regions["status"] == "indeterminate_nondeterministic"
    assert regions["observed"]["baseline_covered_count"] == 1
    assert regions["observed"]["candidate_covered_count"] == 1
    assert regions["observed"]["baseline_only_count"] == 1
    comparison = regions["comparison_to_audit_baseline_only_reference"]
    assert comparison["not_in_reference_count"] == 1
    assert comparison["reference_not_observed_count"] == 1


def test_new_gap_fails_even_when_it_is_in_the_baseline_universe() -> None:
    manifest, baseline, _ = _small_manifest()
    candidate = CoverageUniverse(functions=frozenset(), regions=frozenset())

    result = _evaluate(manifest, baseline, candidate)

    assert result["status"] == "failed"
    assert result["functions"]["new_count"] == 1
    assert result["regions"]["status"] == "indeterminate_nondeterministic"


def test_resolved_gap_reappearing_is_a_regression() -> None:
    manifest, baseline, candidate = _small_manifest()
    manifest = replace(
        manifest,
        resolved_functions=manifest.initial_functions,
    )

    result = _evaluate(manifest, baseline, candidate)

    assert result["status"] == "failed"
    assert result["functions"]["regression_count"] == 1


def test_closed_unresolved_gap_is_advisory() -> None:
    manifest, baseline, _ = _small_manifest()

    result = _evaluate(manifest, baseline, baseline)

    assert result["status"] == "passed"
    assert result["functions"]["eligible_resolution_count"] == 1


def test_unresolved_gap_can_vary_until_it_is_explicitly_ratcheted() -> None:
    manifest, baseline, candidate = _small_manifest()

    observed = _evaluate(manifest, baseline, baseline)
    not_observed = _evaluate(manifest, baseline, candidate)

    assert observed["status"] == "passed"
    assert observed["functions"]["eligible_resolution_count"] == 1
    assert not_observed["status"] == "passed"
    assert not_observed["functions"]["eligible_resolution_count"] == 0

    ratcheted = replace(
        manifest,
        resolved_functions=manifest.initial_functions,
    )
    regression = _evaluate(ratcheted, baseline, candidate)

    assert regression["status"] == "failed"
    assert regression["functions"]["regression_count"] == 1


def test_manifest_gap_must_belong_to_bound_baseline_universe() -> None:
    manifest, baseline, candidate = _small_manifest()
    manifest = replace(
        manifest,
        initial_functions=frozenset({("lib/missing.c", "not_covered")}),
    )

    with pytest.raises(CoverageParityError, match="subset"):
        _evaluate(manifest, baseline, candidate)


def test_evaluation_rejects_binding_mismatches() -> None:
    manifest, baseline, candidate = _small_manifest()

    with pytest.raises(CoverageParityError, match="source identity"):
        evaluate_parity(
            manifest,
            source_identity={"sha256": "c" * 64, "source_files": 1},
            target_pairs=manifest.target_pairs,
            baseline_corpora={BASELINE_TARGET: {"count": 1, "sha256": "b" * 64}},
            baseline=baseline,
            candidate=candidate,
        )
    with pytest.raises(CoverageParityError, match="corpus identity"):
        evaluate_parity(
            manifest,
            source_identity=manifest.source_identity,
            target_pairs=manifest.target_pairs,
            baseline_corpora={BASELINE_TARGET: {"count": 2, "sha256": "b" * 64}},
            baseline=baseline,
            candidate=candidate,
        )
    with pytest.raises(CoverageParityError, match="covered-function universe"):
        _evaluate(
            manifest,
            CoverageUniverse(
                functions=baseline.functions | {("lib/extra.c", "extra")},
                regions=baseline.regions,
            ),
            candidate,
        )
    drifted = _evaluate(
        manifest,
        CoverageUniverse(
            functions=baseline.functions,
            regions=baseline.regions | {("lib/extra.c", "extra", 1, 1, 1, 2)},
        ),
        candidate,
    )
    assert drifted["status"] == "passed"
    assert drifted["regions"]["status"] == "indeterminate_nondeterministic"


def test_baseline_corpus_binding_can_fail_before_replay() -> None:
    manifest, _, _ = _small_manifest()

    with pytest.raises(CoverageParityError, match="corpus identity"):
        validate_baseline_corpora(
            manifest,
            {BASELINE_TARGET: {"count": True, "sha256": "b" * 64}},
        )


def test_source_identity_binding_can_fail_before_corpus_assembly() -> None:
    manifest, _, _ = _small_manifest()

    with pytest.raises(CoverageParityError, match="source identity"):
        validate_source_identity(
            manifest,
            {"sha256": "f" * 64, "source_files": 1},
        )


def test_manifest_progression_rejects_resolved_gap_removal() -> None:
    manifest, _, _ = _small_manifest()
    resolved = frozenset({next(iter(manifest.initial_functions))})
    previous = replace(manifest, resolved_functions=resolved)

    with pytest.raises(CoverageParityError, match="removes previously resolved"):
        validate_manifest_progression(previous, manifest)


def test_manifest_progression_allows_only_more_resolutions() -> None:
    manifest, _, _ = _small_manifest()
    resolved = frozenset({next(iter(manifest.initial_functions))})
    candidate = replace(manifest, resolved_functions=resolved)

    validate_manifest_progression(manifest, candidate)


def test_manifest_progression_rejects_region_resolutions() -> None:
    manifest, _, _ = _small_manifest()
    region = frozenset({next(iter(manifest.initial_regions))})
    candidate = replace(manifest, resolved_regions=region)

    with pytest.raises(CoverageParityError, match="not allowed"):
        validate_manifest_progression(manifest, candidate)


def test_manifest_progression_rejects_immutable_baseline_change() -> None:
    manifest, _, _ = _small_manifest()
    candidate = replace(manifest, immutable_baseline_sha256="f" * 64)

    with pytest.raises(CoverageParityError, match="immutable baseline"):
        validate_manifest_progression(manifest, candidate)
