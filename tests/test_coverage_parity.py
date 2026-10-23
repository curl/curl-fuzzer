"""Tests for the proto-migration function-parity development ratchet."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

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
BASELINE_PATH = REPO_ROOT / "coverage_baselines" / "proto-migration-v1.json"


def _loaded_manifest() -> ParityManifest:
    return load_parity_manifest(BASELINE_PATH)


def _small_manifest() -> tuple[ParityManifest, CoverageUniverse, CoverageUniverse]:
    manifest = _loaded_manifest()
    function_gap = ("lib/example.c", "legacy_only")
    common_function = ("lib/example.c", "common")
    region_gap = ("lib/example.c", "legacy_only", 1, 1, 1, 8)
    common_region = ("lib/example.c", "common", 2, 1, 2, 8)
    baseline = CoverageUniverse(
        functions=frozenset({function_gap, common_function}),
        regions=frozenset({region_gap, common_region}),
    )
    candidate = CoverageUniverse(
        functions=frozenset({common_function}),
        regions=frozenset({common_region}),
    )
    return (
        replace(
            manifest,
            source_identity={"sha256": "a" * 64, "source_files": 1},
            target_pairs=(("legacy", "proto"),),
            baseline_inventory=frozenset({"legacy"}),
            candidate_inventory=frozenset({"proto"}),
            baseline_corpora={"legacy": (1, "b" * 64)},
            baseline_function_count=len(baseline.functions),
            baseline_function_sha256=identity_sha256(baseline.functions),
            baseline_region_count=len(baseline.regions),
            baseline_region_sha256=identity_sha256(baseline.regions),
            initial_functions=frozenset({function_gap}),
            initial_regions=frozenset({region_gap}),
            resolved_functions=frozenset(),
            resolved_regions=frozenset(),
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
        target_pairs=(("legacy", "proto"),),
        baseline_corpora={"legacy": {"count": 1, "sha256": "b" * 64}},
        baseline=baseline,
        candidate=candidate,
    )


def _write_changed_manifest(
    tmp_path: Path, section: str, key: str, value: object
) -> Path:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    document[section][key] = value
    path = tmp_path / "changed.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_committed_manifest_is_exactly_code_pinned() -> None:
    manifest = _loaded_manifest()

    assert manifest.baseline_id == "proto-migration-v1"
    assert manifest.immutable_baseline_sha256 == (
        "97f3b974700a1c2075e311b805257390f39cda9ec0063a3b271484bfe37b08f1"
    )
    assert manifest.replay_input_timeout_seconds == 10
    assert manifest.replay_sanitizer_environment == {
        "ASAN_OPTIONS": "detect_leaks=0",
        "LSAN_OPTIONS": None,
    }
    assert manifest.gate_scope == "development_function_parity"
    assert manifest.retirement_eligible is False
    assert manifest.region_status == "indeterminate_nondeterministic"
    assert "Regions remain diagnostic" in manifest.gate_rationale
    assert len(manifest.initial_functions) == 215
    assert identity_sha256(manifest.initial_functions) == (
        "da37b0ff5442655adb94150e2ae1f2f59cbde2c2d8c3ffddbd5584d79668f538"
    )
    assert len(manifest.initial_regions) == 6470
    assert identity_sha256(manifest.initial_regions) == (
        "90765eab0b68a4d8fe40e57b2eb24c68dc872493bd83e183213dc4c9155f2bf6"
    )
    assert len(manifest.target_pairs) == 31
    assert len(manifest.baseline_inventory) == 16
    assert len(manifest.candidate_inventory) == 30
    assert len(manifest.baseline_corpora) == 16
    assert len(manifest.baseline_inventory) + len(manifest.candidate_inventory) == 46
    assert manifest.baseline_function_count == 2237
    assert manifest.baseline_function_sha256 == (
        "f5b57aac80d1112cd90664abaff61d2d48153e40c2560475b4561bd349ffca80"
    )
    assert manifest.baseline_region_count == 34630
    assert manifest.baseline_region_sha256 == (
        "179879bec5280a4b37ac1c5785dce548e9a5ff20944e79b0dedd39d59b54a043"
    )


@pytest.mark.parametrize(
    "section",
    [
        "curl_source_identity",
        "coverage_replay_policy",
        "gate_policy",
        "baseline_universe",
    ],
)
def test_manifest_rejects_unexpected_nested_keys(tmp_path: Path, section: str) -> None:
    path = _write_changed_manifest(tmp_path, section, "unexpected", True)

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
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    path = _write_changed_manifest(tmp_path, "coverage_replay_policy", field, value)

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
    tmp_path: Path, name: str, value: object, message: str
) -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    document["coverage_replay_policy"]["sanitizer_environment"][name] = value
    path = tmp_path / "bad-replay-environment.json"
    path.write_text(json.dumps(document), encoding="utf-8")

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
    tmp_path: Path, field: str, value: object
) -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    document["gate_policy"][field] = value
    path = tmp_path / "bad-gate-policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CoverageParityError, match="code-pinned"):
        load_parity_manifest(path)


def test_manifest_rejects_region_resolutions_while_diagnostic(
    tmp_path: Path,
) -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    document["resolved_gaps"]["regions"] = {"lib/example.c": {"example": ["1:1-1:2"]}}
    path = tmp_path / "resolved-region.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CoverageParityError, match="must remain empty"):
        load_parity_manifest(path)


def test_manifest_rejects_unexpected_root_and_provenance_keys(
    tmp_path: Path,
) -> None:
    for location in ("root", "provenance"):
        document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        if location == "root":
            document["unexpected"] = True
        else:
            document["provenance"]["unexpected"] = True
        path = tmp_path / f"{location}.json"
        path.write_text(json.dumps(document), encoding="utf-8")

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
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    document["provenance"]["audit_artifacts"]["pairs.json"][field] = value
    path = tmp_path / "bad-evidence.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CoverageParityError, match=message):
        load_parity_manifest(path)


@pytest.mark.parametrize("nested", [False, True])
def test_manifest_rejects_duplicate_json_keys(tmp_path: Path, nested: bool) -> None:
    text = BASELINE_PATH.read_text(encoding="utf-8")
    if nested:
        text = text.replace(
            '    "sha256": "0f91db6bafe72ad83b645d4e1945a26e96f4662fb138153ef5ac97b85652350e",',
            (
                '    "sha256": '
                '"0f91db6bafe72ad83b645d4e1945a26e96f4662fb138153ef5ac97b85652350e",\n'
                '    "sha256": '
                '"0f91db6bafe72ad83b645d4e1945a26e96f4662fb138153ef5ac97b85652350e",'
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


def test_manifest_rejects_target_path_traversal(tmp_path: Path) -> None:
    document = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    document["target_pairs"][0]["baseline"] = "../escape"
    path = tmp_path / "traversal.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CoverageParityError, match="slash-free"):
        load_parity_manifest(path)


def test_live_inventory_matches_every_migration_target() -> None:
    validate_live_inventory(_loaded_manifest(), REPO_ROOT / "scripts" / "fuzz_targets")


@pytest.mark.parametrize("kind", ["omitted", "extra"])
def test_live_inventory_rejects_omitted_and_extra_targets(
    tmp_path: Path, kind: str
) -> None:
    manifest = _loaded_manifest()
    targets = set(
        manifest.baseline_inventory
        | manifest.candidate_inventory
        | manifest.excluded_inventory
    )
    if kind == "omitted":
        targets.remove("curl_fuzzer_proto_http")
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
            baseline_corpora={"legacy": {"count": 1, "sha256": "b" * 64}},
            baseline=baseline,
            candidate=candidate,
        )
    with pytest.raises(CoverageParityError, match="corpus identity"):
        evaluate_parity(
            manifest,
            source_identity=manifest.source_identity,
            target_pairs=manifest.target_pairs,
            baseline_corpora={"legacy": {"count": 2, "sha256": "b" * 64}},
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
            {"legacy": {"count": True, "sha256": "b" * 64}},
        )


def test_source_identity_binding_can_fail_before_corpus_assembly() -> None:
    manifest, _, _ = _small_manifest()

    with pytest.raises(CoverageParityError, match="source identity"):
        validate_source_identity(
            manifest,
            {"sha256": "f" * 64, "source_files": 1},
        )


def test_manifest_progression_rejects_resolved_gap_removal() -> None:
    manifest = _loaded_manifest()
    resolved = frozenset({next(iter(manifest.initial_functions))})
    previous = replace(manifest, resolved_functions=resolved)

    with pytest.raises(CoverageParityError, match="removes previously resolved"):
        validate_manifest_progression(previous, manifest)


def test_manifest_progression_allows_only_more_resolutions() -> None:
    manifest = _loaded_manifest()
    resolved = frozenset({next(iter(manifest.initial_functions))})
    candidate = replace(manifest, resolved_functions=resolved)

    validate_manifest_progression(manifest, candidate)


def test_manifest_progression_rejects_region_resolutions() -> None:
    manifest = _loaded_manifest()
    region = frozenset({next(iter(manifest.initial_regions))})
    candidate = replace(manifest, resolved_regions=region)

    with pytest.raises(CoverageParityError, match="not allowed"):
        validate_manifest_progression(manifest, candidate)


def test_manifest_progression_rejects_immutable_baseline_change() -> None:
    manifest = _loaded_manifest()
    candidate = replace(manifest, immutable_baseline_sha256="f" * 64)

    with pytest.raises(CoverageParityError, match="immutable baseline"):
        validate_manifest_progression(manifest, candidate)
