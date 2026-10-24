"""Validate and apply the immutable proto-migration function ratchet."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar

FunctionKey = tuple[str, str]
RegionKey = tuple[str, str, int, int, int, int]
CoverageKey = TypeVar("CoverageKey", FunctionKey, RegionKey)

_REGION_RE = re.compile(r"^(\d+):(\d+)-(\d+):(\d+)$")
_TARGET_ASSIGNMENT_RE = re.compile(r'^\s*FUZZ_TARGETS_LIST="(?P<value>[^"\\]*)"\s*$')
_TARGET_NARROWING_RE = re.compile(r'^\s*FUZZ_TARGETS_LIST="\$\{CURL_FUZZ_TARGET\}"\s*$')
_TARGET_MUTATION_RE = re.compile(
    r"(?:^|\s)(?:export\s+|declare\s+|readonly\s+)?"
    r"FUZZ_TARGETS_LIST\s*(?:\+?=|$)"
)
TARGET_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_EXCLUDED_STANDALONE = frozenset({"fuzz_url", "fuzz_bufq", "fuzz_doh", "fuzz_netrc"})
_GATE_SCOPE = "development_function_parity"
_REGION_STATUS = "indeterminate_nondeterministic"
_GATE_RATIONALE = (
    "Three complete full-corpus replays reproduced the 2,237-function baseline "
    "exactly, while ordinary regions varied with wall-clock exact-zero paths, "
    "randomized hash topology, resolver scheduling, and a non-atomic derived-"
    "counter underflow. Regions remain diagnostic until a deterministic baseline "
    "reproduces across independent full runs."
)
_EXPECTED_GATE_POLICY: dict[str, object] = {
    "scope": _GATE_SCOPE,
    "blocking_metrics": ["functions"],
    "diagnostic_metrics": ["regions"],
    "retirement_eligible": False,
    "region_status": _REGION_STATUS,
    "rationale": _GATE_RATIONALE,
}
_PINNED_BASELINES = {
    "proto-migration-v1": {
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
}


class CoverageParityError(ValueError):
    """Raised when a parity manifest or its live binding is invalid."""


class DuplicateJsonKeyError(ValueError):
    """Raised when audit JSON repeats an object key."""


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(payload: str | bytes | bytearray) -> object:
    """Decode JSON while rejecting duplicate keys at every nesting level."""
    return json.loads(payload, object_pairs_hook=_reject_duplicate_json_keys)


@dataclass(frozen=True)
class CoverageUniverse:
    """Covered source identities used to evaluate one migration snapshot."""

    functions: frozenset[FunctionKey]
    regions: frozenset[RegionKey]


@dataclass(frozen=True)
class ParityManifest:
    """Validated immutable baseline and its monotonic function-gap ratchet."""

    path: Path
    sha256: str
    baseline_id: str
    immutable_baseline_sha256: str
    source_identity: dict[str, object]
    replay_input_timeout_seconds: int
    replay_sanitizer_environment: dict[str, str | None]
    gate_scope: str
    retirement_eligible: bool
    region_status: str
    gate_rationale: str
    target_pairs: tuple[tuple[str, str], ...]
    baseline_inventory: frozenset[str]
    candidate_inventory: frozenset[str]
    excluded_inventory: frozenset[str]
    baseline_corpora: dict[str, tuple[int, str]]
    baseline_function_count: int
    baseline_function_sha256: str
    baseline_region_count: int
    baseline_region_sha256: str
    initial_functions: frozenset[FunctionKey]
    initial_regions: frozenset[RegionKey]
    resolved_functions: frozenset[FunctionKey]
    resolved_regions: frozenset[RegionKey]
    identity_canonicalization: dict[str, object]
    provenance: dict[str, object]


def _object(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CoverageParityError(f"{location}: expected an object")
    return value


def _list(value: object, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise CoverageParityError(f"{location}: expected an array")
    return value


def _string(value: object, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise CoverageParityError(f"{location}: expected a nonempty string")
    return value


def _count(value: object, location: str) -> int:
    if type(value) is not int or value < 0:
        raise CoverageParityError(f"{location}: expected a nonnegative integer")
    return value


def _sha256(value: object, location: str) -> str:
    digest = _string(value, location)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CoverageParityError(f"{location}: expected a lowercase SHA-256")
    return digest


def _string_set(value: object, location: str) -> frozenset[str]:
    raw = _list(value, location)
    strings = [
        _target_name(item, f"{location}[{index}]") for index, item in enumerate(raw)
    ]
    if len(strings) != len(set(strings)):
        raise CoverageParityError(f"{location}: duplicate target")
    return frozenset(strings)


def _target_name(value: object, location: str) -> str:
    target = _string(value, location)
    if TARGET_NAME_RE.fullmatch(target) is None:
        raise CoverageParityError(
            f"{location}: expected a slash-free alphanumeric target name"
        )
    return target


def _parse_functions(value: object, location: str) -> frozenset[FunctionKey]:
    grouped = _object(value, location)
    identities: list[FunctionKey] = []
    for filename, raw_names in grouped.items():
        source = _string(filename, f"{location} filename")
        names = _list(raw_names, f"{location}.{source}")
        identities.extend(
            (source, _string(name, f"{location}.{source}[{index}]"))
            for index, name in enumerate(names)
        )
    if len(identities) != len(set(identities)):
        raise CoverageParityError(f"{location}: duplicate function identity")
    return frozenset(identities)


def _parse_regions(value: object, location: str) -> frozenset[RegionKey]:
    grouped = _object(value, location)
    identities: list[RegionKey] = []
    for filename, raw_functions in grouped.items():
        source = _string(filename, f"{location} filename")
        functions = _object(raw_functions, f"{location}.{source}")
        for function, raw_coordinates in functions.items():
            function_name = _string(function, f"{location}.{source} function")
            coordinates = _list(raw_coordinates, f"{location}.{source}.{function_name}")
            for index, raw_coordinate in enumerate(coordinates):
                coordinate = _string(
                    raw_coordinate,
                    f"{location}.{source}.{function_name}[{index}]",
                )
                match = _REGION_RE.fullmatch(coordinate)
                if match is None:
                    raise CoverageParityError(
                        f"{location}.{source}.{function_name}[{index}]: "
                        "expected LINE:COLUMN-LINE:COLUMN"
                    )
                start_line, start_column, end_line, end_column = (
                    int(item) for item in match.groups()
                )
                values = (start_line, start_column, end_line, end_column)
                if any(item <= 0 for item in values):
                    raise CoverageParityError(
                        f"{location}.{source}.{function_name}[{index}]: "
                        "coordinates must be positive"
                    )
                identities.append(
                    (
                        source,
                        function_name,
                        start_line,
                        start_column,
                        end_line,
                        end_column,
                    )
                )
    if len(identities) != len(set(identities)):
        raise CoverageParityError(f"{location}: duplicate region identity")
    return frozenset(identities)


def _parse_gap_set(
    value: object, location: str
) -> tuple[frozenset[FunctionKey], frozenset[RegionKey]]:
    record = _object(value, location)
    unexpected = set(record).difference({"functions", "regions"})
    if unexpected:
        raise CoverageParityError(
            f"{location}: unexpected keys: {', '.join(sorted(unexpected))}"
        )
    return (
        _parse_functions(record.get("functions"), f"{location}.functions"),
        _parse_regions(record.get("regions"), f"{location}.regions"),
    )


def identity_sha256(identities: frozenset[CoverageKey]) -> str:
    """Hash one canonical, sorted set of source coverage identities."""
    encoded = json.dumps(
        sorted(identities),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_target_inventory(
    path: Path,
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Parse the repository's complete target superset without sourcing shell."""
    try:
        lines = path.resolve().read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CoverageParityError(
            f"could not read target inventory {path.resolve()}: {error}"
        ) from error
    targets: set[str] = set()
    assignment_count = 0
    for line_number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue
        if _TARGET_NARROWING_RE.match(line) is not None:
            continue
        match = _TARGET_ASSIGNMENT_RE.match(line)
        if match is None:
            if _TARGET_MUTATION_RE.search(line):
                raise CoverageParityError(
                    f"unsupported FUZZ_TARGETS_LIST mutation at {path}:{line_number}"
                )
            continue
        tokens = match.group("value").split()
        if not tokens:
            raise CoverageParityError(
                f"empty FUZZ_TARGETS_LIST assignment at {path}:{line_number}"
            )
        if assignment_count == 0:
            if "${FUZZ_TARGETS_LIST}" in tokens:
                raise CoverageParityError(
                    "first FUZZ_TARGETS_LIST assignment cannot reference itself at "
                    f"{path}:{line_number}"
                )
            additions = tokens
        else:
            if (
                tokens[0] != "${FUZZ_TARGETS_LIST}"
                or tokens.count("${FUZZ_TARGETS_LIST}") != 1
            ):
                raise CoverageParityError(
                    "later FUZZ_TARGETS_LIST assignments must append through an exact "
                    f"self-reference at {path}:{line_number}"
                )
            additions = tokens[1:]
        if not additions or any(
            TARGET_NAME_RE.fullmatch(token) is None
            or not token.startswith(("curl_fuzzer", "fuzz_"))
            for token in additions
        ):
            raise CoverageParityError(
                f"unsupported FUZZ_TARGETS_LIST value at {path}:{line_number}"
            )
        targets.update(additions)
        assignment_count += 1
    if assignment_count == 0:
        raise CoverageParityError(f"target inventory contains no targets: {path}")
    missing_exclusions = _EXCLUDED_STANDALONE.difference(targets)
    if missing_exclusions:
        raise CoverageParityError(
            "target inventory is missing standalone exclusions: "
            + ", ".join(sorted(missing_exclusions))
        )
    migration_targets = targets.difference(_EXCLUDED_STANDALONE)
    candidates = frozenset(
        target for target in migration_targets if target.startswith("curl_fuzzer_proto")
    )
    baselines = frozenset(migration_targets.difference(candidates))
    return baselines, candidates, _EXCLUDED_STANDALONE


def load_parity_manifest(path: Path) -> ParityManifest:
    """Load and strictly validate a proto-migration parity manifest."""
    resolved = path.resolve()
    try:
        raw_bytes = resolved.read_bytes()
        document = strict_json_loads(raw_bytes)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as error:
        raise CoverageParityError(
            f"could not read parity manifest {resolved}: {error}"
        ) from error
    root = _object(document, "parity manifest")
    expected_root_keys = {
        "schema_version",
        "baseline_id",
        "immutable_baseline_sha256",
        "curl_source_identity",
        "coverage_replay_policy",
        "gate_policy",
        "target_inventory",
        "target_pairs",
        "baseline_corpora",
        "baseline_universe",
        "initial_gaps",
        "resolved_gaps",
        "identity_canonicalization",
        "provenance",
    }
    if set(root) != expected_root_keys:
        raise CoverageParityError(
            "parity manifest: unexpected or missing top-level keys"
        )
    schema_version = root.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise CoverageParityError("parity manifest.schema_version: expected 1")
    baseline_id = _string(root.get("baseline_id"), "parity manifest.baseline_id")
    immutable_baseline_sha256 = _sha256(
        root.get("immutable_baseline_sha256"),
        "parity manifest.immutable_baseline_sha256",
    )

    source_identity = _object(
        root.get("curl_source_identity"),
        "parity manifest.curl_source_identity",
    )
    if set(source_identity) != {"sha256", "source_files"}:
        raise CoverageParityError(
            "parity manifest.curl_source_identity: expected sha256 and source_files"
        )
    source_sha = _sha256(
        source_identity.get("sha256"),
        "parity manifest.curl_source_identity.sha256",
    )
    source_files = _count(
        source_identity.get("source_files"),
        "parity manifest.curl_source_identity.source_files",
    )
    if source_files == 0:
        raise CoverageParityError(
            "parity manifest.curl_source_identity.source_files must be positive"
        )

    replay_policy = _object(
        root.get("coverage_replay_policy"),
        "parity manifest.coverage_replay_policy",
    )
    if set(replay_policy) != {
        "input_timeout_seconds",
        "sanitizer_environment",
    }:
        raise CoverageParityError(
            "parity manifest.coverage_replay_policy: expected "
            "input_timeout_seconds and sanitizer_environment"
        )
    replay_input_timeout_seconds = _count(
        replay_policy.get("input_timeout_seconds"),
        "parity manifest.coverage_replay_policy.input_timeout_seconds",
    )
    if replay_input_timeout_seconds == 0:
        raise CoverageParityError(
            "parity manifest.coverage_replay_policy.input_timeout_seconds "
            "must be positive"
        )
    raw_sanitizer_environment = _object(
        replay_policy.get("sanitizer_environment"),
        "parity manifest.coverage_replay_policy.sanitizer_environment",
    )
    if set(raw_sanitizer_environment) != {"ASAN_OPTIONS", "LSAN_OPTIONS"}:
        raise CoverageParityError(
            "parity manifest.coverage_replay_policy.sanitizer_environment: "
            "expected ASAN_OPTIONS and LSAN_OPTIONS"
        )
    replay_sanitizer_environment: dict[str, str | None] = {}
    for name in ("ASAN_OPTIONS", "LSAN_OPTIONS"):
        value = raw_sanitizer_environment[name]
        if value is not None and (not isinstance(value, str) or not value):
            raise CoverageParityError(
                "parity manifest.coverage_replay_policy."
                f"sanitizer_environment.{name}: expected a nonempty string or null"
            )
        replay_sanitizer_environment[name] = value

    gate_policy = _object(
        root.get("gate_policy"),
        "parity manifest.gate_policy",
    )
    if (
        type(gate_policy.get("retirement_eligible")) is not bool
        or gate_policy != _EXPECTED_GATE_POLICY
    ):
        raise CoverageParityError(
            "parity manifest.gate_policy: expected the code-pinned "
            "development function-parity policy"
        )

    raw_pairs = _list(root.get("target_pairs"), "parity manifest.target_pairs")
    pairs: list[tuple[str, str]] = []
    for index, raw_pair in enumerate(raw_pairs):
        pair = _object(raw_pair, f"parity manifest.target_pairs[{index}]")
        if set(pair) != {"baseline", "candidate"}:
            raise CoverageParityError(
                f"parity manifest.target_pairs[{index}]: "
                "expected baseline and candidate"
            )
        pairs.append(
            (
                _target_name(
                    pair.get("baseline"),
                    f"parity manifest.target_pairs[{index}].baseline",
                ),
                _target_name(
                    pair.get("candidate"),
                    f"parity manifest.target_pairs[{index}].candidate",
                ),
            )
        )
    if not pairs or len(pairs) != len(set(pairs)):
        raise CoverageParityError(
            "parity manifest.target_pairs: expected unique nonempty mappings"
        )

    inventory = _object(
        root.get("target_inventory"), "parity manifest.target_inventory"
    )
    if set(inventory) != {"baseline", "candidate", "excluded_standalone"}:
        raise CoverageParityError(
            "parity manifest.target_inventory: expected baseline, candidate, "
            "and excluded_standalone"
        )
    baseline_inventory = _string_set(
        inventory.get("baseline"), "parity manifest.target_inventory.baseline"
    )
    candidate_inventory = _string_set(
        inventory.get("candidate"), "parity manifest.target_inventory.candidate"
    )
    excluded_inventory = _string_set(
        inventory.get("excluded_standalone"),
        "parity manifest.target_inventory.excluded_standalone",
    )
    if {baseline for baseline, _ in pairs} != baseline_inventory:
        raise CoverageParityError(
            "parity manifest.target_pairs do not cover the baseline inventory exactly"
        )
    if {candidate for _, candidate in pairs} != candidate_inventory:
        raise CoverageParityError(
            "parity manifest.target_pairs do not cover the candidate inventory exactly"
        )
    if excluded_inventory != _EXCLUDED_STANDALONE:
        raise CoverageParityError(
            "parity manifest.target_inventory.excluded_standalone must list only "
            "fuzz_url, fuzz_bufq, fuzz_doh, and fuzz_netrc"
        )

    raw_corpora = _object(
        root.get("baseline_corpora"), "parity manifest.baseline_corpora"
    )
    if set(raw_corpora) != baseline_inventory:
        raise CoverageParityError(
            "parity manifest.baseline_corpora must match the baseline inventory"
        )
    baseline_corpora: dict[str, tuple[int, str]] = {}
    for target, raw_corpus in raw_corpora.items():
        corpus = _object(raw_corpus, f"parity manifest.baseline_corpora.{target}")
        if set(corpus) != {"count", "sha256"}:
            raise CoverageParityError(
                f"parity manifest.baseline_corpora.{target}: expected count and sha256"
            )
        count = _count(
            corpus.get("count"),
            f"parity manifest.baseline_corpora.{target}.count",
        )
        if count == 0:
            raise CoverageParityError(
                f"parity manifest.baseline_corpora.{target}.count must be positive"
            )
        baseline_corpora[target] = (
            count,
            _sha256(
                corpus.get("sha256"),
                f"parity manifest.baseline_corpora.{target}.sha256",
            ),
        )

    universe = _object(
        root.get("baseline_universe"), "parity manifest.baseline_universe"
    )
    if set(universe) != {"functions", "regions"}:
        raise CoverageParityError(
            "parity manifest.baseline_universe: expected functions and regions"
        )
    functions = _object(
        universe.get("functions"),
        "parity manifest.baseline_universe.functions",
    )
    regions = _object(
        universe.get("regions"), "parity manifest.baseline_universe.regions"
    )
    for name, record in (("functions", functions), ("regions", regions)):
        if set(record) != {"count", "sha256"}:
            raise CoverageParityError(
                f"parity manifest.baseline_universe.{name}: expected count and sha256"
            )
        if (
            _count(
                record.get("count"),
                f"parity manifest.baseline_universe.{name}.count",
            )
            == 0
        ):
            raise CoverageParityError(
                f"parity manifest.baseline_universe.{name}.count must be positive"
            )

    initial_functions, initial_regions = _parse_gap_set(
        root.get("initial_gaps"), "parity manifest.initial_gaps"
    )
    resolved_functions, resolved_regions = _parse_gap_set(
        root.get("resolved_gaps"), "parity manifest.resolved_gaps"
    )
    if not resolved_functions.issubset(initial_functions):
        raise CoverageParityError(
            "parity manifest.resolved_gaps.functions contains a non-initial identity"
        )
    if resolved_regions:
        raise CoverageParityError(
            "parity manifest.resolved_gaps.regions must remain empty while regions "
            "are diagnostic"
        )

    canonicalization = _object(
        root.get("identity_canonicalization"),
        "parity manifest.identity_canonicalization",
    )
    expected_canonicalization = {
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
    }
    json_canonicalization = canonicalization.get("json")
    strict_boolean_types = (
        isinstance(json_canonicalization, dict)
        and type(json_canonicalization.get("ensure_ascii")) is bool
        and type(json_canonicalization.get("sort_keys")) is bool
    )
    if canonicalization != expected_canonicalization or not strict_boolean_types:
        raise CoverageParityError(
            "parity manifest.identity_canonicalization is unsupported"
        )

    provenance = _object(root.get("provenance"), "parity manifest.provenance")
    expected_provenance_keys = {
        "curl_revision",
        "curl_source_path_manifest_sha256",
        "audit_fuzzer_revision",
        "audit_artifacts",
        "corpus_boundary",
    }
    if set(provenance) != expected_provenance_keys:
        raise CoverageParityError(
            "parity manifest.provenance: unexpected or missing keys"
        )
    for name in ("curl_revision", "audit_fuzzer_revision"):
        revision = _string(provenance.get(name), f"parity manifest.provenance.{name}")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise CoverageParityError(
                f"parity manifest.provenance.{name}: expected a Git object ID"
            )
    _sha256(
        provenance.get("curl_source_path_manifest_sha256"),
        "parity manifest.provenance.curl_source_path_manifest_sha256",
    )
    artifacts = _object(
        provenance.get("audit_artifacts"),
        "parity manifest.provenance.audit_artifacts",
    )
    expected_artifacts = {
        "pairs.json",
        "expected-full-inputs.json",
        "coverage-provenance.json",
        "assembly-completeness.json",
        "full-source-comparison.json",
        "gaps.json",
        "report.md",
        "public-corpus-manifest.json",
    }
    if set(artifacts) != expected_artifacts:
        raise CoverageParityError(
            "parity manifest.provenance.audit_artifacts is incomplete"
        )
    for name, raw_artifact in artifacts.items():
        artifact = _object(
            raw_artifact,
            f"parity manifest.provenance.audit_artifacts.{name}",
        )
        if set(artifact) != {"bytes", "sha256"}:
            raise CoverageParityError(
                f"parity manifest.provenance.audit_artifacts.{name}: "
                "expected bytes and sha256"
            )
        if (
            _count(
                artifact.get("bytes"),
                f"parity manifest.provenance.audit_artifacts.{name}.bytes",
            )
            == 0
        ):
            raise CoverageParityError(
                f"parity manifest.provenance.audit_artifacts.{name}.bytes "
                "must be positive"
            )
        _sha256(
            artifact.get("sha256"),
            f"parity manifest.provenance.audit_artifacts.{name}.sha256",
        )
    boundary = _object(
        provenance.get("corpus_boundary"),
        "parity manifest.provenance.corpus_boundary",
    )
    if set(boundary) != {
        "public_archives_attempted",
        "public_archives_available",
        "public_archives_inaccessible",
        "note",
    }:
        raise CoverageParityError(
            "parity manifest.provenance.corpus_boundary: unexpected or missing keys"
        )
    attempted = _count(
        boundary.get("public_archives_attempted"),
        "parity manifest.provenance.corpus_boundary.public_archives_attempted",
    )
    available = _count(
        boundary.get("public_archives_available"),
        "parity manifest.provenance.corpus_boundary.public_archives_available",
    )
    inaccessible = _count(
        boundary.get("public_archives_inaccessible"),
        "parity manifest.provenance.corpus_boundary.public_archives_inaccessible",
    )
    _string(boundary.get("note"), "parity manifest.provenance.corpus_boundary.note")
    if attempted == 0 or attempted != available + inaccessible:
        raise CoverageParityError(
            "parity manifest.provenance.corpus_boundary counts are inconsistent"
        )

    immutable_document = {
        key: value
        for key, value in root.items()
        if key not in {"immutable_baseline_sha256", "resolved_gaps"}
    }
    computed_immutable_sha256 = _canonical_sha256(immutable_document)
    if immutable_baseline_sha256 != computed_immutable_sha256:
        raise CoverageParityError(
            "parity manifest immutable baseline checksum does not match its contents"
        )
    pinned = _PINNED_BASELINES.get(baseline_id)
    if pinned is None:
        raise CoverageParityError(
            f"parity manifest.baseline_id is not code-pinned: {baseline_id}"
        )
    if immutable_baseline_sha256 != pinned["immutable_baseline_sha256"]:
        raise CoverageParityError(
            "parity manifest immutable baseline does not match the code-pinned digest"
        )
    if (
        len(initial_functions) != pinned["initial_function_count"]
        or identity_sha256(initial_functions) != pinned["initial_function_sha256"]
    ):
        raise CoverageParityError(
            "parity manifest initial function gaps do not match the code-pinned set"
        )
    if (
        len(initial_regions) != pinned["initial_region_count"]
        or identity_sha256(initial_regions) != pinned["initial_region_sha256"]
    ):
        raise CoverageParityError(
            "parity manifest initial region gaps do not match the code-pinned set"
        )
    return ParityManifest(
        path=resolved,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        baseline_id=baseline_id,
        immutable_baseline_sha256=immutable_baseline_sha256,
        source_identity={"sha256": source_sha, "source_files": source_files},
        replay_input_timeout_seconds=replay_input_timeout_seconds,
        replay_sanitizer_environment=replay_sanitizer_environment,
        gate_scope=_GATE_SCOPE,
        retirement_eligible=False,
        region_status=_REGION_STATUS,
        gate_rationale=_GATE_RATIONALE,
        target_pairs=tuple(pairs),
        baseline_inventory=baseline_inventory,
        candidate_inventory=candidate_inventory,
        excluded_inventory=excluded_inventory,
        baseline_corpora=baseline_corpora,
        baseline_function_count=_count(
            functions.get("count"),
            "parity manifest.baseline_universe.functions.count",
        ),
        baseline_function_sha256=_sha256(
            functions.get("sha256"),
            "parity manifest.baseline_universe.functions.sha256",
        ),
        baseline_region_count=_count(
            regions.get("count"),
            "parity manifest.baseline_universe.regions.count",
        ),
        baseline_region_sha256=_sha256(
            regions.get("sha256"),
            "parity manifest.baseline_universe.regions.sha256",
        ),
        initial_functions=initial_functions,
        initial_regions=initial_regions,
        resolved_functions=resolved_functions,
        resolved_regions=resolved_regions,
        identity_canonicalization=canonicalization,
        provenance=provenance,
    )


def validate_manifest_progression(
    previous: ParityManifest, candidate: ParityManifest
) -> None:
    """Require a candidate ratchet to preserve its trusted prior state."""
    if candidate.baseline_id != previous.baseline_id:
        raise CoverageParityError(
            "previous and candidate parity manifests use different baseline IDs"
        )
    if candidate.immutable_baseline_sha256 != previous.immutable_baseline_sha256:
        raise CoverageParityError(
            "candidate parity manifest changes the immutable baseline"
        )
    if not previous.resolved_functions.issubset(candidate.resolved_functions):
        raise CoverageParityError(
            "candidate parity manifest removes previously resolved function gaps"
        )
    if previous.resolved_regions or candidate.resolved_regions:
        raise CoverageParityError(
            "region resolutions are not allowed while regions are diagnostic"
        )


def validate_live_inventory(manifest: ParityManifest, inventory_path: Path) -> None:
    """Require the manifest mapping to cover the repository target superset."""
    baseline, candidate, excluded = read_target_inventory(inventory_path)
    if baseline != manifest.baseline_inventory:
        raise CoverageParityError(
            "live baseline target inventory does not match the parity manifest"
        )
    if candidate != manifest.candidate_inventory:
        raise CoverageParityError(
            "live proto target inventory does not match the parity manifest"
        )
    if excluded != manifest.excluded_inventory:
        raise CoverageParityError(
            "live standalone target exclusions do not match the parity manifest"
        )


def _function_detail(key: FunctionKey) -> dict[str, object]:
    return {"file": key[0], "name": key[1]}


def _region_detail(key: RegionKey) -> dict[str, object]:
    return {
        "file": key[0],
        "function": key[1],
        "start": {"line": key[2], "column": key[3]},
        "end": {"line": key[4], "column": key[5]},
    }


def _ratchet_metric(
    current: frozenset[CoverageKey],
    initial: frozenset[CoverageKey],
    resolved: frozenset[CoverageKey],
    detail: Callable[[CoverageKey], dict[str, object]],
) -> dict[str, object]:
    new = current.difference(initial)
    regressions = current.intersection(resolved)
    eligible = initial.difference(resolved, current)
    return {
        "current_count": len(current),
        "initial_count": len(initial),
        "resolved_count": len(resolved),
        "new_count": len(new),
        "regression_count": len(regressions),
        "eligible_resolution_count": len(eligible),
        "new": [detail(key) for key in sorted(new)],
        "regressions": [detail(key) for key in sorted(regressions)],
        "eligible_resolutions": [detail(key) for key in sorted(eligible)],
    }


def _region_diagnostics(
    manifest: ParityManifest,
    baseline: frozenset[RegionKey],
    candidate: frozenset[RegionKey],
) -> dict[str, object]:
    """Describe unstable region observations without assigning gate semantics."""
    observed_baseline_only = baseline.difference(candidate)
    not_in_audit_reference = observed_baseline_only.difference(manifest.initial_regions)
    audit_reference_not_observed = manifest.initial_regions.difference(
        observed_baseline_only
    )
    return {
        "status": manifest.region_status,
        "blocking": False,
        "authoritative": False,
        "rationale": manifest.gate_rationale,
        "audit_reference": {
            "baseline_covered_count": manifest.baseline_region_count,
            "baseline_covered_sha256": manifest.baseline_region_sha256,
            "baseline_only_count": len(manifest.initial_regions),
            "baseline_only_sha256": identity_sha256(manifest.initial_regions),
        },
        "observed": {
            "baseline_covered_count": len(baseline),
            "baseline_covered_sha256": identity_sha256(baseline),
            "candidate_covered_count": len(candidate),
            "candidate_covered_sha256": identity_sha256(candidate),
            "baseline_only_count": len(observed_baseline_only),
            "baseline_only_sha256": identity_sha256(observed_baseline_only),
        },
        "comparison_to_audit_baseline_only_reference": {
            "not_in_reference_count": len(not_in_audit_reference),
            "not_in_reference_sha256": identity_sha256(not_in_audit_reference),
            "not_in_reference": [
                _region_detail(region) for region in sorted(not_in_audit_reference)
            ],
            "reference_not_observed_count": len(audit_reference_not_observed),
            "reference_not_observed_sha256": identity_sha256(
                audit_reference_not_observed
            ),
            "reference_not_observed": [
                _region_detail(region)
                for region in sorted(audit_reference_not_observed)
            ],
        },
    }


def validate_baseline_corpora(
    manifest: ParityManifest,
    baseline_corpora: dict[str, dict[str, object]],
) -> None:
    """Bind live baseline corpus count/content identities before replay."""
    if set(baseline_corpora) != manifest.baseline_inventory:
        raise CoverageParityError(
            "measured baseline corpora do not match the parity manifest inventory"
        )
    for target, (expected_count, expected_sha) in manifest.baseline_corpora.items():
        actual = _object(baseline_corpora[target], f"baseline corpus {target}")
        actual_count = actual.get("count")
        actual_sha = actual.get("sha256")
        if (
            type(actual_count) is not int
            or not isinstance(actual_sha, str)
            or actual_count != expected_count
            or actual_sha != expected_sha
        ):
            raise CoverageParityError(
                f"baseline corpus identity does not match the parity manifest: {target}"
            )


def validate_source_identity(
    manifest: ParityManifest, source_identity: dict[str, object]
) -> None:
    """Bind the live curl source tree before corpus assembly or replay."""
    if source_identity != manifest.source_identity:
        raise CoverageParityError(
            "curl source identity does not match the parity manifest"
        )


def evaluate_parity(
    manifest: ParityManifest,
    *,
    source_identity: dict[str, object],
    target_pairs: tuple[tuple[str, str], ...],
    baseline_corpora: dict[str, dict[str, object]],
    baseline: CoverageUniverse,
    candidate: CoverageUniverse,
) -> dict[str, object]:
    """Bind live evidence and evaluate the function-parity development ratchet."""
    validate_source_identity(manifest, source_identity)
    if target_pairs != manifest.target_pairs:
        raise CoverageParityError("target mapping does not match the parity manifest")

    actual_baselines = {baseline_target for baseline_target, _ in target_pairs}
    actual_candidates = {candidate_target for _, candidate_target in target_pairs}
    if actual_baselines != manifest.baseline_inventory:
        raise CoverageParityError(
            "selected pairs omit or add baseline inventory targets"
        )
    if actual_candidates != manifest.candidate_inventory:
        raise CoverageParityError(
            "selected pairs omit or add candidate inventory targets"
        )

    validate_baseline_corpora(manifest, baseline_corpora)

    function_sha = identity_sha256(baseline.functions)
    if (
        len(baseline.functions) != manifest.baseline_function_count
        or function_sha != manifest.baseline_function_sha256
    ):
        raise CoverageParityError(
            "baseline covered-function universe does not match the parity manifest"
        )
    if not manifest.initial_functions.issubset(baseline.functions):
        raise CoverageParityError(
            "initial function gaps are not a subset of the bound baseline universe"
        )
    current_functions = baseline.functions.difference(candidate.functions)
    function_result = _ratchet_metric(
        current_functions,
        manifest.initial_functions,
        manifest.resolved_functions,
        _function_detail,
    )
    failed = bool(function_result["new_count"] or function_result["regression_count"])
    status = "failed" if failed else "passed"
    return {
        "manifest": str(manifest.path),
        "manifest_sha256": manifest.sha256,
        "baseline_id": manifest.baseline_id,
        "immutable_baseline_sha256": manifest.immutable_baseline_sha256,
        "gate_scope": manifest.gate_scope,
        "retirement_eligible": manifest.retirement_eligible,
        "status": status,
        "functions": function_result,
        "regions": _region_diagnostics(
            manifest,
            baseline.regions,
            candidate.regions,
        ),
    }
