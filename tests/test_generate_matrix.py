"""Tests for the CI fuzzer artifact sharding helpers."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from curl_fuzzer_tools.generate_matrix import create_shards, main, parse_targets

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = REPO_ROOT / "src" / "curl_fuzzer_tools" / "generate_matrix.py"


def _create_target(
    build_out: Path,
    name: str,
    *,
    executable_size: int = 1,
    corpus_size: int = 1,
    executable: bool = True,
) -> None:
    build_out.mkdir(parents=True, exist_ok=True)
    binary = build_out / name
    binary.write_bytes(b"x" * executable_size)
    binary.chmod(0o755 if executable else 0o644)
    (build_out / f"{name}_seed_corpus.zip").write_bytes(b"z" * corpus_size)


def _assignments(matrix: dict[str, object]) -> dict[str, str]:
    include = matrix["include"]
    assert isinstance(include, list)
    return {row["fuzzer"]: row["shard"] for row in include}


def test_parse_targets_splits_whitespace() -> None:
    assert parse_targets(" fuzzer_one\nfuzzer_two\tfuzzer_three ") == [
        "fuzzer_one",
        "fuzzer_two",
        "fuzzer_three",
    ]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "  \n\t",
        "duplicate duplicate",
        "safe ../escape",
        "safe subdirectory/target",
        "safe target;command",
    ],
)
def test_parse_targets_rejects_invalid_input(value: str) -> None:
    with pytest.raises(ValueError):
        parse_targets(value)


def test_main_rejects_empty_fuzz_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FUZZ_TARGETS", raising=False)

    with pytest.raises(SystemExit, match="FUZZ_TARGETS is empty"):
        main(
            [
                "--build-out",
                str(tmp_path / "build-out"),
                "--output-dir",
                str(tmp_path / "shards"),
                "--shard-count",
                "1",
            ]
        )


def test_script_can_create_shards_when_invoked_directly(tmp_path: Path) -> None:
    build_out = tmp_path / "build-out"
    _create_target(build_out, "fuzzer_b", executable_size=2)
    _create_target(build_out, "fuzzer_a", executable_size=3)
    output_dir = tmp_path / "shards"
    environment = os.environ.copy()
    environment["FUZZ_TARGETS"] = "fuzzer_b fuzzer_a"

    result = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--build-out",
            str(build_out),
            "--output-dir",
            str(output_dir),
            "--shard-count",
            "1",
        ],
        check=True,
        capture_output=True,
        cwd=tmp_path,
        env=environment,
        text=True,
    )

    prefix, encoded_matrix = result.stdout.rstrip("\n").split("=", maxsplit=1)
    assert prefix == "matrix"
    assert json.loads(encoded_matrix) == {
        "include": [
            {
                "fuzzer": "fuzzer_a",
                "shard": "00",
                "artifact": "fuzz-shard-00",
            },
            {
                "fuzzer": "fuzzer_b",
                "shard": "00",
                "artifact": "fuzz-shard-00",
            },
        ]
    }

    archive = output_dir / "fuzz-shard-00.tar"
    assert archive.is_file()
    with tarfile.open(archive) as output:
        assert {member.name for member in output.getmembers()} == {
            "build-out/fuzzer_a",
            "build-out/fuzzer_a_seed_corpus.zip",
            "build-out/fuzzer_b",
            "build-out/fuzzer_b_seed_corpus.zip",
        }


def test_create_shards_is_deterministic_and_balances_sizes(tmp_path: Path) -> None:
    build_out = tmp_path / "build-out"
    sizes = {
        "fuzzer_a": 9,
        "fuzzer_b": 8,
        "fuzzer_c": 7,
        "fuzzer_d": 6,
        "fuzzer_e": 5,
        "fuzzer_f": 4,
    }
    for name, size in sizes.items():
        _create_target(build_out, name, executable_size=size - 1, corpus_size=1)

    forwards = create_shards(
        list(sizes), build_out, tmp_path / "shards-forwards", shard_count=3
    )
    backwards = create_shards(
        list(reversed(sizes)),
        build_out,
        tmp_path / "shards-backwards",
        shard_count=3,
    )

    assert forwards == backwards
    assert _assignments(forwards) == {
        "fuzzer_a": "00",
        "fuzzer_f": "00",
        "fuzzer_b": "01",
        "fuzzer_e": "01",
        "fuzzer_c": "02",
        "fuzzer_d": "02",
    }
    assert {row["artifact"] for row in forwards["include"]} == {
        "fuzz-shard-00",
        "fuzz-shard-01",
        "fuzz-shard-02",
    }


def test_create_shards_keeps_target_counts_near_equal(tmp_path: Path) -> None:
    build_out = tmp_path / "build-out"
    targets = [f"fuzzer_{index}" for index in range(7)]
    for index, target in enumerate(targets):
        # Exercise the count constraint with one target much larger than the rest.
        _create_target(
            build_out,
            target,
            executable_size=10_000 if index == 0 else index + 1,
        )

    matrix = create_shards(targets, build_out, tmp_path / "shards", shard_count=3)
    assignments = _assignments(matrix)
    counts = [list(assignments.values()).count(f"{index:02d}") for index in range(3)]

    assert sorted(counts) == [2, 2, 3]
    assert set(assignments) == set(targets)
    assert len(assignments) == len(targets)


def test_create_shards_packages_only_its_targets_and_shared_metadata(
    tmp_path: Path,
) -> None:
    build_out = tmp_path / "build-out"
    targets = ["fuzzer_a", "fuzzer_b", "fuzzer_c"]
    for index, target in enumerate(targets, start=1):
        _create_target(build_out, target, executable_size=index)

    (build_out / "http.dict").write_text('"GET"\n', encoding="utf-8")
    (build_out / "fuzzer_a.options").write_text(
        "[libfuzzer]\nmax_len = 10000\n", encoding="utf-8"
    )
    (build_out / "unrelated.txt").write_text("exclude me", encoding="utf-8")

    output_dir = tmp_path / "shards"
    matrix = create_shards(targets, build_out, output_dir, shard_count=2)
    assignments = _assignments(matrix)

    for shard in ("00", "01"):
        expected_targets = {
            target
            for target, assigned_shard in assignments.items()
            if assigned_shard == shard
        }
        archive = output_dir / f"fuzz-shard-{shard}.tar"
        assert archive.is_file()
        with tarfile.open(archive) as tar:
            members = {member.name: member for member in tar.getmembers()}

        expected_names = {
            "build-out/http.dict",
            "build-out/fuzzer_a.options",
        }
        for target in expected_targets:
            expected_names.add(f"build-out/{target}")
            expected_names.add(f"build-out/{target}_seed_corpus.zip")

        assert set(members) == expected_names
        assert "build-out/unrelated.txt" not in members
        for target in expected_targets:
            assert members[f"build-out/{target}"].mode & stat.S_IXUSR


@pytest.mark.parametrize("shard_count", [0, 2])
def test_create_shards_rejects_invalid_shard_count(
    tmp_path: Path, shard_count: int
) -> None:
    build_out = tmp_path / "build-out"
    _create_target(build_out, "fuzzer")

    with pytest.raises(ValueError, match="shard"):
        create_shards(["fuzzer"], build_out, tmp_path / "shards", shard_count)


def test_create_shards_requires_binary_and_seed_corpus(tmp_path: Path) -> None:
    build_out = tmp_path / "build-out"
    build_out.mkdir()

    with pytest.raises(FileNotFoundError, match="missing"):
        create_shards(["missing"], build_out, tmp_path / "missing-shards", 1)

    binary = build_out / "missing"
    binary.write_bytes(b"binary")
    binary.chmod(0o755)
    with pytest.raises(FileNotFoundError, match="missing_seed_corpus.zip"):
        create_shards(["missing"], build_out, tmp_path / "missing-corpus-shards", 1)


def test_create_shards_requires_an_executable_binary(tmp_path: Path) -> None:
    build_out = tmp_path / "build-out"
    _create_target(build_out, "fuzzer", executable=False)

    with pytest.raises(ValueError, match="executable"):
        create_shards(["fuzzer"], build_out, tmp_path / "shards", 1)
