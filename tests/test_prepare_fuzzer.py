"""Tests for preparing one fuzzer from a CI artifact shard."""

from __future__ import annotations

import io
import stat
import subprocess
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path

import pytest

from curl_fuzzer_tools.prepare_fuzzer import main, prepare_fuzzer

ArchiveMember = tuple[str, bytes, int]
REPO_ROOT = Path(__file__).resolve().parent.parent
PREPARE_FUZZER = REPO_ROOT / "src" / "curl_fuzzer_tools" / "prepare_fuzzer.py"


def _write_archive(archive: Path, members: Sequence[ArchiveMember]) -> None:
    with tarfile.open(archive, mode="w") as output:
        for name, contents, mode in members:
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.size = len(contents)
            output.addfile(member, io.BytesIO(contents))


def _valid_members(target: str = "fuzzer") -> list[ArchiveMember]:
    return [
        (f"build-out/{target}", b"selected binary", 0o751),
        (f"build-out/{target}_seed_corpus.zip", b"selected corpus", 0o640),
    ]


def test_prepare_fuzzer_extracts_selected_files_and_shared_sidecars(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "fuzz-shard-00.tar"
    _write_archive(
        archive,
        [
            *_valid_members("fuzzer-a.1"),
            ("build-out/other_fuzzer", b"other binary", 0o755),
            (
                "build-out/other_fuzzer_seed_corpus.zip",
                b"other corpus",
                0o644,
            ),
            ("build-out/http.dict", b'"GET"\n', 0o644),
            ("build-out/fuzzer.options", b"[libfuzzer]\n", 0o600),
            ("build-out/notes.txt", b"not a sidecar", 0o644),
        ],
    )
    output_dir = tmp_path / "prepared" / "build-out"
    output_dir.mkdir(parents=True)
    stale_executable = output_dir / "stale_fuzzer"
    stale_executable.write_bytes(b"stale executable")
    stale_executable.chmod(0o755)
    stale_data = output_dir / "keep.txt"
    stale_data.write_bytes(b"keep me")

    prepare_fuzzer(archive, "fuzzer-a.1", output_dir)

    selected = output_dir / "fuzzer-a.1"
    assert selected.read_bytes() == b"selected binary"
    assert stat.S_IMODE(selected.stat().st_mode) == 0o751
    corpus = output_dir / "fuzzer-a.1_seed_corpus.zip"
    assert corpus.read_bytes() == b"selected corpus"
    assert stat.S_IMODE(corpus.stat().st_mode) == 0o640
    assert (output_dir / "http.dict").read_bytes() == b'"GET"\n'
    assert (output_dir / "fuzzer.options").read_bytes() == b"[libfuzzer]\n"

    assert not (output_dir / "other_fuzzer").exists()
    assert not (output_dir / "other_fuzzer_seed_corpus.zip").exists()
    assert not (output_dir / "notes.txt").exists()
    assert not stale_executable.exists()
    assert stale_data.read_bytes() == b"keep me"

    executables = [
        path.name
        for path in output_dir.iterdir()
        if path.is_file() and path.stat().st_mode & 0o111
    ]
    assert executables == ["fuzzer-a.1"]


def test_prepare_fuzzer_creates_output_directory(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(archive, _valid_members())
    output_dir = tmp_path / "nested" / "build-out"

    prepare_fuzzer(archive, "fuzzer", output_dir)

    assert (output_dir / "fuzzer").is_file()
    assert (output_dir / "fuzzer_seed_corpus.zip").is_file()


def test_prepare_fuzzer_defaults_to_build_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(archive, _valid_members())
    monkeypatch.chdir(tmp_path)

    prepare_fuzzer(archive, "fuzzer")

    assert (tmp_path / "build-out" / "fuzzer").is_file()


@pytest.mark.parametrize(
    "target",
    ["", ".", "..", "../fuzzer", "nested/fuzzer", "fuzzer;command"],
)
def test_prepare_fuzzer_rejects_unsafe_target_names(
    tmp_path: Path, target: str
) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(archive, _valid_members())

    with pytest.raises(ValueError, match="unsafe"):
        prepare_fuzzer(archive, target, tmp_path / "build-out")


def test_prepare_fuzzer_requires_selected_executable_in_archive(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(
        archive,
        [("build-out/fuzzer_seed_corpus.zip", b"corpus", 0o644)],
    )
    output_dir = tmp_path / "build-out"
    output_dir.mkdir()
    # A stale file must not satisfy validation of the archive itself.
    stale_selected = output_dir / "fuzzer"
    stale_selected.write_bytes(b"stale")
    stale_selected.chmod(0o755)

    with pytest.raises(FileNotFoundError, match="fuzzer"):
        prepare_fuzzer(archive, "fuzzer", output_dir)


def test_prepare_fuzzer_requires_selected_seed_corpus(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(archive, [("build-out/fuzzer", b"binary", 0o755)])

    with pytest.raises(FileNotFoundError, match="fuzzer_seed_corpus.zip"):
        prepare_fuzzer(archive, "fuzzer", tmp_path / "build-out")


def test_prepare_fuzzer_requires_selected_binary_to_be_executable(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "shard.tar"
    members = _valid_members()
    members[0] = ("build-out/fuzzer", b"binary", 0o644)
    _write_archive(archive, members)

    with pytest.raises(ValueError, match="executable"):
        prepare_fuzzer(archive, "fuzzer", tmp_path / "build-out")


def test_prepare_fuzzer_rejects_duplicate_relevant_members(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(
        archive,
        [
            *_valid_members(),
            ("build-out/fuzzer", b"replacement binary", 0o755),
        ],
    )

    with pytest.raises(ValueError, match="duplicate"):
        prepare_fuzzer(archive, "fuzzer", tmp_path / "build-out")


def test_prepare_fuzzer_rejects_non_regular_selected_member(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    with tarfile.open(archive, mode="w") as output:
        binary = tarfile.TarInfo("build-out/fuzzer")
        binary.type = tarfile.SYMTYPE
        binary.linkname = "/bin/true"
        binary.mode = 0o755
        output.addfile(binary)

        corpus = tarfile.TarInfo("build-out/fuzzer_seed_corpus.zip")
        corpus.size = len(b"corpus")
        output.addfile(corpus, io.BytesIO(b"corpus"))

    with pytest.raises(ValueError, match="regular file"):
        prepare_fuzzer(archive, "fuzzer", tmp_path / "build-out")


def test_prepare_fuzzer_does_not_extract_traversal_members(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(
        archive,
        [
            *_valid_members(),
            ("build-out/../../escaped.options", b"escaped", 0o755),
        ],
    )
    output_dir = tmp_path / "work" / "build-out"

    try:
        prepare_fuzzer(archive, "fuzzer", output_dir)
    except ValueError:
        # Rejecting an unsafe archive is also acceptable; it must never write
        # the traversal member outside the destination.
        pass

    assert not (tmp_path / "escaped.options").exists()
    assert not (tmp_path / "work" / "escaped.options").exists()


def test_main_accepts_archive_target_and_output_directory(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(archive, _valid_members())
    output_dir = tmp_path / "build-out"

    main(
        [
            "--archive",
            str(archive),
            "--target",
            "fuzzer",
            "--output-dir",
            str(output_dir),
        ]
    )

    assert (output_dir / "fuzzer").is_file()


def test_main_reports_preparation_errors_as_command_failures(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(archive, [("build-out/fuzzer", b"binary", 0o755)])

    with pytest.raises(SystemExit, match=r"^prepare_fuzzer: .*seed corpus"):
        main(
            [
                "--archive",
                str(archive),
                "--target",
                "fuzzer",
                "--output-dir",
                str(tmp_path / "build-out"),
            ]
        )


def test_script_can_be_executed_directly(tmp_path: Path) -> None:
    archive = tmp_path / "shard.tar"
    _write_archive(archive, _valid_members())
    output_dir = tmp_path / "prepared"

    subprocess.run(
        [
            sys.executable,
            str(PREPARE_FUZZER),
            "--archive",
            str(archive),
            "--target",
            "fuzzer",
            "--output-dir",
            str(output_dir),
        ],
        check=True,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert (output_dir / "fuzzer").read_bytes() == b"selected binary"
    assert (output_dir / "fuzzer_seed_corpus.zip").read_bytes() == b"selected corpus"
