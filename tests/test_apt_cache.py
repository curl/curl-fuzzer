# Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
# SPDX-License-Identifier: curl
"""Verify APT cache freshness and archive integrity without installing packages."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "apt_cache.py"


def _load_module():  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location("apt_cache", SCRIPT)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _record(
    filename: str = "doxygen_1%3a1.9.8-1_amd64.deb",
    content: bytes = b"trusted package",
    mirror: str = "https://archive.ubuntu.com/ubuntu",
) -> str:
    return (
        f"'{mirror}/pool/{filename}' {filename} {len(content)} "
        f"SHA256:{hashlib.sha256(content).hexdigest()}\n"
    )


def _plan(tmp_path: Path, text: str) -> tuple[Path, dict[str, str]]:
    plan = tmp_path / "plan.txt"
    manifest = tmp_path / "manifest.json"
    plan.write_text(text, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "plan", str(plan), str(manifest)],
        capture_output=True,
        text=True,
        check=True,
    )
    outputs = dict(line.split("=", 1) for line in result.stdout.splitlines())
    return manifest, outputs


def test_plan_accepts_real_apt_output_and_encoded_epoch(tmp_path: Path) -> None:
    manifest, outputs = _plan(
        tmp_path,
        "Reading package lists...\n"
        "The following additional packages will be installed:\n  libclang1-18\n"
        "Need to get 20 MB of archives.\n"
        + _record("libclang1-18_18.0.1-1_amd64.deb")
        + _record(),
    )

    entries = json.loads(manifest.read_text(encoding="utf-8"))
    assert [entry["filename"] for entry in entries] == [
        "doxygen_1%3a1.9.8-1_amd64.deb",
        "libclang1-18_18.0.1-1_amd64.deb",
    ]
    assert entries[0]["sha256"] == hashlib.sha256(b"trusted package").hexdigest()
    assert outputs["has-downloads"] == "true"
    assert len(outputs["key"]) == 64


def test_plan_key_ignores_mirror_and_record_order(tmp_path: Path) -> None:
    _, original = _plan(tmp_path, _record() + _record("dependency_1_all.deb"))
    _, relocated = _plan(
        tmp_path,
        _record("dependency_1_all.deb", mirror="http://azure.archive.ubuntu.com/ubuntu")
        + _record(mirror="http://security.ubuntu.com/ubuntu"),
    )

    assert original["key"] == relocated["key"]


def test_plan_accepts_hosted_runner_mirror_file_transport(tmp_path: Path) -> None:
    manifest, direct = _plan(tmp_path, _record("sl_5.02-1_amd64.deb"))
    expected_manifest = manifest.read_text(encoding="utf-8")
    manifest, mirrored = _plan(
        tmp_path,
        _record("sl_5.02-1_amd64.deb", mirror="mirror+file:/etc/apt/apt-mirrors.txt"),
    )

    assert mirrored == direct
    assert manifest.read_text(encoding="utf-8") == expected_manifest


@pytest.mark.parametrize(
    "replacement",
    [
        _record("dependency_2_all.deb"),
        _record("dependency_1_all.deb", content=b"updated package"),
        _record("dependency_1_all.deb", content=b"different length package"),
    ],
)
def test_plan_key_changes_when_transitive_archive_changes(
    tmp_path: Path, replacement: str
) -> None:
    _, original = _plan(tmp_path, _record() + _record("dependency_1_all.deb"))
    _, updated = _plan(tmp_path, _record() + replacement)

    assert original["key"] != updated["key"]


def test_empty_plan_skips_cache(tmp_path: Path) -> None:
    manifest, outputs = _plan(
        tmp_path, "doxygen is already the newest version.\n0 newly installed.\n"
    )

    assert json.loads(manifest.read_text(encoding="utf-8")) == []
    assert outputs["has-downloads"] == "false"


@pytest.mark.parametrize(
    "text",
    [
        _record("../escape.deb"),
        _record("/absolute.deb"),
        _record("back\\slash.deb"),
        _record(".hidden.deb"),
        _record("package.tar"),
        _record() + _record(),
        _record().replace("SHA256:", "MD5Sum:"),
        _record().replace("SHA256:", "SHA256:broken"),
        _record().replace(" 15 SHA256:", " -1 SHA256:"),
        _record().replace(" 15 SHA256:", " not-a-size SHA256:"),
        _record() + "'https://example.com/broken.deb' malformed\n",
        _record().replace("'https://archive.ubuntu.com/ubuntu/pool/", "'invalid/"),
        _record().replace("'", ""),
        _record(mirror="mirror+file:/etc/apt/apt-mirrors.txt").replace("'", ""),
    ],
)
def test_plan_rejects_malformed_or_unsafe_records(text: str) -> None:
    module = _load_module()

    with pytest.raises(ValueError, match="APT download plan line"):
        module.parse_plan(text)


def test_verified_cache_retains_valid_archives_and_removes_invalid_files(
    tmp_path: Path,
) -> None:
    module = _load_module()
    archives = tmp_path / "archives"
    archives.mkdir()
    valid = archives / "valid_1_all.deb"
    valid.write_bytes(b"valid package")
    corrupt = archives / "corrupt_1_all.deb"
    corrupt.write_bytes(b"wrong package")  # Same size as the trusted bytes.
    short = archives / "short_1_all.deb"
    short.write_bytes(b"short")
    outside = tmp_path / "outside.deb"
    outside.write_bytes(b"valid package")
    linked = archives / "linked_1_all.deb"
    linked.symlink_to(outside)
    dangling = archives / "dangling_1_all.deb"
    dangling.symlink_to(tmp_path / "missing")
    unplanned = archives / "obsolete_1_all.deb"
    unplanned.write_bytes(b"unplanned package")
    nested = archives / "directory.deb"
    nested.mkdir()
    (nested / "junk").write_bytes(b"junk")
    # The cache action never saves lock files or partial download directories.
    (archives / "lock").write_text("", encoding="utf-8")
    (archives / "partial").mkdir()
    manifest, _ = _plan(
        tmp_path,
        "".join(
            _record(name, content=b"valid package")
            for name in [
                valid.name,
                corrupt.name,
                short.name,
                linked.name,
                "missing_1_all.deb",
            ]
        ),
    )

    assert module.verify_archives(module.read_manifest(manifest), archives) == (1, 6)
    assert sorted(path.name for path in archives.glob("*.deb")) == [valid.name]
    assert valid.read_bytes() == b"valid package"
    assert outside.read_bytes() == b"valid package"
    assert (archives / "lock").exists()
    assert (archives / "partial").is_dir()
    assert module.verify_archives(module.read_manifest(manifest), archives) == (1, 0)


def test_verify_cli_discards_corruption_and_leaves_missing_archive_for_apt(
    tmp_path: Path,
) -> None:
    archives = tmp_path / "archives"
    archives.mkdir()
    (archives / "package_1_all.deb").write_bytes(b"bad")
    manifest, _ = _plan(tmp_path, _record("package_1_all.deb", content=b"new"))

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "verify", str(manifest), str(archives)],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "retained 0 verified archives; discarded 1" in result.stdout
    assert list(archives.glob("*.deb")) == []


def test_cli_rejects_invalid_manifest_before_touching_archive(tmp_path: Path) -> None:
    archives = tmp_path / "archives"
    archives.mkdir()
    cached = archives / "keep_1_all.deb"
    cached.write_bytes(b"keep")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps([{"filename": "../escape.deb", "size": 4, "sha256": "a" * 64}]),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "verify", str(manifest), str(archives)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "unsafe APT archive filename" in result.stderr
    assert cached.read_bytes() == b"keep"
