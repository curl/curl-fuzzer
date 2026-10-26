"""Tests for the Python Protobuf runtime check."""

from __future__ import annotations

from pathlib import Path

import pytest

from curl_fuzzer_tools import check_python_protobuf

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    ("version", "supported"),
    [
        ("5.28.9", False),
        ("5.29.0", True),
        ("6.33.6", True),
        ("7.36.2", True),
        ("7.36.2rc1", True),
        ("8.0.0", False),
        ("invalid", False),
    ],
)
def test_supports_version(version: str, supported: bool) -> None:
    assert check_python_protobuf.supports_version(version) is supported


def test_main_accepts_installed_supported_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(check_python_protobuf, "package_version", lambda _name: "7.36.2")
    assert check_python_protobuf.main() == 0


def test_main_reports_missing_runtime(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing(_name: str) -> str:
        raise check_python_protobuf.PackageNotFoundError

    monkeypatch.setattr(check_python_protobuf, "package_version", missing)

    assert check_python_protobuf.main() == 1
    assert "protobuf is not installed" in capsys.readouterr().err


def test_main_reports_unsupported_runtime(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(check_python_protobuf, "package_version", lambda _name: "8.0.0")

    assert check_python_protobuf.main() == 1
    assert "found protobuf 8.0.0" in capsys.readouterr().err


def test_requirement_matches_project_dependency() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'"{check_python_protobuf.REQUIREMENT}"' in pyproject
    assert (
        'check_python_protobuf = "curl_fuzzer_tools.check_python_protobuf:main"'
        in pyproject
    )
