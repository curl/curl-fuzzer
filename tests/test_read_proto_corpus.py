"""Schema discovery tests for the structured-corpus decoder."""

from __future__ import annotations

from pathlib import Path

import pytest

from curl_fuzzer_tools import read_proto_corpus


def _place_module(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    module = root / "src" / "curl_fuzzer_tools" / "read_proto_corpus.py"
    module.parent.mkdir(parents=True)
    module.touch()
    monkeypatch.setattr(read_proto_corpus, "__file__", str(module))
    monkeypatch.chdir(root)


def test_explicit_schema_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = tmp_path / "chosen.proto"
    explicit.touch()
    monkeypatch.setenv("CURL_FUZZER_PROTO", str(tmp_path / "other.proto"))

    assert read_proto_corpus.find_proto_file(explicit) == explicit


def test_missing_explicit_schema_is_an_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.proto"

    with pytest.raises(FileNotFoundError, match="--proto-file"):
        read_proto_corpus.find_proto_file(missing)


def test_environment_schema_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _place_module(monkeypatch, tmp_path)
    configured = tmp_path / "configured.proto"
    configured.touch()
    staged = tmp_path / "build" / "schemas" / "curl_fuzzer.proto"
    staged.parent.mkdir(parents=True)
    staged.touch()
    monkeypatch.setenv("CURL_FUZZER_PROTO", str(configured))

    assert read_proto_corpus.find_proto_file(None) == configured


def test_checked_in_schema_precedes_staged_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _place_module(monkeypatch, tmp_path)
    monkeypatch.delenv("CURL_FUZZER_PROTO", raising=False)
    staged = tmp_path / "build" / "schemas" / "curl_fuzzer.proto"
    staged.parent.mkdir(parents=True)
    staged.touch()
    checked_in = tmp_path / "schemas" / "curl_fuzzer.proto"
    checked_in.parent.mkdir(parents=True)
    checked_in.touch()

    assert read_proto_corpus.find_proto_file(None) == checked_in


def test_checked_in_schema_is_used_without_a_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _place_module(monkeypatch, tmp_path)
    monkeypatch.delenv("CURL_FUZZER_PROTO", raising=False)
    checked_in = tmp_path / "schemas" / "curl_fuzzer.proto"
    checked_in.parent.mkdir(parents=True)
    checked_in.touch()

    assert read_proto_corpus.find_proto_file(None) == checked_in


def test_checked_in_schema_is_found_from_working_tree_after_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _place_module(monkeypatch, tmp_path / "installed")
    checkout = tmp_path / "checkout"
    checked_in = checkout / "schemas" / "curl_fuzzer.proto"
    checked_in.parent.mkdir(parents=True)
    checked_in.touch()
    monkeypatch.chdir(checkout)

    assert read_proto_corpus.find_proto_file(None) == checked_in


def test_missing_schema_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _place_module(monkeypatch, tmp_path)
    monkeypatch.delenv("CURL_FUZZER_PROTO", raising=False)

    assert read_proto_corpus.find_proto_file(None) is None
