"""Tests for a reproducible, byte-preserving historical HTTP/2 handoff."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from curl_fuzzer_tools import bootstrap_http2_corpus as bootstrapper
from curl_fuzzer_tools.fuzzer_corpus import CorpusError, resolve_corpus_sources

SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "curl_fuzzer.proto"
H2_OPTION = "options {\n  option_id: CURLOPT_HTTP_VERSION\n  uint_value: 5\n}\n"
H1_OPTION = H2_OPTION.replace("uint_value: 5", "uint_value: 2")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (H2_OPTION, True),
        (H2_OPTION + H1_OPTION, False),
        (H1_OPTION + H2_OPTION, True),
        ("options {\n}\n" * 63 + H2_OPTION, True),
        ("options {\n}\n" * 64 + H2_OPTION, False),
        ("api_plan {\n  " + H2_OPTION.replace("\n", "\n  ") + "}\n", False),
        (H2_OPTION.replace("uint_value: 5", "bool_value: true"), False),
        (H2_OPTION + "options {\n  option_id: CURLOPT_HTTP_VERSION\n}\n", False),
        ('host_path: "options {\\n  uint_value: 5\\n}"\n', False),
        (H2_OPTION.replace("uint_value: 5", "uint_value: 50"), False),
    ],
)
def test_selection_respects_final_version_and_visible_option_prefix(
    text: str, expected: bool
) -> None:
    assert bootstrapper.selects_prior_knowledge(text) is expected


def test_option_prefix_matches_harness_limit() -> None:
    header = SCHEMA.parents[1] / "proto_fuzzer" / "scenario_limits.h"
    assert f"kMaxOptions = {bootstrapper._MAX_OPTIONS};" in header.read_text()


def test_missing_protoc_fails_before_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrapper.shutil, "which", lambda _: None)
    with pytest.raises(CorpusError, match="protoc is required"):
        bootstrapper.bootstrap(
            [tmp_path / "source"], tmp_path / "out", tmp_path / "manifest", SCHEMA
        )
    assert not (tmp_path / "out").exists()


def test_interrupted_publication_preserves_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "native"
    destination.mkdir()
    target = destination / "input"
    target.write_bytes(b"original")

    def interrupt(source: Path, destination: Path) -> None:
        assert source.parent == tmp_path
        assert destination == target
        assert source.read_bytes() == b"complete replacement"
        raise OSError("interrupted")

    monkeypatch.setattr(bootstrapper.os, "replace", interrupt)
    with pytest.raises(OSError, match="interrupted"):
        bootstrapper._atomic_write(target, b"complete replacement", tmp_path)
    assert target.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc unavailable")
def test_empty_source_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(CorpusError, match="historical corpus is empty"):
        bootstrapper.bootstrap(
            [source], tmp_path / "out", tmp_path / "manifest", SCHEMA
        )
    assert not (tmp_path / "out").exists()


@pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc unavailable")
def test_wrong_named_schema_is_rejected(tmp_path: Path) -> None:
    schema = tmp_path / "wrong.proto"
    schema.write_text(
        'syntax = "proto3"; package curl.fuzzer.proto; message Scenario {}'
    )
    with pytest.raises(CorpusError, match="HTTP_VERSION selector"):
        bootstrapper.bootstrap(
            [tmp_path / "source"], tmp_path / "out", tmp_path / "manifest", schema
        )
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("artifact", ["manifest", "zip"])
def test_artifacts_cannot_become_replayed_inputs(tmp_path: Path, artifact: str) -> None:
    if shutil.which("protoc") is None:
        pytest.skip("protoc unavailable")
    source = tmp_path / "source"
    source.mkdir()
    kwargs = {"output_zip": source / "bootstrap.zip"} if artifact == "zip" else {}
    manifest = (
        source / "bootstrap.json" if artifact == "manifest" else tmp_path / "manifest"
    )
    with pytest.raises(CorpusError, match="outside corpus directories"):
        bootstrapper.bootstrap([source], tmp_path / "out", manifest, SCHEMA, **kwargs)


@pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc unavailable")
def test_real_protobuf_handoff_is_stable_and_discovered_as_native(
    tmp_path: Path,
) -> None:
    def encode(text: str) -> bytes:
        return subprocess.check_output(
            [
                "protoc",
                f"--proto_path={SCHEMA.parent}",
                "--encode=curl.fuzzer.proto.Scenario",
                SCHEMA.name,
            ],
            input=text.encode(),
        )

    h2 = encode(
        'options { option_id: CURLOPT_HTTP_VERSION uint_value: 5 } connection { initial_response: "\\000\\377" }'
    )
    h1 = encode("options { option_id: CURLOPT_HTTP_VERSION uint_value: 2 }")
    oneof_override = b"\x1a\x06\x08\x54\x58\x05\x60\x01"
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as archive:
        for name, data in {
            "h2": h2,
            "duplicate": h2,
            "h1": h1,
            "oneof": oneof_override,
            "bad": b"\xff",
        }.items():
            archive.writestr(name, data)
    original = source.read_bytes()
    public = tmp_path / "public"
    destination = public / "curl_fuzzer_proto_http2"
    destination.mkdir(parents=True)
    (destination / "native-entry").write_bytes(b"native")
    manifest = public / ".manifests" / "http2-bootstrap.json"
    first_zip, second_zip = tmp_path / "first.zip", tmp_path / "second.zip"
    first = bootstrapper.bootstrap([source], destination, manifest, SCHEMA, first_zip)
    first_manifest = manifest.read_bytes()
    second = bootstrapper.bootstrap([source], destination, manifest, SCHEMA, second_zip)

    assert first == second == json.loads(first_manifest)
    assert manifest.read_bytes() == first_manifest
    assert first_zip.read_bytes() == second_zip.read_bytes()
    assert first["source"]["count"] == 4
    assert first["selected"]["count"] == 1
    assert first["selected_sha256"] == [hashlib.sha256(h2).hexdigest()]
    assert first["rejected_sha256"] == [hashlib.sha256(b"\xff").hexdigest()]
    assert (destination / first["selected_sha256"][0]).read_bytes() == h2
    assert (destination / "native-entry").read_bytes() == b"native"
    assert source.read_bytes() == original
    assert resolve_corpus_sources(
        "curl_fuzzer_proto_http2", tmp_path / "bin", None, public, {}
    ) == [destination]
