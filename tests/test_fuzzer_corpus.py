"""Tests for reproducible fuzzer corpus snapshots."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from curl_fuzzer_tools.fuzzer_corpus import (
    COMPATIBLE_CORPUS_TARGETS,
    HISTORICAL_PROTO_CORPUS_TARGETS,
    CorpusError,
    CorpusSnapshotBuilder,
    parse_corpus_mappings,
    resolve_corpus_sources,
)


def test_snapshot_combines_supported_sources_and_deduplicates_content(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    (directory / "alpha").write_bytes(b"alpha")
    (directory / "duplicate-alpha").write_bytes(b"alpha")

    archive = tmp_path / "corpus.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("nested/", b"")
        output.writestr("nested/duplicate-alpha", b"alpha")
        output.writestr("beta", b"beta")

    single_file = tmp_path / "gamma"
    single_file.write_bytes(b"gamma")
    destination = tmp_path / "snapshot"
    builder = CorpusSnapshotBuilder(destination)

    for source in (directory, archive, single_file):
        builder.add(source)

    assert {path.read_bytes() for path in destination.iterdir()} == {
        b"alpha",
        b"beta",
        b"gamma",
    }
    assert {path.name for path in destination.iterdir()} == {
        "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
        "be9d587defa1f0c09ef49eb17e206983a5f8f8289e4281860bd0ee5a19592c67",
        "f44e64e75f3948e9f73f8dfa94721c4ce8cbb4f265c4790c702b2d41cfbf2753",
    }
    assert builder.metadata() == {
        "count": 3,
        "bytes": 14,
        "sha256": ("0d84ccec67b73f9b65b20bc9d7f0dc0df9079c357d05df46648030f8060bf71d"),
        "sources": [
            str(source.resolve()) for source in (directory, archive, single_file)
        ],
    }


def test_snapshot_rejects_a_missing_source(tmp_path: Path) -> None:
    builder = CorpusSnapshotBuilder(tmp_path / "snapshot")

    with pytest.raises(CorpusError, match="corpus source does not exist"):
        builder.add(tmp_path / "missing")


def test_parse_corpus_mappings_preserves_repeated_paths_and_equals_signs() -> None:
    assert parse_corpus_mappings(
        ["target=first", "target=path=with=equals", "other=third"]
    ) == {
        "target": [Path("first"), Path("path=with=equals")],
        "other": [Path("third")],
    }


@pytest.mark.parametrize("value", ["target", "=path", "target="])
def test_parse_corpus_mappings_rejects_malformed_values(value: str) -> None:
    with pytest.raises(CorpusError, match="expected TARGET=PATH"):
        parse_corpus_mappings([value])


def test_override_replaces_all_discovered_sources(tmp_path: Path) -> None:
    override = tmp_path / "override"
    sources = resolve_corpus_sources(
        "target",
        tmp_path / "bin",
        tmp_path / "corpora",
        tmp_path / "public",
        {"target": [override]},
    )

    assert sources == [override]


def test_resolver_rejects_a_target_without_corpus_sources(tmp_path: Path) -> None:
    with pytest.raises(CorpusError, match="no corpus found for missing"):
        resolve_corpus_sources(
            "missing",
            tmp_path / "bin",
            tmp_path / "corpora",
            tmp_path / "public",
            {},
        )


def test_target_uses_its_matching_checked_in_corpus(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpora"
    proto_http = corpus_root / "curl_fuzzer_proto_http"
    proto_http.mkdir(parents=True)
    (proto_http / "seed").write_bytes(b"proto")

    sources = resolve_corpus_sources(
        "curl_fuzzer_proto_http",
        tmp_path / "bin",
        corpus_root,
        None,
        {},
    )

    assert sources == [proto_http]


def test_fixed_proto_lane_includes_historical_public_corpus(tmp_path: Path) -> None:
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

    sources = resolve_corpus_sources(
        "curl_fuzzer_proto_http",
        tmp_path / "bin",
        corpus_root,
        public_root,
        {},
    )

    assert sources == [proto_http, current_public, historical_public]


@pytest.mark.parametrize(
    "target",
    ["curl_fuzzer_proto_https_gnutls", "curl_fuzzer_proto_https_mbedtls"],
)
def test_tls_lane_reuses_compatible_https_corpora(tmp_path: Path, target: str) -> None:
    corpus_root = tmp_path / "corpora"
    https_corpus = corpus_root / "curl_fuzzer_proto_https"
    https_corpus.mkdir(parents=True)
    (https_corpus / "seed").write_bytes(b"https")

    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    https_seed_archive = binary_dir / "curl_fuzzer_proto_https_seed_corpus.zip"
    https_seed_archive.write_bytes(b"seed archive")

    public_root = tmp_path / "public"
    target_public = public_root / target
    https_public = public_root / "curl_fuzzer_proto_https"
    historical_public = public_root / "curl_fuzzer_proto"
    for directory in (target_public, https_public, historical_public):
        directory.mkdir(parents=True)
        (directory / "input").write_bytes(directory.name.encode())

    sources = resolve_corpus_sources(
        target,
        binary_dir,
        corpus_root,
        public_root,
        {},
    )

    assert sources == [
        https_corpus,
        https_seed_archive,
        target_public,
        https_public,
        historical_public,
    ]


def test_http3_lane_reuses_compatible_https_corpora(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpora"
    http3_corpus = corpus_root / "curl_fuzzer_proto_http3"
    https_corpus = corpus_root / "curl_fuzzer_proto_https"
    http3_corpus.mkdir(parents=True)
    https_corpus.mkdir()
    (http3_corpus / "h3-seed").write_bytes(b"http3")
    (https_corpus / "https-seed").write_bytes(b"https")

    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    https_seed_archive = binary_dir / "curl_fuzzer_proto_https_seed_corpus.zip"
    https_seed_archive.write_bytes(b"seed archive")

    public_root = tmp_path / "public"
    http3_public = public_root / "curl_fuzzer_proto_http3"
    https_public = public_root / "curl_fuzzer_proto_https"
    historical_public = public_root / "curl_fuzzer_proto"
    for directory in (http3_public, https_public, historical_public):
        directory.mkdir(parents=True)
        (directory / "input").write_bytes(directory.name.encode())

    sources = resolve_corpus_sources(
        "curl_fuzzer_proto_http3",
        binary_dir,
        corpus_root,
        public_root,
        {},
    )

    assert sources == [
        http3_corpus,
        https_corpus,
        https_seed_archive,
        http3_public,
        https_public,
        historical_public,
    ]


def test_compatible_target_policy_keeps_wire_formats_aligned() -> None:
    assert COMPATIBLE_CORPUS_TARGETS == {
        "curl_fuzzer_proto_http2": ("curl_fuzzer_proto_https_h2",),
        "curl_fuzzer_proto_https_gnutls": ("curl_fuzzer_proto_https",),
        "curl_fuzzer_proto_https_mbedtls": ("curl_fuzzer_proto_https",),
        "curl_fuzzer_proto_http3": ("curl_fuzzer_proto_https",),
    }


@pytest.mark.parametrize(
    ("target", "uses_historical_proto"),
    [
        ("curl_fuzzer_proto_http_deep", True),
        ("curl_fuzzer_proto_telnet", True),
        ("curl_fuzzer_proto_h2_proxy", False),
        ("curl_fuzzer_proto_https_h2", False),
        ("curl_fuzzer_proto_http2", False),
        ("curl_fuzzer_proto_socks4", False),
        ("curl_fuzzer_proto_resolver", False),
    ],
)
def test_historical_proto_corpus_policy(
    target: str, uses_historical_proto: bool
) -> None:
    assert (target in HISTORICAL_PROTO_CORPUS_TARGETS) is uses_historical_proto
