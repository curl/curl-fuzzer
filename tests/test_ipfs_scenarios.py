"""Reachability checks for the IPFS/IPNS gateway seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "ipfs"
DEFAULT_CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
DEFAULT_IPNS_NAME = "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8"


def test_ipfs_schema_appends_gateway_schemes(
    active_option_names: frozenset[str],
) -> None:
    """Keep both gateway schemes on their dedicated append-only values."""
    schema = SCENARIO_SCHEMA.read_text(encoding="utf-8")
    assert "SCHEME_IPFS = 24;" in schema
    assert "SCHEME_IPNS = 25;" in schema
    assert {
        "CURLOPT_FAILONERROR",
        "CURLOPT_RANGE",
        "CURLOPT_USERAGENT",
    } <= active_option_names


def test_ipfs_get_seed_uses_gateway_path_and_http_response() -> None:
    """An IPFS GET must parse as a complete HTTP/1.1 gateway exchange."""
    seed = (SCENARIO_ROOT / "ipfs_gateway_get.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_IPFS" in seed
    assert f'host_path: "{DEFAULT_CID}/index.html"' in seed
    assert 'useragent: "curl-fuzzer-ipfs"' in seed
    assert "HTTP/1.1 200 OK" in seed
    assert "Content-Length: 18" in seed
    assert "ipfs gateway body" in seed


def test_ipns_get_seed_preserves_name_namespace() -> None:
    """IPNS uses the same HTTP exchange under the /ipns/ gateway namespace."""
    seed = (SCENARIO_ROOT / "ipns_gateway_get.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_IPNS" in seed
    assert f'host_path: "{DEFAULT_IPNS_NAME}/site/index.html"' in seed
    assert "X-Ipns-Path: /ipns/" + DEFAULT_IPNS_NAME in seed
    assert "HTTP/1.1 200 OK" in seed


def test_ipfs_error_seed_reaches_gateway_status() -> None:
    """A gateway 404 becomes a completed transfer error with FAILONERROR."""
    seed = (SCENARIO_ROOT / "ipfs_gateway_not_found.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_IPFS" in seed
    assert "failonerror: true" in seed
    assert "HTTP/1.1 404 Not Found" in seed
    assert "Content-Length: 0" in seed
