"""Reachability checks for the structured TLS lane and its correlated seeds."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_OPTIONS = REPO_ROOT / "schemas" / "curl_fuzzer_supported_curlopts.txt"
TLS_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "https"


def _supported_options() -> set[str]:
    return {
        line
        for raw_line in SUPPORTED_OPTIONS.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }


def test_tls_controls_are_reachable_as_copied_values() -> None:
    """Keep TLS mutation state scalar/string-backed and independent of files."""
    supported = _supported_options()
    assert {
        "CURLOPT_SSL_VERIFYPEER",
        "CURLOPT_SSL_VERIFYHOST",
        "CURLOPT_CERTINFO",
        "CURLOPT_SSLVERSION",
        "CURLOPT_SSL_CIPHER_LIST",
        "CURLOPT_TLS13_CIPHERS",
        "CURLOPT_SSL_EC_CURVES",
        "CURLOPT_SSL_SIGNATURE_ALGORITHMS",
        "CURLOPT_SSL_SESSIONID_CACHE",
        "CURLOPT_SSL_ENABLE_ALPN",
        "CURLOPT_SSL_OPTIONS",
        "CURLOPT_PINNEDPUBLICKEY",
    } <= supported
    assert {
        "CURLOPT_CAINFO",
        "CURLOPT_CAPATH",
        "CURLOPT_SSLCERT",
        "CURLOPT_SSLKEY",
    }.isdisjoint(supported)


def test_tls_seeds_retain_version_pin_and_session_correlations() -> None:
    """Protect values that blind protobuf mutation is unlikely to recreate."""
    expected_tokens = {
        "https_tls13_certinfo.textproto": (
            "CURLOPT_CERTINFO bool_value: true",
            "CURLOPT_SSL_VERIFYHOST uint_value: 2",
            "tls13",
        ),
        "https_tls12_ciphers.textproto": (
            "CURLOPT_SSLVERSION uint_value: 393222",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ecdsa_secp256r1_sha256",
        ),
        "https_pinned_public_key.textproto": (
            "CURLOPT_PINNEDPUBLICKEY",
            "sha256//ohF20oHrdt/MM3YpyIewiTdtTbgZwq3qatd40TjMtYg=",
            "pinned",
        ),
        "https_session_redirect.textproto": (
            "CURLOPT_SSL_SESSIONID_CACHE bool_value: true",
            "Connection: close",
            "subsequent_connections {",
        ),
    }

    for name, tokens in expected_tokens.items():
        scenario = (TLS_SCENARIOS / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
