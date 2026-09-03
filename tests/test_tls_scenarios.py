"""Reachability checks for the structured TLS lane and its correlated seeds."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_OPTIONS = REPO_ROOT / "schemas" / "curl_fuzzer_supported_curlopts.txt"
TLS_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "https"
TLS_CREDENTIALS = REPO_ROOT / "proto_fuzzer" / "tls_test_credentials.h"


def _supported_options() -> set[str]:
    return {
        line
        for raw_line in SUPPORTED_OPTIONS.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }


def _ech_config_list() -> str:
    credentials = TLS_CREDENTIALS.read_text(encoding="utf-8")
    declaration = re.search(
        r"kEchConfigListBase64\[\]\s*=\s*((?:\s*\"[^\"]*\")+)\s*;",
        credentials,
    )
    assert declaration is not None
    return "".join(re.findall(r'"([^"]*)"', declaration.group(1)))


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
        "CURLOPT_ECH",
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
        "https_certinfo_all_key_types.textproto": (
            "TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES",
            "CURLOPT_CERTINFO bool_value: true",
            "all-keys",
        ),
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
        "https_gnutls_tls12_priority.textproto": (
            "CURLOPT_SSLVERSION uint_value: 393222",
            "NORMAL:-VERS-ALL:+VERS-TLS1.2",
            "gnutls-tls12",
        ),
        "https_pinned_public_key.textproto": (
            "CURLOPT_PINNEDPUBLICKEY",
            "sha256//ohF20oHrdt/MM3YpyIewiTdtTbgZwq3qatd40TjMtYg=",
            "pinned",
        ),
        "https_session_redirect.textproto": (
            "CURLOPT_SSL_SESSIONID_CACHE bool_value: true",
            "CURLOPT_SSLVERSION uint_value: 393222",
            "Connection: close",
            "subsequent_connections {",
        ),
        "https_ech_success.textproto": (
            "CURLOPT_ECH",
            f"ecl:{_ech_config_list()}",
            "ech-success",
        ),
    }

    for name, tokens in expected_tokens.items():
        scenario = (TLS_SCENARIOS / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
