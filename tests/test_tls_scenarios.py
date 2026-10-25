"""Reachability checks for the structured TLS lane and its correlated seeds."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
TLS_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "https"
TLS_CREDENTIALS = REPO_ROOT / "proto_fuzzer" / "tls_test_credentials.h"


def _ech_config_list() -> str:
    credentials = TLS_CREDENTIALS.read_text(encoding="utf-8")
    declaration = re.search(
        r"kEchConfigListBase64\[\]\s*=\s*((?:\s*\"[^\"]*\")+)\s*;",
        credentials,
    )
    assert declaration is not None
    return "".join(re.findall(r'"([^"]*)"', declaration.group(1)))


def test_tls_controls_are_reachable_as_copied_values(
    active_option_names: frozenset[str],
) -> None:
    """Keep TLS mutation state scalar/string-backed and independent of files."""
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
        "CURLOPT_SSL_VERIFYSTATUS",
        "CURLOPT_PINNEDPUBLICKEY",
        "CURLOPT_ECH",
    } <= active_option_names
    assert {
        "CURLOPT_CAINFO",
        "CURLOPT_CAPATH",
        "CURLOPT_SSLCERT",
        "CURLOPT_SSLKEY",
    }.isdisjoint(active_option_names)


def test_tls_seeds_retain_version_pin_and_session_correlations() -> None:
    """Protect values that blind protobuf mutation is unlikely to recreate."""
    expected_tokens = {
        "https_certinfo_all_key_types.textproto": (
            "TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES",
            "certinfo: true",
            "all-keys",
        ),
        "https_tls13_certinfo.textproto": (
            "certinfo: true",
            "ssl_verifyhost: 2",
            "tls13",
        ),
        "https_tls12_ciphers.textproto": (
            "sslversion: 393222",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ecdsa_secp256r1_sha256",
        ),
        "https_gnutls_tls12_priority.textproto": (
            "sslversion: 393222",
            "NORMAL:-VERS-ALL:+VERS-TLS1.2",
            "gnutls-tls12",
        ),
        "https_pinned_public_key.textproto": (
            "pinnedpublickey:",
            "sha256//ohF20oHrdt/MM3YpyIewiTdtTbgZwq3qatd40TjMtYg=",
            "pinned",
        ),
        "https_session_redirect.textproto": (
            "ssl_sessionid_cache: true",
            "sslversion: 393222",
            "Connection: close",
            "subsequent_connections {",
        ),
        "https_tls_cert_status.textproto": (
            "ssl_verifystatus: true",
            "status-probe",
        ),
        "https_tls_client_engine.textproto": (
            "TLS_CLIENT_CREDENTIAL_ENGINE_DEV_NULL",
            "unreachable",
        ),
        "https_tls_client_pkcs12.textproto": (
            "TLS_CLIENT_CREDENTIAL_MALFORMED_PKCS12",
            "unreachable",
        ),
        "https_tls_client_provider.textproto": (
            "TLS_CLIENT_CREDENTIAL_DEFAULT_PROVIDER_DEV_NULL",
            "unreachable",
        ),
        "https_tls_client_provider_unloaded.textproto": (
            "TLS_CLIENT_CREDENTIAL_UNLOADED_PROVIDER_DEV_NULL",
            "unreachable",
        ),
        "https_tls_openssl_close_notify.textproto": (
            "TLS_HANDSHAKE_OPENSSL_CLOSE_NOTIFY",
            "openssl-close-notify",
            "unreachable",
        ),
        "https_ech_success.textproto": (
            "ech:",
            f"ecl:{_ech_config_list()}",
            "ech-success",
        ),
    }

    for name, tokens in expected_tokens.items():
        scenario = (TLS_SCENARIOS / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
