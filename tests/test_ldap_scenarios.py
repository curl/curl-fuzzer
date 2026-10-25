"""Reachability checks for correlated LDAP protocol seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "ldap"


def test_ldap_schema_exposes_bind_credentials(
    active_option_names: frozenset[str],
) -> None:
    """Keep simple-bind credentials reachable through the scalar option path."""
    assert {
        "CURLOPT_USERNAME",
        "CURLOPT_PASSWORD",
        "CURLOPT_USERPWD",
        "CURLOPT_LOGIN_OPTIONS",
        "CURLOPT_SASL_AUTHZID",
        "CURLOPT_SASL_IR",
    } <= active_option_names
    schema = SCENARIO_SCHEMA.read_text(encoding="utf-8")
    assert "SCHEME_LDAP = 17;" in schema
    assert "SCHEME_LDAPS = 18;" in schema


def test_ldap_sasl_seed_pairs_mechanism_discovery_with_search() -> None:
    """The SASL seed must select PLAIN and retain a data-search response."""
    sasl = (SCENARIO_ROOT / "ldap_sasl_plain_search.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_LDAP" in sasl
    assert 'login_options: "AUTH=PLAIN"' in sasl
    assert 'sasl_authzid: "authorization-id"' in sasl
    assert "sasl_ir: true" in sasl
    assert 'on_readable: "\\060\\106\\002\\001\\002\\144' in sasl

    unavailable = (SCENARIO_ROOT / "ldap_sasl_unavailable.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=LOGIN"' in unavailable
    assert "on_readable:" not in unavailable


def test_ldap_success_seed_pairs_bind_with_search_entry() -> None:
    """The success seed must reach the LDIF formatter with a BER entry."""
    success = (SCENARIO_ROOT / "ldap_bind_search.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_LDAP" in success
    assert 'host_path: "ldap.test/dc=example,dc=com?cn?sub?(objectclass=*)"' in success
    assert 'username: "cn=admin,dc=example,dc=com"' in success
    assert 'password: "secret"' in success
    # searchResEntry: SEQUENCE, messageID 2, application tag 4 (0x64).
    assert 'on_readable: "\\060\\106\\002\\001\\002\\144' in success
    assert "initial_response" not in success


def test_ldap_rejected_bind_seed_stops_before_search() -> None:
    """A scripted bind failure must not carry search-result chunks."""
    rejected = (SCENARIO_ROOT / "ldap_bind_rejected.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_LDAP" in rejected
    # bindResponse with resultCode 49 (LDAP_INVALID_CREDENTIALS).
    assert (
        'initial_response: "\\060\\037\\002\\001\\001\\141\\032\\012\\001\\061'
        in rejected
    )
    assert "on_readable" not in rejected


def test_ldaps_seed_runs_bind_and_search_over_implicit_tls() -> None:
    """The LDAPS seed must reach the same BER peer through the TLS transport."""
    secure = (SCENARIO_ROOT / "ldaps_bind_search.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_LDAPS" in secure
    assert 'host_path: "tls.test/dc=example,dc=com?cn?sub?(objectclass=*)"' in secure
    assert 'username: "cn=admin,dc=example,dc=com"' in secure
    assert 'password: "secret"' in secure
    # searchResEntry: SEQUENCE, messageID 2, application tag 4 (0x64).
    assert 'on_readable: "\\060\\106\\002\\001\\002\\144' in secure
    assert "initial_response" not in secure


def test_ldap_starttls_seed_correlates_the_upgrade_mode() -> None:
    """Keep StartTLS separate from both plaintext bind and implicit LDAPS."""
    starttls = (SCENARIO_ROOT / "ldap_starttls.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_LDAP" in starttls
    assert 'host_path: "ldap.test/' in starttls
    assert "ldap_starttls: true" in starttls
    assert "SCHEME_LDAPS" not in starttls
