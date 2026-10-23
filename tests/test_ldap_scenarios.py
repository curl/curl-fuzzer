"""Reachability checks for correlated LDAP protocol seeds."""

from __future__ import annotations

from pathlib import Path

from curl_fuzzer_tools.generate_option_manifest import parse_proto_options

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "ldap"


def _supported_options() -> set[str]:
    return {
        option.name
        for option in parse_proto_options(SCENARIO_SCHEMA.read_text(encoding="utf-8"))
    }


def test_ldap_schema_exposes_bind_credentials() -> None:
    """Keep simple-bind credentials reachable through the scalar option path."""
    assert {
        "CURLOPT_USERNAME",
        "CURLOPT_PASSWORD",
        "CURLOPT_USERPWD",
    } <= _supported_options()
    schema = SCENARIO_SCHEMA.read_text(encoding="utf-8")
    assert "SCHEME_LDAP = 17;" in schema
    assert "SCHEME_LDAPS" not in schema


def test_ldap_success_seed_pairs_bind_with_search_entry() -> None:
    """The success seed must reach the LDIF formatter with a BER entry."""
    success = (SCENARIO_ROOT / "ldap_bind_search.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_LDAP" in success
    assert 'host_path: "ldap.test/dc=example,dc=com?cn?sub?(objectclass=*)"' in success
    assert 'CURLOPT_USERNAME string_value: "cn=admin,dc=example,dc=com"' in success
    assert 'CURLOPT_PASSWORD string_value: "secret"' in success
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
