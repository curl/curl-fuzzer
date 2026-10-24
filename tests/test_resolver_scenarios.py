"""Checks the resolver lane's source scenarios and isolation wiring."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "resolver"


def test_resolver_lane_has_localhost_and_structured_resolve_seeds() -> None:
    localhost = (SCENARIO_DIR / "localhost.textproto").read_text()
    structured = (SCENARIO_DIR / "resolve_entries.textproto").read_text()

    assert 'host_path: "localhost/' in localhost
    assert "resolve_entries:" not in localhost
    assert 'host_path: "resolve.test/' in structured
    assert 'resolve_entries: "+' in structured
    assert 'resolve_entries: "*:' in structured
    assert 'resolve_entries: "-' in structured


def test_resolver_lane_has_a_doh_httpsrr_seed() -> None:
    doh = (SCENARIO_DIR / "doh_httpsrr_alpn.textproto").read_text()

    assert "scheme: SCHEME_HTTPS" in doh
    assert 'host_path: "tls.test/' in doh
    assert "doh_https_rr: true" in doh
    assert "http2_plan {" in doh
    assert "HTTP2_CLIENT_EVENT_HEADERS" in doh


def test_resolver_httpsrr_trace_seed_only_enables_per_input_tracing() -> None:
    control = (SCENARIO_DIR / "doh_httpsrr_alpn.textproto").read_text()
    traced = (SCENARIO_DIR / "doh_httpsrr_alpn_trace.textproto").read_text()

    def scenario_fields(text: str) -> list[str]:
        return [line for line in text.splitlines() if not line.startswith("#")]

    assert 'trace_config: "all"' not in control
    expected = scenario_fields(control)
    expected.insert(expected.index("http2_plan {"), 'trace_config: "all"')
    assert scenario_fields(traced) == expected


def test_resolver_lane_has_target_local_threaded_outcomes() -> None:
    positive = (SCENARIO_DIR / "threaded_positive.textproto").read_text()
    negative = (SCENARIO_DIR / "threaded_negative.textproto").read_text()
    link_local = (SCENARIO_DIR / "threaded_link_local.textproto").read_text()
    partial = (SCENARIO_DIR / "threaded_partial.textproto").read_text()

    assert "RESOLVER_MODE_THREADED_POSITIVE" in positive
    assert 'host_path: "resolver-positive.test/' in positive
    assert "RESOLVER_MODE_THREADED_NEGATIVE" in negative
    assert 'host_path: "resolver-negative.test/' in negative
    assert "RESOLVER_MODE_THREADED_LINK_LOCAL" in link_local
    assert 'host_path: "resolver-link-local.test/' in link_local
    assert "RESOLVER_MODE_THREADED_PARTIAL" in partial
    assert 'host_path: "resolver-partial.test/' in partial
    for scenario in (positive, negative, link_local, partial):
        assert "resolve_entries:" not in scenario


def test_resolver_lane_has_confined_unix_and_doh_error_outcomes() -> None:
    unix_socket = (SCENARIO_DIR / "unix_socket.textproto").read_text()
    doh_error = (SCENARIO_DIR / "doh_error.textproto").read_text()
    global_lifecycle = (SCENARIO_DIR / "global_lifecycle.textproto").read_text()

    assert "RESOLVER_MODE_UNIX_SOCKET" in unix_socket
    assert 'host_path: "resolver-unix.test/' in unix_socket
    assert "/curl-fuzzer-resolver.sock" not in unix_socket
    assert "RESOLVER_MODE_DOH_ERROR" in doh_error
    assert 'host_path: "tls.test/' in doh_error
    assert "doh_https_rr: true" not in doh_error
    assert "http2_plan {" in doh_error
    assert 'trace_config: "+DOH"' in doh_error
    assert "RESOLVER_MODE_GLOBAL_LIFECYCLE" in global_lifecycle
    assert 'host_path: "localhost/' in global_lifecycle
