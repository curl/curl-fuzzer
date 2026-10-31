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
    assert "doh {" in doh
    assert "DOH_RESPONSE_MODE_NORMAL" in doh
    assert "transport_mode:" not in doh
    assert "http2_plan {" in doh
    assert "HTTP2_CLIENT_EVENT_HEADERS" in doh

    for legacy_name in (
        "doh_error.textproto",
        "doh_http_error.textproto",
        "doh_httpsrr_alpn.textproto",
        "doh_httpsrr_alpn_trace.textproto",
        "doh_httpsrr_ech_pending.textproto",
    ):
        assert "transport_mode:" not in (SCENARIO_DIR / legacy_name).read_text()


def test_resolver_lane_has_a_pending_httpsrr_ech_seed() -> None:
    doh = (SCENARIO_DIR / "doh_httpsrr_ech_pending.textproto").read_text()

    assert "scheme: SCHEME_HTTPS" in doh
    assert 'host_path: "tls.test/' in doh
    assert "doh {" in doh
    assert "DOH_RESPONSE_MODE_NORMAL" in doh
    assert 'trace_config: "all"' in doh
    assert 'ech: "true"' in doh
    assert "http2_plan {" in doh


def test_resolver_lane_has_https_doh_transport_seeds() -> None:
    success = (SCENARIO_DIR / "doh_https_transport.textproto").read_text()
    transport_error = (SCENARIO_DIR / "doh_https_transport_error.textproto").read_text()

    for scenario in (success, transport_error):
        assert "scheme: SCHEME_HTTPS" in scenario
        assert "transport_mode: DOH_TRANSPORT_HTTPS" in scenario
        assert 'host_path: "tls.test/' in scenario
        assert 'trace_config: "+DOH"' in scenario
        assert "http2_plan {" in scenario
    assert "DOH_RESPONSE_MODE_NORMAL" in success
    assert "HTTP2_CLIENT_EVENT_HEADERS" in success
    assert "DOH_RESPONSE_MODE_TRANSPORT_ERROR" in transport_error


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
    queued_cancel = (SCENARIO_DIR / "threaded_queued_cancel.textproto").read_text()

    assert "RESOLVER_MODE_THREADED_POSITIVE" in positive
    assert 'host_path: "resolver-positive.test/' in positive
    assert "RESOLVER_MODE_THREADED_NEGATIVE" in negative
    assert 'host_path: "resolver-negative.test/' in negative
    assert "RESOLVER_MODE_THREADED_LINK_LOCAL" in link_local
    assert 'host_path: "resolver-link-local.test/' in link_local
    assert "RESOLVER_MODE_THREADED_PARTIAL" in partial
    assert 'host_path: "resolver-partial.test/' in partial
    assert "RESOLVER_MODE_THREADED_QUEUED_CANCEL" in queued_cancel
    assert 'host_path: "resolver-queued-cancel.test/' in queued_cancel
    assert 'trace_config: "+THREADS"' in queued_cancel
    for scenario in (positive, negative, link_local, partial, queued_cancel):
        assert "resolve_entries:" not in scenario


def test_resolver_lane_has_confined_unix_and_doh_error_outcomes() -> None:
    unix_socket = (SCENARIO_DIR / "unix_socket.textproto").read_text()
    doh_error = (SCENARIO_DIR / "doh_error.textproto").read_text()
    doh_http_error = (SCENARIO_DIR / "doh_http_error.textproto").read_text()
    global_lifecycle = (SCENARIO_DIR / "global_lifecycle.textproto").read_text()

    assert "RESOLVER_MODE_UNIX_SOCKET" in unix_socket
    assert 'host_path: "resolver-unix.test/' in unix_socket
    assert "/curl-fuzzer-resolver.sock" not in unix_socket
    assert "DOH_RESPONSE_MODE_MALFORMED_DNS" in doh_error
    assert 'host_path: "tls.test/' in doh_error
    assert "resolver_mode:" not in doh_error
    assert "http2_plan {" in doh_error
    assert 'trace_config: "+DOH"' in doh_error
    assert "DOH_RESPONSE_MODE_HTTP_ERROR" in doh_http_error
    assert 'host_path: "tls.test/' in doh_http_error
    assert "http2_plan {" in doh_http_error
    assert 'trace_config: "+DOH"' in doh_http_error
    assert "RESOLVER_MODE_GLOBAL_LIFECYCLE" in global_lifecycle
    assert 'host_path: "localhost/' in global_lifecycle
