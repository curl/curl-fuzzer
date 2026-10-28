"""Static contracts for deterministic Gopher coverage seeds."""

from pathlib import Path

ROOT = (
    Path(__file__).resolve().parents[1] / "scenarios" / "curl_fuzzer_proto" / "gopher"
)


def test_gopher_probe_seeds_use_closed_modes() -> None:
    """Keep timing and oversized-host controls owned by the harness."""
    partial = (ROOT / "gopher_partial_write_no_timeout.textproto").read_text(
        encoding="utf-8"
    )
    assert "GOPHER_PROBE_PARTIAL_WRITE_NO_TIMEOUT" in partial
    assert "timeout_ms" not in partial

    timeout = (ROOT / "gopher_send_timeout.textproto").read_text(encoding="utf-8")
    assert "GOPHER_PROBE_SEND_TIMEOUT" in timeout
    assert "timeout_ms" not in timeout
    assert "backpressure" not in timeout

    tls_limit = (ROOT / "gophers_tls_session_key_limit.textproto").read_text(
        encoding="utf-8"
    )
    assert "GOPHER_PROBE_TLS_SESSION_KEY_LIMIT" in tls_limit
    assert "ssl_options: 1" in tls_limit
    assert "ssl_verifypeer: false" in tls_limit
    assert "g" * 10163 not in tls_limit
