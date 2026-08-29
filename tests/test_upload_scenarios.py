"""Keep upload callback seeds correlated with the retries that consume them."""

from __future__ import annotations

from pathlib import Path


SCENARIOS = (
    Path(__file__).resolve().parent.parent / "scenarios" / "curl_fuzzer_proto" / "http"
)


def test_upload_retry_seeds_keep_rewind_and_follow_on_responses() -> None:
    """A seek result alone is dead unless a completed flow requests replay."""
    for name, trigger in (
        ("http_upload_redirect_rewind.textproto", "307 Temporary Redirect"),
        ("http_upload_auth_retry.textproto", "401 Unauthorized"),
    ):
        scenario = (SCENARIOS / name).read_text(encoding="utf-8")
        assert "upload {" in scenario
        assert "seek_result: UPLOAD_SEEK_OK" in scenario
        assert "CURLOPT_UPLOAD bool_value: true" in scenario
        assert "subsequent_connections {" in scenario
        assert trigger in scenario


def test_upload_abort_seed_reaches_callback_terminal() -> None:
    """Retain a tiny deterministic input for CURL_READFUNC_ABORT coverage."""
    scenario = (SCENARIOS / "http_upload_callback_abort.textproto").read_text(
        encoding="utf-8"
    )
    assert "terminal: UPLOAD_TERMINAL_ABORT" in scenario
    assert "read_sizes:" in scenario
    assert "BackpressureConfig" not in scenario


def test_upload_cantseek_seed_drives_a_real_redirect_retry() -> None:
    """A curl-level retry is needed to cover rewind failure handling."""
    scenario = (SCENARIOS / "http_upload_redirect_cantseek.textproto").read_text(
        encoding="utf-8"
    )
    assert "307 Temporary Redirect" in scenario
    assert "seek_result: UPLOAD_SEEK_CANTSEEK" in scenario
    assert "CURLOPT_FOLLOWLOCATION uint_value: 1" in scenario
    assert "subsequent_connections {" not in scenario


def test_upload_crlf_seed_rewinds_the_line_conversion_reader() -> None:
    """CRLF conversion needs a replay event to exercise reader control."""
    scenario = (SCENARIOS / "http_upload_crlf_redirect_rewind.textproto").read_text(
        encoding="utf-8"
    )
    assert "CURLOPT_CRLF bool_value: true" in scenario
    assert 'data: "alpha\\nbeta\\n"' in scenario
    assert "seek_result: UPLOAD_SEEK_OK" in scenario
    assert "307 Temporary Redirect" in scenario
    assert "subsequent_connections {" in scenario
