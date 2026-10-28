"""Safety and reachability checks for the peerless FILE lane."""

from __future__ import annotations

from pathlib import Path

SCENARIO_ROOT = (
    Path(__file__).resolve().parent.parent / "scenarios" / "curl_fuzzer_proto" / "file"
)


def test_file_upload_seed_uses_bounded_callback_and_anonymous_sink() -> None:
    """The authored upload must select a harness-owned anonymous sink."""
    scenario = (SCENARIO_ROOT / "file_upload.textproto").read_text(encoding="utf-8")

    assert "scheme: SCHEME_FILE" in scenario
    assert 'file_source: "sink"' in scenario
    assert "host_path:" not in scenario
    assert "upload {" in scenario
    assert "read_sizes:" in scenario
    assert "terminal: UPLOAD_TERMINAL_EOF" in scenario
    assert "upload: true" in scenario
    assert "infilesize_large: 20" in scenario


def test_file_resume_seed_correlates_resume_and_upload() -> None:
    """Resume controls are dead unless a bounded local upload is selected."""
    scenario = (SCENARIO_ROOT / "file_upload_resume.textproto").read_text(
        encoding="utf-8"
    )

    assert "upload {" in scenario
    assert "upload: true" in scenario
    assert "resume_from_large: 4" in scenario
    assert "infilesize_large: 15" in scenario


def test_file_upload_abort_seed_uses_bounded_error_after_payload() -> None:
    """The upload error remains finite against the anonymous sink."""
    scenario = (SCENARIO_ROOT / "file_upload_abort.textproto").read_text(
        encoding="utf-8"
    )

    assert 'file_source: "sink"' in scenario
    assert "host_path:" not in scenario
    assert 'data: "partial"' in scenario
    assert "read_sizes: 7" in scenario
    assert "terminal: UPLOAD_TERMINAL_ABORT" in scenario
    assert "upload: true" in scenario
    assert "infilesize_large: 8" in scenario


def test_file_range_seed_correlates_source_and_successful_seek() -> None:
    """A ten-byte source and range 4-4 reach the successful resume path."""
    scenario = (SCENARIO_ROOT / "file_resume_range.textproto").read_text(
        encoding="utf-8"
    )

    assert 'file_source: "0123456789"' in scenario
    assert 'range: "4-4"' in scenario
    assert "host_path:" not in scenario


def test_file_upload_rate_limit_seed_starts_the_send_limiter() -> None:
    """A multi-byte upload with speed one reaches Curl_client_read limiting."""
    scenario = (SCENARIO_ROOT / "file_upload_rate_limit.textproto").read_text(
        encoding="utf-8"
    )

    assert 'data: "AB"' in scenario
    assert "read_sizes: 2" in scenario
    assert "upload: true" in scenario
    assert "infilesize_large: 2" in scenario
    assert "max_send_speed_large: 1" in scenario
