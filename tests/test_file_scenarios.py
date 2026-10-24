"""Safety and reachability checks for the peerless FILE lane."""

from __future__ import annotations

from pathlib import Path

SCENARIO_ROOT = (
    Path(__file__).resolve().parent.parent / "scenarios" / "curl_fuzzer_proto" / "file"
)


def test_file_upload_seed_uses_bounded_callback_and_fixed_sink_contract() -> None:
    """The authored upload must select file_upload without naming a host path."""
    scenario = (SCENARIO_ROOT / "file_upload.textproto").read_text(encoding="utf-8")

    assert "scheme: SCHEME_FILE" in scenario
    assert 'host_path: "localhost/should-not-exist"' in scenario
    assert "upload {" in scenario
    assert "read_sizes:" in scenario
    assert "terminal: UPLOAD_TERMINAL_EOF" in scenario
    assert "CURLOPT_UPLOAD bool_value: true" in scenario
    assert "CURLOPT_INFILESIZE_LARGE uint_value: 20" in scenario


def test_file_resume_seed_correlates_resume_and_upload() -> None:
    """Resume controls are dead unless a bounded local upload is selected."""
    scenario = (SCENARIO_ROOT / "file_upload_resume.textproto").read_text(
        encoding="utf-8"
    )

    assert "upload {" in scenario
    assert "CURLOPT_UPLOAD bool_value: true" in scenario
    assert "CURLOPT_RESUME_FROM_LARGE uint_value: 4" in scenario
    assert "CURLOPT_INFILESIZE_LARGE uint_value: 15" in scenario


def test_file_upload_abort_seed_uses_bounded_error_after_payload() -> None:
    """The upload error remains finite and still requires path pinning."""
    scenario = (SCENARIO_ROOT / "file_upload_abort.textproto").read_text(
        encoding="utf-8"
    )

    assert 'host_path: "localhost/not-an-output-file"' in scenario
    assert "/dev/null" not in next(
        line for line in scenario.splitlines() if line.startswith("host_path:")
    )
    assert 'data: "partial"' in scenario
    assert "read_sizes: 7" in scenario
    assert "terminal: UPLOAD_TERMINAL_ABORT" in scenario
    assert "CURLOPT_UPLOAD bool_value: true" in scenario
    assert "CURLOPT_INFILESIZE_LARGE uint_value: 8" in scenario
