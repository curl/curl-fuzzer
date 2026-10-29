"""Reachability checks for correlated RTSP protocol seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "rtsp"


def test_rtsp_schema_exposes_request_metadata_controls(
    active_option_names: frozenset[str],
) -> None:
    """Keep method, stream, session, transport, and CSeq reachable."""
    assert {
        "CURLOPT_RTSP_REQUEST",
        "CURLOPT_RTSP_SESSION_ID",
        "CURLOPT_RTSP_STREAM_URI",
        "CURLOPT_RTSP_TRANSPORT",
        "CURLOPT_RTSP_CLIENT_CSEQ",
        "CURLOPT_RTSP_SERVER_CSEQ",
        "CURLOPT_RANGE",
    } <= active_option_names
    assert "SCHEME_RTSP = 19;" in SCENARIO_SCHEMA.read_text(encoding="utf-8")


def test_rtsp_describe_seed_pairs_sdp_length_with_body() -> None:
    """A DESCRIBE response must announce exactly the SDP bytes it carries."""
    describe = (SCENARIO_ROOT / "rtsp_describe_sdp.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_RTSP" in describe
    assert 'host_path: "rtsp.test/twister/video"' in describe
    assert "rtsp_request: 2" in describe
    assert "RTSP/1.0 200 OK" in describe
    assert "CSeq: 1" in describe
    assert "Content-Length: 95" in describe
    assert r"a=control:rtsp://rtsp.test/twister/video" in describe


def test_rtsp_options_seed_waits_for_the_request() -> None:
    """OPTIONS has no greeting; its reply is the first scripted chunk."""
    options = (SCENARIO_ROOT / "rtsp_options.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_RTSP" in options
    assert "rtsp_request: 1" in options
    assert "initial_response" not in options
    assert "Public: DESCRIBE, OPTIONS, SETUP, PLAY" in options


def test_rtsp_play_seed_preserves_interleaved_rtp() -> None:
    """The PLAY reply combines a transport mask with an interleaved frame."""
    play = (SCENARIO_ROOT / "rtsp_play_interleaved_rtp.textproto").read_text(
        encoding="utf-8"
    )
    assert "rtsp_request: 5" in play
    assert 'rtsp_session_id: "12345678"' in play
    assert 'range: "npt=0.000-"' in play
    assert "Transport: RTP/AVP/TCP;unicast;interleaved=0-1" in play
    assert "Content-Length: 0" in play
    assert r"$\000\000\014\200\340" in play


def test_rtsp_error_seed_reaches_status_failure() -> None:
    """FAILONERROR turns the 454 status into a completed error transfer."""
    error = (SCENARIO_ROOT / "rtsp_describe_not_found.textproto").read_text(
        encoding="utf-8"
    )
    assert "failonerror: true" in error
    assert "RTSP/1.0 454 Session Not Found" in error
    assert "CSeq: 1" in error


def test_rtsp_retirement_probes_keep_lifecycle_and_faults_harness_owned() -> None:
    lifecycle = (SCENARIO_ROOT / "rtsp_cross_origin_session_reuse.textproto").read_text(
        encoding="utf-8"
    )
    assert "RTSP_PROBE_CROSS_ORIGIN_REUSE" in lifecycle
    assert "Session: learned-session" in lifecycle
    assert "rtsp-other.test" not in lifecycle
    assert lifecycle.count("on_readable:") == 3

    write_failure = (
        SCENARIO_ROOT / "rtsp_split_invalid_rtp_write_failure.textproto"
    ).read_text(encoding="utf-8")
    assert "RTSP_PROBE_SPLIT_INVALID_RTP_WRITE_FAILURE" in write_failure
    assert "buffersize" not in write_failure
    assert "on_readable:" not in write_failure
