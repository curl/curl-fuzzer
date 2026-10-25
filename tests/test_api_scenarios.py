"""Reachability checks for public easy/multi API coverage seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
API_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "api"


def test_copy_postfields_is_a_supported_option(
    active_option_names: frozenset[str],
) -> None:
    assert {
        "CURLOPT_COPYPOSTFIELDS",
        "CURLOPT_LOCALPORT",
        "CURLOPT_LOCALPORTRANGE",
    } <= active_option_names


def test_api_seeds_preserve_correlated_entrypoints_and_peer_data() -> None:
    expected_tokens = {
        "api_easy_events_allocation_failure.textproto": (
            "API_DRIVE_EASY_EVENTS",
            "fail_allocations: 53",
            'host_path: "api.test/event\\201s"',
        ),
        "api_easy_events.textproto": (
            "API_DRIVE_EASY_EVENTS",
            'on_readable: "events"',
        ),
        "api_connect_only.textproto": (
            "API_DRIVE_CONNECT_ONLY",
            'data: "direct-request"',
            'initial_response: "direct-response"',
        ),
        "api_response_pause.textproto": (
            "pause_response_once: true",
            'on_readable: "paused"',
        ),
        "api_pause_buffered.textproto": (
            "pause_response_once: true",
            'accept_encoding: "gzip"',
            "Content-Encoding: gzip",
            "Content-Length: 12311",
        ),
        "api_reentrancy.textproto": (
            "reentrant_probe_selectors: 0",
            "reentrant_probe_selectors: 13",
            "API_DRIVE_MULTI_PERFORM",
        ),
        "api_copy_postfields.textproto": ('copypostfields: "copy\\000body"',),
        "api_url_guess_local_port.textproto": (
            "localport: 12345",
            "localportrange: 3",
            "guess_scheme_url: true",
            "probe_version_info: true",
        ),
        "api_mime_callback_reuse.textproto": (
            "upload_callback: true",
            'data: "callback-mime-reuse-body"',
            "UPLOAD_SEEK_CANTSEEK",
            "repeat_mime_post: true",
            "Content-Length: 0",
        ),
    }

    for name, tokens in expected_tokens.items():
        scenario = (API_SCENARIOS / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
