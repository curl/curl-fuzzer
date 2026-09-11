"""Reachability checks for public easy/multi API coverage seeds."""

from __future__ import annotations

from pathlib import Path

from curl_fuzzer_tools.generate_option_manifest import parse_proto_options

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
API_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "api"


def test_copy_postfields_is_a_supported_option() -> None:
    supported = {
        option.name
        for option in parse_proto_options(SCENARIO_SCHEMA.read_text(encoding="utf-8"))
    }
    assert "CURLOPT_COPYPOSTFIELDS" in supported


def test_api_seeds_preserve_correlated_entrypoints_and_peer_data() -> None:
    expected_tokens = {
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
        "api_copy_postfields.textproto": (
            "CURLOPT_COPYPOSTFIELDS",
            'string_value: "copy\\000body"',
        ),
    }

    for name, tokens in expected_tokens.items():
        scenario = (API_SCENARIOS / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
