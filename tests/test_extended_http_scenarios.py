"""Reachability checks for request, framing, and connection-control seeds."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_OPTIONS = REPO_ROOT / "schemas" / "curl_fuzzer_supported_curlopts.txt"
HTTP_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "http"


def _supported_options() -> set[str]:
    return {
        line
        for raw_line in SUPPORTED_OPTIONS.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }


def test_extended_http_options_are_reachable_without_pointer_hazards() -> None:
    """Expose only copied strings/scalars; keep routing and path ownership fixed."""
    supported = _supported_options()
    assert {
        "CURLOPT_RANGE",
        "CURLOPT_RESUME_FROM_LARGE",
        "CURLOPT_FILETIME",
        "CURLOPT_REQUEST_TARGET",
        "CURLOPT_PATH_AS_IS",
        "CURLOPT_EXPECT_100_TIMEOUT_MS",
        "CURLOPT_KEEP_SENDING_ON_ERROR",
        "CURLOPT_POSTREDIR",
        "CURLOPT_TRANSFER_ENCODING",
        "CURLOPT_HTTP_TRANSFER_DECODING",
        "CURLOPT_HTTP_CONTENT_DECODING",
        "CURLOPT_IGNORE_CONTENT_LENGTH",
        "CURLOPT_DISALLOW_USERNAME_IN_URL",
        "CURLOPT_FRESH_CONNECT",
        "CURLOPT_FORBID_REUSE",
        "CURLOPT_MAXAGE_CONN",
        "CURLOPT_MAXLIFETIME_CONN",
        "CURLOPT_UPLOAD_BUFFERSIZE",
        "CURLOPT_MIME_OPTIONS",
        "CURLOPT_MAXFILESIZE_LARGE",
        "CURLOPT_BUFFERSIZE",
        "CURLOPT_CRLF",
        "CURLOPT_CERTINFO",
    } <= supported
    assert {
        "CURLOPT_CONNECT_TO",
        "CURLOPT_RESOLVE",
        "CURLOPT_OPENSOCKETFUNCTION",
        "CURLOPT_READFUNCTION",
        "CURLOPT_COOKIEFILE",
        "CURLOPT_CRLFILE",
        "CURLOPT_MAXCONNECTS",
    }.isdisjoint(supported)


def test_extended_http_seeds_retain_correlated_wire_state() -> None:
    """Protect the option/response pairs mutation is unlikely to rediscover."""
    expected_tokens = {
        "http_range_206.textproto": (
            "CURLOPT_RANGE",
            "206 Partial Content",
            "Content-Range: bytes 5-11/20",
        ),
        "http_resume_filetime_206.textproto": (
            "CURLOPT_RESUME_FROM_LARGE",
            "CURLOPT_FILETIME",
            "Last-Modified:",
        ),
        "http_request_target_path_as_is.textproto": (
            "CURLOPT_REQUEST_TARGET",
            "CURLOPT_PATH_AS_IS",
            "/wire/../target",
        ),
        "http_expect_417_retry.textproto": (
            "417 Expectation Failed",
            "Expect: 100-continue",
            "subsequent_connections {",
        ),
        "http_early_413_keep_sending.textproto": (
            "413 Content Too Large",
            "CURLOPT_KEEP_SENDING_ON_ERROR",
            "Expect: 100-continue",
        ),
        "http_postredir_preserve_method.textproto": (
            "CURLOPT_POSTREDIR",
            "301 Moved Permanently",
            "subsequent_connections {",
        ),
        "http_follow_obeycode_custom_method.textproto": (
            "CURLOPT_FOLLOWLOCATION uint_value: 2",
            'CURLOPT_CUSTOMREQUEST string_value: "PATCH"',
            "302 Found",
        ),
        "http_follow_firstonly_custom_method.textproto": (
            "CURLOPT_FOLLOWLOCATION uint_value: 3",
            'CURLOPT_CUSTOMREQUEST string_value: "PURGE"',
            "307 Temporary Redirect",
        ),
        "http_decoding_controls_conflicting_length.textproto": (
            "CURLOPT_TRANSFER_ENCODING",
            "CURLOPT_HTTP_TRANSFER_DECODING",
            "Content-Length: 999",
        ),
        "url_disallow_userinfo.textproto": (
            "CURLOPT_DISALLOW_USERNAME_IN_URL",
            "user:pass@userinfo.test",
        ),
        "http_certinfo_result_probe.textproto": (
            "CURLOPT_CERTINFO bool_value: true",
            "Content-Type: text/plain",
        ),
        "http_relative_redirect_chain.textproto": (
            "Location: child path",
            "Location: ?step=2",
            "Location: #done",
        ),
        "http_protocol_relative_redirect.textproto": (
            "Location: //redirect-target.test/final?from=origin",
            "subsequent_connections {",
        ),
        "http_custom_host_ipv6.textproto": (
            "Host: [2001:db8::1]:8443",
            "Set-Cookie: hostonly=1",
        ),
        "http_empty_host_header.textproto": (
            'request_headers: "Host:"',
            "204 No Content",
        ),
        "http2_prior_knowledge.textproto": (
            "CURLOPT_HTTP_VERSION uint_value: 5",
            "text/plain",
        ),
    }

    for name, tokens in expected_tokens.items():
        scenario = (HTTP_SCENARIOS / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
