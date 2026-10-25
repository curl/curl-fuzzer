"""Reachability checks for request, framing, and connection-control seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HTTP_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "http"


def test_extended_http_options_are_reachable_without_pointer_hazards(
    active_option_names: frozenset[str],
) -> None:
    """Expose only copied strings/scalars; keep routing and path ownership fixed."""
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
        "CURLOPT_HTTPSIG_ALGORITHM",
        "CURLOPT_HTTPSIG_KEY",
        "CURLOPT_HTTPSIG_KEYID",
        "CURLOPT_HTTPSIG_HEADERS",
    } <= active_option_names
    assert {
        "CURLOPT_CONNECT_TO",
        "CURLOPT_RESOLVE",
        "CURLOPT_OPENSOCKETFUNCTION",
        "CURLOPT_READFUNCTION",
        "CURLOPT_COOKIEFILE",
        "CURLOPT_CRLFILE",
        "CURLOPT_MAXCONNECTS",
    }.isdisjoint(active_option_names)


def test_extended_http_seeds_retain_correlated_wire_state() -> None:
    """Protect the option/response pairs mutation is unlikely to rediscover."""
    expected_tokens = {
        "http_range_206.textproto": (
            'range: "5-11"',
            "206 Partial Content",
            "Content-Range: bytes 5-11/20",
        ),
        "http_resume_filetime_206.textproto": (
            "resume_from_large: 8",
            "filetime: true",
            "Last-Modified:",
        ),
        "http_request_target_path_as_is.textproto": (
            'request_target: "/wire/../target?encoded=%2F"',
            "path_as_is: true",
            "/wire/../target",
        ),
        "http_expect_417_retry.textproto": (
            "417 Expectation Failed",
            "Expect: 100-continue",
            "subsequent_connections {",
        ),
        "http_early_413_keep_sending.textproto": (
            "413 Content Too Large",
            "keep_sending_on_error: true",
            "Expect: 100-continue",
        ),
        "http_postredir_preserve_method.textproto": (
            "postredir: 1",
            "301 Moved Permanently",
            "subsequent_connections {",
        ),
        "http_follow_obeycode_custom_method.textproto": (
            "followlocation: 2",
            'customrequest: "PATCH"',
            "302 Found",
        ),
        "http_follow_firstonly_custom_method.textproto": (
            "followlocation: 3",
            'customrequest: "PURGE"',
            "307 Temporary Redirect",
        ),
        "http_decoding_controls_conflicting_length.textproto": (
            "transfer_encoding: true",
            "http_transfer_decoding: false",
            "Content-Length: 999",
        ),
        "http_brotli_decode.textproto": (
            'accept_encoding: ""',
            "Content-Encoding: br",
            "Content-Length: 31",
        ),
        "url_disallow_userinfo.textproto": (
            "disallow_username_in_url: true",
            "user:pass@userinfo.test",
        ),
        "http_certinfo_result_probe.textproto": (
            "certinfo: true",
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
            "http_version: 5",
            "text/plain",
        ),
        "http2_upgrade.textproto": (
            "http_version: 3",
            "101 Switching Protocols",
            "Upgrade: h2c",
            r"\x00\x00\x00\x04",
        ),
        "http_httpsig_ed25519.textproto": (
            "httpsig_algorithm: 1",
            "9f8362f87a484a954e6e740c5b4c0e84229139a20aa8ab56ff66586f6a7d29c5",
            'httpsig_keyid: "fuzz-ed25519"',
            'httpsig_headers: "date: method path authority query content-type: x-fuzz-meta:"',
            'request_headers: "Date: Tue, 20 Apr 2021 02:07:55 GMT"',
            'request_headers: "Content-Type: application/json"',
            'request_headers: "X-Fuzz-Meta: first"',
            'request_headers: "X-Fuzz-Meta: second"',
            "postfields:",
        ),
        "http_httpsig_hmac_sha256.textproto": (
            "httpsig_algorithm: 2",
            'httpsig_key: "7365637265742d66757a7a2d6b6579"',
            'httpsig_keyid: "fuzz-hmac-sha256"',
            "mode=default",
        ),
    }

    for name, tokens in expected_tokens.items():
        scenario = (HTTP_SCENARIOS / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
