"""Reachability checks for the deep-HTTP transport scenarios."""

from pathlib import Path

SCENARIO_ROOT = (
    Path(__file__).parents[1] / "scenarios" / "curl_fuzzer_proto" / "http_deep"
)


def test_http_transport_seeds_cover_proxy_and_unix_modes() -> None:
    expected = {
        "http_forward_proxy.textproto": (
            "HTTP_TRANSPORT_FORWARD_PROXY",
            "HTTP/1.1 200 OK",
        ),
        "http_connect_proxy_staged.textproto": (
            "HTTP_TRANSPORT_CONNECT_PROXY",
            "probe_multi_pollset: true",
            "HTTP/1.1 200 Connection Established",
            "tunneled",
        ),
        "http_connect_haproxy_backpressure.textproto": (
            "HTTP_TRANSPORT_CONNECT_PROXY",
            "haproxy_protocol: true",
            "probe_multi_pollset: true",
            "recv_buf_bytes: 2048",
            "drain_limit: 48",
            "HTTP/1.1 200 Connection Established",
            "proxied",
        ),
        "http_unix_socket.textproto": (
            "HTTP_TRANSPORT_UNIX_SOCKET",
            "HTTP/1.1 200 OK",
        ),
    }

    for name, markers in expected.items():
        text = (SCENARIO_ROOT / name).read_text(encoding="utf-8")
        for marker in markers:
            assert marker in text, f"{name} lost {marker}"

    haproxy = (SCENARIO_ROOT / "http_connect_haproxy_backpressure.textproto").read_text(
        encoding="utf-8"
    )
    assert haproxy.count('request_headers: "X-Haproxy-Pad-') == 1
    pad_line = next(
        line
        for line in haproxy.splitlines()
        if line.startswith('request_headers: "X-Haproxy-Pad-1: ')
    )
    assert len(pad_line.removeprefix('request_headers: "').removesuffix('"')) == 3867
