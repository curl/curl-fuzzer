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
        "http_unix_socket.textproto": (
            "HTTP_TRANSPORT_UNIX_SOCKET",
            "HTTP/1.1 200 OK",
        ),
    }

    for name, markers in expected.items():
        text = (SCENARIO_ROOT / name).read_text(encoding="utf-8")
        for marker in markers:
            assert marker in text, f"{name} lost {marker}"
