"""Reachability checks for fixed deep-HTTP proxy and socket options."""

from pathlib import Path

SCENARIO_ROOT = (
    Path(__file__).parents[1] / "scenarios" / "curl_fuzzer_proto" / "http_deep"
)


def test_proxy_option_seeds_cover_closed_modes() -> None:
    expected = {
        "http_noproxy_hostname.textproto": "PROXY_SOCKET_OPTION_NOPROXY_HOSTNAME",
        "http_noproxy_ipv4_cidr.textproto": "PROXY_SOCKET_OPTION_NOPROXY_IPV4_CIDR",
        "http_noproxy_ipv6_cidr.textproto": "PROXY_SOCKET_OPTION_NOPROXY_IPV6_CIDR",
        "http_proxy_environment.textproto": "PROXY_SOCKET_OPTION_ENV_HTTP_PROXY",
        "http_loopback_interface_keepalive.textproto": (
            "PROXY_SOCKET_OPTION_LOOPBACK_INTERFACE_KEEPALIVE"
        ),
    }

    for name, mode in expected.items():
        text = (SCENARIO_ROOT / name).read_text(encoding="utf-8")
        assert mode in text, f"{name} lost {mode}"
        assert "HTTP/1.1 200 OK" in text, f"{name} lost its response"
