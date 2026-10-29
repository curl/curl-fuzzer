"""Reachability checks for HTTP/3 and CONNECT-UDP seed correlations."""

from pathlib import Path

SCENARIO_DIR = (
    Path(__file__).resolve().parents[1] / "scenarios" / "curl_fuzzer_proto" / "http3"
)


def test_connect_udp_seeds_keep_hostname_and_ipv6_destinations() -> None:
    hostname = (SCENARIO_DIR / "http3_connect_udp_proxy.textproto").read_text()
    ipv6 = (SCENARIO_DIR / "http3_connect_udp_proxy_ipv6.textproto").read_text()

    assert 'host_path: "tls.test/capsule"' in hostname
    assert 'host_path: "[2001:db8::1]/capsule"' in ipv6
    for scenario in (hostname, ipv6):
        assert "use_h1_connect_udp_proxy: true" in scenario
        assert "101 Switching Protocols" in scenario
        assert "Upgrade: connect-udp" in scenario
