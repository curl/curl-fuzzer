"""Reachability checks for correlated MQTT protocol seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "mqtt"


def test_mqtt_schema_exposes_publish_and_credential_controls(
    active_option_names: frozenset[str],
) -> None:
    """Keep the publish body and CONNECT credentials reachable."""
    assert {
        "CURLOPT_POSTFIELDS",
        "CURLOPT_USERNAME",
        "CURLOPT_PASSWORD",
        "CURLOPT_USERPWD",
    } <= active_option_names
    assert "SCHEME_MQTT = 13;" in SCENARIO_SCHEMA.read_text(encoding="utf-8")
    assert "SCHEME_MQTTS = 22;" in SCENARIO_SCHEMA.read_text(encoding="utf-8")
    assert "MqttProbeMode mqtt_probe_mode = 45" in SCENARIO_SCHEMA.read_text(
        encoding="utf-8"
    )


def test_mqtt_publish_seed_preloads_connack_before_publish() -> None:
    """Pair the binary CONNACK with a POSTFIELDS publish body."""
    publish = (SCENARIO_ROOT / "mqtt_publish.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_MQTT" in publish
    assert 'host_path: "mqtt.test/sensors/kitchen"' in publish
    assert 'postfields: "hello mqtt"' in publish
    assert "probe_multi_pollset: true" in publish
    assert 'initial_response: "\\040\\002\\000\\000"' in publish


def test_mqtt_subscribe_seed_preserves_server_packet_order() -> None:
    """Keep SUBACK-triggered PUBLISH and DISCONNECT chunks separate."""
    subscribe = (SCENARIO_ROOT / "mqtt_subscribe_server_publish.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_MQTT" in subscribe
    assert 'on_readable: "\\060\\033\\000\\017sensors/kitchenhello mqtt"' in subscribe
    assert 'on_readable: "\\340\\000"' in subscribe


def test_mqtt_rejected_connack_seed_has_no_server_packets() -> None:
    """A non-zero CONNACK return code must end before PUBLISH."""
    rejected = (SCENARIO_ROOT / "mqtt_connack_rejected.textproto").read_text(
        encoding="utf-8"
    )
    assert 'initial_response: "\\040\\002\\000\\005"' in rejected
    assert "on_readable" not in rejected


def test_mqtt_send_backpressure_seed_uses_closed_probe() -> None:
    """Keep the queued-tail probe independent of mutation-sized payloads."""
    probe = (SCENARIO_ROOT / "mqtt_send_backpressure.textproto").read_text(
        encoding="utf-8"
    )
    assert "mqtt_probe_mode: MQTT_PROBE_SEND_BACKPRESSURE" in probe
    assert "postfields" not in probe
    assert "backpressure" not in probe
    assert 'initial_response: "\\040\\002\\000\\000"' in probe


def test_mqtt_credential_limit_seeds_use_closed_probes() -> None:
    """Keep oversized credential bytes out of the serialized corpus."""
    expected = {
        "mqtt_oversized_username.textproto": "MQTT_PROBE_OVERSIZED_USERNAME",
        "mqtt_oversized_password.textproto": "MQTT_PROBE_OVERSIZED_PASSWORD",
    }
    for filename, selector in expected.items():
        probe = (SCENARIO_ROOT / filename).read_text(encoding="utf-8")
        assert f"mqtt_probe_mode: {selector}" in probe
        assert "options {" not in probe


def test_mqtts_publish_seed_uses_certifiable_authority() -> None:
    """Keep the implicit-TLS seed pinned to the checked-in trust anchor."""
    publish = (SCENARIO_ROOT / "mqtts_publish.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_MQTTS" in publish
    assert 'host_path: "tls.test/sensors/kitchen"' in publish
    assert 'postfields: "hello mqtt"' in publish
    assert "probe_multi_pollset: true" in publish
    assert 'initial_response: "\\040\\002\\000\\000"' in publish


def test_mqtts_rejected_connack_seed_preloads_only_failure() -> None:
    """The MQTTS rejection seed must not script server packets."""
    rejected = (SCENARIO_ROOT / "mqtts_connack_rejected.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_MQTTS" in rejected
    assert 'host_path: "tls.test/sensors/rejected"' in rejected
    assert 'initial_response: "\\040\\002\\000\\005"' in rejected
    assert "on_readable" not in rejected
