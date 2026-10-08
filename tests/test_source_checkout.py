"""Tests for curl-fuzzer source-checkout discovery."""

from pathlib import Path

from curl_fuzzer_tools import source_checkout


def test_unrelated_installed_package_parent_is_not_a_checkout(
    monkeypatch, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    installed_module = (
        tmp_path
        / "venv"
        / "lib"
        / "python"
        / "site-packages"
        / "curl_fuzzer_tools"
        / "source_checkout.py"
    )
    outside_checkout = tmp_path / "work"
    outside_checkout.mkdir()
    monkeypatch.setattr(source_checkout, "__file__", str(installed_module))
    monkeypatch.chdir(outside_checkout)

    assert source_checkout.find_source_checkout() is None


def test_working_directory_can_supply_the_checkout(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    installed_module = (
        tmp_path / "venv" / "site-packages" / "curl_fuzzer_tools" / "source_checkout.py"
    )
    checkout = tmp_path / "curl-fuzzer"
    (checkout / "corpora").mkdir(parents=True)
    (checkout / "pyproject.toml").touch()
    (checkout / "ossfuzz.sh").touch()
    monkeypatch.setattr(source_checkout, "__file__", str(installed_module))
    monkeypatch.chdir(checkout)

    assert source_checkout.find_source_checkout() == checkout
