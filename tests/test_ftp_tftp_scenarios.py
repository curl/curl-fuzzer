"""Reachability checks for correlated FTP and TFTP protocol seeds."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_OPTIONS = REPO_ROOT / "schemas" / "curl_fuzzer_supported_curlopts.txt"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto"


def _supported_options() -> set[str]:
    return {
        line
        for raw_line in SUPPORTED_OPTIONS.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }


def test_file_transfer_controls_are_reachable_without_active_networking() -> None:
    """Expose passive/scalar controls while the harness owns all routing."""
    supported = _supported_options()
    assert {
        "CURLOPT_DIRLISTONLY",
        "CURLOPT_APPEND",
        "CURLOPT_TRANSFERTEXT",
        "CURLOPT_FTP_USE_EPSV",
        "CURLOPT_FTP_CREATE_MISSING_DIRS",
        "CURLOPT_FTP_ACCOUNT",
        "CURLOPT_FTP_SKIP_PASV_IP",
        "CURLOPT_FTP_FILEMETHOD",
        "CURLOPT_FTP_ALTERNATIVE_TO_USER",
        "CURLOPT_FTP_USE_PRET",
        "CURLOPT_WILDCARDMATCH",
        "CURLOPT_TFTP_BLKSIZE",
        "CURLOPT_TFTP_NO_OPTIONS",
    } <= supported
    assert {
        "CURLOPT_FTPPORT",
        "CURLOPT_FTP_USE_EPRT",
        "CURLOPT_USE_SSL",
        "CURLOPT_QUOTE",
        "CURLOPT_PREQUOTE",
        "CURLOPT_POSTQUOTE",
    }.isdisjoint(supported)


def test_ftp_seeds_retain_control_and_data_correlations() -> None:
    """Keep command replies paired with passive-channel payloads."""
    expected_tokens = {
        "ftp_epsv_retr.textproto": (
            "229 Entering Extended Passive Mode",
            "150 opening data connection",
            'initial_response: "hello world"',
        ),
        "ftp_pasv_fallback.textproto": (
            "500 EPSV unsupported",
            "227 Entering Passive Mode",
            'initial_response: "fallback"',
        ),
        "ftp_upload_stor.textproto": (
            "CURLOPT_UPLOAD bool_value: true",
            'data: "upload-bytes"',
            "226 stored",
        ),
        "ftp_create_directories.textproto": (
            "CURLOPT_FTP_CREATE_MISSING_DIRS uint_value: 2",
            "550 missing a",
            "257 a created",
        ),
        "ftp_custom_list.textproto": (
            'CURLOPT_CUSTOMREQUEST string_value: "X-LIST"',
            "150 custom listing",
            'initial_response: "custom-entry\\r\\n"',
        ),
        "ftp_completion_eof.textproto": (
            "150 data",
            'on_readable: ""',
            'initial_response: "body"',
        ),
    }
    ftp_root = SCENARIO_ROOT / "ftp"
    for name, tokens in expected_tokens.items():
        scenario = (ftp_root / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name


def test_tftp_seeds_preserve_datagram_boundaries_and_state_pairs() -> None:
    """Protect OACK/DATA/ACK sequences mutation is unlikely to rediscover."""
    expected_tokens = {
        "tftp_rrq_oack_multiblock.textproto": (
            "\\000\\006blksize\\0008",
            "\\000\\003\\000\\001abcdefgh",
            "\\000\\003\\000\\002ijk",
        ),
        "tftp_wrq_oack_exact_block.textproto": (
            "CURLOPT_INFILESIZE_LARGE uint_value: 8",
            "\\000\\004\\000\\001",
            "\\000\\004\\000\\002",
        ),
        "tftp_duplicate_data.textproto": (
            "\\000\\003\\000\\001abcdefgh",
            "\\000\\003\\000\\002z",
        ),
        "tftp_error_not_found.textproto": (
            "\\000\\005\\000\\001not found\\000",
        ),
    }
    tftp_root = SCENARIO_ROOT / "tftp"
    for name, tokens in expected_tokens.items():
        scenario = (tftp_root / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name
