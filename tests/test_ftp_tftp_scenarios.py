"""Reachability checks for correlated FTP and TFTP protocol seeds."""

from __future__ import annotations

from pathlib import Path

from curl_fuzzer_tools.generate_option_manifest import parse_proto_options

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto"


def _supported_options() -> set[str]:
    return {
        option.name
        for option in parse_proto_options(SCENARIO_SCHEMA.read_text(encoding="utf-8"))
    }


def test_file_transfer_controls_are_reachable_with_owned_networking() -> None:
    """Expose passive/active controls while the harness owns all routing."""
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
        "CURLOPT_FTPPORT",
        "CURLOPT_FTP_USE_EPRT",
        "CURLOPT_WILDCARDMATCH",
        "CURLOPT_TFTP_BLKSIZE",
        "CURLOPT_TFTP_NO_OPTIONS",
    } <= supported
    assert {
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
        "ftp_epsv_malformed_tuple.textproto": (
            "229 Entering Extended Passive Mode (||1025|)",
            'host_path: "ftp.test/malformed-epsv-tuple.bin"',
        ),
        "ftp_pasv_fallback.textproto": (
            "500 EPSV unsupported",
            "227 Entering Passive Mode",
            'initial_response: "fallback"',
        ),
        "ftp_malformed_epsv_pasv_fallback.textproto": (
            "200 EPSV reply missing port tuple",
            "227 Entering Passive Mode",
            'initial_response: "pasv-fallback"',
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
        "ftp_active_eprt.textproto": (
            'CURLOPT_FTPPORT string_value: "127.0.0.1"',
            "200 EPRT accepted",
            'initial_response: "active-eprt"',
        ),
        "ftp_active_port.textproto": (
            "CURLOPT_FTP_USE_EPRT bool_value: false",
            "200 PORT accepted",
            'initial_response: "active-port"',
        ),
        "ftp_eprt_port_fallback.textproto": (
            "CURLOPT_FTP_USE_EPRT bool_value: true",
            "500 EPRT unsupported",
            "200 PORT accepted",
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
        "tftp_error_not_found.textproto": ("\\000\\005\\000\\001not found\\000",),
    }
    tftp_root = SCENARIO_ROOT / "tftp"
    for name, tokens in expected_tokens.items():
        scenario = (tftp_root / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name


def test_smtp_seeds_keep_envelope_and_data_order() -> None:
    """Keep MAIL/RCPT/DATA replies paired with the body exchange."""
    smtp_root = SCENARIO_ROOT / "smtp"
    upload = (smtp_root / "smtp_upload_mail.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_SMTP" in upload
    assert 'host_path: "smtp.test/client.test"' in upload
    assert "CURLOPT_UPLOAD bool_value: true" in upload
    assert 'CURLOPT_MAIL_FROM string_value: "sender@example.test"' in upload
    assert 'mail_rcpt: "recipient@example.test"' in upload
    assert "250 sender accepted" in upload
    assert "250 recipient accepted" in upload
    assert "354 send the message" in upload
    assert "250 message queued" in upload

    rejected = (smtp_root / "smtp_data_rejected.textproto").read_text(encoding="utf-8")
    assert "550 data rejected" in rejected
    assert "354" not in rejected

    smtps = (smtp_root / "smtps_upload_mail.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_SMTPS" in smtps
    assert 'host_path: "tls.test/client.test"' in smtps
    assert 'CURLOPT_MAIL_FROM string_value: "sender@example.test"' in smtps
    assert "354 send the message" in smtps
    assert "250 message queued" in smtps


def test_dict_seeds_keep_lookup_paths_and_response_terminators() -> None:
    """Keep DICT commands URL-derived and responses in one body chunk."""
    dict_root = SCENARIO_ROOT / "dict"
    define = (dict_root / "dict_define_word.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_DICT" in define
    assert 'host_path: "dict.test/d:word"' in define
    assert "150 1 definitions retrieved" in define
    assert "151 " in define
    assert "\\r\\n.\\r\\n" in define

    no_match = (dict_root / "dict_no_match.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_DICT" in no_match
    assert 'host_path: "dict.test/d:missing"' in no_match
    assert 'CURLOPT_USERNAME string_value: "fuzz"' in no_match
    assert "552 no match" in no_match


def test_imap_and_pop3_seeds_keep_command_and_literal_order() -> None:
    """Keep tagless status replies paired with literal and multi-line bodies."""
    imap_root = SCENARIO_ROOT / "imap"
    fetch = (imap_root / "imap_fetch_literal.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_IMAP" in fetch
    assert 'host_path: "imap.test/INBOX;UID=1"' in fetch
    assert "* CAPABILITY IMAP4rev1" in fetch
    assert "OK LOGIN completed" in fetch
    assert "OK [UIDVALIDITY 7] SELECT completed" in fetch
    assert "* 1 FETCH (BODY[] {17}" in fetch
    assert "Hello from IMAP" in fetch
    # The peer supplies curl's generated tag, so seeds stay tagless.
    assert "A001" not in fetch

    append = (imap_root / "imap_append_upload.textproto").read_text(encoding="utf-8")
    assert "CURLOPT_UPLOAD bool_value: true" in append
    assert "CURLOPT_INFILESIZE_LARGE uint_value: 17" in append
    assert "+ Ready for literal" in append
    assert "OK APPEND completed" in append

    denied = (imap_root / "imap_login_denied.textproto").read_text(encoding="utf-8")
    assert "NO [AUTHENTICATIONFAILED] invalid credentials" in denied

    imaps = (imap_root / "imaps_login_fetch.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_IMAPS" in imaps
    assert 'host_path: "tls.test/INBOX;UID=1"' in imaps
    assert "OK LOGIN completed" in imaps
    assert "* 1 FETCH (BODY[] {18}" in imaps
    assert "Hello from IMAPS" in imaps
    assert "A001" not in imaps

    pop3_root = SCENARIO_ROOT / "pop3"
    retr = (pop3_root / "pop3_retr_message.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_POP3" in retr
    assert 'host_path: "pop3.test/1"' in retr
    assert "+OK capabilities" in retr
    assert "USER\\r\\n.\\r\\n" in retr
    assert "+OK pass accepted" in retr
    assert "+OK 17 octets" in retr
    assert "Hello from POP3" in retr

    pop3s = (pop3_root / "pop3s_retr_message.textproto").read_text(
        encoding="utf-8"
    )
    assert "scheme: SCHEME_POP3S" in pop3s
    assert 'host_path: "tls.test/1"' in pop3s
    assert "+OK pass accepted" in pop3s
    assert "+OK 18 octets" in pop3s
    assert "Hello from POP3S" in pop3s

    listing = (pop3_root / "pop3_list_mailbox.textproto").read_text(encoding="utf-8")
    assert 'host_path: "pop3.test/"' in listing
    assert "+OK 2 messages" in listing

    rejected = (pop3_root / "pop3_user_denied.textproto").read_text(encoding="utf-8")
    assert "-ERR no such user" in rejected
