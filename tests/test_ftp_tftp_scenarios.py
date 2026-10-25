"""Reachability checks for correlated FTP and TFTP protocol seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto"


def test_file_transfer_controls_are_reachable_with_owned_networking(
    active_option_names: frozenset[str],
) -> None:
    """Expose passive/active controls while the harness owns all routing."""
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
    } <= active_option_names
    assert {
        "CURLOPT_USE_SSL",
        "CURLOPT_QUOTE",
        "CURLOPT_PREQUOTE",
        "CURLOPT_POSTQUOTE",
    }.isdisjoint(active_option_names)


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
            "upload: true",
            'data: "upload-bytes"',
            "226 stored",
        ),
        "ftp_create_directories.textproto": (
            "ftp_create_missing_dirs: 2",
            "550 missing a",
            "257 a created",
        ),
        "ftp_custom_list.textproto": (
            'customrequest: "X-LIST"',
            "150 custom listing",
            'initial_response: "custom-entry\\r\\n"',
        ),
        "ftp_completion_eof.textproto": (
            "150 data",
            'on_readable: ""',
            'initial_response: "body"',
        ),
        "ftp_active_eprt.textproto": (
            'ftpport: "127.0.0.1"',
            "200 EPRT accepted",
            'initial_response: "active-eprt"',
        ),
        "ftp_active_port.textproto": (
            "ftp_use_eprt: 0",
            "200 PORT accepted",
            'initial_response: "active-port"',
        ),
        "ftp_active_listener_allocation_failure.textproto": (
            'ftpport: "127.0.0.1"',
            "fail_allocations: 86",
            "harness-owned loopback socket",
        ),
        "ftp_eprt_port_fallback.textproto": (
            "ftp_use_eprt: 1",
            "500 EPRT unsupported",
            "200 PORT accepted",
        ),
        "ftp_wildcard_unix_symlink.textproto": (
            "probe_multi_pollset: true",
            "wildcardmatch: true",
            "link.txt -> match.txt",
            'initial_response: "match"',
        ),
        "ftp_wildcard_windows_list.textproto": (
            "wildcardmatch: true",
            "04-27-26  11:01AM",
            'initial_response: "match"',
        ),
        "ftp_url_type_ascii.textproto": (
            'host_path: "ftp.test/file.txt;type=a"',
            "229 Entering Extended Passive Mode",
            'initial_response: "ascii"',
        ),
    }
    ftp_root = SCENARIO_ROOT / "ftp"
    for name, tokens in expected_tokens.items():
        scenario = (ftp_root / name).read_text(encoding="utf-8")
        assert all(token in scenario for token in tokens), name


def test_ftps_seeds_pair_tls_data_and_protection() -> None:
    """Keep PBSZ/PROT, control handshake, and data payload in command order."""
    assert "SCHEME_FTPS = 23;" in SCENARIO_SCHEMA.read_text(encoding="utf-8")
    ftp_root = SCENARIO_ROOT / "ftp"
    retr = (ftp_root / "ftps_epsv_retr.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_FTPS" in retr
    assert 'host_path: "tls.test/file.bin"' in retr
    assert "200 PBSZ accepted" in retr
    assert "200 PROT accepted" in retr
    assert "229 Entering Extended Passive Mode" in retr
    assert "150 opening secure data connection" in retr
    assert 'initial_response: "secret over tls"' in retr
    assert "ftpport:" not in retr

    rejected = (ftp_root / "ftps_prot_rejected.textproto").read_text(encoding="utf-8")
    assert "500 PROT unsupported" in rejected
    assert "150 " not in rejected


def test_tftp_seeds_preserve_datagram_boundaries_and_state_pairs() -> None:
    """Protect OACK/DATA/ACK sequences mutation is unlikely to rediscover."""
    expected_tokens = {
        "tftp_rrq_oack_multiblock.textproto": (
            "\\000\\006blksize\\0008",
            "\\000\\003\\000\\001abcdefgh",
            "\\000\\003\\000\\002ijk",
        ),
        "tftp_wrq_oack_exact_block.textproto": (
            "infilesize_large: 8",
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
    assert "probe_multi_pollset: true" in upload
    assert 'host_path: "smtp.test/client.test"' in upload
    assert "upload: true" in upload
    assert 'mail_from: "sender@example.test"' in upload
    assert 'mail_rcpt: "recipient@example.test"' in upload
    assert "250 sender accepted" in upload
    assert "250 recipient accepted" in upload
    assert "354 send the message" in upload
    assert "250 message queued" in upload

    rejected = (smtp_root / "smtp_data_rejected.textproto").read_text(encoding="utf-8")
    assert "550 data rejected" in rejected
    assert "354" not in rejected

    smtps = (smtp_root / "smtps_upload_mail.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_SMTPS" in smtps
    assert 'host_path: "tls.test/client.test"' in smtps
    assert 'mail_from: "sender@example.test"' in smtps
    assert "354 send the message" in smtps
    assert "250 message queued" in smtps

    cram = (smtp_root / "smtp_auth_cram_md5_mail.textproto").read_text(encoding="utf-8")
    assert 'login_options: "AUTH=CRAM-MD5"' in cram
    assert "PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UuZXhhbXBsZS5uZXQ+" in cram
    assert "235 2.7.0 authentication succeeded" in cram
    assert "354 send the message" in cram
    assert "250 message queued" in cram

    fallback = (smtp_root / "smtp_auth_cram_fallback.textproto").read_text(
        encoding="utf-8"
    )
    assert "AUTH CRAM-MD5 PLAIN" in fallback
    assert 'on_readable: "334 !\\r\\n"' in fallback
    assert "501 authentication exchange cancelled" in fallback
    assert 'on_readable: "334 \\r\\n"' in fallback
    assert "235 2.7.0 authentication succeeded" in fallback

    plain_ir = (smtp_root / "smtp_auth_plain_sasl_ir.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=PLAIN"' in plain_ir
    assert "sasl_ir: true" in plain_ir
    assert "250-AUTH PLAIN" in plain_ir

    helo = (smtp_root / "smtp_ehlo_helo_fallback.textproto").read_text(encoding="utf-8")
    assert "500 EHLO unavailable" in helo
    assert "250 smtp.test greets client" in helo
    assert "214 smtp.test help" in helo

    expn = (smtp_root / "smtp_custom_expn.textproto").read_text(encoding="utf-8")
    assert 'customrequest: "EXPN"' in expn
    assert 'mail_rcpt: "list@example.test"' in expn
    assert "upload:" not in expn
    assert "250 member@example.test" in expn

    unavailable = (smtp_root / "smtp_auth_unavailable_ntlm.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=NTLM"' in unavailable
    assert "250-AUTH NTLM" in unavailable
    assert "235" not in unavailable


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
    assert 'username: "fuzz"' in no_match
    assert "552 no match" in no_match


def test_imap_and_pop3_seeds_keep_command_and_literal_order() -> None:
    """Keep tagless status replies paired with literal and multi-line bodies."""
    imap_root = SCENARIO_ROOT / "imap"
    fetch = (imap_root / "imap_fetch_literal.textproto").read_text(encoding="utf-8")
    assert "probe_multi_pollset: true" in fetch
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
    assert "upload: true" in append
    assert "infilesize_large: 17" in append
    assert "+ Ready for literal" in append
    assert "OK APPEND completed" in append

    denied = (imap_root / "imap_login_denied.textproto").read_text(encoding="utf-8")
    assert "NO [AUTHENTICATIONFAILED] invalid credentials" in denied

    plain = (imap_root / "imap_auth_plain_continuation.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=PLAIN"' in plain
    assert 'sasl_authzid: "authorization-id"' in plain
    assert "* OK authentication continues\\r\\n+ \\r\\n" in plain
    assert "OK AUTHENTICATE completed" in plain
    assert "OK FETCH completed" in plain

    login_listing = (imap_root / "imap_auth_login_custom_fetch.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=LOGIN"' in login_listing
    assert "* CAPABILITY IMAP4rev1 AUTH=LOGIN" in login_listing
    assert login_listing.count('on_readable: "+') == 2
    assert "UID FETCH 1:* (FLAGS)" in login_listing
    assert "OK FETCH completed" in login_listing

    oauth = (imap_root / "imap_auth_oauthbearer_error.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=OAUTHBEARER"' in oauth
    assert 'xoauth2_bearer: "invalid-token"' in oauth
    assert oauth.count('on_readable: "+') == 2
    assert "NO Authentication failed" in oauth

    xoauth2 = (imap_root / "imap_auth_xoauth2_success.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=XOAUTH2"' in xoauth2
    assert 'xoauth2_bearer: "fuzz-xoauth2-token"' in xoauth2
    assert "A002 OK AUTHENTICATE completed" in xoauth2
    assert "A004 OK FETCH completed" in xoauth2

    digest = (imap_root / "imap_auth_digest_md5_search.textproto").read_text(
        encoding="utf-8"
    )
    assert 'host_path: "imap.test/INBOX?ALL"' in digest
    assert 'login_options: "AUTH=DIGEST-MD5"' in digest
    assert "AUTH=DIGEST-MD5\\r\\nOK CAPABILITY completed" in digest
    assert digest.count('on_readable: "+') == 2
    assert "OK AUTHENTICATE completed" in digest
    assert "* SEARCH 1 2\\r\\nOK SEARCH completed" in digest

    fallback = (imap_root / "imap_auth_cram_fallback.textproto").read_text(
        encoding="utf-8"
    )
    assert "AUTH=CRAM-MD5 AUTH=PLAIN" in fallback
    assert 'on_readable: "+ !\\r\\n"' in fallback
    assert "NO AUTH exchange cancelled by client" in fallback
    assert "OK AUTHENTICATE completed" in fallback
    assert "OK FETCH completed" in fallback

    imaps = (imap_root / "imaps_login_fetch.textproto").read_text(encoding="utf-8")
    assert "scheme: SCHEME_IMAPS" in imaps
    assert 'host_path: "tls.test/INBOX;UID=1"' in imaps
    assert "OK LOGIN completed" in imaps
    assert "* 1 FETCH (BODY[] {18}" in imaps
    assert "Hello from IMAPS" in imaps
    assert "A001" not in imaps

    pop3_root = SCENARIO_ROOT / "pop3"
    retr = (pop3_root / "pop3_retr_message.textproto").read_text(encoding="utf-8")
    assert "probe_multi_pollset: true" in retr
    assert "scheme: SCHEME_POP3" in retr
    assert 'host_path: "pop3.test/1"' in retr
    assert "+OK capabilities" in retr
    assert "USER\\r\\n.\\r\\n" in retr
    assert "+OK pass accepted" in retr
    assert "+OK 17 octets" in retr
    assert "Hello from POP3" in retr

    pop3s = (pop3_root / "pop3s_retr_message.textproto").read_text(encoding="utf-8")
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

    cram = (pop3_root / "pop3_auth_cram_md5_retr.textproto").read_text(encoding="utf-8")
    assert 'login_options: "AUTH=CRAM-MD5"' in cram
    assert "SASL CRAM-MD5" in cram
    assert "PDE4OTYuNjk3MTcwOTUy" in cram
    assert "+OK authentication succeeded" in cram

    fallback = (pop3_root / "pop3_auth_cram_fallback.textproto").read_text(
        encoding="utf-8"
    )
    assert "SASL CRAM-MD5 PLAIN" in fallback
    assert 'on_readable: "+ !\\r\\n"' in fallback
    assert "-ERR authentication exchange cancelled" in fallback
    assert 'on_readable: "+ \\r\\n"' in fallback

    plain_ir = (pop3_root / "pop3_auth_plain_sasl_ir.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=PLAIN"' in plain_ir
    assert "sasl_ir: true" in plain_ir
    assert "SASL PLAIN" in plain_ir

    apop = (pop3_root / "pop3_apop_retr.textproto").read_text(encoding="utf-8")
    assert 'login_options: "AUTH=+APOP"' in apop
    assert "<id@host>" in apop
    assert "+OK authentication succeeded" in apop

    apop_denied = (pop3_root / "pop3_apop_denied.textproto").read_text(encoding="utf-8")
    assert 'login_options: "AUTH=+APOP"' in apop_denied
    assert "-ERR invalid digest" in apop_denied

    unavailable = (pop3_root / "pop3_auth_unavailable_ntlm.textproto").read_text(
        encoding="utf-8"
    )
    assert 'login_options: "AUTH=NTLM"' in unavailable
    assert "SASL NTLM" in unavailable
    assert "+OK authentication succeeded" not in unavailable

    uidl = (pop3_root / "pop3_uidl_mailbox.textproto").read_text(encoding="utf-8")
    assert 'customrequest: "UIDL"' in uidl
    assert "+OK unique ids follow" in uidl
    assert "whqtswO00QHEf7kmZ" in uidl

    top = (pop3_root / "pop3_top_long_dot_stuffed.textproto").read_text(
        encoding="utf-8"
    )
    assert 'customrequest: "TOP 1 0"' in top
    assert "buffersize: 1024" in top
    assert "..dot-stuffed\\r\\n" in top
    assert "...two-leading-dots\\r\\n.\\r\\n" in top
    assert top.count("A" * 80) >= 16
