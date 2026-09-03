"""Keep process-wide TLS keylog setup before libcurl global initialization."""

from pathlib import Path

FUZZER_MAIN = Path(__file__).resolve().parent.parent / "proto_fuzzer" / "fuzzer_main.cc"


def test_sslkeylogfile_is_set_before_curl_global_init() -> None:
    source = FUZZER_MAIN.read_text(encoding="utf-8")
    setenv = '(void)setenv("SSLKEYLOGFILE", "/dev/null", 0);'

    assert setenv in source
    assert source.index(setenv) < source.index("curl_global_init(CURL_GLOBAL_ALL)")
