"""Keep process-wide libcurl environment setup before global initialization."""

from pathlib import Path

FUZZER_MAIN = Path(__file__).resolve().parent.parent / "proto_fuzzer" / "fuzzer_main.cc"


def test_libcurl_environment_is_set_before_curl_global_init() -> None:
    source = FUZZER_MAIN.read_text(encoding="utf-8")
    setenv_calls = (
        '(void)setenv("CURL_ENTROPY", "12345678", 0);',
        '(void)setenv("SSLKEYLOGFILE", "/dev/null", 0);',
    )

    for setenv_call in setenv_calls:
        assert setenv_call in source
        assert source.index(setenv_call) < source.index("curl_global_init(CURL_GLOBAL_ALL)")
