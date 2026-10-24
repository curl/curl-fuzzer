"""Keep process-wide TLS keylog setup before libcurl global initialization."""

from pathlib import Path

GLOBAL_LIFECYCLE = (
    Path(__file__).resolve().parent.parent / "proto_fuzzer" / "curl_global_lifecycle.cc"
)


def test_sslkeylogfile_is_set_before_curl_global_init() -> None:
    source = GLOBAL_LIFECYCLE.read_text(encoding="utf-8")
    setenv = '(void)setenv("SSLKEYLOGFILE", "/dev/null", 0);'

    assert setenv in source
    assert source.index(setenv) < source.index(
        "allocation_fault_injection::InitializeCurl()"
    )
