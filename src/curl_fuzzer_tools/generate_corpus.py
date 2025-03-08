#!/usr/bin/env python
#
"""Simple script which generates corpus files."""

import argparse
import logging
import sys
from pathlib import Path

from curl_fuzzer_tools import common_logging
from curl_fuzzer_tools.corpus import TLVEncoder
from curl_fuzzer_tools.corpus_curl_opt_http_auth import CurlOptHttpAuth
from curl_fuzzer_tools.curl_test_data import TestData

log = logging.getLogger(__name__)


def generate_corpus(args: argparse.Namespace) -> None:
    """Generate a corpus file from the given arguments."""
    curl_test_dir = Path(args.curl_test_dir)
    if not curl_test_dir.exists():
        raise FileNotFoundError(
            f"curl test directory {args.curl_test_dir} does not exist"
        )

    sys.path.append(args.curl_test_dir)

    td = TestData(curl_test_dir / "data")

    with open(args.output, "wb") as f:
        enc = TLVEncoder(f, td)

        # Write the URL to the file.
        enc.write_string(enc.TYPE_URL, args.url)

        # Write any responses to the file.
        enc.maybe_write_response(enc.TYPE_RSP0, args.rsp0, args.rsp0file, args.rsp0test)
        enc.maybe_write_response(enc.TYPE_RSP1, args.rsp1, args.rsp1file, args.rsp1test)
        enc.maybe_write_response(enc.TYPE_RSP2, args.rsp2, args.rsp2file, args.rsp2test)
        enc.maybe_write_response(enc.TYPE_RSP3, args.rsp3, args.rsp3file, args.rsp3test)
        enc.maybe_write_response(enc.TYPE_RSP4, args.rsp4, args.rsp4file, args.rsp4test)
        enc.maybe_write_response(enc.TYPE_RSP5, args.rsp5, args.rsp5file, args.rsp5test)
        enc.maybe_write_response(enc.TYPE_RSP6, args.rsp6, args.rsp6file, args.rsp6test)
        enc.maybe_write_response(enc.TYPE_RSP7, args.rsp7, args.rsp7file, args.rsp7test)
        enc.maybe_write_response(enc.TYPE_RSP8, args.rsp8, args.rsp8file, args.rsp8test)
        enc.maybe_write_response(enc.TYPE_RSP9, args.rsp9, args.rsp9file, args.rsp9test)
        enc.maybe_write_response(
            enc.TYPE_RSP10, args.rsp10, args.rsp10file, args.rsp10test
        )

        # Write any second socket responses to the file.
        enc.maybe_write_response(
            enc.TYPE_SECRSP0, args.secrsp0, args.secrsp0file, args.secrsp0test
        )
        enc.maybe_write_response(
            enc.TYPE_SECRSP1, args.secrsp1, args.secrsp1file, args.secrsp1test
        )

        # Write other options to file.
        enc.maybe_write_string(enc.TYPE_USERNAME, args.username)
        enc.maybe_write_string(enc.TYPE_PASSWORD, args.password)
        enc.maybe_write_string(enc.TYPE_POSTFIELDS, args.postfields)
        enc.maybe_write_string(enc.TYPE_HTTPPOSTBODY, args.postbody)
        enc.maybe_write_string(enc.TYPE_COOKIE, args.cookie)
        enc.maybe_write_string(enc.TYPE_RANGE, args.range)
        enc.maybe_write_string(enc.TYPE_CUSTOMREQUEST, args.customrequest)
        enc.maybe_write_string(enc.TYPE_MAIL_FROM, args.mailfrom)
        enc.maybe_write_string(enc.TYPE_ACCEPT_ENCODING, args.acceptencoding)
        enc.maybe_write_string(enc.TYPE_RTSP_SESSION_ID, args.rtspsessionid)
        enc.maybe_write_string(enc.TYPE_RTSP_STREAM_URI, args.rtspstreamuri)
        enc.maybe_write_string(enc.TYPE_RTSP_TRANSPORT, args.rtsptransport)
        enc.maybe_write_string(enc.TYPE_MAIL_AUTH, args.mailauth)
        enc.maybe_write_string(enc.TYPE_LOGIN_OPTIONS, args.loginoptions)
        enc.maybe_write_string(enc.TYPE_XOAUTH2_BEARER, args.bearertoken)
        enc.maybe_write_string(enc.TYPE_USERPWD, args.user_and_pass)
        enc.maybe_write_string(enc.TYPE_USERAGENT, args.useragent)
        enc.maybe_write_string(enc.TYPE_SSH_HOST_PUBLIC_KEY_SHA256, args.hostpksha256)
        enc.maybe_write_string(enc.TYPE_HSTS, args.hsts)

        enc.maybe_write_u32(enc.TYPE_OPTHEADER, args.optheader)
        enc.maybe_write_u32(enc.TYPE_NOBODY, args.nobody)
        enc.maybe_write_u32(enc.TYPE_FOLLOWLOCATION, args.followlocation)
        enc.maybe_write_u32(enc.TYPE_WILDCARDMATCH, args.wildcardmatch)
        enc.maybe_write_u32(enc.TYPE_RTSP_REQUEST, args.rtsprequest)
        enc.maybe_write_u32(enc.TYPE_RTSP_CLIENT_CSEQ, args.rtspclientcseq)
        enc.maybe_write_u32(enc.TYPE_HTTP_VERSION, args.httpversion)
        enc.maybe_write_u32(enc.TYPE_NETRC, args.netrclevel)
        enc.maybe_write_u32(enc.TYPE_CONNECT_ONLY, args.connectonly)

        if args.httpauth:
            # translate a string HTTP auth name to an unsigned long bitmask
            # value in the format CURLOPT_HTTPAUTH expects
            log.debug(
                f"Mapping provided CURLOPT_HTTPAUTH='{args.httpauth}' "
                f"to {CurlOptHttpAuth[args.httpauth].value}L (ulong)"
            )
            http_auth_value = CurlOptHttpAuth[args.httpauth].value
            enc.maybe_write_u32(enc.TYPE_HTTPAUTH, http_auth_value)

        if args.wsoptions:
            # can only be 1 or unset currently.
            # https://curl.se/libcurl/c/CURLOPT_WS_args.html
            enc.write_u32(enc.TYPE_WS_OPTIONS, 1)

        if args.post:
            # can only be set to 1 or unset
            # https://curl.se/libcurl/c/CURLOPT_POST.html
            enc.write_u32(enc.TYPE_POST, 1)

        # Write the first upload to the file.
        if args.upload1:
            enc.write_bytes(enc.TYPE_UPLOAD1, args.upload1.encode("utf-8"))
        elif args.upload1file:
            with open(args.upload1file, "rb") as g:
                enc.write_bytes(enc.TYPE_UPLOAD1, g.read())

        # Write an array of headers to the file.
        if args.header:
            for header in args.header:
                enc.write_string(enc.TYPE_HEADER, header)

        # Write an array of headers to the file.
        if args.mailrecipient:
            for mailrecipient in args.mailrecipient:
                enc.write_string(enc.TYPE_MAIL_RECIPIENT, mailrecipient)

        # Write an array of mimeparts to the file.
        if args.mimepart:
            for mimepart in args.mimepart:
                enc.write_mimepart(mimepart)


def main() -> None:
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--curl_test_dir", default=".")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--postfields")
    parser.add_argument("--postbody", type=str)
    parser.add_argument("--header", action="append")
    parser.add_argument("--cookie")
    parser.add_argument("--range")
    parser.add_argument("--customrequest")
    parser.add_argument("--mailfrom")
    parser.add_argument("--mailrecipient", action="append")
    parser.add_argument("--mimepart", action="append")
    parser.add_argument("--httpauth", type=str)
    parser.add_argument("--optheader", type=int)
    parser.add_argument("--nobody", type=int)
    parser.add_argument("--followlocation", type=int)
    parser.add_argument("--acceptencoding")
    parser.add_argument("--wildcardmatch", type=int)
    parser.add_argument("--rtsprequest", type=int)
    parser.add_argument("--rtspsessionid")
    parser.add_argument("--rtspstreamuri")
    parser.add_argument("--rtsptransport")
    parser.add_argument("--rtspclientcseq", type=int)
    parser.add_argument("--mailauth")
    parser.add_argument("--httpversion", type=int)
    parser.add_argument("--loginoptions", type=str)
    parser.add_argument("--bearertoken", type=str)
    parser.add_argument("--user_and_pass", type=str)
    parser.add_argument("--useragent", type=str)
    parser.add_argument("--netrclevel", type=int)
    parser.add_argument("--hostpksha256", type=str)
    parser.add_argument("--wsoptions", action="store_true")
    parser.add_argument("--connectonly", type=int)
    parser.add_argument("--post", action="store_true")
    parser.add_argument("--hsts")

    upload1 = parser.add_mutually_exclusive_group()
    upload1.add_argument("--upload1")
    upload1.add_argument("--upload1file")

    for ii in range(0, 11):
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--rsp{0}".format(ii))
        group.add_argument("--rsp{0}file".format(ii))
        group.add_argument("--rsp{0}test".format(ii), type=int)

    for ii in range(0, 2):
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--secrsp{0}".format(ii))
        group.add_argument("--secrsp{0}file".format(ii))
        group.add_argument("--secrsp{0}test".format(ii), type=int)

    args = parser.parse_args()

    # Run main script.
    generate_corpus(args)


def run() -> None:
    """Set up common logging and run the main function."""
    common_logging(__name__, __file__)
    main()


if __name__ == "__main__":
    run()
