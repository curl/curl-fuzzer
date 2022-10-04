#!/usr/bin/env python
#
# Simple script which generates corpus files.

import argparse
import logging
import os
import sys
import corpus
from corpus_curl_opt_http_auth import CurlOptHttpAuth
log = logging.getLogger(__name__)


def generate_corpus(options):
    sys.path.append(options.curl_test_dir)
    import curl_test_data

    td = curl_test_data.TestData(os.path.join(options.curl_test_dir,
                                              "data"))

    with open(options.output, "wb") as f:
        enc = corpus.TLVEncoder(f, td)

        # Write the URL to the file.
        enc.write_string(enc.TYPE_URL, options.url)

        # Write any responses to the file.
        enc.maybe_write_response(enc.TYPE_RSP0, options.rsp0, options.rsp0file, options.rsp0test)
        enc.maybe_write_response(enc.TYPE_RSP1, options.rsp1, options.rsp1file, options.rsp1test)
        enc.maybe_write_response(enc.TYPE_RSP2, options.rsp2, options.rsp2file, options.rsp2test)
        enc.maybe_write_response(enc.TYPE_RSP3, options.rsp3, options.rsp3file, options.rsp3test)
        enc.maybe_write_response(enc.TYPE_RSP4, options.rsp4, options.rsp4file, options.rsp4test)
        enc.maybe_write_response(enc.TYPE_RSP5, options.rsp5, options.rsp5file, options.rsp5test)
        enc.maybe_write_response(enc.TYPE_RSP6, options.rsp6, options.rsp6file, options.rsp6test)
        enc.maybe_write_response(enc.TYPE_RSP7, options.rsp7, options.rsp7file, options.rsp7test)
        enc.maybe_write_response(enc.TYPE_RSP8, options.rsp8, options.rsp8file, options.rsp8test)
        enc.maybe_write_response(enc.TYPE_RSP9, options.rsp9, options.rsp9file, options.rsp9test)
        enc.maybe_write_response(enc.TYPE_RSP10, options.rsp10, options.rsp10file, options.rsp10test)

        # Write any second socket responses to the file.
        enc.maybe_write_response(enc.TYPE_SECRSP0, options.secrsp0, options.secrsp0file, options.secrsp0test)
        enc.maybe_write_response(enc.TYPE_SECRSP1, options.secrsp1, options.secrsp1file, options.secrsp1test)

        # Write other options to file.
        enc.maybe_write_string(enc.TYPE_USERNAME, options.username)
        enc.maybe_write_string(enc.TYPE_PASSWORD, options.password)
        enc.maybe_write_string(enc.TYPE_POSTFIELDS, options.postfields)
        enc.maybe_write_string(enc.TYPE_HTTPPOSTBODY, options.postbody)
        enc.maybe_write_string(enc.TYPE_COOKIE, options.cookie)
        enc.maybe_write_string(enc.TYPE_RANGE, options.range)
        enc.maybe_write_string(enc.TYPE_CUSTOMREQUEST, options.customrequest)
        enc.maybe_write_string(enc.TYPE_MAIL_FROM, options.mailfrom)
        enc.maybe_write_string(enc.TYPE_ACCEPT_ENCODING, options.acceptencoding)
        enc.maybe_write_string(enc.TYPE_RTSP_SESSION_ID, options.rtspsessionid)
        enc.maybe_write_string(enc.TYPE_RTSP_STREAM_URI, options.rtspstreamuri)
        enc.maybe_write_string(enc.TYPE_RTSP_TRANSPORT, options.rtsptransport)
        enc.maybe_write_string(enc.TYPE_MAIL_AUTH, options.mailauth)
        enc.maybe_write_string(enc.TYPE_LOGIN_OPTIONS, options.loginoptions)
        enc.maybe_write_string(enc.TYPE_XOAUTH2_BEARER, options.bearertoken)
        enc.maybe_write_string(enc.TYPE_USERPWD, options.user_and_pass)
        enc.maybe_write_string(enc.TYPE_USERAGENT, options.useragent)
        enc.maybe_write_string(enc.TYPE_SSH_HOST_PUBLIC_KEY_SHA256, options.hostpksha256)
        enc.maybe_write_string(enc.TYPE_HSTS, options.hsts)

        enc.maybe_write_u32(enc.TYPE_OPTHEADER, options.optheader)
        enc.maybe_write_u32(enc.TYPE_NOBODY, options.nobody)
        enc.maybe_write_u32(enc.TYPE_FOLLOWLOCATION, options.followlocation)
        enc.maybe_write_u32(enc.TYPE_WILDCARDMATCH, options.wildcardmatch)
        enc.maybe_write_u32(enc.TYPE_RTSP_REQUEST, options.rtsprequest)
        enc.maybe_write_u32(enc.TYPE_RTSP_CLIENT_CSEQ, options.rtspclientcseq)
        enc.maybe_write_u32(enc.TYPE_HTTP_VERSION, options.httpversion)
        enc.maybe_write_u32(enc.TYPE_NETRC, options.netrclevel)
        enc.maybe_write_u32(enc.TYPE_CONNECT_ONLY, options.connectonly)

        if options.httpauth:
            # translate a string HTTP auth name to an unsigned long bitmask
            # value in the format CURLOPT_HTTPAUTH expects
            log.debug(f"Mapping provided CURLOPT_HTTPAUTH='{options.httpauth}' "
                f"to {CurlOptHttpAuth[options.httpauth].value}L (ulong)")
            http_auth_value = CurlOptHttpAuth[options.httpauth].value
            enc.maybe_write_u32(enc.TYPE_HTTPAUTH, http_auth_value)

        if options.wsoptions:
            # can only be 1 or unset currently.
            # https://curl.se/libcurl/c/CURLOPT_WS_OPTIONS.html
            enc.write_u32(enc.TYPE_WS_OPTIONS, 1)

        if options.post:
            # can only be set to 1 or unset
            # https://curl.se/libcurl/c/CURLOPT_POST.html
            enc.write_u32(enc.TYPE_POST, 1)

        # Write the first upload to the file.
        if options.upload1:
            enc.write_bytes(enc.TYPE_UPLOAD1, options.upload1.encode("utf-8"))
        elif options.upload1file:
            with open(options.upload1file, "rb") as g:
                enc.write_bytes(enc.TYPE_UPLOAD1, g.read())

        # Write an array of headers to the file.
        if options.header:
            for header in options.header:
                enc.write_string(enc.TYPE_HEADER, header)

        # Write an array of headers to the file.
        if options.mailrecipient:
            for mailrecipient in options.mailrecipient:
                enc.write_string(enc.TYPE_MAIL_RECIPIENT, mailrecipient)

        # Write an array of mimeparts to the file.
        if options.mimepart:
            for mimepart in options.mimepart:
                enc.write_mimepart(mimepart)

    return ScriptRC.SUCCESS


def get_options():
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
    parser.add_argument("--wsoptions", action='store_true')
    parser.add_argument("--connectonly", type=int)
    parser.add_argument("--post", action='store_true')
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

    return parser.parse_args()


def setup_logging():
    """
    Set up logging from the command line options
    """
    root_logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s %(levelname)-5.5s %(message)s")
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stdout_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(stdout_handler)
    root_logger.setLevel(logging.DEBUG)


class ScriptRC(object):
    """Enum for script return codes"""
    SUCCESS = 0
    FAILURE = 1
    EXCEPTION = 2


class ScriptException(Exception):
    pass


def main():
    # Get the options from the user.
    options = get_options()

    setup_logging()

    # Run main script.
    try:
        rc = generate_corpus(options)
    except Exception as e:
        log.exception(e)
        rc = ScriptRC.EXCEPTION

    log.info("Returning %d", rc)
    return rc


if __name__ == '__main__':
    sys.exit(main())
