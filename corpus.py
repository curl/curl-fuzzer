#!/usr/bin/env python
#
# Common corpus functions
import logging
import struct
log = logging.getLogger(__name__)


class BaseType(object):
    TYPE_URL = 1
    TYPE_RSP0 = 2
    TYPE_USERNAME = 3
    TYPE_PASSWORD = 4
    TYPE_POSTFIELDS = 5
    TYPE_HEADER = 6
    TYPE_COOKIE = 7
    TYPE_UPLOAD1 = 8
    TYPE_RANGE = 9
    TYPE_CUSTOMREQUEST = 10
    TYPE_MAIL_RECIPIENT = 11
    TYPE_MAIL_FROM = 12
    TYPE_MIME_PART = 13
    TYPE_MIME_PART_NAME = 14
    TYPE_MIME_PART_DATA = 15
    TYPE_HTTPAUTH = 16
    TYPE_RSP1 = 17
    TYPE_RSP2 = 18
    TYPE_RSP3 = 19
    TYPE_RSP4 = 20
    TYPE_RSP5 = 21
    TYPE_RSP6 = 22
    TYPE_RSP7 = 23
    TYPE_RSP8 = 24
    TYPE_RSP9 = 25
    TYPE_RSP10 = 26
    TYPE_OPTHEADER = 27
    TYPE_NOBODY = 28
    TYPE_FOLLOWLOCATION = 29
    TYPE_ACCEPT_ENCODING = 30
    TYPE_SECRSP0 = 31
    TYPE_SECRSP1 = 32
    TYPE_WILDCARDMATCH = 33
    TYPE_RTSP_REQUEST = 34
    TYPE_RTSP_SESSION_ID = 35
    TYPE_RTSP_STREAM_URI = 36
    TYPE_RTSP_TRANSPORT = 37
    TYPE_RTSP_CLIENT_CSEQ = 38
    TYPE_MAIL_AUTH = 39
    TYPE_HTTP_VERSION = 40
    TYPE_DOH_URL = 41
    TYPE_LOGIN_OPTIONS = 42
    TYPE_XOAUTH2_BEARER = 43
    TYPE_USERPWD = 44
    TYPE_USERAGENT = 45
    TYPE_NETRC = 46
    TYPE_SSH_HOST_PUBLIC_KEY_SHA256 = 47
    TYPE_POST = 48
    TYPE_WS_OPTIONS = 49
    TYPE_CONNECT_ONLY = 50
    TYPE_HSTS = 51
    TYPE_HTTPPOSTBODY = 52 # https://curl.se/libcurl/c/CURLOPT_HTTPPOST.html

    TYPEMAP = {
        TYPE_URL: "CURLOPT_URL",
        TYPE_RSP0: "Server banner (sent on connection)",
        TYPE_RSP1: "Server response 1",
        TYPE_RSP2: "Server response 2",
        TYPE_RSP3: "Server response 3",
        TYPE_RSP4: "Server response 4",
        TYPE_RSP5: "Server response 5",
        TYPE_RSP6: "Server response 6",
        TYPE_RSP7: "Server response 7",
        TYPE_RSP8: "Server response 8",
        TYPE_RSP9: "Server response 9",
        TYPE_RSP10: "Server response 10",
        TYPE_SECRSP0: "Socket 2: Server banner (sent on connection)",
        TYPE_SECRSP1: "Socket 2: Server response 1",
        TYPE_USERNAME: "CURLOPT_USERNAME",
        TYPE_PASSWORD: "CURLOPT_PASSWORD",
        TYPE_POSTFIELDS: "CURLOPT_POSTFIELDS",
        TYPE_HEADER: "CURLOPT_HEADER",
        TYPE_COOKIE: "CURLOPT_COOKIE",
        TYPE_UPLOAD1: "CURLOPT_UPLOAD / CURLOPT_INFILESIZE_LARGE",
        TYPE_RANGE: "CURLOPT_RANGE",
        TYPE_CUSTOMREQUEST: "CURLOPT_CUSTOMREQUEST",
        TYPE_MAIL_RECIPIENT: "curl_slist_append(mail recipient)",
        TYPE_MAIL_FROM: "CURLOPT_MAIL_FROM",
        TYPE_MIME_PART: "curl_mime_addpart",
        TYPE_MIME_PART_NAME: "curl_mime_name",
        TYPE_MIME_PART_DATA: "curl_mime_data",
        TYPE_HTTPAUTH: "CURLOPT_HTTPAUTH",
        TYPE_OPTHEADER: "CURLOPT_HEADER",
        TYPE_NOBODY: "CURLOPT_NOBODY",
        TYPE_FOLLOWLOCATION: "CURLOPT_FOLLOWLOCATION",
        TYPE_ACCEPT_ENCODING: "CURLOPT_ACCEPT_ENCODING",
        TYPE_WILDCARDMATCH: "CURLOPT_WILDCARDMATCH",
        TYPE_RTSP_REQUEST: "CURLOPT_RTSP_REQUEST",
        TYPE_RTSP_SESSION_ID: "CURLOPT_RTSP_SESSION_ID",
        TYPE_RTSP_STREAM_URI: "CURLOPT_RTSP_STREAM_URI",
        TYPE_RTSP_TRANSPORT: "CURLOPT_RTSP_TRANSPORT",
        TYPE_RTSP_CLIENT_CSEQ: "CURLOPT_RTSP_CLIENT_CSEQ",
        TYPE_MAIL_AUTH: "CURLOPT_MAIL_AUTH",
        TYPE_HTTP_VERSION: "CURLOPT_HTTP_VERSION",
        TYPE_DOH_URL: "CURLOPT_DOH_URL",
        TYPE_LOGIN_OPTIONS: "CURLOPT_LOGIN_OPTIONS",
        TYPE_XOAUTH2_BEARER: "CURLOPT_XOAUTH2_BEARER",
        TYPE_USERPWD: "CURLOPT_USERPWD",
        TYPE_USERAGENT: "CURLOPT_USERAGENT",
        TYPE_NETRC: "CURLOPT_NETRC",
        TYPE_SSH_HOST_PUBLIC_KEY_SHA256: "CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256",
        TYPE_POST: "CURLOPT_POST",
        TYPE_WS_OPTIONS: "CURLOPT_WS_OPTIONS",
        TYPE_CONNECT_ONLY: "CURLOPT_CONNECT_ONLY",
        TYPE_HSTS: "CURLOPT_HSTS",
        TYPE_HTTPPOSTBODY: "CURLOPT_HTTPPOST",
    }


class TLVEncoder(BaseType):
    def __init__(self, output, test_data):
        self.output = output
        self.test_data = test_data

    def write_string(self, tlv_type, wstring):
        data = wstring.encode("utf-8")
        self.write_tlv(tlv_type, len(data), data)

    def write_u32(self, tlv_type, num):
        data = struct.pack("!L", num)
        self.write_tlv(tlv_type, len(data), data)

    def write_bytes(self, tlv_type, bytedata):
        self.write_tlv(tlv_type, len(bytedata), bytedata)

    def maybe_write_string(self, tlv_type, wstring):
        if wstring is not None:
            self.write_string(tlv_type, wstring)

    def maybe_write_u32(self, tlv_type, num):
        if num is not None:
            self.write_u32(tlv_type, num)

    def maybe_write_response(self, rsp_type, rsp, rsp_file, rsp_test):
        if rsp:
            self.write_bytes(rsp_type,
                             rsp.encode("utf-8"))
        elif rsp_file:
            with open(rsp_file, "rb") as g:
                self.write_bytes(rsp_type, g.read())
        elif rsp_test:
            wstring = self.test_data.get_test_data(rsp_test)
            self.write_bytes(rsp_type, wstring.encode("utf-8"))

    def write_mimepart(self, namevalue):
        (name, value) = namevalue.split(":", 1)

        # Create some mimepart TLVs for the name and value
        name_tlv = self.encode_tlv(self.TYPE_MIME_PART_NAME, len(name), name)
        value_tlv = self.encode_tlv(self.TYPE_MIME_PART_DATA, len(value), value)

        # Combine the two TLVs into a single TLV.
        part_tlv = name_tlv + value_tlv
        self.write_tlv(self.TYPE_MIME_PART, len(part_tlv), part_tlv)

    def encode_tlv(self, tlv_type, tlv_length, tlv_data=None):
        log.debug("Encoding TLV %r, length %d, data %r",
                  self.TYPEMAP.get(tlv_type, "<unknown>"),
                  tlv_length,
                  tlv_data)

        data = struct.pack("!H", tlv_type)
        data = data + struct.pack("!L", tlv_length)
        if tlv_data:
            data = data + tlv_data

        return data

    def write_tlv(self, tlv_type, tlv_length, tlv_data=None):
        log.debug("Writing TLV %r, length %d, data %r",
                  self.TYPEMAP.get(tlv_type, "<unknown>"),
                  tlv_length,
                  tlv_data)

        data = self.encode_tlv(tlv_type, tlv_length, tlv_data)
        self.output.write(data)


class TLVDecoder(BaseType):
    def __init__(self, inputdata):
        self.inputdata = inputdata
        self.pos = 0
        self.tlv = None

    def __iter__(self):
        self.pos = 0
        self.tlv = None
        return self

    def __next__(self):
        if self.tlv:
            self.pos += self.tlv.total_length()

        if (self.pos + TLVHeader.TLV_DECODE_FMT_LEN) > len(self.inputdata):
            raise StopIteration

        # Get the next TLV
        self.tlv = TLVHeader(self.inputdata[self.pos:])
        return self.tlv

    next = __next__


class TLVHeader(BaseType):
    TLV_DECODE_FMT = "!HL"
    TLV_DECODE_FMT_LEN = struct.calcsize(TLV_DECODE_FMT)

    def __init__(self, data):
        # Parse the data to populate the TLV fields
        (self.type, self.length) = struct.unpack(self.TLV_DECODE_FMT, data[0:self.TLV_DECODE_FMT_LEN])

        # Get the remaining data and store it.
        self.data = data[self.TLV_DECODE_FMT_LEN:self.TLV_DECODE_FMT_LEN + self.length]

    def __repr__(self):
        return ("{self.__class__.__name__}(type={stype!r} ({self.type!r}), length={self.length!r}, data={self.data!r})"
                .format(self=self,
                        stype=self.TYPEMAP.get(self.type, "<unknown>")))

    def total_length(self):
        return self.TLV_DECODE_FMT_LEN + self.length
