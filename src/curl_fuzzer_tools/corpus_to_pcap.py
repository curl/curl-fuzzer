#!/usr/bin/env python
#
# Script which converts corpus files to pcap files.

import argparse
import logging
import sys

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP

from curl_fuzzer_tools.corpus import BaseType, TLVDecoder

log = logging.getLogger(__name__)


# All the responses we want to convert to pcap
RESPONSES = [
    BaseType.TYPE_RSP0,
    BaseType.TYPE_RSP1,
    BaseType.TYPE_RSP2,
    BaseType.TYPE_RSP3,
    BaseType.TYPE_RSP4,
    BaseType.TYPE_RSP5,
    BaseType.TYPE_RSP6,
    BaseType.TYPE_RSP7,
    BaseType.TYPE_RSP8,
    BaseType.TYPE_RSP9,
    BaseType.TYPE_RSP10,
    BaseType.TYPE_SECRSP0,
    BaseType.TYPE_SECRSP1,
]


def corpus_to_pcap(options):
    response_tlvs = {}

    with open(options.input, "rb") as f:
        dec = TLVDecoder(f.read())
        for tlv in dec:
            if tlv.type in RESPONSES:
                log.debug("Found response: %s", tlv)
                response_tlvs[tlv.type] = tlv
            else:
                log.debug("Ignoring: %s", tlv)

    response_packets = []

    for rsp in RESPONSES:
        if rsp in response_tlvs:
            tlv = response_tlvs[rsp]

            # By default generate a packet with source port 80. This hints at HTTP; in future we can be smart and
            # pick a port that'll influence Wireshark. But for now, you can just Decode As.. in Wireshark to get
            # whatever protocol you want.
            pkt = IP() / TCP(sport=80, flags="SA") / tlv.data
            log.debug("Converted %s to packet: %s", tlv.TYPEMAP[rsp], pkt)
            response_packets.append(pkt)

    log.debug("Writing %d packets to %s", len(response_packets), options.output)
    wrpcap(options.output, response_packets)

    return ScriptRC.SUCCESS


def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
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
        rc = corpus_to_pcap(options)
    except Exception as e:
        log.exception(e)
        rc = ScriptRC.EXCEPTION

    log.info("Returning %d", rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
