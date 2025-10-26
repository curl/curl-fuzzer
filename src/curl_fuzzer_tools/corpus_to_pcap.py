#!/usr/bin/env python
#
"""Script which converts corpus files to pcap files."""

import argparse
import logging
from pathlib import Path
from typing import Dict

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from curl_fuzzer_tools.corpus import BaseType, TLVContents, TLVDecoder
from curl_fuzzer_tools.logger import common_logging

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


def corpus_to_pcap(args: argparse.Namespace) -> None:
    """Convert the given corpus file to a pcap file."""
    response_tlvs: Dict[int, TLVContents] = {}

    input_file = Path(args.input)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file {args.input} does not exist")

    with open(input_file, "rb") as f:
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

            # By default generate a packet with source port 80. This hints at HTTP;
            # in future we can be smart and pick a port that'll influence Wireshark.
            # But for now, you can just Decode As.. in Wireshark to get
            # whatever protocol you want.
            pkt = IP() / TCP(sport=80, flags="SA") / Raw(tlv.data)

            log.debug("Converted %s to packet: %s", tlv.TYPEMAP[rsp], pkt)
            response_packets.append(pkt)

    output_file = str(args.output)

    log.info("Writing %d packets to %s", len(response_packets), output_file)
    wrpcap(output_file, response_packets)


def main() -> None:
    """Begin main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # Run main script.
    corpus_to_pcap(args)


def run() -> None:
    """Set up common logging and run the main function."""
    common_logging(__name__, __file__)
    main()


if __name__ == "__main__":
    run()
