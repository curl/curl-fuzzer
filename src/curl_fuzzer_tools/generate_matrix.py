#!/usr/bin/env python3
"""Generate a matrix of fuzzers for Github Actions"""

import json
import logging
import os
import sys

log = logging.getLogger(__name__)

def main() -> None:
    """Begin main function"""
    # Get FUZZ_TARGETS from the environment
    fuzz_targets = os.getenv("FUZZ_TARGETS", "")
    log.info("Fuzz targets: %s", fuzz_targets)
    if not fuzz_targets:
        log.error("No fuzz targets found in the environment variable FUZZ_TARGETS")

    # Split the targets by whitespace
    targets = fuzz_targets.split()
    log.info("Parsed targets: %s", targets)

    # Generate a matrix for Github Actions
    output_data = {
        "fuzzer": targets
    }
    print(f"matrix={json.dumps(output_data)}")

def run() -> None:
    """Run the main function"""
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    main()

if __name__ == "__main__":
    run()
