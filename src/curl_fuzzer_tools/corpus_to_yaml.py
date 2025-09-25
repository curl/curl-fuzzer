#!/usr/bin/env python3
"""Tool to read corpus files and convert them to YAML format."""

import argparse
import logging
import re
import yaml
from pathlib import Path
from typing import Dict, Any, List, Union

from curl_fuzzer_tools import common_logging
from curl_fuzzer_tools.corpus import TLVDecoder

log = logging.getLogger(__name__)


def extract_tlv_types_from_header(header_file_path: Path) -> Dict[int, str]:
    """Extract TLV type definitions from curl_fuzzer.h header file."""
    tlv_types = {}

    if not header_file_path.exists():
        log.warning(f"Header file {header_file_path} not found, using built-in types")
        return {}

    with open(header_file_path, "r") as f:
        content = f.read()

    # Pattern to match #define TLV_TYPE_NAME value
    pattern = r'#define\s+TLV_TYPE_(\w+)\s+(\d+)'

    for match in re.finditer(pattern, content):
        type_name = match.group(1)
        type_value = int(match.group(2))
        tlv_types[type_value] = type_name

    log.info(f"Extracted {len(tlv_types)} TLV type definitions")
    return tlv_types


def get_tlv_type_name(tlv_type: int, tlv_types: Dict[int, str]) -> str:
    """Get the human-readable name for a TLV type."""
    return tlv_types.get(tlv_type, f"UNKNOWN_{tlv_type}")


def format_value_for_yaml(data: bytes, verbose: bool = False) -> Union[str, int, Dict[str, Any]]:
    """Format TLV value appropriately for YAML output."""
    if len(data) == 0:
        return ""

    # Try to decode as UTF-8 string
    try:
        decoded = data.decode('utf-8')
        # Check if it's printable ASCII/UTF-8
        if decoded.isprintable():
            return decoded
    except UnicodeDecodeError:
        pass

    # Check if it's a 4-byte integer (common in TLVs)
    if len(data) == 4:
        # Try big-endian first (network byte order)
        import struct
        try:
            value = struct.unpack('!I', data)[0]
            # Return both representations for clarity if verbose
            if verbose:
                return {
                    'integer': value,
                    'hex': data.hex()
                }
            else:
                return value
        except struct.error:
            pass

    # For non-verbose mode, just return hex for binary data
    if not verbose:
        return data.hex()

    # Check if it's binary data that might be partially printable
    try:
        decoded = data.decode('utf-8', errors='replace')
        if any(c.isprintable() or c.isspace() for c in decoded):
            return {
                'hex': data.hex(),
                'partial_text': decoded,
                'note': 'Binary data with some printable characters'
            }
    except:
        pass

    # For pure binary data, represent as hex
    return {
        'hex': data.hex(),
        'note': 'Binary data'
    }


def corpus_to_yaml(corpus_file: Path, tlv_types: Dict[int, str], verbose: bool = False) -> Dict[str, Any]:
    """Convert a corpus file to a YAML-ready dictionary."""
    result = {
        'corpus_file': str(corpus_file),
        'tlvs': []
    }

    with open(corpus_file, "rb") as f:
        data = f.read()

    result['file_size'] = len(data)

    try:
        decoder = TLVDecoder(data)
        for tlv in decoder:
            tlv_entry = {
                'type': get_tlv_type_name(tlv.type, tlv_types),
                'type_id_v1': tlv.type,
                'length': tlv.length
            }

            if tlv.length > 0:
                tlv_entry['value'] = format_value_for_yaml(tlv.data, verbose)

            result['tlvs'].append(tlv_entry)

    except Exception as e:
        log.error(f"Error parsing corpus file {corpus_file}: {e}")
        result['error'] = str(e)

    return result


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Convert curl fuzzer corpus files to YAML format"
    )
    parser.add_argument(
        "input",
        help="Corpus file or directory to convert"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (default: create yaml directory structure)"
    )
    parser.add_argument(
        "--header",
        help="Path to curl_fuzzer.h header file (default: auto-detect)",
        type=Path
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print YAML output"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include verbose output with multiple data representations"
    )
    parser.add_argument(
        "--yaml-dir",
        help="Base directory for YAML output (default: yaml/)",
        type=Path,
        default=Path("yaml")
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Output to stdout instead of creating files"
    )

    args = parser.parse_args()

    # Auto-detect header file if not provided
    if args.header is None:
        header_file = Path(__file__).parent.parent.parent / "curl_fuzzer.h"
    else:
        header_file = args.header

    # Extract TLV type definitions
    tlv_types = extract_tlv_types_from_header(header_file)

    input_path = Path(args.input)

    # Configure YAML output
    yaml_args = {
        'default_flow_style': False,
        'allow_unicode': True,
    }

    if args.pretty:
        yaml_args['indent'] = 2
        yaml_args['width'] = 120

    if input_path.is_file():
        # Single file processing
        yaml_data = corpus_to_yaml(input_path, tlv_types, args.verbose)

        if args.output:
            # Use specified output file
            with open(args.output, 'w', encoding='utf-8') as f:
                yaml.dump(yaml_data, f, **yaml_args)
            log.info(f"Output written to {args.output}")
        elif args.stdout:
            # Output to stdout
            import sys
            yaml.dump(yaml_data, sys.stdout, **yaml_args)
        else:
            # Create corresponding YAML file in yaml directory
            yaml_file = create_yaml_path(input_path, args.yaml_dir)
            yaml_file.parent.mkdir(parents=True, exist_ok=True)
            with open(yaml_file, 'w', encoding='utf-8') as f:
                yaml.dump(yaml_data, f, **yaml_args)
            log.info(f"Output written to {yaml_file}")

    elif input_path.is_dir():
        # Directory processing - create yaml directory structure
        if args.stdout:
            log.error("Cannot output directory contents to stdout. Use --output for single file or remove --stdout.")
            return

        corpus_files = list(input_path.rglob("*"))
        corpus_files = [f for f in corpus_files if f.is_file()]

        processed_count = 0
        for corpus_file in corpus_files:
            try:
                yaml_data = corpus_to_yaml(corpus_file, tlv_types, args.verbose)

                if args.output:
                    # For directory input with single output file, create a list
                    if processed_count == 0:
                        all_yaml_data = []
                    all_yaml_data.append(yaml_data)
                else:
                    # Create corresponding YAML file maintaining directory structure
                    # Use the input directory itself as the base, so subdirectories are preserved
                    yaml_file = create_yaml_path(corpus_file, args.yaml_dir, input_path)
                    yaml_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(yaml_file, 'w', encoding='utf-8') as f:
                        yaml.dump(yaml_data, f, **yaml_args)
                    log.debug(f"Converted {corpus_file} -> {yaml_file}")

                processed_count += 1

            except Exception as e:
                log.error(f"Error processing {corpus_file}: {e}")

        if args.output and processed_count > 0:
            with open(args.output, 'w', encoding='utf-8') as f:
                yaml.dump(all_yaml_data, f, **yaml_args)
            log.info(f"Output written to {args.output}")
        elif not args.output:
            log.info(f"Processed {processed_count} files to {args.yaml_dir}/")

    else:
        raise FileNotFoundError(f"Input path {args.input} does not exist")


def create_yaml_path(corpus_file: Path, yaml_base_dir: Path, corpus_base_dir: Path = None) -> Path:
    """Create the corresponding YAML file path maintaining directory structure."""
    if corpus_base_dir:
        # For directory processing, maintain relative structure
        try:
            relative_path = corpus_file.relative_to(corpus_base_dir)
            # Create YAML filename while preserving directory structure
            yaml_path = yaml_base_dir / relative_path.with_suffix(relative_path.suffix + '.yaml')
            return yaml_path
        except ValueError:
            # If corpus_file is not relative to corpus_base_dir, use just the filename
            relative_path = corpus_file.name
    else:
        # For single file processing, use just the filename
        relative_path = corpus_file.name

    # Create YAML filename
    yaml_filename = f"{relative_path}.yaml"
    return yaml_base_dir / yaml_filename


def run() -> None:
    """Set up common logging and run the main function."""
    common_logging(__name__, __file__)
    main()


if __name__ == "__main__":
    run()
