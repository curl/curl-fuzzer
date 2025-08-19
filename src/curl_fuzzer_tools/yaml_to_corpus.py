#!/usr/bin/env python3
"""Tool to convert YAML files back to binary corpus format."""

import argparse
import logging
import yaml
import struct
from pathlib import Path
from typing import Dict, Any

from curl_fuzzer_tools import common_logging
from curl_fuzzer_tools.corpus import TLVEncoder

log = logging.getLogger(__name__)


def extract_tlv_types_from_header(header_file_path: Path) -> Dict[str, int]:
    """Extract TLV type definitions from curl_fuzzer.h header file and return name->value mapping."""
    import re
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
        tlv_types[type_name] = type_value

    log.info(f"Extracted {len(tlv_types)} TLV type definitions")
    return tlv_types


def get_tlv_type_id(type_name: str, tlv_types: Dict[str, int]) -> int:
    """Get the numeric ID for a TLV type name."""
    if type_name in tlv_types:
        return tlv_types[type_name]

    # Handle UNKNOWN_<number> format
    if type_name.startswith("UNKNOWN_"):
        try:
            return int(type_name.split("_", 1)[1])
        except (ValueError, IndexError):
            pass

    raise ValueError(f"Unknown TLV type: {type_name}")


def parse_yaml_value(value: Any) -> bytes:
    """Convert a YAML value back to bytes."""
    if value == "" or value is None:
        return b""

    if isinstance(value, str):
        # Check if it's a hex string
        if all(c in '0123456789abcdefABCDEF' for c in value) and len(value) % 2 == 0:
            try:
                return bytes.fromhex(value)
            except ValueError:
                pass

        # Otherwise treat as UTF-8 string
        return value.encode('utf-8')

    elif isinstance(value, int):
        # Convert integer to 4-byte big-endian
        return struct.pack('!I', value)

    elif isinstance(value, dict):
        # Handle verbose format with hex/integer/partial_text
        if 'hex' in value:
            return bytes.fromhex(value['hex'])
        elif 'integer' in value:
            return struct.pack('!I', value['integer'])
        elif 'partial_text' in value:
            # For partial text, we'll use the hex representation if available
            if 'hex' in value:
                return bytes.fromhex(value['hex'])
            else:
                return value['partial_text'].encode('utf-8', errors='replace')

    # Fallback: convert to string and then to bytes
    return str(value).encode('utf-8')


def yaml_to_corpus(yaml_file: Path, tlv_types: Dict[str, int], force_v1_ids: bool = False) -> bytes:
    """Convert a YAML file back to binary corpus format."""
    with open(yaml_file, 'r', encoding='utf-8') as f:
        yaml_data = yaml.safe_load(f)

    if not isinstance(yaml_data, dict) or 'tlvs' not in yaml_data:
        raise ValueError("Invalid YAML format: missing 'tlvs' key")

    # Create a temporary in-memory file-like object for the encoder
    import io
    output = io.BytesIO()

    # We don't have test_data for this use case, so pass None
    encoder = TLVEncoder(output, None)

    for tlv_entry in yaml_data['tlvs']:
        if not isinstance(tlv_entry, dict):
            log.warning(f"Skipping invalid TLV entry: {tlv_entry}")
            continue

        # Get type ID
        if force_v1_ids:
            # Force using v1 type IDs
            if 'type_id_v1' in tlv_entry:
                type_id = tlv_entry['type_id_v1']
            elif 'type_id' in tlv_entry:
                type_id = tlv_entry['type_id']
            else:
                log.warning(f"TLV entry missing type_id_v1 or type_id when --force-v1-ids is used: {tlv_entry}")
                continue
        else:
            # Default behavior: prefer type name lookup, fall back to IDs
            if 'type' in tlv_entry:
                try:
                    type_id = get_tlv_type_id(tlv_entry['type'], tlv_types)
                except ValueError as e:
                    log.warning(f"Type name lookup failed: {e}. Falling back to numeric ID.")
                    if 'type_id_v1' in tlv_entry:
                        type_id = tlv_entry['type_id_v1']
                    elif 'type_id' in tlv_entry:
                        type_id = tlv_entry['type_id']
                    else:
                        log.warning(f"TLV entry missing type information: {tlv_entry}")
                        continue
            elif 'type_id_v1' in tlv_entry:
                type_id = tlv_entry['type_id_v1']
            elif 'type_id' in tlv_entry:
                type_id = tlv_entry['type_id']
            else:
                log.warning(f"TLV entry missing type information: {tlv_entry}")
                continue

        # Get length and value
        length = tlv_entry.get('length', 0)

        if length > 0:
            if 'value' not in tlv_entry:
                log.warning(f"TLV entry with length {length} but no value: {tlv_entry}")
                value_bytes = b""
            else:
                value_bytes = parse_yaml_value(tlv_entry['value'])
                # Verify length matches
                if len(value_bytes) != length:
                    log.warning(f"Length mismatch: expected {length}, got {len(value_bytes)}. Using actual length.")
                    length = len(value_bytes)
        else:
            value_bytes = b""

        # Write the TLV
        encoder.write_bytes(type_id, value_bytes)
        log.debug(f"Wrote TLV type {type_id}, length {len(value_bytes)}")

    return output.getvalue()


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Convert YAML files back to curl fuzzer corpus format"
    )
    parser.add_argument(
        "input",
        help="YAML file or directory to convert"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file or directory (default: create corpus files alongside YAML files)"
    )
    parser.add_argument(
        "--header",
        help="Path to curl_fuzzer.h header file (default: auto-detect)",
        type=Path
    )
    parser.add_argument(
        "--corpus-dir",
        help="Base directory for corpus output (default: corpus_output/)",
        type=Path,
        default=Path("corpus_output")
    )
    parser.add_argument(
        "--force-v1-ids",
        action="store_true",
        help="Force using type_id_v1 field instead of type name lookup"
    )

    args = parser.parse_args()

    # Auto-detect header file if not provided
    if args.header is None:
        header_file = Path(__file__).parent.parent.parent / "curl_fuzzer.h"
    else:
        header_file = args.header

    # Extract TLV type definitions (name -> value mapping)
    tlv_types = extract_tlv_types_from_header(header_file)

    input_path = Path(args.input)

    if input_path.is_file():
        # Single file processing
        if not input_path.suffix == '.yaml':
            log.warning(f"Input file {input_path} doesn't have .yaml extension")

        corpus_data = yaml_to_corpus(input_path, tlv_types, args.force_v1_ids)

        if args.output:
            output_file = Path(args.output)
        else:
            # Create corpus file alongside YAML file
            output_file = input_path.with_suffix('')  # Remove .yaml extension

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'wb') as f:
            f.write(corpus_data)

        log.info(f"Converted {input_path} -> {output_file} ({len(corpus_data)} bytes)")

    elif input_path.is_dir():
        # Directory processing
        yaml_files = list(input_path.rglob("*.yaml"))

        if not yaml_files:
            log.error(f"No YAML files found in {input_path}")
            return

        processed_count = 0
        for yaml_file in yaml_files:
            try:
                corpus_data = yaml_to_corpus(yaml_file, tlv_types, args.force_v1_ids)

                if args.output:
                    # Create relative path structure in output directory
                    relative_path = yaml_file.relative_to(input_path)
                    output_file = Path(args.output) / relative_path.with_suffix('')
                else:
                    # Create corresponding corpus file maintaining directory structure
                    output_file = create_corpus_path(yaml_file, args.corpus_dir, input_path)

                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'wb') as f:
                    f.write(corpus_data)

                log.debug(f"Converted {yaml_file} -> {output_file} ({len(corpus_data)} bytes)")
                processed_count += 1

            except Exception as e:
                log.error(f"Error processing {yaml_file}: {e}")

        log.info(f"Processed {processed_count} YAML files")

    else:
        raise FileNotFoundError(f"Input path {args.input} does not exist")


def create_corpus_path(yaml_file: Path, corpus_base_dir: Path, yaml_base_dir: Path = None) -> Path:
    """Create the corresponding corpus file path maintaining directory structure."""
    if yaml_base_dir:
        # For directory processing, maintain relative structure
        try:
            relative_path = yaml_file.relative_to(yaml_base_dir)
            # Remove .yaml extension
            corpus_path = corpus_base_dir / relative_path.with_suffix('')
            return corpus_path
        except ValueError:
            # If yaml_file is not relative to yaml_base_dir, use just the filename
            relative_path = yaml_file.stem  # filename without extension
    else:
        # For single file processing, use just the filename without extension
        relative_path = yaml_file.stem

    return corpus_base_dir / relative_path


def run() -> None:
    """Set up common logging and run the main function."""
    common_logging(__name__, __file__)
    main()


if __name__ == "__main__":
    run()
