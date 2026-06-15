#!/usr/bin/env python3
"""
Build a curl-fuzzer repro Docker image.

Orchestrates the oss-fuzz build pipeline:
1. Clone oss-fuzz (if needed)
2. Build the curl builder image
3. Build fuzzers with GDB support
4. Package into a repro image with the built GDB
"""

import argparse
import logging
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SANITIZERS = ["address", "undefined", "memory", "none"]
ENGINES = ["libfuzzer", "honggfuzz", "afl", "centipede", "none"]
ARCHITECTURES = ["x86_64", "i386"]

REPO_ROOT = Path(__file__).resolve().parent.parent


def run(cmd: list[object], **kwargs: Any) -> None:
    log.info("+ %s", " ".join(str(c) for c in cmd))
    subprocess.check_call([str(c) for c in cmd], **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--sanitizer",
        default="address",
        choices=SANITIZERS,
    )
    parser.add_argument(
        "--engine",
        default="libfuzzer",
        choices=ENGINES,
    )
    parser.add_argument(
        "--architecture",
        default="x86_64",
        choices=ARCHITECTURES,
    )
    parser.add_argument(
        "--oss-fuzz-dir",
        type=Path,
        help="Path to existing oss-fuzz checkout (cloned automatically if omitted)",
    )
    parser.add_argument(
        "--source-path",
        type=Path,
        help="Local curl-fuzzer source to mount into the build container",
    )
    parser.add_argument(
        "--tag",
        help="Docker image tag (default: curl-fuzzer:{sanitizer}-{engine}-{date})",
    )
    args = parser.parse_args()

    oss_fuzz_dir = args.oss_fuzz_dir
    if not oss_fuzz_dir:
        oss_fuzz_dir = REPO_ROOT / ".oss-fuzz"
        if not oss_fuzz_dir.exists():
            run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/google/oss-fuzz.git",
                    oss_fuzz_dir,
                ]
            )

    helper = oss_fuzz_dir / "infra" / "helper.py"
    if not helper.exists():
        sys.exit(f"helper.py not found at {helper}")

    # Step 1: Build the curl builder image.
    run([sys.executable, helper, "build_image", "--pull", "--cache", "curl"])

    # Step 2: Build fuzzers with GDB mode and GDB install.
    build_cmd = [
        sys.executable,
        helper,
        "build_fuzzers",
        "--clean",
        "--sanitizer",
        args.sanitizer,
        "--engine",
        args.engine,
        "--architecture",
        args.architecture,
        "-e",
        "GDBMODE=1",
        "-e",
        "GDBINSTALL=1",
        "curl",
    ]
    if args.source_path:
        build_cmd.append(str(args.source_path.resolve()))
    run(build_cmd)

    # Step 3: Build the repro Docker image.
    out_dir = oss_fuzz_dir / "build" / "out" / "curl"
    if not out_dir.exists():
        sys.exit(f"Build output not found at {out_dir}")

    date_tag = datetime.now(timezone.utc).strftime("%Y%m%d")
    tag = args.tag or f"curl-fuzzer:{args.sanitizer}-{args.engine}-{date_tag}"
    dockerfile = REPO_ROOT / "docker" / "Dockerfile.repro"

    with tempfile.TemporaryDirectory() as tmpdir:
        context = Path(tmpdir)
        shutil.copytree(out_dir, context / "out")
        run(
            [
                "docker",
                "build",
                "-f",
                dockerfile,
                "-t",
                tag,
                context,
            ]
        )

    log.info("Repro image built: %s", tag)
    log.info(
        "Usage: docker run --rm -v /path/to/testcase:/testcase %s ./curl_fuzzer /testcase",
        tag,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
