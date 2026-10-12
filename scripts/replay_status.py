#!/usr/bin/env python3
"""Initialize and update selected-target coverage replay status."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from summarize_coverage import CoverageReportError, record_replay_result


def _exit_code(value: str) -> int | None:
    """Parse an exit code or the null marker used for skipped targets."""
    return None if value == "null" else int(value)


def main(argv: Sequence[str] | None = None) -> int:
    """Initialize selected targets or record one target's replay evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init", help="Replace stale replay status")
    initialize.add_argument("--status", type=Path, required=True)
    initialize.add_argument("targets", nargs="*")

    record = commands.add_parser("record", help="Record one selected target's result")
    record.add_argument("--status", type=Path, required=True)
    record.add_argument("--target", required=True)
    record.add_argument(
        "--outcome",
        choices=("executed", "missing_binary", "no_corpus", "empty_corpus"),
        required=True,
    )
    record.add_argument("--exit-code", type=_exit_code, required=True)
    record.add_argument("--expected-inputs", type=int, required=True)
    record.add_argument("--count-errors", type=int, required=True)
    record.add_argument("--counters", type=Path, required=True)
    record.add_argument("--log", type=Path, required=True)
    record.add_argument("--profiles", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            status = {
                "complete": False,
                "targets": [
                    {"target": name, "outcome": "incomplete"} for name in args.targets
                ],
            }
            args.status.write_text(json.dumps(status) + "\n", encoding="utf-8")
        else:
            record_replay_result(
                args.status,
                args.target,
                args.outcome,
                args.exit_code,
                args.expected_inputs,
                args.count_errors,
                args.counters,
                args.log,
                args.profiles,
            )
    except (OSError, UnicodeError, json.JSONDecodeError, CoverageReportError) as error:
        print(f"coverage replay status: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
