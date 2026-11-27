"""Inspect-only command line interface for pyzipcage."""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any, Optional, Sequence

from .core import inspect_zip_file
from .errors import ZipCageError
from .models import ZipPolicy


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _positive_ratio(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number")
    if math.isnan(value) or value < 1.0:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""

    from . import __version__

    parser = argparse.ArgumentParser(
        prog="pyzipcage",
        description="Inspect a classic ZIP archive without extracting it.",
    )
    parser.add_argument("--version", action="version", version="pyzipcage {}".format(__version__))
    subparsers = parser.add_subparsers(dest="command")
    inspect_parser = subparsers.add_parser("inspect", help="parse headers and report safety findings")
    inspect_parser.add_argument("path", help="ZIP file to inspect")
    inspect_parser.add_argument("--max-entries", type=_positive_int, default=1000)
    inspect_parser.add_argument("--max-entry-bytes", type=_positive_int, default=50 * 1024 * 1024)
    inspect_parser.add_argument("--max-total-bytes", type=_positive_int, default=200 * 1024 * 1024)
    inspect_parser.add_argument("--max-compression-ratio", type=_positive_ratio, default=100.0)
    inspect_parser.add_argument("--max-archive-bytes", type=_positive_int, default=512 * 1024 * 1024)
    inspect_parser.add_argument("--max-depth", type=_positive_int, default=20)
    inspect_parser.add_argument("--max-path-length", type=_positive_int, default=512)
    inspect_parser.add_argument("--allow-polyglot", action="store_true", help="tolerate prepended, trailing or gap bytes")
    inspect_parser.add_argument(
        "--case-sensitive-duplicates",
        action="store_true",
        help="do not flag duplicates that differ only by case",
    )
    return parser


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        if math.isnan(value):
            return "NaN"
        return "Infinity" if value > 0 else "-Infinity"
    return value


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "inspect":
        parser.print_help(sys.stderr)
        return 2
    try:
        policy = ZipPolicy(
            max_entries=args.max_entries,
            max_entry_bytes=args.max_entry_bytes,
            max_total_bytes=args.max_total_bytes,
            max_compression_ratio=args.max_compression_ratio,
            max_archive_bytes=args.max_archive_bytes,
            max_depth=args.max_depth,
            max_path_length=args.max_path_length,
            reject_polyglot=not args.allow_polyglot,
            case_insensitive_duplicates=not args.case_sensitive_duplicates,
        )
        report = inspect_zip_file(args.path, policy)
    except ZipCageError as exc:
        print("pyzipcage: error: {}".format(exc), file=sys.stderr)
        return 3
    print(json.dumps(_json_ready(report.to_dict()), indent=2, sort_keys=True))
    return 0 if report.safe else 3


__all__ = ["build_parser", "main"]
