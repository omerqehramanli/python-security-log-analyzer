"""Command-line interface for the Security Log Analyzer.

Examples:
    python main.py                                  # analyze ./security.log
    python main.py sample_logs/security.log
    python main.py sample_logs/auth.log --year 2026 # OpenSSH auth.log
    python main.py auth.log --threshold 10 --window 10 --json report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from log_analyzer import (
    DEFAULT_HIGH,
    DEFAULT_MEDIUM,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_MINUTES,
    analyze,
    render_text,
    to_dict,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect failed logins and brute-force activity in authentication logs."
    )
    parser.add_argument(
        "logfile", nargs="?", default="security.log", help="log file to analyze (default: security.log)"
    )
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help=f"failed logins that count as a brute-force burst (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--window", type=int, default=DEFAULT_WINDOW_MINUTES,
        help=f"time window in minutes for the burst rule (default: {DEFAULT_WINDOW_MINUTES})",
    )
    parser.add_argument(
        "--medium", type=int, default=DEFAULT_MEDIUM,
        help=f"total failures for MEDIUM risk (default: {DEFAULT_MEDIUM})",
    )
    parser.add_argument(
        "--high", type=int, default=DEFAULT_HIGH,
        help=f"total failures for HIGH risk (default: {DEFAULT_HIGH})",
    )
    parser.add_argument(
        "--year", type=int, default=None,
        help="year to assume for syslog timestamps, which have none (default: current year)",
    )
    parser.add_argument(
        "--output", default="security_report.txt", help="text report path (default: security_report.txt)"
    )
    parser.add_argument("--no-file", action="store_true", help="print the report only, do not write a file")
    parser.add_argument("--json", metavar="PATH", help="also write the results as JSON")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.logfile)

    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            result = analyze(
                handle,
                year=args.year,
                threshold=args.threshold,
                window_minutes=args.window,
                medium_threshold=args.medium,
                high_threshold=args.high,
            )
    except FileNotFoundError:
        print(f"Error: log file not found: {path}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: cannot read {path}: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    report = render_text(result)
    print(report)

    if not args.no_file:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report saved to {args.output}")
    if args.json:
        Path(args.json).write_text(json.dumps(to_dict(result), indent=2), encoding="utf-8")
        print(f"JSON saved to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
