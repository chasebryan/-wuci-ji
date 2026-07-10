#!/usr/bin/env python3
"""Validate every tracked public site JSON string against Daylight claims."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from daylight_claim_scan import (
    ClaimScanWriteError,
    dump_report,
    report_exit_code,
    report_path_overlaps_inputs,
    scan_tracked_public_json_claims,
    write_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default="-", help="report path below the current directory, or -")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = scan_tracked_public_json_claims()
    if args.report == "-":
        print(dump_report(report), end="")
    else:
        root = Path.cwd().resolve(strict=True)
        output = (root / args.report).absolute()
        try:
            output.relative_to(root)
        except ValueError:
            print("public JSON claim report path must stay under the current directory", file=sys.stderr)
            return 2
        if report_path_overlaps_inputs(output, report["inputs"], root=root):
            print("public JSON claim report path must not overwrite a scanned input", file=sys.stderr)
            return 2
        try:
            write_report(output, report)
        except ClaimScanWriteError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    for error in report["errors"]:
        print(f"{error['path']}: {error['code']}: {error['message']}", file=sys.stderr)
    for finding in report["findings"]:
        print(
            f"{finding['path']} {finding['json_path']}: unsupported authority phrase: {finding['phrase']}",
            file=sys.stderr,
        )
    return report_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
