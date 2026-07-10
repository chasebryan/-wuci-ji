#!/usr/bin/env python3
"""Scan public text for unsupported Daylight product-boundary claims."""

from __future__ import annotations

import argparse
import sys

from daylight_claim_scan import report_exit_code, scan_paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    report = scan_paths(args.paths)
    for error in report["errors"]:
        print(f"{error['path']}: {error['code']}: {error['message']}", file=sys.stderr)
    for finding in report["findings"]:
        print(
            f"{finding['path']}: unsupported authority phrase: {finding['phrase']} "
            f"(line {finding['line']}, column {finding['column']})",
            file=sys.stderr,
        )
    if report["status"] == "pass":
        print("daylight market boundary: pass")
    return report_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
