#!/usr/bin/env python3
"""Scan public text for unsupported Daylight product-boundary claims."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from daylight_standard_validate import unsupported_claims_in_text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    failed = False
    for raw_path in args.paths:
        path = Path(raw_path)
        text = path.read_text(encoding="utf-8")
        findings = unsupported_claims_in_text(text)
        for finding in findings:
            print(f"{path}: unsupported authority phrase: {finding}", file=sys.stderr)
        failed = failed or bool(findings)
    if not failed:
        print("daylight market boundary: pass")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
