#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WITNESS_TOOL = REPO_ROOT / "tools" / "wuci_witness.py"


def normalize_args(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    command = argv[0]
    rest = argv[1:]
    normalized: list[str] = [command]
    bundle_seen = False
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg == "--runner":
            if index + 1 >= len(rest):
                raise SystemExit("missing value for --runner")
            os.environ["WUCI_JI_RUNNER"] = rest[index + 1]
            index += 2
            continue
        if arg == "--bundle":
            bundle_seen = True
            normalized.extend(rest[index : index + 2])
            index += 2
            continue
        if not arg.startswith("-") and not bundle_seen:
            normalized.extend(["--bundle", arg])
            bundle_seen = True
            index += 1
            continue
        normalized.append(arg)
        index += 1
    return normalized


def main() -> None:
    argv = [str(WITNESS_TOOL), *normalize_args(sys.argv[1:])]
    os.execv(sys.executable, [sys.executable, *argv])


if __name__ == "__main__":
    main()
