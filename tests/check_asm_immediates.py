#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


ABS_LOAD_RE = re.compile(r"\bmov\w*\s+0x([0-9a-f]+),%[a-z0-9]+")


def run_tool(argv: list[str]) -> str:
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.stderr or f"{argv[0]} failed with {proc.returncode}")
    return proc.stdout


def watched_lengths(nm_output: str) -> dict[int, list[str]]:
    watched: dict[int, list[str]] = {}
    for line in nm_output.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1].lower() != "a":
            continue
        name = parts[2]
        if not name.endswith("_len"):
            continue
        watched.setdefault(int(parts[0], 16), []).append(name)
    return watched


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_asm_immediates.py <object>")

    obj = Path(sys.argv[1])
    nm = os.environ.get("NM", "nm")
    objdump = os.environ.get("OBJDUMP", "objdump")
    lengths = watched_lengths(run_tool([nm, "-a", str(obj)]))
    if not lengths:
        raise SystemExit("no absolute *_len symbols found to check")

    offenders: list[str] = []
    for line in run_tool([objdump, "-dr", str(obj)]).splitlines():
        match = ABS_LOAD_RE.search(line)
        if not match:
            continue
        value = int(match.group(1), 16)
        if value in lengths:
            names = ", ".join(sorted(lengths[value]))
            offenders.append(f"{line.strip()}  ; {names}")

    if offenders:
        print("absolute memory reads found for assembly length constants:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
