#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import test_wuci_ji as wuci_tests


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "frost_secp256k1_workflow.py"
MESSAGE = "wuci-ji frost integration"


def output_labels(stdout: bytes) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in stdout.decode("ascii").splitlines():
        label, value = line.split(": ", 1)
        labels[label] = value
    return labels


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the user-facing FROST(secp256k1,SHA-256) workflow helper."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress signature field output",
    )
    args = parser.parse_args()

    signature = wuci_tests.assert_frost_end_to_end_cli_flow()
    proc = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--bin",
            os.environ.get("WUCI_JI_BIN", str(REPO_ROOT / "build" / "wuci-ji")),
            "--message",
            MESSAGE,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    labels = output_labels(proc.stdout)
    for name, value in signature.items():
        assert labels[name] == value, (name, labels[name], value)
    assert labels["verification"] == "valid"

    if args.quiet:
        return

    print(proc.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    main()
