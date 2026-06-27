#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_crypto_audit.py"


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI crypto self-audit evidence.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="wuci-crypto-audit-") as tmp_name:
        audit = Path(tmp_name) / "crypto-self-audit.json"
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "emit",
                    "--repo",
                    str(REPO_ROOT),
                    "--out",
                    str(audit),
                    "--quiet",
                ]
            ),
            "emit crypto self-audit",
        )
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    "--repo",
                    str(REPO_ROOT),
                    "--audit",
                    str(audit),
                    "--quiet",
                ]
            ),
            "verify crypto self-audit",
        )
        value = json.loads(audit.read_text(encoding="utf-8"))
        assert value["schema"] == "wuci-crypto-self-audit-v1"
        assert value["external_audit"] is False
        assert value["production_sufficient"] is False
        assert "check-asm-immediates" in value["required_targets"]

    if not args.quiet:
        print("wuci crypto self-audit: PASS")


if __name__ == "__main__":
    main()
