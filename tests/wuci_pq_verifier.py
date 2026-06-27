#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_pq_verifier.py"


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
    parser = argparse.ArgumentParser(description="Check local PQ verifier detection.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="wuci-pq-") as tmp_name:
        evidence = Path(tmp_name) / "pq-verifier.json"
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "detect",
                    "--out",
                    str(evidence),
                    "--quiet",
                ]
            ),
            "detect PQ verifier",
        )
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    "--evidence",
                    str(evidence),
                    "--quiet",
                ]
            ),
            "verify PQ verifier evidence",
        )
        value = json.loads(evidence.read_text(encoding="utf-8"))
        assert value["schema"] == "wuci-pq-verifier-detection-v1"
        assert value["quantum_safe_claim_allowed"] is False
        if not value["real_pq_signature_verifier_available"]:
            required = run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    "--evidence",
                    str(evidence),
                    "--require-real",
                    "--quiet",
                ]
            )
            assert required.returncode != 0
            assert b"no real pinned PQ signature verifier" in required.stderr

    if not args.quiet:
        print("wuci pq verifier: PASS")


if __name__ == "__main__":
    main()
