#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = REPO / "daylight-equation" / "fixtures" / "daylight-v06-m1"


def run_cmd(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Daylight v0.6 M1 fixture vector corpus."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    fixture = Path(os.environ.get("DAYLIGHT_V06_M1_FIXTURE", str(DEFAULT_FIXTURE)))
    if not fixture.is_absolute():
        fixture = REPO / fixture
    fixture = fixture.resolve()
    runner = fixture / "scripts" / "run_vectors.py"
    vectors = fixture / "vectors"
    if not runner.is_file():
        raise AssertionError(f"missing fixture runner: {runner}")
    if not vectors.is_dir():
        raise AssertionError(f"missing fixture vectors: {vectors}")
    symlinks = [path for path in fixture.rglob("*") if path.is_symlink()]
    if symlinks:
        raise AssertionError(f"fixture contains symlinks: {symlinks}")

    proc = run_cmd([sys.executable, str(runner), str(vectors)], cwd=fixture)
    if proc.returncode != 0:
        if "ModuleNotFoundError" in proc.stderr and "cryptography" in proc.stderr:
            raise AssertionError(
                f"missing optional dependency from {fixture / 'requirements.txt'}"
            ) from None
        raise AssertionError(
            "Daylight v0.6 M1 fixture runner failed\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )

    results = json.loads(proc.stdout)
    assert results["total"] == 32, results
    assert results["passed"] == 32, results
    assert results["failed"] == 0, results

    if not args.quiet:
        print(
            "daylight-v06-m1-fixture: "
            f"{results['passed']}/{results['total']} vectors passed"
        )


if __name__ == "__main__":
    main()
