#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "daylight_1000_gate.py"


def run_tool(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the Daylight 1000 claim gate.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    blocked = run_tool("verify", "--repo", str(REPO), "--json")
    assert blocked.returncode != 0
    assert blocked.stderr == b""
    summary = json.loads(blocked.stdout.decode("utf-8"))
    assert summary["schema"] == "daylight-v06-1000-claim-gate-v1"
    assert summary["subject"] == "Daylight_v0.6"
    assert summary["status"] == "blocked"
    assert summary["ready"] is False
    assert summary["score"] == 975
    assert summary["maximum_score"] == 1000
    assert summary["scorecard_hard_gates"]["integrated_public_authority"] is False
    assert summary["scorecard_hard_gates"]["external_review"] is False
    assert summary["scorecard_hard_gates"]["production_authority"] is False
    assert summary["external_review_set"]["provided"] is False
    assert summary["daylight_authority"]["provided"] is False
    blockers = "\n".join(summary["blockers"])
    assert "score is 975/1000, not 1000/1000" in blockers
    assert "external review set evidence missing" in blockers
    assert "integrated Daylight authority evidence missing" in blockers
    assert "scorecard hard gate is open: external_review" in blockers
    for non_claim in (
        "this gate does not create external review evidence",
        "this gate does not create production authority",
        "this gate does not claim runtime containment",
        "this gate does not claim whole-system post-quantum safety",
    ):
        assert non_claim in summary["non_claims"]

    with tempfile.TemporaryDirectory(prefix="daylight-1000-gate-") as tmp_name:
        tmp = Path(tmp_name)
        bad_reviews = tmp / "bad-review-set.json"
        bad_authority = tmp / "bad-authority.json"
        bad_reviews.write_text('{"schema":"wrong"}\n', encoding="ascii")
        bad_authority.write_text('{"schema":"wrong"}\n', encoding="ascii")
        bad = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--review-set",
            str(bad_reviews),
            "--authority-evidence",
            str(bad_authority),
            "--json",
        )
        assert bad.returncode != 0
        bad_summary = json.loads(bad.stdout.decode("utf-8"))
        bad_blockers = "\n".join(bad_summary["blockers"])
        assert "external review set failed: unsupported Daylight external review set schema" in bad_blockers
        assert "Daylight authority evidence failed: unsupported Daylight authority evidence schema" in bad_blockers

    if not args.quiet:
        print("Daylight 1000 claim gate: BLOCKED as expected")


if __name__ == "__main__":
    main()
