#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "daylight_1000_checkpoint.py"


def run_tool(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the guarded Daylight 1000 checkpoint writer.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="daylight-1000-checkpoint-") as tmp_name:
        tmp = Path(tmp_name)
        out = tmp / "checkpoint.json"
        blocked = run_tool(
            "write",
            "--repo",
            str(REPO),
            "--review-set",
            str(tmp / "missing-review-set.json"),
            "--authority-evidence",
            str(tmp / "missing-authority.json"),
            "--out",
            str(out),
            "--quiet",
        )
        assert blocked.returncode != 0
        assert b"Daylight 1000 checkpoint blocked" in blocked.stderr
        assert not out.exists()

        sys.path.insert(0, str(REPO / "tools"))
        checkpoint = importlib.import_module("daylight_1000_checkpoint")

        def fake_ready_gate(*, repo: Path, review_set: str, authority_evidence: str, ssh_keygen: str | None) -> dict:
            return {
                "schema": "daylight-v06-1000-claim-gate-v1",
                "subject": "Daylight_v0.6",
                "status": "ready-for-1000-checkpoint",
                "ready": True,
                "reviewed_commit": "0" * 40,
                "score": 1000,
                "maximum_score": 1000,
                "external_review_set": {"provided": True, "verified": True},
                "daylight_authority": {"provided": True, "verified": True},
                "blockers": [],
            }

        original = checkpoint.daylight_1000_gate.evaluate_gate
        checkpoint.daylight_1000_gate.evaluate_gate = fake_ready_gate
        try:
            value = checkpoint.checkpoint_value(
                repo=REPO,
                review_set="/review-set.json",
                authority_evidence="/authority.json",
                ssh_keygen=None,
            )
        finally:
            checkpoint.daylight_1000_gate.evaluate_gate = original
        assert value["schema"] == "daylight-v06-1000-checkpoint-v1"
        assert value["status"] == "ready-for-push"
        assert value["score"] == 1000
        assert value["claim_gate_ready"] is True
        assert value["review_set"] == "/review-set.json"
        assert value["authority_evidence"] == "/authority.json"
        assert "this checkpoint does not create production authority" in value["non_claims"]

        checkpoint_path = tmp / "synthetic-checkpoint.json"
        checkpoint.write_json_new(checkpoint_path, value, "synthetic Daylight checkpoint")
        parsed = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        assert parsed == value

    if not args.quiet:
        print("Daylight 1000 checkpoint writer: BLOCKED as expected")


if __name__ == "__main__":
    main()
