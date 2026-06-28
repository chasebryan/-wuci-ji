#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "daylight_cap_removal.py"
PLAN = REPO / "daylight-equation" / "research" / "daylight-v06-cap-removal-plan.v1.json"


def run_tool(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=REPO,
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
    parser = argparse.ArgumentParser(description="Check Daylight cap-removal blocker plan.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    verified = run_tool("verify", "--repo", str(REPO), "--plan", str(PLAN), "--json")
    assert_ok(verified, "verify cap-removal plan")
    summary = json.loads(verified.stdout.decode("utf-8"))
    assert summary["schema"] == "daylight-v06-cap-removal-verification-v1"
    assert summary["subject"] == "Daylight_v0.6"
    assert summary["status"] == "verified-fail-closed-cap-removal-plan"
    assert summary["score_increase_authorized"] is False
    assert summary["peer_review_evaluation_score"] == 8250
    assert summary["peer_review_evaluation_maximum"] == 10000
    assert summary["verified_publish_trust_command_contracts"] == [
        "publish-authorized-rooted",
        "trust-authorized-rooted",
    ]
    assert summary["verified_fixture_rejection_paths"] == [
        "authority/wuci-root.fixture.txt",
        "authority/wuci-release-root.fixture.txt",
    ]
    for required in (
        "no_production_authority_publish_authority_or_trust_gate",
        "no_runtime_containment_enforcement",
    ):
        assert required in summary["active_cap_blockers"]
    for non_claim in (
        "this plan does not raise the Daylight score",
        "this plan does not create production authority",
        "this plan does not implement publish or trust Gate commands",
    ):
        assert non_claim in summary["non_claims"]

    with tempfile.TemporaryDirectory(prefix="daylight-cap-removal-test-") as tmp_name:
        tmp = Path(tmp_name)
        value = json.loads(PLAN.read_text(encoding="utf-8"))

        inactive = json.loads(json.dumps(value))
        for blocker in inactive["active_cap_blockers"]:
            if blocker["name"] == "no_production_authority_publish_authority_or_trust_gate":
                blocker["active"] = False
        inactive_path = tmp / "inactive.json"
        inactive_path.write_text(json.dumps(inactive, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        inactive_result = run_tool("verify", "--repo", str(REPO), "--plan", str(inactive_path), "--quiet")
        assert inactive_result.returncode != 0
        assert b"required cap blocker is not active" in inactive_result.stderr

        implemented = json.loads(json.dumps(value))
        implemented["publish_trust_command_contracts"][0]["implemented"] = True
        implemented_path = tmp / "implemented.json"
        implemented_path.write_text(json.dumps(implemented, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        implemented_result = run_tool("verify", "--repo", str(REPO), "--plan", str(implemented_path), "--quiet")
        assert implemented_result.returncode != 0
        assert b"must not be marked implemented" in implemented_result.stderr

        fixture_allowed = json.loads(json.dumps(value))
        fixture_allowed["fixture_authority_rejections"]["required_fields"]["allow-publish"] = "true"
        fixture_path = tmp / "fixture-allowed.json"
        fixture_path.write_text(json.dumps(fixture_allowed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        fixture_result = run_tool("verify", "--repo", str(REPO), "--plan", str(fixture_path), "--quiet")
        assert fixture_result.returncode != 0
        assert b"fixture rejection required fields changed" in fixture_result.stderr

    if not args.quiet:
        print("Daylight cap-removal plan: PASS")


if __name__ == "__main__":
    main()
