#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "daylight-equation" / "evidence" / "daylight-v06-external-review-packet.v1.json"
PACKET_DOC = REPO / "daylight-equation" / "analysis" / "daylight-v06-external-review-packet.md"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
SCORECARD_JSON = REPO / "daylight-equation" / "SCORECARD.v1.json"
MAKEFILE = REPO / "Makefile"
BUILD_TARGETS = REPO / "docs" / "BUILD_TARGETS.md"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Daylight v0.6 external review packet.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    doc = PACKET_DOC.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    machine = json.loads(SCORECARD_JSON.read_text(encoding="utf-8"))
    makefile = MAKEFILE.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")

    assert packet["schema"] == "daylight-v06-external-review-packet-v1"
    assert packet["subject"] == "Daylight_v0.6"
    assert packet["status"] == "review-packet-not-external-review"
    assert packet["current_score"] == 975
    assert packet["external_reviews_tracked"] == 0
    assert "Daylight_v0.6_research_score = 975 / 1000" in scorecard
    assert machine["score"]["external_review_claim"] is False

    for item in packet["review_packet_items"]:
        assert (REPO / item["path"]).exists(), item["path"]
        assert item["purpose"]
    paths = {item["path"] for item in packet["review_packet_items"]}
    for required in (
        "daylight-equation/SCORECARD.md",
        "daylight-equation/research/daylight-v06-m4-z3-proof.smt2",
        "daylight-equation/research/daylight-v06-1000-preflight.v1.json",
        "daylight-equation/evidence/daylight-v6-provider-vector-agreement.v1.json",
        "tools/daylight_external_review.py",
        "tests/daylight_external_review.py",
        "tools/daylight_authority.py",
        "tests/daylight_authority.py",
        "tools/daylight_1000_gate.py",
        "tests/daylight_1000_gate.py",
        "tools/daylight_1000_checkpoint.py",
        "tests/daylight_1000_checkpoint.py",
    ):
        assert required in paths

    for command in packet["required_local_commands"]:
        target = command.removeprefix("make ")
        assert f"{target}:" in makefile
        assert command in doc

    questions = packet["review_questions"]
    assert "formal_model" in questions
    assert "cryptography" in questions
    assert "implementation_boundary" in questions
    assert any("SMT predicate model" in item for item in questions["formal_model"])
    assert any("ML-KEM-1024" in item for item in questions["cryptography"])
    assert any("public authority evidence" in item for item in questions["implementation_boundary"])

    criteria = packet["external_review_acceptance_criteria"]
    assert "at least two independent reviewers" in criteria
    assert "reviewed commit equals current release candidate commit" in criteria
    assert "review artifacts are attributable and signed or otherwise independently verifiable" in criteria

    for non_claim in packet["non_claims"]:
        assert non_claim in doc
    assert "this packet is not an external review" in doc
    assert "ExternalReviewClaim = 0" in scorecard
    assert "daylight-v06-external-review-packet-test" in scorecard
    assert "daylight-v06-external-review-packet-test:" in makefile
    assert "daylight-v06-external-review-packet-test" in build_targets
    evidence = set(machine["evidence"])
    assert "daylight-equation/evidence/daylight-v06-external-review-packet.v1.json" in evidence
    assert "daylight-equation/analysis/daylight-v06-external-review-packet.md" in evidence
    assert "tests/daylight_v06_external_review_packet.py" in evidence
    assert "tools/daylight_external_review.py" in evidence
    assert "tests/daylight_external_review.py" in evidence
    assert "tools/daylight_authority.py" in evidence
    assert "tests/daylight_authority.py" in evidence
    assert "tools/daylight_1000_gate.py" in evidence
    assert "tests/daylight_1000_gate.py" in evidence
    assert "tools/daylight_1000_checkpoint.py" in evidence
    assert "tests/daylight_1000_checkpoint.py" in evidence
    hard_gates = {gate["name"]: gate["satisfied"] for gate in machine["hard_gates"]}
    assert hard_gates.get("external_review_packet") is True
    assert hard_gates.get("external_review_verifier") is True
    assert hard_gates.get("daylight_authority_verifier") is True
    assert hard_gates.get("daylight_1000_claim_gate") is True
    assert hard_gates.get("daylight_1000_checkpoint_writer") is True
    assert hard_gates.get("external_review") is False

    if not args.quiet:
        print("Daylight v0.6 external review packet: PASS")


if __name__ == "__main__":
    main()
