#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PREFLIGHT = REPO / "daylight-equation" / "research" / "daylight-v06-1000-preflight.v1.json"
PREFLIGHT_DOC = REPO / "daylight-equation" / "research" / "daylight-v06-1000-preflight.md"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
SCORECARD_JSON = REPO / "daylight-equation" / "SCORECARD.v1.json"
MAKEFILE = REPO / "Makefile"
BUILD_TARGETS = REPO / "docs" / "BUILD_TARGETS.md"


def score_from_text(text: str) -> int:
    match = re.search(
        r"^Daylight_v0\.6_research_score\s*=\s*(\d+)\s*/\s*1000$",
        text,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError("scorecard missing Daylight v0.6 score")
    return int(match.group(1))


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Daylight v0.6 1000 preflight discipline.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    preflight = json.loads(PREFLIGHT.read_text(encoding="utf-8"))
    doc = PREFLIGHT_DOC.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    machine = json.loads(SCORECARD_JSON.read_text(encoding="utf-8"))
    makefile = MAKEFILE.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")

    score = score_from_text(scorecard)
    assert preflight["schema"] == "daylight-v06-1000-preflight-v1"
    assert preflight["subject"] == "Daylight_v0.6"
    assert preflight["status"] == "blocked-until-external-and-production-evidence"
    assert preflight["current_score"] == score
    assert preflight["current_score"] == machine["score"]["value"]
    assert preflight["maximum_score"] == 1000
    assert score < 1000
    assert "do not claim or push a 1000 checkpoint" in preflight["claim_policy"]

    for claim_name in (
        "ProductionAllowed",
        "RuntimeContainmentClaim",
        "WholeSystemPostQuantumSafetyClaim",
        "ExternalReviewClaim",
    ):
        assert f"{claim_name} = 0" in scorecard

    hard_gates = {gate["name"]: gate["satisfied"] for gate in machine["hard_gates"]}
    for required in preflight["required_open_scorecard_gates"]:
        assert hard_gates.get(required) is False

    claim_gates = {gate["name"]: gate for gate in preflight["claim_gates"]}
    assert claim_gates["score_exactly_1000"]["satisfied"] is False
    assert claim_gates["integrated_public_authority"]["satisfied"] is False
    assert claim_gates["mechanized_or_independently_reviewed_formal_model"]["satisfied"] is False
    assert claim_gates["two_independent_external_reviews"]["satisfied"] is False
    assert claim_gates["production_authority"]["satisfied"] is False

    requirements = preflight["signed_external_input_requirements"]
    assert requirements["external_review_count_minimum"] == 2
    assert requirements["reviewed_commit_must_match_head"] is True
    assert requirements["production_blocking_findings_closed"] is True
    assert requirements["fixture_material_rejected"] is True
    assert requirements["unsigned_review_evidence_is_test_only"] is True
    assert requirements["compatible_wuci_external_audit_schema"] == "wuci-external-audit-evidence-v1"
    assert requirements["compatible_wuci_external_audit_signature_namespace"] == "wuci-external-audit-v1"
    assert requirements["compatible_wuci_production_authority_schema"] == "wuci-production-authority-ceremony-v1"
    assert requirements["compatible_wuci_production_authority_signature_namespace"] == "wuci-production-authority-v1"

    for evidence in (
        "daylight-equation/research/daylight-v06-1000-preflight.md",
        "daylight-equation/research/daylight-v06-1000-preflight.v1.json",
        "tests/daylight_v06_1000_preflight.py",
    ):
        assert evidence in machine["evidence"]
        assert Path(evidence).name in scorecard
    assert hard_gates.get("daylight_1000_preflight") is True
    assert "daylight-v06-1000-preflight-test:" in makefile
    assert "daylight-v06-1000-preflight-test" in scorecard
    assert "daylight-v06-1000-preflight-test" in build_targets

    doc_flat = " ".join(doc.split())
    for phrase in (
        "deliberately fails closed today",
        "current valid score is 970/1000",
        "at least two independent external reviews",
        "signed non-fixture production, publish, and trust authority evidence",
    ):
        assert phrase in doc_flat
    for non_claim in preflight["non_claims"]:
        assert non_claim in doc

    if not args.quiet:
        print(f"Daylight v0.6 1000 preflight: BLOCKED as expected ({score}/1000)")


if __name__ == "__main__":
    main()
