#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
SCORECARD_JSON = REPO / "daylight-equation" / "SCORECARD.v1.json"


def require(pattern: str, text: str, label: str) -> re.Match[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing scorecard field: {label}")
    return match


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    text = SCORECARD.read_text(encoding="utf-8")
    machine = json.loads(SCORECARD_JSON.read_text(encoding="utf-8"))
    score = int(
        require(
            r"^Daylight_v0\.6_research_score\s*=\s*(\d+)\s*/\s*1000$",
            text,
            "Daylight_v0.6_research_score",
        ).group(1)
    )
    if machine["score"]["name"] != "Daylight_v0.6_research_score":
        raise AssertionError("machine scorecard has wrong score name")
    if machine["score"]["value"] != score or machine["score"]["maximum"] != 1000:
        raise AssertionError("machine scorecard score does not match Markdown")
    if sum(component["value"] for component in machine["components"]) != score:
        raise AssertionError("machine scorecard component sum does not match score")
    if sum(component["maximum"] for component in machine["components"]) != 1000:
        raise AssertionError("machine scorecard component maximums do not sum to 1000")

    for claim_name in (
        "ProductionAllowed",
        "RuntimeContainmentClaim",
        "WholeSystemPostQuantumSafetyClaim",
        "ExternalReviewClaim",
    ):
        require(rf"^{claim_name}\s*=\s*0$", text, claim_name)

    for claim_key in (
        "production_allowed",
        "runtime_containment_claim",
        "whole_system_post_quantum_safety_claim",
        "external_review_claim",
    ):
        if machine["score"][claim_key] is not False:
            raise AssertionError(f"machine scorecard claim must remain false: {claim_key}")

    open_gates = [gate["name"] for gate in machine["hard_gates"] if gate["satisfied"] is not True]
    for required_gate in (
        "real_crypto_provider",
        "provider_backed_reference_seal_open",
        "formal_model",
        "external_review",
        "production_authority",
    ):
        if required_gate not in open_gates:
            raise AssertionError(f"machine scorecard dropped open hard gate: {required_gate}")

    hard_blockers = (
        "RealCryptoProvider = 0",
        "M1Progress = partial",
        "No formal model is tracked.",
        "No external reviews are tracked.",
        "still lacks provider-backed v6 `Seal`/`Open`",
        "not yet a complete provider-backed reference `Seal`/`Open`",
    )
    missing = [blocker for blocker in hard_blockers if blocker not in text]
    if missing:
        raise AssertionError("scorecard dropped hard blocker text: " + ", ".join(missing))

    if score >= 1000:
        raise AssertionError("scorecard claims 1000 while hard blockers remain documented")
    if score > 860 and "public-precheck evaluator" not in text:
        raise AssertionError("scorecard exceeds recorded upper estimate without new gate evidence")
    if score > 870:
        if "private `Open` verifier" not in text:
            raise AssertionError("scorecard exceeds public-precheck evidence without private Open evidence")
        evidence = set(machine["evidence"])
        if "tests/daylight_v06_m1_independent_open.py" not in evidence:
            raise AssertionError("machine scorecard missing independent private Open evidence")
    if score > 890:
        raise AssertionError("scorecard exceeds current fixture-profile private Open evidence")

    if not args.quiet:
        print(f"Daylight scorecard gate OK: {score}/1000")


if __name__ == "__main__":
    main()
