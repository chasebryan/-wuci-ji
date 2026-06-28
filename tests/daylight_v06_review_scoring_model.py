#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODEL = REPO / "daylight-equation" / "analysis" / "daylight-v06-peer-review-scoring-model-10000.v1.json"
MODEL_DOC = REPO / "daylight-equation" / "analysis" / "daylight-v06-peer-review-scoring-model-10000.md"
CHATGPT_REVIEW = REPO / "daylight-equation" / "analysis" / "daylight-v06-chatgpt-desk-review-scorecard.v1.json"
CHATGPT_REVIEW_DOC = REPO / "daylight-equation" / "analysis" / "daylight-v06-chatgpt-desk-review-scorecard.md"
ANALYSIS_README = REPO / "daylight-equation" / "analysis" / "README.md"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
SCORECARD_JSON = REPO / "daylight-equation" / "SCORECARD.v1.json"
MAKEFILE = REPO / "Makefile"
BUILD_TARGETS = REPO / "docs" / "BUILD_TARGETS.md"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Daylight v0.6 10000-point peer-review score.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    model = json.loads(MODEL.read_text(encoding="utf-8"))
    doc = MODEL_DOC.read_text(encoding="utf-8")
    chatgpt_review = json.loads(CHATGPT_REVIEW.read_text(encoding="utf-8"))
    chatgpt_review_doc = CHATGPT_REVIEW_DOC.read_text(encoding="utf-8")
    analysis_readme = ANALYSIS_README.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    machine_scorecard = json.loads(SCORECARD_JSON.read_text(encoding="utf-8"))
    makefile = MAKEFILE.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")

    assert model["schema"] == "daylight-v06-peer-review-scoring-model-10000-v1"
    assert model["subject"] == "Daylight_v0.6"
    assert model["status"] == "lawful-defensive-peer-review-evaluation-not-replacement-scorecard"
    assert model["score"]["name"] == "Daylight_v0.6_peer_review_evaluation_score"
    assert model["score"]["maximum"] == 10000
    assert model["score"]["cap_limited"] is True
    assert model["score"]["replaces_daylight_research_scorecard"] is False

    component_total = sum(component["value"] for component in model["components"])
    component_maximum = sum(component["maximum"] for component in model["components"])
    assert component_total == model["score"]["component_total"] == 8250
    assert component_maximum == model["score"]["maximum"] == 10000
    for component in model["components"]:
        assert 0 <= component["value"] <= component["maximum"], component["name"]
        assert component["name"] in doc
        assert component["reason"]

    active_caps = [cap["maximum_score"] for cap in model["hard_caps"] if cap["active"] is True]
    assert active_caps
    cap_ceiling = min(active_caps)
    assert cap_ceiling == model["score"]["cap_ceiling"] == 8250
    expected_legal_factor = 0 if model["legal_safety_nullifier"]["triggered"] else 1
    assert expected_legal_factor == model["score"]["legal_factor"] == 1
    expected_final = expected_legal_factor * min(component_total, cap_ceiling)
    assert expected_final == model["score"]["value"] == 8250

    assert chatgpt_review["schema"] == "daylight-v06-chatgpt-desk-review-scorecard-v1"
    assert chatgpt_review["status"] == "desk-review-evidence-not-independent-peer-review"
    assert chatgpt_review["determination"]["chatgpt_assessed_research_score"] == 900
    assert chatgpt_review["determination"]["category_row_sum"] == 810
    assert chatgpt_review["determination"]["category_row_sum_matches_reported_score"] is False
    assert chatgpt_review["determination"]["confidence_range"] == {
        "low": 880,
        "high": 930,
        "maximum": 1000,
    }
    assert chatgpt_review["determination"]["classification"] == "Strong Executable Research Artifact"
    assert chatgpt_review["counts_as_external_review"] is False
    assert chatgpt_review["counts_as_official_endorsement"] is False
    assert sum(item["value"] for item in chatgpt_review["score_breakdown"]) == 810
    assert sum(item["maximum"] for item in chatgpt_review["score_breakdown"]) == 1000
    assert "not an OpenAI certification" in chatgpt_review_doc
    assert "not a government endorsement" in chatgpt_review_doc
    assert "not independent peer review" in chatgpt_review_doc
    assert "OfficialEndorsementClaim = 0" in chatgpt_review_doc

    desk_review = model["desk_review_inputs"]
    assert desk_review["chatgpt_assessed_research_score"] == 900
    assert desk_review["category_row_sum"] == 810
    assert desk_review["category_row_sum_matches_reported_score"] is False
    assert desk_review["confidence_range"] == {"low": 880, "high": 930, "maximum": 1000}
    assert desk_review["classification"] == "Strong Executable Research Artifact"
    assert desk_review["path"] == "daylight-equation/analysis/daylight-v06-chatgpt-desk-review-scorecard.v1.json"
    assert desk_review["counts_as_external_review"] is False
    assert desk_review["counts_as_official_endorsement"] is False

    for cap in model["hard_caps"]:
        assert cap["active"] is True
        assert cap["maximum_score"] <= 10000
        assert cap["name"] in doc
        assert cap["reason"]

    for trigger in model["legal_safety_nullifier"]["triggers"]:
        assert trigger in doc
    assert "authorized defensive cryptography, protocol, and evidence review only" in doc
    assert "not authorization to test any third-party system" in doc
    assert "Reviewers should limit reproduction to the local repository" in doc

    assert "Daylight_v0.6_peer_review_evaluation_score = 8250 / 10000" in doc
    assert "Daylight_v0.6_research_score = 975 / 1000" in doc
    assert "ChatGPT_Assessed_Research_Score = 900 / 1000" in doc
    assert "ChatGPT_Assessed_Research_Score_Range = 880-930 / 1000" in doc
    assert "ChatGPT_Category_Row_Sum = 810 / 1000" in doc
    assert "OfficialEndorsementClaim = 0" in doc
    assert "This 10,000-point score is therefore best read as a cap-limited peer-review readiness" in doc
    assert "It is not a deployment score." in doc
    assert "does not replace `daylight-equation/SCORECARD.md`" in doc
    assert "does not count as independent peer review" in doc
    assert "Raising it above 8250 requires removing or changing those blockers" in doc

    assert "Daylight_v0.6_research_score = 975 / 1000" in scorecard
    assert "ProductionAllowed = 0" in scorecard
    assert "RuntimeContainmentClaim = 0" in scorecard
    assert "WholeSystemPostQuantumSafetyClaim = 0" in scorecard
    assert "ExternalReviewClaim = 0" in scorecard
    assert machine_scorecard["score"]["value"] == 975
    assert machine_scorecard["score"]["maximum"] == 1000
    assert machine_scorecard["score"]["production_allowed"] is False
    assert machine_scorecard["score"]["runtime_containment_claim"] is False
    assert machine_scorecard["score"]["whole_system_post_quantum_safety_claim"] is False
    assert machine_scorecard["score"]["external_review_claim"] is False

    for key in (
        "production_allowed",
        "runtime_containment_claim",
        "whole_system_post_quantum_safety_claim",
        "external_review_claim",
        "official_endorsement_claim",
    ):
        assert model["score"][key] is False

    required_components = {
        "lawful_review_boundary_and_claim_control": 1000,
        "specification_schema_transcript_and_kdf_surface": 1500,
        "reproducible_corpora_and_kat_bundle": 1400,
        "fail_closed_implementation_and_negative_behavior": 1150,
        "cryptographic_provider_evidence": 975,
        "formal_model_and_smt_support": 975,
        "review_packet_provenance_and_verifier_automation": 900,
        "integrated_public_authority_and_trust_model": 350,
        "independent_external_peer_review": 0,
        "production_runtime_containment_and_deployment": 0,
    }
    observed = {component["name"]: component["value"] for component in model["components"]}
    assert observed == required_components

    for source in model["source_evidence"]:
        assert (REPO / source).exists(), source

    for command in model["required_local_commands"]:
        target = command.removeprefix("make ")
        assert f"{target}:" in makefile
        assert command in doc
    assert "daylight-v06-peer-review-score-test" in makefile
    assert "daylight-v06-peer-review-score-test" in build_targets
    assert "daylight-v06-peer-review-scoring-model-10000.md" in analysis_readme
    assert "daylight-v06-chatgpt-desk-review-scorecard.md" in analysis_readme

    for non_claim in model["non_claims"]:
        assert non_claim in doc
    for non_claim in chatgpt_review["non_claims"]:
        assert non_claim in chatgpt_review_doc

    assert "No independent signed external reviews are tracked." in json.dumps(model, sort_keys=True)
    assert "No production authority, runtime containment, deployment authority" in json.dumps(
        model,
        sort_keys=True,
    )

    if not args.quiet:
        print("Daylight v0.6 peer-review score model: PASS")


if __name__ == "__main__":
    main()
