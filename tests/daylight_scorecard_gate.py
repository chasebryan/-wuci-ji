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
        "integrated_public_authority",
        "external_review",
        "production_authority",
    ):
        if required_gate not in open_gates:
            raise AssertionError(f"machine scorecard dropped open hard gate: {required_gate}")

    hard_blockers = (
        "RealCryptoProvider = 0",
        "M1Progress = partial",
        "No external reviews are tracked.",
        "provider-backed reference `Seal`/`Open` remains non-production",
        "public authority remains external",
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
        if "cross-agreement evidence" not in text:
            raise AssertionError("scorecard exceeds private Open evidence without cross-agreement evidence")
        evidence = set(machine["evidence"])
        if "daylight-equation/evidence/daylight-v06-m1-cross-agreement.v1.json" not in evidence:
            raise AssertionError("machine scorecard missing cross-agreement evidence")
    if score > 900:
        if "provider-backed v6 KEM/key-schedule evidence" not in text:
            raise AssertionError("scorecard exceeds cross-agreement evidence without provider-KEM evidence")
        evidence = set(machine["evidence"])
        if "daylight-equation/rust/daylight-crypto/vectors/daylight-v6-provider-kem-evidence-v1.txt" not in evidence:
            raise AssertionError("machine scorecard missing provider-KEM evidence vector")
        if "daylight-v6-provider-kem-evidence-test" not in text:
            raise AssertionError("scorecard missing provider-KEM evidence test target")
    if score > 910:
        if "partial fail-closed formal model" not in text:
            raise AssertionError("scorecard exceeds provider-KEM evidence without partial formal model evidence")
        evidence = set(machine["evidence"])
        if "daylight-equation/research/daylight-v06-fail-closed-model.v1.json" not in evidence:
            raise AssertionError("machine scorecard missing partial fail-closed model evidence")
        if "tests/daylight_v06_fail_closed_model.py" not in evidence:
            raise AssertionError("machine scorecard missing partial fail-closed model verifier")
        if "daylight-v06-fail-closed-model-test" not in text:
            raise AssertionError("scorecard missing partial fail-closed model test target")
    if score > 915:
        if "provider-backed v6 private-roundtrip evidence" not in text:
            raise AssertionError("scorecard exceeds partial model evidence without private-roundtrip evidence")
        evidence = set(machine["evidence"])
        if "daylight-equation/rust/daylight-crypto/vectors/daylight-v6-provider-private-roundtrip-evidence-v1.txt" not in evidence:
            raise AssertionError("machine scorecard missing private-roundtrip evidence vector")
        if "daylight-v6-provider-private-roundtrip-test" not in text:
            raise AssertionError("scorecard missing private-roundtrip test target")
    if score > 920:
        if "provider-backed v6 reference `Seal`/`Open` evidence" not in text:
            raise AssertionError("scorecard exceeds private-roundtrip evidence without reference Seal/Open evidence")
        if "provider-backed v6 reference negative corpus" not in text:
            raise AssertionError("scorecard exceeds private-roundtrip evidence without reference negative corpus")
        if "Provider-backed v6 vector-agreement evidence" not in text:
            raise AssertionError("scorecard exceeds private-roundtrip evidence without provider vector-agreement evidence")
        evidence = set(machine["evidence"])
        if "daylight-equation/rust/daylight-crypto/vectors/daylight-v6-reference-seal-open-evidence-v1.txt" not in evidence:
            raise AssertionError("machine scorecard missing reference Seal/Open evidence vector")
        if "daylight-equation/rust/daylight-crypto/vectors/daylight-v6-reference-negative-corpus-v1.txt" not in evidence:
            raise AssertionError("machine scorecard missing reference negative corpus vector")
        if "daylight-equation/evidence/daylight-v6-provider-vector-agreement.v1.json" not in evidence:
            raise AssertionError("machine scorecard missing provider vector-agreement evidence")
        if "tests/daylight_v6_provider_vector_agreement.py" not in evidence:
            raise AssertionError("machine scorecard missing provider vector-agreement verifier")
        if "daylight-v6-reference-seal-open-test" not in text:
            raise AssertionError("scorecard missing reference Seal/Open test target")
        if "daylight-v6-reference-negative-corpus-test" not in text:
            raise AssertionError("scorecard missing reference negative corpus test target")
        if "daylight-v6-provider-vector-agreement-test" not in text:
            raise AssertionError("scorecard missing provider vector-agreement test target")
        hard_gates = {gate["name"]: gate["satisfied"] for gate in machine["hard_gates"]}
        if hard_gates.get("provider_backed_reference_seal_open") is not True:
            raise AssertionError("scorecard exceeds private-roundtrip evidence without satisfying reference Seal/Open gate")
        if hard_gates.get("provider_backed_vector_agreement") is not True:
            raise AssertionError("scorecard exceeds private-roundtrip evidence without satisfying provider vector-agreement gate")
        if hard_gates.get("provider_backed_reference_negative_corpus") is not True:
            raise AssertionError("scorecard exceeds private-roundtrip evidence without satisfying reference negative corpus gate")
    if score > 945:
        if "schema-freeze evidence" not in text:
            raise AssertionError("scorecard exceeds reference corpus without schema-freeze evidence")
        evidence = set(machine["evidence"])
        for required in (
            "daylight-equation/research/daylight-v06-schema-freeze.md",
            "daylight-equation/research/daylight-v06-schema-freeze.v1.json",
            "tests/daylight_v06_schema_freeze.py",
        ):
            if required not in evidence:
                raise AssertionError(f"machine scorecard missing schema-freeze evidence: {required}")
        if "daylight-v06-schema-freeze-test" not in text:
            raise AssertionError("scorecard missing schema-freeze test target")
        hard_gates = {gate["name"]: gate["satisfied"] for gate in machine["hard_gates"]}
        if hard_gates.get("byte_schema_freeze_evidence") is not True:
            raise AssertionError("scorecard exceeds reference corpus without satisfying schema-freeze gate")
    if score > 955:
        if "expanded M4 symbolic model" not in text:
            raise AssertionError("scorecard exceeds schema-freeze evidence without M4 symbolic model evidence")
        evidence = set(machine["evidence"])
        for required in (
            "daylight-equation/research/daylight-v06-m4-symbolic-model.md",
            "daylight-equation/research/daylight-v06-m4-symbolic-model.v1.json",
            "tests/daylight_v06_m4_symbolic_model.py",
        ):
            if required not in evidence:
                raise AssertionError(f"machine scorecard missing M4 symbolic model evidence: {required}")
        if "daylight-v06-m4-symbolic-model-test" not in text:
            raise AssertionError("scorecard missing M4 symbolic model test target")
        hard_gates = {gate["name"]: gate["satisfied"] for gate in machine["hard_gates"]}
        if hard_gates.get("m4_symbolic_model") is not True:
            raise AssertionError("scorecard exceeds schema-freeze evidence without satisfying M4 symbolic model gate")
    if score > 970:
        if "Z3-backed SMT proof" not in text:
            raise AssertionError("scorecard exceeds M4 symbolic evidence without Z3 proof evidence")
        evidence = set(machine["evidence"])
        for required in (
            "daylight-equation/research/daylight-v06-m4-z3-proof.md",
            "daylight-equation/research/daylight-v06-m4-z3-proof.v1.json",
            "daylight-equation/research/daylight-v06-m4-z3-proof.smt2",
            "tests/daylight_v06_m4_z3_proof.py",
        ):
            if required not in evidence:
                raise AssertionError(f"machine scorecard missing M4 Z3 proof evidence: {required}")
        if "daylight-v06-m4-z3-proof-test" not in text:
            raise AssertionError("scorecard missing M4 Z3 proof test target")
        hard_gates = {gate["name"]: gate["satisfied"] for gate in machine["hard_gates"]}
        if hard_gates.get("m4_z3_proof") is not True:
            raise AssertionError("scorecard exceeds M4 symbolic evidence without satisfying M4 Z3 proof gate")
        if hard_gates.get("formal_model") is not True:
            raise AssertionError("scorecard exceeds M4 symbolic evidence without satisfying formal model gate")
    if score > 975:
        raise AssertionError(
            "scorecard exceeds M4 Z3 proof evidence without external review, integrated authority, and production authority evidence"
        )

    if not args.quiet:
        print(f"Daylight scorecard gate OK: {score}/1000")


if __name__ == "__main__":
    main()
