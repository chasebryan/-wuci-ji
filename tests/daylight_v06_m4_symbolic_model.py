#!/usr/bin/env python3
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODEL = REPO / "daylight-equation" / "research" / "daylight-v06-m4-symbolic-model.v1.json"
MODEL_DOC = REPO / "daylight-equation" / "research" / "daylight-v06-m4-symbolic-model.md"
REFERENCE = REPO / "daylight-equation" / "references" / "dlv0.5" / "v0.6M1-HARDENING.md"
FAIL_CLOSED_MODEL = REPO / "daylight-equation" / "research" / "daylight-v06-fail-closed-model.v1.json"
SCHEMA_FREEZE = REPO / "daylight-equation" / "research" / "daylight-v06-schema-freeze.v1.json"
NEGATIVE_CORPUS = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "vectors" / "daylight-v6-reference-negative-corpus-v1.txt"
STATIC_VERIFIER = REPO / "tests" / "daylight_v06_m1_static_vectors.py"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
MAKEFILE = REPO / "Makefile"


AUTHORIZATION_REQUIRED = {
    "V_Auth",
    "GateOK",
    "PolicyOK",
    "ClaimOK",
    "ContentReviewPreOK",
}
DOWNGRADE_REQUIRED = {
    "NoDowngradeFinal",
    "ModeOK",
    "PolicyOK",
    "ClaimOK",
}


def open_succeeds(state: dict[str, bool], public_predicates: list[str], private_predicates: list[str]) -> bool:
    return all(state[predicate] for predicate in public_predicates + private_predicates)


def private_ops_allowed(state: dict[str, bool], public_predicates: list[str]) -> bool:
    return all(state[predicate] for predicate in public_predicates)


def confidentiality_claim_holds(assumptions: dict[str, bool]) -> bool:
    return all(assumptions.values())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    model = json.loads(MODEL.read_text(encoding="utf-8"))
    doc = MODEL_DOC.read_text(encoding="utf-8")
    reference = REFERENCE.read_text(encoding="utf-8")
    fail_closed_model = json.loads(FAIL_CLOSED_MODEL.read_text(encoding="utf-8"))
    schema_freeze = json.loads(SCHEMA_FREEZE.read_text(encoding="utf-8"))
    negative_corpus = NEGATIVE_CORPUS.read_text(encoding="utf-8")
    static_verifier = STATIC_VERIFIER.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert model["schema"] == "daylight-v06-m4-symbolic-model-v1"
    assert model["subject"] == "Daylight_v0.6"
    assert model["status"] == "symbolic-m4-model-not-mechanized-proof"
    assert "Open(omega) != bottom iff" in model["open_predicate"]
    assert "blocks private KEM" in model["private_operation_barrier"]

    public_predicates = model["public_precheck_predicates"]
    private_predicates = model["private_open_predicates"]
    all_predicates = public_predicates + private_predicates
    assert public_predicates == fail_closed_model["public_precheck_predicates"]
    assert private_predicates == fail_closed_model["private_open_predicates"]
    assert len(public_predicates) == 15
    assert len(private_predicates) == 5
    assert set(AUTHORIZATION_REQUIRED).issubset(public_predicates)
    assert set(DOWNGRADE_REQUIRED).issubset(public_predicates)

    for claim in (
        "Hybrid confidentiality claim:",
        "Authorization claim:",
        "Downgrade claim:",
        "Fail-closed claim:",
    ):
        assert claim in reference
    for claim_key in (
        "confidentiality",
        "authorization",
        "downgrade_resistance",
        "fail_closed_release",
    ):
        assert claim_key in model["security_claims"]

    truth_table_states = 0
    for bits in itertools.product((False, True), repeat=len(all_predicates)):
        state = dict(zip(all_predicates, bits))
        truth_table_states += 1
        opened = open_succeeds(state, public_predicates, private_predicates)
        assert opened is all(bits)
        public_ok = all(state[predicate] for predicate in public_predicates)
        assert private_ops_allowed(state, public_predicates) is public_ok
        if not public_ok:
            assert not opened
        if any(not state[predicate] for predicate in all_predicates):
            assert not opened
        if any(not state[predicate] for predicate in AUTHORIZATION_REQUIRED):
            assert not opened
        if any(not state[predicate] for predicate in DOWNGRADE_REQUIRED):
            assert not opened

    assert truth_table_states == model["checked_properties"]["truth_table_states"]
    assert truth_table_states == 2 ** len(all_predicates)

    for predicate in all_predicates:
        state = {item: True for item in all_predicates}
        state[predicate] = False
        assert not open_succeeds(state, public_predicates, private_predicates)
        if predicate in public_predicates:
            assert not private_ops_allowed(state, public_predicates)

    confidentiality_assumptions = model["security_assumptions"]["confidentiality"]
    assert confidentiality_assumptions == [
        "AtLeastOneKEMSharedSecretPseudorandom",
        "HKDF_SHA512_Extractor_PRF",
        "AEAD_IND_CCA",
        "PublicKeysValidate",
        "SideChannelsBounded",
    ]
    assumption_state = {assumption: True for assumption in confidentiality_assumptions}
    assert confidentiality_claim_holds(assumption_state)
    for assumption in confidentiality_assumptions:
        mutated = assumption_state.copy()
        mutated[assumption] = False
        assert not confidentiality_claim_holds(mutated)

    assert model["checked_properties"] == {
        "truth_table_states": 1048576,
        "open_iff_all_public_and_private_predicates": True,
        "single_failure_fail_closed": True,
        "public_precheck_blocks_private_operations": True,
        "authorization_predicates_required": True,
        "downgrade_predicates_required": True,
        "confidentiality_assumptions_required_for_confidentiality_claim": True,
        "forbidden_claims_pinned": True,
    }

    assert schema_freeze["checked_properties"]["rejection_stages_present_in_reference_and_rust"] is True
    assert "all_fail_closed=true" in negative_corpus
    assert "verify_authorization" in static_verifier
    assert "no_downgrade" in static_verifier

    for linked in model["implementation_links"]:
        assert (REPO / linked).exists()

    for forbidden in model["forbidden_claims"]:
        assert forbidden in reference

    for non_claim in model["non_claims"]:
        assert non_claim in doc

    doc_flat = " ".join(doc.split())
    for phrase in (
        "confidentiality, authorization, downgrade resistance, and fail-closed release behavior",
        "1,048,576 states",
        "V_Auth",
        "NoDowngradeFinal",
        "this symbolic model is not production authority",
    ):
        assert phrase in doc_flat

    assert "daylight-v06-m4-symbolic-model-test" in scorecard
    assert "daylight-v06-m4-symbolic-model-test:" in makefile
    assert "daylight-v06-m4-symbolic-model.v1.json" in scorecard
    assert "Daylight_v0.6_research_score = 975 / 1000" in scorecard

    if not args.quiet:
        print(f"Daylight v0.6 M4 symbolic model: PASS ({truth_table_states} states)")


if __name__ == "__main__":
    main()
