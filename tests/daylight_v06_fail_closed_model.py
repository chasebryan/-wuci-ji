#!/usr/bin/env python3
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODEL = REPO / "daylight-equation" / "research" / "daylight-v06-fail-closed-model.v1.json"
MODEL_DOC = REPO / "daylight-equation" / "research" / "daylight-v06-fail-closed-model.md"
REFERENCE = REPO / "daylight-equation" / "references" / "dlv0.5" / "2.md"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
MAKEFILE = REPO / "Makefile"

PUBLIC_PREDICATES = [
    "ParseOK",
    "SuiteOK",
    "AuxHashOK",
    "KEMBlockOK",
    "ModeOK",
    "PolicyOK",
    "ClaimOK",
    "GateOK",
    "ProvenanceOK",
    "ContentReviewPreOK",
    "V_Auth",
    "NoDowngradeFinal",
    "LogOK",
    "InstallOK",
    "WitnessOK",
]

PRIVATE_PREDICATES = [
    "DeriveOK",
    "AEAD.Dec",
    "PayloadOK",
    "CommitOK",
    "LeakOK",
]


def open_succeeds(state: dict[str, bool]) -> bool:
    return all(state[predicate] for predicate in PUBLIC_PREDICATES + PRIVATE_PREDICATES)


def private_ops_allowed(state: dict[str, bool]) -> bool:
    return all(state[predicate] for predicate in PUBLIC_PREDICATES)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    model = json.loads(MODEL.read_text(encoding="utf-8"))
    doc = MODEL_DOC.read_text(encoding="utf-8")
    reference = REFERENCE.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert model["schema"] == "daylight-v06-fail-closed-model-v1"
    assert model["subject"] == "Daylight_v0.6"
    assert model["status"] == "partial-fail-closed-ordering-not-full-formal-proof"
    assert model["public_precheck_predicates"] == PUBLIC_PREDICATES
    assert model["private_open_predicates"] == PRIVATE_PREDICATES
    assert "PublicPreOK(omega)" in model["open_predicate"]
    assert "PrivateOpenOK(A_prime, omega)" in model["open_predicate"]

    invariants = set(model["fail_closed_invariants"])
    for predicate in PUBLIC_PREDICATES:
        expected = f"{predicate} = 0 => Open = bottom"
        assert expected in invariants
        assert expected in reference
    for predicate in ("DeriveOK", "PayloadOK", "CommitOK", "LeakOK"):
        expected = f"{predicate} = 0 => Open = bottom"
        assert expected in invariants
        assert expected in reference
    assert "AEAD.Dec = bottom => Open = bottom" in invariants
    assert "AEAD.Dec = bottom => Open = bottom" in reference

    barrier = model["private_operation_barrier"]
    assert barrier["predicate"] == "PublicPreOK = 0"
    assert barrier["forbidden_operations"] == [
        "private KEM operation",
        "AEAD.Dec",
        "plaintext materialization",
    ]
    assert "PublicPreOK = 0 =>" in reference
    for operation in barrier["forbidden_operations"]:
        assert operation in reference

    all_predicates = PUBLIC_PREDICATES + PRIVATE_PREDICATES
    success_state = {predicate: True for predicate in all_predicates}
    assert open_succeeds(success_state)
    assert private_ops_allowed(success_state)

    for predicate in all_predicates:
        state = success_state.copy()
        state[predicate] = False
        assert not open_succeeds(state), predicate
    for predicate in PUBLIC_PREDICATES:
        state = success_state.copy()
        state[predicate] = False
        assert not private_ops_allowed(state), predicate
    for predicate in PRIVATE_PREDICATES:
        state = success_state.copy()
        state[predicate] = False
        assert private_ops_allowed(state), predicate

    for bits in itertools.product((False, True), repeat=len(PUBLIC_PREDICATES)):
        public_state = dict(zip(PUBLIC_PREDICATES, bits))
        state = {**public_state, **{predicate: True for predicate in PRIVATE_PREDICATES}}
        assert private_ops_allowed(state) is all(bits)
        if not all(bits):
            assert not open_succeeds(state)

    assert model["checked_properties"] == {
        "single_failure_fail_closed": True,
        "public_precheck_blocks_private_operations": True,
        "open_requires_public_and_private_predicates": True,
        "success_requires_all_predicates_true": True,
    }
    assert model["coverage"]["fail_closed_ordering"] == "partial"
    assert model["coverage"]["confidentiality"] == "not-modeled"
    assert model["coverage"]["provider_backed_v6_seal_open"] == "not-modeled"

    for non_claim in (
        "this model is not a complete Daylight formal model",
        "this model does not prove confidentiality",
        "this model does not implement provider-backed v6 Seal/Open",
        "this model does not make fixture predicates production authority",
        "this model does not claim runtime containment",
        "this model does not replace independent external review",
    ):
        assert non_claim in model["non_claims"]
        assert non_claim.removeprefix("this model ") in doc

    doc_flat = " ".join(doc.split())
    for phrase in (
        "partial fail-closed ordering model",
        "Open(omega) != bottom iff",
        "PublicPreOK = 0 =>",
        "no private KEM operation",
        "no AEAD.Dec",
        "no plaintext materialization",
        "does not satisfy the 1000/1000 formal-model gate",
    ):
        assert phrase in doc_flat

    assert "daylight-v06-fail-closed-model-test" in scorecard
    assert "daylight-v06-fail-closed-model-test:" in makefile
    assert "daylight-v06-fail-closed-model.v1.json" in scorecard
    assert "No complete formal model is tracked." in scorecard

    if not args.quiet:
        print("Daylight v0.6 fail-closed model: PASS")


if __name__ == "__main__":
    main()
