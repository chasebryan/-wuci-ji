"""Daylight v17.1 Event Horizon declaration gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import agreement, falsification, fracture, proof_atoms, registry, scorecard


def run_declaration_gate(
    *,
    state_path: Path | str,
    fields_path: Path | str = registry.DEFAULT_FIELDS_PATH,
    proof_atoms_path: Path | str = proof_atoms.DEFAULT_PROOF_ATOMS_PATH,
    open_breaks_path: Path | str = falsification.DEFAULT_OPEN_BREAKS,
) -> dict[str, Any]:
    state = scorecard.load_state(state_path)
    fields = registry.load_fields_registry(fields_path)
    atoms = proof_atoms.load_proof_atom_registry(proof_atoms_path)
    card = scorecard.build_scorecard(state, fields, atoms)
    scorecard.verify_scorecard_object(card, state, fields, atoms)
    fracture_result = fracture.run_fracture_suite(state, fields, atoms, card)
    agreement_result = agreement.check_cross_verifier_agreement(card)
    falsification_result = falsification.verify_no_critical_open_breaks(open_breaks_path)
    allowed = (
        card["declared"]
        and card["claim_usable"] is True
        and not card["fixture"]
        and fracture_result["passed"]
        and agreement_result["passed"]
        and falsification_result["passed"]
    )
    return {
        "version": "daylight-v17.1-event-horizon-declaration-gate-v0.1",
        "allowed": allowed,
        "decision": "declaration_allowed" if allowed else "declaration_refused",
        "score_AM_plus": card["score_AM_plus"],
        "declared_by_scorecard": card["declared"],
        "status": card["status"],
        "weakest_field": card["weakest_field"],
        "omega_sum_decimal": card["omega_sum_decimal"],
        "omega_weak_decimal": card["omega_weak_decimal"],
        "omega_eff_decimal": card["omega_decimal"],
        "field_thresholds_pass": card["field_thresholds_pass"],
        "collapse": card["collapse"],
        "collapse_reasons": card["collapse_reasons"],
        "fracture_suite": fracture_result,
        "cross_verifier_agreement": agreement_result,
        "falsification": falsification_result,
        "scorecard_digest": card["scorecard_digest"],
        "proof_atom_digest": card["proof_atom_digest"],
        "non_claim": "refusal is expected until proof atoms, thresholds, fracture, agreement, and falsification evidence all pass",
    }

