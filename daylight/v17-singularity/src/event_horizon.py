"""Daylight v17.1 Event Horizon declaration gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical_json import load_json_no_floats
from . import fracture, proof_atoms, registry, scorecard
from .singularity_math import (
    B,
    DECLARATION_TARGET_AM_PLUS,
    EPSILON,
    KAPPA,
    LN_1E9,
    LN_1E9_DECIMAL_TEXT,
    PERFECT_RESERVED_AM_PLUS,
    UNIT,
)


def run_declaration_gate(
    *,
    state_path: Path | str,
    scorecard_path: Path | str | None = None,
    fields_path: Path | str = registry.DEFAULT_FIELDS_PATH,
    proof_atoms_path: Path | str = proof_atoms.DEFAULT_PROOF_ATOMS_PATH,
) -> dict[str, Any]:
    state = scorecard.load_state(state_path)
    fields = registry.load_fields_registry(fields_path)
    atoms = proof_atoms.load_proof_atom_registry(proof_atoms_path)
    if scorecard_path is None:
        card = scorecard.build_scorecard(state, fields, atoms)
    else:
        card = load_json_no_floats(scorecard_path)
        scorecard.verify_scorecard_object(card, state, fields, atoms)
    fracture_result = fracture.run_fracture_suite(state, fields, atoms, card)
    blockers = scorecard.declaration_blockers(card, fracture_result)
    allowed = not blockers
    return {
        "version": "daylight-v17-event-horizon-declaration-gate-v0.1",
        "allowed": allowed,
        "decision": "declaration_allowed" if allowed else "declaration_refused",
        "blockers": blockers,
        "score_AM_plus": card["score_AM_plus"],
        "declaration_residue_AM_plus": card["declaration_residue_AM_plus"],
        "declaration_score_gap_AM_plus": card["declaration_score_gap_AM_plus"],
        "declared_by_scorecard": card["declared"],
        "status": card["status"],
        "weakest_field": card["weakest_field"],
        "omega_sum_decimal": card["omega_sum_decimal"],
        "omega_weak_decimal": card["omega_weak_decimal"],
        "omega_eff_decimal": card["omega_eff_decimal"],
        "omega_gap_to_declaration": card["omega_gap_to_declaration"],
        "residue_collapse_factor_to_declaration": card["residue_collapse_factor_to_declaration"],
        "field_thresholds_pass": card["field_thresholds_pass"],
        "collapse": card["collapse"],
        "collapse_reasons": card["collapse_reasons"],
        "fracture_suite": fracture_result,
        "cross_verifier_agreement_passed": card["cross_verifier_agreement_passed"],
        "cross_verifier_agreement_status": card["cross_verifier_agreement_status"],
        "cross_verifier_quorum": card["cross_verifier_quorum"],
        "cross_verifier_blockers": card["cross_verifier_blockers"],
        "cross_verifier_vector_count": card["cross_verifier_vector_count"],
        "cross_verifier_implementation_families": card["cross_verifier_implementation_families"],
        "claim_usable": card["claim_usable"],
        "fixture": card["fixture"],
        "scorecard_digest": card["scorecard_digest"],
        "fields_digest": card["fields_digest"],
        "proof_atoms_digest": card["proof_atoms_digest"],
        "state_digest": card["state_digest"],
        "non_claim": "declaration is refused unless regenerated proof atoms, fracture mutations, and cross-verifier evidence all pass",
    }
