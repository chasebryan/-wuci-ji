"""Daylight v17.1 Event Horizon scorecard construction and verification."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256, dumps_canonical, load_json_no_floats, reject_floats_recursive
from . import registry as registry_mod
from . import proof_atoms
from .singularity_math import (
    B,
    DECLARATION_TARGET_AM_PLUS,
    EPSILON,
    EPSILON_DENOMINATOR,
    KAPPA,
    LN_1E9,
    LN_1E9_DECIMAL_TEXT,
    PERFECT_RESERVED_AM_PLUS,
    UNIT,
    VERSION,
    debt_uomega_to_decimal,
    decimal_text,
    declared as declared_rule,
    effective_omega,
    field_closure,
    fraction_to_decimal,
    parse_rational_alpha,
    require_decimal_runtime,
    require_int,
    require_nonnegative_int,
    score_from_omega,
    status_for_score,
)


D_STATE = "DAYLIGHT-v17-EVENT-HORIZON-STATE:"
D_SCORECARD = "DAYLIGHT-v17-EVENT-HORIZON-SCORECARD:"
D_FRACTURE = "DAYLIGHT-v17-EVENT-HORIZON-FRACTURE:"
STATE_VERSION = "daylight-v17-event-horizon-state-v0.1"

NON_CLAIMS = [
    "Daylight v17.3 Triangulation Gate is a deterministic research scoring kernel.",
    "AM+ does not modify the conservative Daylight M score.",
    "999,999,999 AM+ is a residue-collapse declaration, not production certification.",
    "1,000,000,000 AM+ is mathematically reserved.",
    "No manual score is accepted.",
    "A fixture declaration is not claim-usable.",
]

FORBIDDEN_STATE_SCORE_KEYS = {
    "score_AM_plus",
    "declared",
    "status",
    "omega_decimal",
    "omega_eff_decimal",
    "residue_decimal",
    "scorecard_digest",
    "fields",
}

COLLAPSE_FLAG_KEYS = [
    "manual_score_detected",
    "forged_scorecard_accepted",
    "opens_without_policy_evidence",
    "severe_boundary_overclaim",
]

BOUNDARY_KEYS = [
    "production_allowed",
    "runtime_containment_claim",
    "whole_system_post_quantum_safety_claim",
    "external_certification_claim",
]

FRACTURE_MUTATIONS = [
    "M1 edited score_AM_plus",
    "M2 edited omega_eff_decimal",
    "M3 edited field verified_credit",
    "M4 edited debt_uomega",
    "M5 edited fields_digest",
    "M6 edited proof_atoms_digest",
    "M7 edited state_digest",
    "M8 removed proof atom",
    "M9 forged fixture flag",
    "M10 forged claim_usable flag",
    "M11 score_inflation_M changed to nonzero",
    "M12 collapse flag edited",
    "M13 status edited",
    "M14 declared edited",
    "M15 scorecard_digest edited",
]


class ScorecardError(ValueError):
    pass


def _walk_forbidden_state_keys(value: Any, path: str = "state") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            in_verifier_output = path.startswith("state.verifier_outputs[")
            if key in FORBIDDEN_STATE_SCORE_KEYS and not in_verifier_output:
                raise ScorecardError(f"generated score field is not allowed in input state: {path}.{key}")
            _walk_forbidden_state_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_forbidden_state_keys(item, f"{path}[{index}]")


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ScorecardError(f"{name} must be boolean")
    return value


def load_state(path: Path | str) -> dict[str, Any]:
    state = load_json_no_floats(path)
    validate_state(state)
    return state


def validate_state(state: dict[str, Any]) -> None:
    reject_floats_recursive(state, "state")
    _walk_forbidden_state_keys(state)
    if state.get("version") != STATE_VERSION:
        raise ScorecardError("unsupported Daylight v17.1 state version")
    if not isinstance(state.get("candidate"), str) or not state["candidate"]:
        raise ScorecardError("state candidate must be a non-empty string")
    _require_bool(state.get("fixture"), "fixture")
    _require_bool(state.get("claim_usable"), "claim_usable")
    if not isinstance(state.get("boundary"), str) or not state["boundary"]:
        raise ScorecardError("state boundary must be a non-empty string")
    for key in ("debt_uomega", "overclaim_debt_uomega", "staleness_debt_uomega", "contradiction_debt", "critical_break_debt"):
        require_nonnegative_int(state.get(key), key)
    require_int(state.get("score_inflation_M"), "score_inflation_M")
    for key in COLLAPSE_FLAG_KEYS:
        _require_bool(state.get(key), key)
    for key in BOUNDARY_KEYS:
        _require_bool(state.get(key), key)
        if state.get(key) is True:
            raise ScorecardError(f"{key} must remain false in Daylight v17.1 state")
    outputs = state.get("verifier_outputs", [])
    if not isinstance(outputs, list):
        raise ScorecardError("verifier_outputs must be a list")
    for index, output in enumerate(outputs):
        if not isinstance(output, dict):
            raise ScorecardError(f"verifier_outputs[{index}] must be an object")


def state_digest(state: dict[str, Any]) -> str:
    validate_state(state)
    body = {key: value for key, value in state.items() if key != "verifier_outputs"}
    return canonical_sha256(body, D_STATE)


def fracture_digest() -> str:
    return canonical_sha256({"mutations": FRACTURE_MUTATIONS}, D_FRACTURE)


def _fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def _closure_rational(verified: int, possible: int, perfect_reserve_applied: bool) -> str:
    if perfect_reserve_applied:
        return f"{EPSILON_DENOMINATOR - 1}/{EPSILON_DENOMINATOR}"
    return f"{verified}/{possible}"


def _threshold_pass(closure: Decimal, threshold: Fraction) -> bool:
    return closure >= fraction_to_decimal(threshold)


def _build_fields(
    fields_registry: dict[str, Any],
    atom_result: dict[str, Any],
) -> tuple[list[dict[str, Any]], Decimal, Decimal, bool, str]:
    out: list[dict[str, Any]] = []
    omega_sum = Decimal(0)
    omega_min: Decimal | None = None
    weakest_field = ""
    thresholds = registry_mod.field_thresholds(fields_registry)
    for field_def in fields_registry["fields"]:
        field_id = field_def["id"]
        closure = field_closure(
            verified_credit=atom_result["field_verified_credit"][field_id],
            possible_credit=atom_result["field_possible_credit"][field_id],
            epsilon_denominator=int(fields_registry["epsilon_denominator"]),
        )
        alpha_fraction = parse_rational_alpha(field_def["alpha"])
        alpha_decimal = fraction_to_decimal(alpha_fraction)
        weighted_omega = alpha_decimal * closure["omega"]
        omega_sum += weighted_omega
        if omega_min is None or closure["omega"] < omega_min:
            omega_min = closure["omega"]
            weakest_field = field_id
        threshold = thresholds[field_id]
        threshold_passed = _threshold_pass(closure["closure"], threshold)
        out.append({
            "id": field_id,
            "name": field_def["name"],
            "alpha": field_def["alpha"],
            "threshold": field_def["threshold"],
            "possible_credit": closure["possible_credit"],
            "verified_credit": closure["verified_credit"],
            "closure_rational": _closure_rational(
                closure["verified_credit"],
                closure["possible_credit"],
                closure["perfect_reserve_applied"],
            ),
            "closure_decimal": decimal_text(closure["closure"]),
            "omega_i_decimal": decimal_text(closure["omega"]),
            "weighted_omega_decimal": decimal_text(weighted_omega),
            "threshold_passed": threshold_passed,
            "perfect_reserve_applied": closure["perfect_reserve_applied"],
            "closed_atoms": atom_result["field_closed_atoms"][field_id],
            "open_atoms": atom_result["field_open_atoms"][field_id],
        })
    if omega_min is None:
        raise ScorecardError("no fields available")
    return out, omega_sum, omega_min, all(field["threshold_passed"] for field in out), weakest_field


def _collapse_reasons(state: dict[str, Any], atom_result: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if int(state.get("contradiction_debt", 0)) > 0:
        reasons.append("contradiction_debt")
    if int(state.get("critical_break_debt", 0)) > 0:
        reasons.append("critical_break_debt")
    if int(state.get("score_inflation_M", 0)) != 0:
        reasons.append("score_inflation_M")
    for key in COLLAPSE_FLAG_KEYS:
        if state.get(key) is True:
            reasons.append(key)
    reasons.extend(atom_result["collapse_reasons"])
    return reasons


def _output_vector_digest(
    *,
    fields_digest_value: str,
    proof_atoms_digest_value: str,
    state_digest_value: str,
    score_am_plus: int,
    omega_eff_decimal: str,
) -> str:
    return canonical_sha256(
        {
            "fields_digest": fields_digest_value,
            "proof_atoms_digest": proof_atoms_digest_value,
            "state_digest": state_digest_value,
            "score_AM_plus": score_am_plus,
            "omega_eff_decimal": omega_eff_decimal,
        },
        D_SCORECARD + "OUTPUT-VECTOR:",
    )


def cross_verifier_agreement_result(
    state: dict[str, Any],
    *,
    reference_vector: dict[str, Any],
) -> dict[str, Any]:
    outputs = state.get("verifier_outputs", [])
    if not isinstance(outputs, list):
        return {
            "passed": False,
            "blockers": ["verifier_outputs must be a list"],
            "vector_count": 0,
            "valid_vector_count": 0,
            "distinct_family_count": 0,
            "quorum": "0/3",
            "agreement_status": "failed",
            "implementation_families": [],
            "reference_implementation_family": reference_vector.get("implementation_family"),
        }
    from . import verifier_vector

    return verifier_vector.verify_vectors_against_reference(outputs, reference_vector)


def declaration_blockers(card: dict[str, Any], fracture_result: dict[str, Any] | None = None) -> list[str]:
    blockers: list[str] = []
    if Decimal(card["omega_eff_decimal"]) < LN_1E9:
        blockers.append("omega_eff below declaration threshold")
    if int(card["score_AM_plus"]) < DECLARATION_TARGET_AM_PLUS:
        blockers.append("score_AM_plus below declaration target")
    if card.get("field_thresholds_pass") is not True:
        blockers.append("field threshold failure")
    if card.get("collapse") is True:
        blockers.append("collapse=true")
    if int(card.get("contradiction_debt", 0)) > 0:
        blockers.append("contradiction_debt > 0")
    if int(card.get("critical_break_debt", 0)) > 0:
        blockers.append("critical_break_debt > 0")
    if int(card.get("score_inflation_M", 0)) != 0:
        blockers.append("score_inflation_M != 0")
    fracture_passed = card.get("fracture_suite_passed") is True
    if fracture_result is not None:
        fracture_passed = fracture_passed and fracture_result.get("passed") is True
    if not fracture_passed:
        blockers.append("fracture_suite_passed=false")
    if card.get("cross_verifier_agreement_passed") is not True:
        blockers.append("cross_verifier_agreement_passed=false")
        agreement_status = card.get("cross_verifier_agreement_status")
        quorum = card.get("cross_verifier_quorum")
        if isinstance(agreement_status, str) and agreement_status.startswith("partial_") and isinstance(quorum, str):
            blockers.append(f"verifier quorum incomplete: {quorum}")
    if card.get("claim_usable") is not True:
        blockers.append("claim_usable=false")
    if card.get("fixture") is True:
        blockers.append("fixture=true")
    return blockers


def build_scorecard(
    state: dict[str, Any],
    fields_registry: dict[str, Any],
    proof_atom_registry: dict[str, Any],
) -> dict[str, Any]:
    require_decimal_runtime()
    registry_mod.validate_fields_registry(fields_registry)
    validate_state(state)
    atom_result = proof_atoms.verify_proof_atoms(proof_atom_registry, state)
    fields, omega_sum, omega_min, field_thresholds_pass, weakest_field = _build_fields(fields_registry, atom_result)
    debt_omega = debt_uomega_to_decimal(state["debt_uomega"], "debt_uomega")
    overclaim_debt_omega = debt_uomega_to_decimal(state["overclaim_debt_uomega"], "overclaim_debt_uomega")
    staleness_debt_omega = debt_uomega_to_decimal(state["staleness_debt_uomega"], "staleness_debt_uomega")
    omega_parts = effective_omega(
        omega_sum=omega_sum,
        omega_min=omega_min,
        debt_omega=debt_omega,
        overclaim_debt_omega=overclaim_debt_omega,
        staleness_debt_omega=staleness_debt_omega,
        kappa=int(fields_registry["kappa"]),
    )
    collapse_reasons = _collapse_reasons(state, atom_result)
    collapse = bool(collapse_reasons)
    omega_eff = Decimal(0) if collapse else omega_parts["omega_eff"]
    score, residue = score_from_omega(omega_eff, collapse=collapse)
    fields_digest_value = registry_mod.fields_digest(fields_registry)
    proof_atoms_digest_value = proof_atoms.proof_atoms_digest(proof_atom_registry)
    state_digest_value = state_digest(state)
    omega_eff_decimal = decimal_text(omega_eff)
    declaration_residue = B - score
    declaration_score_gap = DECLARATION_TARGET_AM_PLUS - score
    omega_gap = LN_1E9 - omega_eff
    residue_collapse_factor = omega_gap.exp()
    fracture_passed = True
    predicted_declared_with_agreement = declared_rule(
        omega_eff=omega_eff,
        score_am_plus=score,
        field_thresholds_pass=field_thresholds_pass,
        contradiction_debt=int(state["contradiction_debt"]),
        critical_break_debt=int(state["critical_break_debt"]),
        score_inflation_M=int(state["score_inflation_M"]),
        collapse=collapse,
        fracture_suite_passed=fracture_passed,
        cross_verifier_agreement_passed=True,
        claim_usable=bool(state["claim_usable"]),
        fixture=bool(state["fixture"]),
    )
    predicted_status_with_agreement = status_for_score(
        score_am_plus=score,
        is_declared=predicted_declared_with_agreement,
        collapse=collapse,
    )
    from . import verifier_vector

    reference_vector = {
        "implementation_family": "python-reference",
        "implementation_digest": verifier_vector.python_reference_implementation_digest(),
        "fields_digest": fields_digest_value,
        "proof_atoms_digest": proof_atoms_digest_value,
        "state_digest": state_digest_value,
        "omega_sum_decimal": decimal_text(omega_sum),
        "omega_weak_decimal": decimal_text(omega_parts["omega_weak"]),
        "omega_eff_decimal": omega_eff_decimal,
        "score_AM_plus": score,
        "residue_AM_plus": declaration_residue,
        "declaration_residue_AM_plus": declaration_residue,
        "declaration_score_gap_AM_plus": declaration_score_gap,
        "collapse": collapse,
        "declared": predicted_declared_with_agreement,
        "status": predicted_status_with_agreement,
    }
    reference_vector["scorecard_predigest"] = verifier_vector.scorecard_predigest_from_parts(reference_vector)
    cross_result = cross_verifier_agreement_result(state, reference_vector=reference_vector)
    cross_passed = bool(cross_result["passed"])
    is_declared = declared_rule(
        omega_eff=omega_eff,
        score_am_plus=score,
        field_thresholds_pass=field_thresholds_pass,
        contradiction_debt=int(state["contradiction_debt"]),
        critical_break_debt=int(state["critical_break_debt"]),
        score_inflation_M=int(state["score_inflation_M"]),
        collapse=collapse,
        fracture_suite_passed=fracture_passed,
        cross_verifier_agreement_passed=cross_passed,
        claim_usable=bool(state["claim_usable"]),
        fixture=bool(state["fixture"]),
    )
    card = {
        "scorecard_version": VERSION,
        "name": "Daylight v17 Singularity",
        "implementation_layer": "Daylight v17.3 Triangulation Gate over Daylight v17.1 Event Horizon Kernel",
        "candidate": state["candidate"],
        "unit": UNIT,
        "scale": B,
        "perfect_reserved_AM_plus": PERFECT_RESERVED_AM_PLUS,
        "declaration_target_AM_plus": DECLARATION_TARGET_AM_PLUS,
        "omega_sum_decimal": decimal_text(omega_sum),
        "omega_weak_decimal": decimal_text(omega_parts["omega_weak"]),
        "omega_eff_decimal": omega_eff_decimal,
        "omega_threshold_decimal": LN_1E9_DECIMAL_TEXT,
        "residue_decimal": decimal_text(residue),
        "declaration_residue_AM_plus": declaration_residue,
        "declaration_score_gap_AM_plus": declaration_score_gap,
        "omega_gap_to_declaration": decimal_text(omega_gap),
        "residue_collapse_factor_to_declaration": decimal_text(residue_collapse_factor),
        "score_AM_plus": score,
        "declared": is_declared,
        "status": status_for_score(score_am_plus=score, is_declared=is_declared, collapse=collapse),
        "fields": fields,
        "field_thresholds_pass": field_thresholds_pass,
        "weakest_field": weakest_field,
        "alpha_sum": _fraction_text(registry_mod.alpha_sum(fields_registry)),
        "kappa": KAPPA,
        "epsilon": f"1/{EPSILON_DENOMINATOR}",
        "debt_uomega": int(state["debt_uomega"]),
        "overclaim_debt_uomega": int(state["overclaim_debt_uomega"]),
        "staleness_debt_uomega": int(state["staleness_debt_uomega"]),
        "contradiction_debt": int(state["contradiction_debt"]),
        "critical_break_debt": int(state["critical_break_debt"]),
        "score_inflation_M": int(state["score_inflation_M"]),
        "collapse": collapse,
        "collapse_reasons": collapse_reasons,
        "fracture_suite_passed": fracture_passed,
        "cross_verifier_agreement_passed": cross_passed,
        "cross_verifier_agreement_status": cross_result["agreement_status"],
        "cross_verifier_quorum": cross_result["quorum"],
        "cross_verifier_blockers": cross_result["blockers"],
        "cross_verifier_vector_count": cross_result["vector_count"],
        "cross_verifier_implementation_families": cross_result["implementation_families"],
        "claim_usable": bool(state["claim_usable"]),
        "fixture": bool(state["fixture"]),
        "state_boundary": state["boundary"],
        "fields_digest": fields_digest_value,
        "proof_atoms_digest": proof_atoms_digest_value,
        "state_digest": state_digest_value,
        "fracture_digest": fracture_digest(),
        "proof_atoms": atom_result["atom_results"],
        "boundary": {
            "production_allowed": False,
            "runtime_containment_claim": False,
            "whole_system_post_quantum_safety_claim": False,
            "external_certification_claim": False,
            "perfect_reserved": True,
        },
        "non_claims": NON_CLAIMS,
    }
    card["scorecard_digest"] = scorecard_digest(card)
    return card


def build_scorecard_from_paths(
    *,
    state_path: Path | str,
    fields_path: Path | str = registry_mod.DEFAULT_FIELDS_PATH,
    proof_atoms_path: Path | str = proof_atoms.DEFAULT_PROOF_ATOMS_PATH,
) -> dict[str, Any]:
    return build_scorecard(
        load_state(state_path),
        registry_mod.load_fields_registry(fields_path),
        proof_atoms.load_proof_atom_registry(proof_atoms_path),
    )


def scorecard_digest(scorecard: dict[str, Any]) -> str:
    reject_floats_recursive(scorecard, "scorecard")
    body = {key: value for key, value in scorecard.items() if key != "scorecard_digest"}
    return canonical_sha256(body, D_SCORECARD)


def verify_scorecard_object(
    scorecard: dict[str, Any],
    state: dict[str, Any],
    fields_registry: dict[str, Any],
    proof_atom_registry: dict[str, Any],
    *,
    check_fracture: bool = True,
) -> None:
    reject_floats_recursive(scorecard, "scorecard")
    if scorecard.get("scorecard_version") != VERSION:
        raise ScorecardError("unsupported scorecard version")
    if scorecard_digest(scorecard) != scorecard.get("scorecard_digest"):
        raise ScorecardError("scorecard digest mismatch")
    expected = build_scorecard(state, fields_registry, proof_atom_registry)
    if dumps_canonical(scorecard) != dumps_canonical(expected):
        raise ScorecardError("scorecard does not match regenerated state")
    if check_fracture:
        from . import fracture

        result = fracture.run_fracture_suite(state, fields_registry, proof_atom_registry, scorecard)
        if not result["passed"]:
            raise ScorecardError("fracture suite did not reject all mutations")


def verify_scorecard_path(
    *,
    scorecard_path: Path | str,
    state_path: Path | str,
    fields_path: Path | str = registry_mod.DEFAULT_FIELDS_PATH,
    proof_atoms_path: Path | str = proof_atoms.DEFAULT_PROOF_ATOMS_PATH,
) -> None:
    scorecard = load_json_no_floats(scorecard_path)
    state = load_state(state_path)
    fields_registry = registry_mod.load_fields_registry(fields_path)
    proof_atom_registry = proof_atoms.load_proof_atom_registry(proof_atoms_path)
    verify_scorecard_object(scorecard, state, fields_registry, proof_atom_registry)
