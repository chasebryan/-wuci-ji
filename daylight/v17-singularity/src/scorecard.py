"""Daylight v17 Singularity scorecard construction and verification."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256, dumps_canonical, load_json_no_floats, reject_python_floats
from . import registry as registry_mod
from . import proof_atoms
from .singularity_math import (
    B,
    DECLARATION_TARGET_AM_PLUS,
    OMEGA_THRESHOLD,
    OMEGA_THRESHOLD_DECIMAL_TEXT,
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
    require_nonnegative_int,
    score_from_omega,
    status_for_score,
)


D_STATE = "DAYLIGHT-v17-SINGULARITY-STATE:"
D_SCORECARD = "DAYLIGHT-v17-SINGULARITY-SCORECARD:"
STATE_VERSION = "daylight-v17-singularity-state-v0.1"

NON_CLAIMS = [
    "Daylight v17 Singularity is a research scoring layer.",
    "AM+ does not modify the conservative Daylight M score.",
    "999,999,999 AM+ is a residue-collapse declaration, not production certification.",
    "1,000,000,000 AM+ is mathematically reserved.",
    "No manual score is accepted.",
]

FORBIDDEN_STATE_SCORE_KEYS = {
    "score_AM_plus",
    "declared",
    "status",
    "omega_decimal",
    "residue_decimal",
    "scorecard_digest",
}

COLLAPSE_FLAGS = [
    "forged_scorecard_accepted",
    "opens_without_policy_evidence",
    "severe_boundary_overclaim",
    "manual_score_detected",
    "manual_score_accepted",
    "unsigned_external_credit",
    "production_overclaim",
    "whole_system_pq_overclaim",
    "runtime_containment_overclaim",
    "implementation_disagreement",
    "parser_ambiguity",
]

BOUNDARY_KEYS = [
    "production_allowed",
    "runtime_containment_claim",
    "whole_system_post_quantum_safety_claim",
    "external_certification_claim",
]


class ScorecardError(ValueError):
    pass


def _walk_forbidden_state_keys(value: Any, path: str = "state") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_STATE_SCORE_KEYS:
                raise ScorecardError(f"generated score field is not allowed in input state: {path}.{key}")
            _walk_forbidden_state_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_forbidden_state_keys(item, f"{path}[{index}]")


def load_state(path: Path | str) -> dict[str, Any]:
    state = load_json_no_floats(path)
    validate_state(state)
    return state


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ScorecardError(f"{name} must be boolean")
    return value


def validate_state(state: dict[str, Any]) -> None:
    reject_python_floats(state, "state")
    _walk_forbidden_state_keys(state)
    if state.get("version") != STATE_VERSION:
        raise ScorecardError("unsupported Daylight v17 state version")
    if not isinstance(state.get("candidate"), str) or not state["candidate"]:
        raise ScorecardError("state candidate must be a non-empty string")
    _require_bool(state.get("fixture", False), "fixture")
    _require_bool(state.get("claim_usable", True), "claim_usable")
    if not isinstance(state.get("boundary"), str) or not state["boundary"]:
        raise ScorecardError("state boundary must be a non-empty string")
    if "fields" in state:
        raise ScorecardError("v17.1 Event Horizon state cannot carry manual field credits")
    for key in ("debt_uomega", "overclaim_debt_uomega", "staleness_debt_uomega", "contradiction_debt", "critical_break_debt"):
        require_nonnegative_int(state.get(key, 0), key)
    score_inflation = state.get("score_inflation_M", 0)
    if isinstance(score_inflation, bool) or not isinstance(score_inflation, int):
        raise ScorecardError("score_inflation_M must be an integer")
    if score_inflation != 0:
        raise ScorecardError("score_inflation_M must be zero")
    collapse_flags = state.get("collapse_flags", {})
    if not isinstance(collapse_flags, dict):
        raise ScorecardError("collapse_flags must be an object")
    for key in COLLAPSE_FLAGS:
        _require_bool(collapse_flags.get(key, False), f"collapse_flags.{key}")
    boundary_claims = state.get("boundary_claims", {})
    if not isinstance(boundary_claims, dict):
        raise ScorecardError("boundary_claims must be an object")
    for key in BOUNDARY_KEYS:
        if boundary_claims.get(key, False) is True:
            raise ScorecardError(f"{key} must remain false in Daylight v17 state")
        if key in boundary_claims:
            _require_bool(boundary_claims[key], f"boundary_claims.{key}")


def state_digest(state: dict[str, Any]) -> str:
    validate_state(state)
    return canonical_sha256(state, D_STATE)


def _fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def _threshold_pass(closure: Decimal, threshold: Fraction) -> bool:
    return closure >= fraction_to_decimal(threshold)


def _build_fields(fields_registry: dict[str, Any], atom_result: dict[str, Any]) -> tuple[list[dict[str, Any]], Decimal, Decimal, bool, str]:
    out: list[dict[str, Any]] = []
    omega_raw = Decimal(0)
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
        omega_raw += weighted_omega
        if omega_min is None or closure["omega"] < omega_min:
            omega_min = closure["omega"]
            weakest_field = field_id
        threshold = thresholds[field_id]
        pass_threshold = _threshold_pass(closure["closure"], threshold)
        out.append({
            "id": field_id,
            "name": field_def["name"],
            "alpha": field_def["alpha"],
            "threshold": field_def["threshold"],
            "verified_credit": closure["verified_credit"],
            "possible_credit": closure["possible_credit"],
            "closure_decimal": decimal_text(closure["closure"]),
            "residue_decimal": decimal_text(closure["residue"]),
            "omega_decimal": decimal_text(closure["omega"]),
            "weighted_omega_decimal": decimal_text(weighted_omega),
            "threshold_pass": pass_threshold,
            "perfect_reserve_applied": closure["perfect_reserve_applied"],
        })
    if omega_min is None:
        raise ScorecardError("no fields available")
    return out, omega_raw, omega_min, all(field["threshold_pass"] for field in out), weakest_field


def _collapse_reasons(state: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if state.get("contradiction_debt", 0) > 0:
        reasons.append("contradiction_debt")
    if state.get("critical_break_debt", 0) > 0:
        reasons.append("critical_break_debt")
    flags = state.get("collapse_flags", {})
    for key in COLLAPSE_FLAGS:
        if flags.get(key, False):
            reasons.append(key)
    return reasons


def build_scorecard(state: dict[str, Any], fields_registry: dict[str, Any], proof_atom_registry: dict[str, Any]) -> dict[str, Any]:
    require_decimal_runtime()
    registry_mod.validate_fields_registry(fields_registry)
    validate_state(state)
    atom_result = proof_atoms.verify_proof_atoms(proof_atom_registry)
    fields, omega_sum, omega_min, field_thresholds_pass, weakest_field = _build_fields(fields_registry, atom_result)
    debt_omega = debt_uomega_to_decimal(state.get("debt_uomega", 0), "debt_uomega")
    overclaim_debt_omega = debt_uomega_to_decimal(state.get("overclaim_debt_uomega", 0), "overclaim_debt_uomega")
    staleness_debt_omega = debt_uomega_to_decimal(state.get("staleness_debt_uomega", 0), "staleness_debt_uomega")
    omega_parts = effective_omega(
        omega_sum=omega_sum,
        omega_min=omega_min,
        debt_omega=debt_omega,
        overclaim_debt_omega=overclaim_debt_omega,
        staleness_debt_omega=staleness_debt_omega,
        kappa=int(fields_registry["weak_governor_kappa"]),
    )
    omega = omega_parts["omega_eff"]
    collapse_reasons = _collapse_reasons(state) + atom_result["collapse_reasons"]
    collapse = bool(collapse_reasons)
    score, residue = score_from_omega(omega, collapse=collapse)
    is_declared = declared_rule(
        omega=omega,
        score_am_plus=score,
        field_thresholds_pass=field_thresholds_pass,
        contradiction_debt=int(state.get("contradiction_debt", 0)),
        critical_break_debt=int(state.get("critical_break_debt", 0)),
        score_inflation_M=int(state.get("score_inflation_M", 0)),
        collapse=collapse,
    )
    scorecard = {
        "scorecard_version": VERSION,
        "candidate": state["candidate"],
        "unit": UNIT,
        "scale": B,
        "perfect_reserved_AM_plus": PERFECT_RESERVED_AM_PLUS,
        "declaration_target_AM_plus": DECLARATION_TARGET_AM_PLUS,
        "omega_decimal": decimal_text(Decimal(0) if collapse else omega),
        "omega_sum_decimal": decimal_text(omega_sum),
        "omega_weak_decimal": decimal_text(omega_parts["omega_weak"]),
        "omega_governed_decimal": decimal_text(omega_parts["omega_governed"]),
        "omega_min_field_decimal": decimal_text(omega_min),
        "weakest_field": weakest_field,
        "omega_threshold_decimal": OMEGA_THRESHOLD_DECIMAL_TEXT,
        "residue_decimal": decimal_text(residue),
        "score_AM_plus": score,
        "declared": is_declared,
        "status": status_for_score(score_am_plus=score, is_declared=is_declared, collapse=collapse),
        "fields": fields,
        "field_thresholds_pass": field_thresholds_pass,
        "alpha_sum": _fraction_text(registry_mod.alpha_sum(fields_registry)),
        "weak_governor_kappa": int(fields_registry["weak_governor_kappa"]),
        "debt_uomega": int(state.get("debt_uomega", 0)),
        "overclaim_debt_uomega": int(state.get("overclaim_debt_uomega", 0)),
        "staleness_debt_uomega": int(state.get("staleness_debt_uomega", 0)),
        "contradiction_debt": int(state.get("contradiction_debt", 0)),
        "critical_break_debt": int(state.get("critical_break_debt", 0)),
        "score_inflation_M": int(state.get("score_inflation_M", 0)),
        "collapse": collapse,
        "collapse_reasons": collapse_reasons,
        "fixture": bool(state.get("fixture", False)),
        "claim_usable": bool(state.get("claim_usable", True)),
        "state_boundary": state["boundary"],
        "proof_registry_digest": registry_mod.proof_registry_digest(fields_registry),
        "proof_atom_digest": proof_atoms.proof_atom_registry_digest(proof_atom_registry),
        "proof_atoms": atom_result["atom_results"],
        "state_digest": state_digest(state),
        "boundary": {
            "production_allowed": False,
            "runtime_containment_claim": False,
            "whole_system_post_quantum_safety_claim": False,
            "external_certification_claim": False,
            "perfect_reserved": True,
        },
        "non_claims": NON_CLAIMS,
    }
    scorecard["scorecard_digest"] = scorecard_digest(scorecard)
    return scorecard


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
    reject_python_floats(scorecard, "scorecard")
    body = {key: value for key, value in scorecard.items() if key != "scorecard_digest"}
    return canonical_sha256(body, D_SCORECARD)


def verify_scorecard_object(
    scorecard: dict[str, Any],
    state: dict[str, Any],
    fields_registry: dict[str, Any],
    proof_atom_registry: dict[str, Any],
) -> None:
    reject_python_floats(scorecard, "scorecard")
    if scorecard.get("scorecard_version") != VERSION:
        raise ScorecardError("unsupported scorecard version")
    if scorecard_digest(scorecard) != scorecard.get("scorecard_digest"):
        raise ScorecardError("scorecard digest mismatch")
    expected = build_scorecard(state, fields_registry, proof_atom_registry)
    if dumps_canonical(scorecard) != dumps_canonical(expected):
        raise ScorecardError("scorecard does not match regenerated state")


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
