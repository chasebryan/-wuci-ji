"""Boundary debt reporting and non-claim enforcement for v20."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Any

from .canonical import load_json_no_floats, reject_floats_recursive

SCHEMA_ID = "daylight-v20-boundary-debt-report"
SCHEMA_VERSION = "0.1.0"

NON_CLAIMS = [
    "not production cryptography",
    "not runtime containment",
    "not host cleanliness proof",
    "not FIPS validated",
    "not government validated",
    "not externally certified",
    "not whole-system post-quantum safe",
    "not an independent audit",
    "not a perfect Daylight score claim from repository-owned evidence",
]
REQUIRED_NON_CLAIMS = frozenset(NON_CLAIMS)

FORBIDDEN_CLAIM_KEYS = {
    "production_cryptography",
    "runtime_containment",
    "host_cleanliness",
    "fips_validation",
    "government_validation",
    "external_certification",
    "whole_system_post_quantum_safety",
    "independent_audit_completed",
    "perfect_daylight_score_from_repo_evidence",
}
DEBT_CLASSES = {"none", "minor", "major", "critical", "contradiction"}
DEBT_OMEGA = {
    "none": Decimal("0"),
    "minor": Decimal("0.001"),
    "major": Decimal("0.01"),
    "critical": Decimal("1"),
    "contradiction": Decimal("1"),
}


class BoundaryDebtError(ValueError):
    pass


def _decimal_text(value: Decimal) -> str:
    text = format(+value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise BoundaryDebtError(f"{name} must be boolean")
    return value


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BoundaryDebtError(f"{name} must be an integer")
    return value


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BoundaryDebtError(f"{name} must be a non-empty string")
    return value


def validate_claim_boundary(value: Any) -> list[str]:
    if not isinstance(value, dict):
        raise BoundaryDebtError("claim_boundary must be an object")
    blockers: list[str] = []
    missing = sorted(FORBIDDEN_CLAIM_KEYS - set(value))
    if missing:
        raise BoundaryDebtError(f"claim_boundary missing keys: {missing}")
    for key in FORBIDDEN_CLAIM_KEYS:
        if value.get(key) is not False:
            blockers.append(f"forbidden claim enabled: {key}")
    return blockers


def evaluate_report(report: dict[str, Any]) -> dict[str, Any]:
    reject_floats_recursive(report, "boundary_debt")
    if not isinstance(report, dict):
        raise BoundaryDebtError("boundary debt report must be an object")
    required = {
        "schema_id",
        "schema_version",
        "fixture",
        "claim_usable",
        "score_inflation_M",
        "manual_score_override",
        "reserved_perfect_AM_plus_used",
        "claim_boundary",
        "non_claims",
        "debts",
    }
    if set(report) != required:
        raise BoundaryDebtError("boundary debt report field set invalid")
    if report["schema_id"] != SCHEMA_ID or report["schema_version"] != SCHEMA_VERSION:
        raise BoundaryDebtError("unsupported boundary debt report schema")
    fixture = _require_bool(report["fixture"], "fixture")
    claim_usable = _require_bool(report["claim_usable"], "claim_usable")
    score_inflation = _require_int(report["score_inflation_M"], "score_inflation_M")
    manual_score_override = _require_bool(report["manual_score_override"], "manual_score_override")
    reserved_perfect = _require_bool(report["reserved_perfect_AM_plus_used"], "reserved_perfect_AM_plus_used")

    blockers = validate_claim_boundary(report["claim_boundary"])
    non_claims = report["non_claims"]
    if not isinstance(non_claims, list):
        raise BoundaryDebtError("non_claims must be a list")
    for item in non_claims:
        _require_str(item, "non_claims item")
    if not REQUIRED_NON_CLAIMS.issubset(set(non_claims)):
        blockers.append("required non-claims incomplete")

    debts = report["debts"]
    if not isinstance(debts, list):
        raise BoundaryDebtError("debts must be a list")
    critical_count = 0
    contradiction_count = 0
    debt_omega = Decimal("0")
    for index, debt in enumerate(debts):
        if not isinstance(debt, dict):
            raise BoundaryDebtError(f"debts[{index}] must be an object")
        required_debt = {"debt_id", "debt_class", "description", "evidence_digest_optional"}
        if set(debt) != required_debt:
            raise BoundaryDebtError(f"debts[{index}] field set invalid")
        _require_str(debt["debt_id"], f"debts[{index}].debt_id")
        debt_class = _require_str(debt["debt_class"], f"debts[{index}].debt_class")
        _require_str(debt["description"], f"debts[{index}].description")
        if debt["evidence_digest_optional"] is not None:
            _require_str(debt["evidence_digest_optional"], f"debts[{index}].evidence_digest_optional")
        if debt_class not in DEBT_CLASSES:
            raise BoundaryDebtError(f"unsupported debt_class: {debt_class}")
        debt_omega += DEBT_OMEGA[debt_class]
        if debt_class == "critical":
            critical_count += 1
            blockers.append("critical boundary debt present")
        if debt_class == "contradiction":
            contradiction_count += 1
            blockers.append("contradiction boundary debt present")

    if manual_score_override:
        blockers.append("manual score override rejected")
    if score_inflation != 0:
        blockers.append("score_inflation_M != 0")
    if reserved_perfect:
        blockers.append("reserved perfect AM+ value used")
    if fixture and claim_usable:
        blockers.append("fixture claim usable rejected")

    atoms = {
        "debt_register_explicit": isinstance(debts, list),
        "no_critical_debt": critical_count == 0,
        "no_contradiction_debt": contradiction_count == 0,
        "non_claims_complete": REQUIRED_NON_CLAIMS.issubset(set(non_claims)),
        "no_forbidden_claims": not validate_claim_boundary(report["claim_boundary"]),
        "no_manual_score_override": not manual_score_override,
        "score_inflation_zero": score_inflation == 0,
        "no_reserved_perfect_am_plus": not reserved_perfect,
        "fixture_not_claim_usable": not (fixture and claim_usable),
    }
    return {
        "schema_id": SCHEMA_ID,
        "passed": not blockers,
        "blockers": blockers,
        "fixture": fixture,
        "claim_usable": claim_usable,
        "score_inflation_M": score_inflation,
        "critical_debt": critical_count,
        "contradiction_debt": contradiction_count,
        "reserved_perfect_AM_plus_used": reserved_perfect,
        "debt_omega": _decimal_text(debt_omega),
        "non_claims": non_claims,
        "claim_boundary": report["claim_boundary"],
        "atoms": atoms,
    }


def default_claim_boundary() -> dict[str, Any]:
    return {
        "boundary_version": "daylight-v20-aperture-singularity-boundary-v1",
        "statement": "Daylight v20 binds public evidence intake to Singularity blockers; it grants no production, runtime, government, external certification, audit, or quantum-safety authority.",
        "production_cryptography": False,
        "runtime_containment": False,
        "host_cleanliness": False,
        "fips_validation": False,
        "government_validation": False,
        "external_certification": False,
        "whole_system_post_quantum_safety": False,
        "independent_audit_completed": False,
        "perfect_daylight_score_from_repo_evidence": False,
    }


def load_and_evaluate(path: Path | str) -> dict[str, Any]:
    return evaluate_report(load_json_no_floats(path))
