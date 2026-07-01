"""Policy-aware Daylight v16 evidence verification."""

from __future__ import annotations

from typing import Any

from .canonical import require_keys
from .constants import D_EVIDENCE
from .errors import D16AWEError
from .hashing import domain_hash
from .policy import policy_satisfied, validate_policy

EVIDENCE_ARTIFACT_VERSION = "daylight-v16-evidence-artifact-v0.1"
EVIDENCE_CONTEXT_VERSION = "daylight-v16-evidence-context-v0.1"
PROOF_MASS_DOMAIN = "DAYLIGHT-v16-PROOF-MASS:"

CONTEXT_KEYS = {
    "version",
    "daylight_claim_score_M",
    "analemma_score_A",
    "proof_mass",
    "proof_mass_baseline",
    "proof_mass_digest",
    "solstice_scorecard_digest",
    "solstice_artifact_manifest_digest",
    "analemma_registry_digest",
    "zenith_report_digest",
    "claim_level",
    "production_allowed",
    "runtime_containment_claim",
    "whole_system_post_quantum_safety_claim",
    "external_certification_claim",
    "score_inflation_M",
}


def _require_int(value: Any, name: str, *, positive: bool = False) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise D16AWEError(f"{name} must be an integer")
    if positive and value <= 0:
        raise D16AWEError(f"{name} must be positive")
    if not positive and value < 0:
        raise D16AWEError(f"{name} must be nonnegative")


def _require_bool(value: Any, name: str) -> None:
    if not isinstance(value, bool):
        raise D16AWEError(f"{name} must be boolean")


def _compute_proof_mass(statement: dict[str, Any]) -> tuple[int, int, int]:
    units = statement.get("units")
    if not isinstance(units, list):
        raise D16AWEError("proof_mass_statement.units must be a list")
    closed_mass = 0
    for unit in units:
        if not isinstance(unit, dict):
            raise D16AWEError("proof mass unit must be an object")
        require_keys(unit, required={"id", "base_credit", "closed"})
        if not isinstance(unit["id"], str):
            raise D16AWEError("proof mass unit id must be a string")
        _require_int(unit["base_credit"], "proof mass unit base_credit")
        _require_bool(unit["closed"], "proof mass unit closed")
        if unit["closed"]:
            closed_mass += unit["base_credit"]
    regression = statement.get("regression_debt", 0)
    staleness = statement.get("staleness_debt", 0)
    baseline = statement.get("baseline")
    _require_int(regression, "regression_debt")
    _require_int(staleness, "staleness_debt")
    _require_int(baseline, "proof_mass_baseline", positive=True)
    proof_mass = closed_mass - regression - staleness
    if proof_mass < 0:
        raise D16AWEError("proof mass cannot be negative")
    analemma_score = (1_000_000 * proof_mass) // baseline
    return proof_mass, baseline, analemma_score


def _verify_context_shape(context: dict[str, Any]) -> None:
    require_keys(context, required=CONTEXT_KEYS)
    if context["version"] != EVIDENCE_CONTEXT_VERSION:
        raise D16AWEError("unsupported evidence context version")
    for key in (
        "daylight_claim_score_M",
        "analemma_score_A",
        "proof_mass",
        "score_inflation_M",
    ):
        _require_int(context[key], key)
    _require_int(context["proof_mass_baseline"], "proof_mass_baseline", positive=True)
    for key in (
        "production_allowed",
        "runtime_containment_claim",
        "whole_system_post_quantum_safety_claim",
        "external_certification_claim",
    ):
        _require_bool(context[key], key)
    if not isinstance(context["claim_level"], str):
        raise D16AWEError("claim_level must be a string")


def verify_daylight_v16_evidence(artifact: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Verify the local v16 evidence artifact and return canonical context."""
    policy = validate_policy(policy)
    require_keys(
        artifact,
        required={
            "version",
            "context",
            "proof_mass_statement",
            "closed_obligations",
            "closed_proof_units",
        },
    )
    if artifact["version"] != EVIDENCE_ARTIFACT_VERSION:
        raise D16AWEError("unsupported evidence artifact version")
    context = dict(artifact["context"])
    _verify_context_shape(context)
    proof_mass, baseline, analemma_score = _compute_proof_mass(artifact["proof_mass_statement"])
    proof_mass_digest = domain_hash(PROOF_MASS_DOMAIN, artifact["proof_mass_statement"])
    if context["proof_mass"] != proof_mass:
        raise D16AWEError("proof_mass does not match proof_mass_statement")
    if context["proof_mass_baseline"] != baseline:
        raise D16AWEError("proof_mass_baseline does not match proof_mass_statement")
    if context["analemma_score_A"] != analemma_score:
        raise D16AWEError("analemma_score_A does not match proof mass")
    if context["proof_mass_digest"] != proof_mass_digest:
        raise D16AWEError("proof_mass_digest does not match proof_mass_statement")
    if context["score_inflation_M"] != 0:
        raise D16AWEError("score_inflation_M must be zero")

    closed_obligations = artifact["closed_obligations"]
    closed_proof_units = artifact["closed_proof_units"]
    if not isinstance(closed_obligations, list) or any(not isinstance(item, str) for item in closed_obligations):
        raise D16AWEError("closed_obligations must be a list of strings")
    if not isinstance(closed_proof_units, list) or any(not isinstance(item, str) for item in closed_proof_units):
        raise D16AWEError("closed_proof_units must be a list of strings")
    missing_obligations = sorted(set(policy["required_closed_obligations"]) - set(closed_obligations))
    if missing_obligations:
        raise D16AWEError("required obligations not closed: " + ", ".join(missing_obligations))
    missing_units = sorted(set(policy["required_proof_units"]) - set(closed_proof_units))
    if missing_units:
        raise D16AWEError("required proof units not closed: " + ", ".join(missing_units))

    ok, reason = policy_satisfied(context, policy)
    if not ok:
        raise D16AWEError("policy not satisfied: " + reason)
    return context


def evidence_tag(context: dict[str, Any]) -> str:
    _verify_context_shape(context)
    return domain_hash(D_EVIDENCE, context)
