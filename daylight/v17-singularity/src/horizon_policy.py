"""Daylight Horizon Alpha policy checks.

Horizon policy is the product-facing layer over Event Horizon scorecards. It
does not raise scores and it does not create production authority; it decides
whether a vault or release operation may proceed under the regenerated proof
state.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .canonical_json import canonical_sha256, reject_floats_recursive
from .singularity_math import DECLARATION_TARGET_AM_PLUS, require_nonnegative_int


POLICY_VERSION = "daylight-horizon-policy-v0.1"
D_HORIZON_POLICY = "DAYLIGHT-HORIZON-POLICY:"
D_HORIZON_AUTH = "DAYLIGHT-HORIZON-AUTHORIZATION:"

DEFAULT_RESEARCH_POLICY = {
    "policy_version": POLICY_VERSION,
    "min_daylight_claim_score_M": 998900,
    "min_event_horizon_score_AM_plus": 999999000,
    "require_fracture_suite_passed": True,
    "require_cross_verifier_agreement": False,
    "allow_fixture": False,
    "production_allowed_required": False,
    "required_proof_atoms": [],
}

DECLARATION_POLICY = {
    **DEFAULT_RESEARCH_POLICY,
    "min_event_horizon_score_AM_plus": DECLARATION_TARGET_AM_PLUS,
    "require_cross_verifier_agreement": True,
}

PRODUCTION_POLICY = {
    **DECLARATION_POLICY,
    "production_allowed_required": True,
}


class HorizonPolicyError(ValueError):
    pass


class HorizonPolicyRefused(Exception):
    pass


def policy_for_mode(mode: str) -> dict[str, Any]:
    if mode == "research":
        return dict(DEFAULT_RESEARCH_POLICY)
    if mode == "declaration":
        return dict(DECLARATION_POLICY)
    if mode == "production":
        return dict(PRODUCTION_POLICY)
    raise HorizonPolicyError("unknown Horizon policy mode")


def validate_policy(policy: dict[str, Any]) -> None:
    reject_floats_recursive(policy, "horizon_policy")
    if not isinstance(policy, dict):
        raise HorizonPolicyError("policy must be an object")
    if policy.get("policy_version") != POLICY_VERSION:
        raise HorizonPolicyError("unsupported Horizon policy version")
    require_nonnegative_int(policy.get("min_daylight_claim_score_M"), "min_daylight_claim_score_M")
    require_nonnegative_int(policy.get("min_event_horizon_score_AM_plus"), "min_event_horizon_score_AM_plus")
    for key in (
        "require_fracture_suite_passed",
        "require_cross_verifier_agreement",
        "allow_fixture",
        "production_allowed_required",
    ):
        if not isinstance(policy.get(key), bool):
            raise HorizonPolicyError(f"{key} must be boolean")
    required = policy.get("required_proof_atoms")
    if not isinstance(required, list):
        raise HorizonPolicyError("required_proof_atoms must be a list")
    for atom_id in required:
        if not isinstance(atom_id, str) or not atom_id:
            raise HorizonPolicyError("required_proof_atoms entries must be non-empty strings")


def canonical_policy(policy: dict[str, Any]) -> dict[str, Any]:
    validate_policy(policy)
    return {
        "policy_version": policy["policy_version"],
        "min_daylight_claim_score_M": int(policy["min_daylight_claim_score_M"]),
        "min_event_horizon_score_AM_plus": int(policy["min_event_horizon_score_AM_plus"]),
        "require_fracture_suite_passed": bool(policy["require_fracture_suite_passed"]),
        "require_cross_verifier_agreement": bool(policy["require_cross_verifier_agreement"]),
        "allow_fixture": bool(policy["allow_fixture"]),
        "production_allowed_required": bool(policy["production_allowed_required"]),
        "required_proof_atoms": sorted(set(policy["required_proof_atoms"])),
    }


def policy_digest(policy: dict[str, Any]) -> str:
    return canonical_sha256(canonical_policy(policy), D_HORIZON_POLICY)


def daylight_claim_score_m(scorecard: dict[str, Any]) -> int:
    """Return the conservative claim-closure score implied by field F1.

    The Event Horizon card does not modify the v15 M score. For Horizon Alpha,
    F1 ClaimClosure is the policy bridge and is integer-credit based.
    """
    for field in scorecard.get("fields", []):
        if field.get("id") == "F1":
            possible = require_nonnegative_int(field.get("possible_credit"), "F1.possible_credit")
            verified = require_nonnegative_int(field.get("verified_credit"), "F1.verified_credit")
            if possible == 1_000_000:
                return verified
            rational = field.get("closure_rational")
            if not isinstance(rational, str) or "/" not in rational:
                raise HorizonPolicyError("F1 closure_rational missing")
            fraction = Fraction(rational)
            return int(fraction * 1_000_000)
    raise HorizonPolicyError("scorecard missing F1 ClaimClosure field")


def closed_proof_atoms(scorecard: dict[str, Any]) -> set[str]:
    return {
        atom["id"]
        for atom in scorecard.get("proof_atoms", [])
        if isinstance(atom, dict) and atom.get("closed") is True and isinstance(atom.get("id"), str)
    }


def policy_blockers(scorecard: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    validate_policy(policy)
    blockers: list[str] = []
    claim_score = daylight_claim_score_m(scorecard)
    if claim_score < int(policy["min_daylight_claim_score_M"]):
        blockers.append(
            f"daylight_claim_score_M {claim_score} < policy min_daylight_claim_score_M {policy['min_daylight_claim_score_M']}"
        )
    if int(scorecard.get("score_AM_plus", -1)) < int(policy["min_event_horizon_score_AM_plus"]):
        blockers.append(
            f"score_AM_plus {scorecard.get('score_AM_plus')} < policy min_event_horizon_score_AM_plus {policy['min_event_horizon_score_AM_plus']}"
        )
    if scorecard.get("collapse") is True:
        blockers.append("event_horizon collapse=true")
    if policy["require_fracture_suite_passed"] and scorecard.get("fracture_suite_passed") is not True:
        blockers.append("fracture_suite_passed=false")
    if policy["require_cross_verifier_agreement"] and scorecard.get("cross_verifier_agreement_passed") is not True:
        blockers.append("cross_verifier_agreement_passed=false")
    if not policy["allow_fixture"] and scorecard.get("fixture") is True:
        blockers.append("fixture evidence is not allowed")
    boundary = scorecard.get("boundary", {})
    if policy["production_allowed_required"] and boundary.get("production_allowed") is not True:
        blockers.append("production_allowed=false")
    closed = closed_proof_atoms(scorecard)
    missing = sorted(set(policy["required_proof_atoms"]) - closed)
    if missing:
        blockers.append("required proof atoms not closed: " + ", ".join(missing))
    return blockers


def policy_satisfied(scorecard: dict[str, Any], policy: dict[str, Any]) -> bool:
    return not policy_blockers(scorecard, policy)


def authorization_tag(
    *,
    scorecard: dict[str, Any],
    policy: dict[str, Any],
    object_type: str,
    artifact_digest: str | None = None,
) -> str:
    binding = {
        "object_type": object_type,
        "artifact_digest": artifact_digest,
        "policy_digest": policy_digest(policy),
        "policy": canonical_policy(policy),
        "scorecard_digest": scorecard["scorecard_digest"],
        "fields_digest": scorecard["fields_digest"],
        "proof_atoms_digest": scorecard["proof_atoms_digest"],
        "state_digest": scorecard["state_digest"],
        "fracture_digest": scorecard["fracture_digest"],
        "score_AM_plus": int(scorecard["score_AM_plus"]),
        "daylight_claim_score_M": daylight_claim_score_m(scorecard),
        "declared": bool(scorecard["declared"]),
        "status": scorecard["status"],
        "collapse": bool(scorecard["collapse"]),
        "cross_verifier_agreement_passed": bool(scorecard["cross_verifier_agreement_passed"]),
        "fracture_suite_passed": bool(scorecard["fracture_suite_passed"]),
        "fixture": bool(scorecard["fixture"]),
    }
    return canonical_sha256(binding, D_HORIZON_AUTH)
