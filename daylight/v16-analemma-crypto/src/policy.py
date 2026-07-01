"""D16-AWE policy validation and satisfaction checks."""

from __future__ import annotations

from typing import Any

from .canonical import require_keys
from .errors import D16AWEError

POLICY_VERSION = "daylight-v16-awe-policy-v0.1"

CLAIM_LEVELS = {
    "research": 0,
    "operational": 1,
    "production-candidate": 2,
    "production": 3,
    "external-certified": 4,
}

REQUIRED_POLICY_KEYS = {
    "version",
    "min_daylight_claim_score_M",
    "min_analemma_score_A",
    "required_claim_level",
    "require_production_allowed",
    "require_runtime_containment",
    "require_whole_system_pq_safety",
    "require_external_certification",
    "required_closed_obligations",
    "required_proof_units",
    "require_sender_signature",
    "require_backup_signature",
    "critical",
}

OPTIONAL_POLICY_KEYS = {
    "required_solstice_scorecard_digest",
    "required_artifact_manifest_digest",
    "required_analemma_registry_digest",
}


def claim_rank(level: str) -> int:
    try:
        return CLAIM_LEVELS[level]
    except KeyError as exc:
        raise D16AWEError(f"unknown claim level: {level}") from exc


def _require_bool(value: Any, name: str) -> None:
    if not isinstance(value, bool):
        raise D16AWEError(f"{name} must be boolean")


def _require_nonnegative_int(value: Any, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise D16AWEError(f"{name} must be a nonnegative integer")


def _require_string_list(value: Any, name: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise D16AWEError(f"{name} must be a list of strings")


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    require_keys(policy, required=REQUIRED_POLICY_KEYS, optional=OPTIONAL_POLICY_KEYS)
    if policy["version"] != POLICY_VERSION:
        raise D16AWEError("unsupported policy version")
    _require_nonnegative_int(policy["min_daylight_claim_score_M"], "min_daylight_claim_score_M")
    _require_nonnegative_int(policy["min_analemma_score_A"], "min_analemma_score_A")
    claim_rank(policy["required_claim_level"])
    for key in (
        "require_production_allowed",
        "require_runtime_containment",
        "require_whole_system_pq_safety",
        "require_external_certification",
        "require_sender_signature",
        "require_backup_signature",
        "critical",
    ):
        _require_bool(policy[key], key)
    _require_string_list(policy["required_closed_obligations"], "required_closed_obligations")
    _require_string_list(policy["required_proof_units"], "required_proof_units")
    if policy["require_backup_signature"] and not policy["require_sender_signature"]:
        raise D16AWEError("backup signature cannot be required without sender signature")
    return {
        **policy,
        "required_closed_obligations": sorted(set(policy["required_closed_obligations"])),
        "required_proof_units": sorted(set(policy["required_proof_units"])),
    }


def policy_satisfied(context: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, str]:
    policy = validate_policy(policy)
    if context["daylight_claim_score_M"] < policy["min_daylight_claim_score_M"]:
        return False, "daylight claim score below policy floor"
    if context["analemma_score_A"] < policy["min_analemma_score_A"]:
        return False, "Analemma score below policy floor"
    if claim_rank(context["claim_level"]) < claim_rank(policy["required_claim_level"]):
        return False, "claim level below policy requirement"
    flag_map = (
        ("require_production_allowed", "production_allowed", "production not allowed"),
        ("require_runtime_containment", "runtime_containment_claim", "runtime containment not proved"),
        (
            "require_whole_system_pq_safety",
            "whole_system_post_quantum_safety_claim",
            "whole-system PQ safety not proved",
        ),
        ("require_external_certification", "external_certification_claim", "external certification not proved"),
    )
    for policy_key, context_key, reason in flag_map:
        if policy[policy_key] and context[context_key] is not True:
            return False, reason
    digest_map = (
        ("required_solstice_scorecard_digest", "solstice_scorecard_digest"),
        ("required_artifact_manifest_digest", "solstice_artifact_manifest_digest"),
        ("required_analemma_registry_digest", "analemma_registry_digest"),
    )
    for policy_key, context_key in digest_map:
        required = policy.get(policy_key)
        if required is not None and context[context_key] != required:
            return False, f"{context_key} does not match policy"
    return True, "ok"
