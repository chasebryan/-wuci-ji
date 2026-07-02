"""Firewall profile expansion evidence for v20 public artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .boundary_debt import REQUIRED_NON_CLAIMS
from .canonical import canonical_sha256, load_json_no_floats, reject_floats_recursive

SCHEMA_ID = "daylight-v20-firewall-profile-expansion"
SCHEMA_VERSION = "0.1.0"
D_PROFILE = "DAYLIGHT-v20-FIREWALL-PROFILE-EXPANSION:"
D_BUNDLE = "DAYLIGHT-v20-FIREWALL-PROFILE-EXPANSION-BUNDLE:"
D_CASE = "DAYLIGHT-v20-FIREWALL-PROFILE-CASE:"
PROFILE_ID = "daylight-v20-aperture-singularity-public-review-v1"

REQUIRED_CASES: dict[str, str] = {
    "unexpected_file": "unexpected_public_artifact_file",
    "missing_expected_file": "missing_public_artifact_file",
    "hidden_file": "hidden_component_in_public_artifact",
    "symlink": "symlink_in_public_artifact",
    "hardlink": "hardlink_in_public_artifact",
    "nested_path": "nested_public_artifact_path_unexpected",
    "private_filename": "forbidden_secret_path",
    "private_directory": "public_artifact_contains_private_directory",
    "private_suffix": "forbidden_private_material_suffix",
    "private_content_marker": "known_secret_marker",
    "sha256_drift": "sha256sum_mismatch",
    "sha3_512_drift": "sha3_512sum_mismatch",
    "invalid_sha256sums": "sha256sums_invalid",
    "invalid_sha3_512sums": "sha3_512sums_invalid",
}


class FirewallProfileError(ValueError):
    pass


def profile_digest() -> str:
    return canonical_sha256(
        {
            "profile_id": PROFILE_ID,
            "required_cases": REQUIRED_CASES,
        },
        D_PROFILE,
    )


def bundle_digest(bundle: dict[str, Any]) -> str:
    return canonical_sha256(bundle, D_BUNDLE)


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise FirewallProfileError(f"{name} must be a non-empty string")
    return value


def _require_hex64(value: Any, name: str) -> str:
    text = _require_str(value, name)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise FirewallProfileError(f"{name} must be a lowercase SHA-256 hex digest")
    return text


def case_digest(case: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "case_id": case["case_id"],
            "expected_reason": case["expected_reason"],
            "observed_reasons": case["observed_reasons"],
            "outcome": case["outcome"],
        },
        D_CASE,
    )


def evaluate_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    reject_floats_recursive(bundle, "firewall_profile")
    if not isinstance(bundle, dict):
        raise FirewallProfileError("firewall profile expansion bundle must be an object")
    required = {
        "schema_id",
        "schema_version",
        "profile_id",
        "profile_digest",
        "fixture",
        "claim_usable",
        "authority_scope",
        "non_claims_acknowledged",
        "cases",
    }
    if set(bundle) != required:
        raise FirewallProfileError("firewall profile expansion field set invalid")
    if bundle["schema_id"] != SCHEMA_ID or bundle["schema_version"] != SCHEMA_VERSION:
        raise FirewallProfileError("unsupported firewall profile expansion schema")
    if bundle["profile_id"] != PROFILE_ID:
        raise FirewallProfileError("unsupported firewall profile id")
    expected_profile_digest = profile_digest()
    if bundle["profile_digest"] != expected_profile_digest:
        raise FirewallProfileError("firewall profile digest mismatch")
    if not isinstance(bundle["fixture"], bool):
        raise FirewallProfileError("fixture must be boolean")
    if not isinstance(bundle["claim_usable"], bool):
        raise FirewallProfileError("claim_usable must be boolean")
    if bundle["authority_scope"] != "repo-owned-firewall-negative-matrix-only":
        raise FirewallProfileError("authority_scope must remain repo-owned-firewall-negative-matrix-only")
    acknowledged = bundle["non_claims_acknowledged"]
    if not isinstance(acknowledged, list):
        raise FirewallProfileError("non_claims_acknowledged must be a list")
    for item in acknowledged:
        _require_str(item, "non_claims_acknowledged item")

    cases = bundle["cases"]
    if not isinstance(cases, list):
        raise FirewallProfileError("cases must be a list")
    blockers: list[str] = []
    by_case: dict[str, dict[str, Any]] = {}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise FirewallProfileError(f"cases[{index}] must be an object")
        case_required = {"case_id", "expected_reason", "observed_reasons", "outcome", "evidence_digest"}
        if set(case) != case_required:
            raise FirewallProfileError(f"cases[{index}] field set invalid")
        case_id = _require_str(case["case_id"], f"cases[{index}].case_id")
        expected_reason = _require_str(case["expected_reason"], f"cases[{index}].expected_reason")
        outcome = _require_str(case["outcome"], f"cases[{index}].outcome")
        _require_hex64(case["evidence_digest"], f"cases[{index}].evidence_digest")
        observed = case["observed_reasons"]
        if not isinstance(observed, list):
            raise FirewallProfileError(f"cases[{index}].observed_reasons must be a list")
        for reason in observed:
            _require_str(reason, f"cases[{index}].observed_reasons item")
        if case_id in by_case:
            raise FirewallProfileError(f"duplicate firewall profile case: {case_id}")
        if case["evidence_digest"] != case_digest(case):
            blockers.append(f"firewall case evidence digest mismatch: {case_id}")
        if REQUIRED_CASES.get(case_id) != expected_reason:
            blockers.append(f"firewall case expected reason mismatch: {case_id}")
        if outcome != "rejected":
            blockers.append(f"firewall case did not reject: {case_id}")
        if expected_reason not in observed:
            blockers.append(f"firewall case missing observed reason: {case_id}")
        by_case[case_id] = case

    for case_id in REQUIRED_CASES:
        if case_id not in by_case:
            blockers.append(f"missing firewall profile case: {case_id}")
    if bundle["fixture"] is True:
        blockers.append("firewall profile expansion is fixture evidence")
    if bundle["claim_usable"] is not True:
        blockers.append("firewall profile expansion is not claim-usable")
    if not REQUIRED_NON_CLAIMS.issubset(set(acknowledged)):
        blockers.append("firewall profile expansion non-claims incomplete")

    atoms = {
        "public_artifact_firewall_negative_matrix_verified": not blockers,
        "firewall_profile_externally_expanded": False,
    }
    return {
        "schema_id": SCHEMA_ID,
        "passed": not blockers,
        "blockers": blockers,
        "profile_id": bundle["profile_id"],
        "profile_digest": expected_profile_digest,
        "fixture": bundle["fixture"],
        "claim_usable": bundle["claim_usable"],
        "case_count": len(cases),
        "required_case_count": len(REQUIRED_CASES),
        "atoms": atoms,
    }


def load_and_evaluate(path: Path | str) -> dict[str, Any]:
    return evaluate_bundle(load_json_no_floats(path))
