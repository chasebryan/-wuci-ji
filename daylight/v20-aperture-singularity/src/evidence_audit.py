"""Classify v20 Singularity blockers by required evidence owner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import singularity_gate
from .canonical import load_json_no_floats

SCHEMA_ID = "daylight-v20-evidence-audit-report"
SCHEMA_VERSION = "0.1.0"
SCORE_CEILING_SCHEMA_ID = "daylight-v20-score-ceiling-report"

REQUIREMENT_META: dict[str, dict[str, Any]] = {
    "reproducible_build.non_fixture_subject_bound_rebuilds": {
        "category": "independent_rebuild_evidence",
        "evidence_class": "independent_external_evidence_required",
        "repo_owned_code_gap": False,
        "external_evidence_required": True,
    },
    "aperture_firewall_boundary.external_profile_expansion": {
        "category": "public_firewall_boundary_review",
        "evidence_class": "external_review_evidence_required",
        "repo_owned_code_gap": False,
        "external_evidence_required": True,
    },
    "independent_verifier_quorum.claim_usable_3_of_3": {
        "category": "independent_verifier_quorum",
        "evidence_class": "independent_external_evidence_required",
        "repo_owned_code_gap": False,
        "external_evidence_required": True,
    },
    "external_attestation.pinned_cryptographic_verification": {
        "category": "external_attestation_verification",
        "evidence_class": "external_cryptographic_evidence_required",
        "repo_owned_code_gap": False,
        "external_evidence_required": True,
    },
    "claim_boundary.non_fixture_claim_usable_inputs": {
        "category": "claim_boundary",
        "evidence_class": "non_fixture_claim_usable_input_required",
        "repo_owned_code_gap": False,
        "external_evidence_required": False,
    },
    "omega_eff.threshold": {
        "category": "weakest_field_governor",
        "evidence_class": "derived_from_open_requirements",
        "repo_owned_code_gap": False,
        "external_evidence_required": False,
    },
}

REPO_OWNED_GAP_META = {
    "category": "repo_owned_evidence_gap",
    "evidence_class": "repo_owned_evidence_or_code_required",
    "repo_owned_code_gap": True,
    "external_evidence_required": False,
}


def _meta(requirement_id: str | None) -> dict[str, Any]:
    if requirement_id is None:
        return dict(REPO_OWNED_GAP_META)
    return dict(REQUIREMENT_META.get(requirement_id, REPO_OWNED_GAP_META))


def classify_blocker(blocker: str) -> dict[str, Any]:
    requirement_id: str | None
    if blocker in {
        "omega_eff below declaration threshold",
        "score_AM_plus below declaration target",
        "field threshold failure",
    }:
        requirement_id = "omega_eff.threshold"
    elif blocker == "field threshold failed: reproducible_build" or blocker.startswith("reproducible build "):
        requirement_id = "reproducible_build.non_fixture_subject_bound_rebuilds"
    elif blocker == "field threshold failed: aperture_firewall_boundary" or blocker.startswith("aperture firewall "):
        requirement_id = "aperture_firewall_boundary.external_profile_expansion"
    elif blocker == "field threshold failed: independent_verifier_quorum" or blocker.startswith("verifier "):
        requirement_id = "independent_verifier_quorum.claim_usable_3_of_3"
    elif blocker in {"cross_verifier_agreement_passed=false"}:
        requirement_id = "independent_verifier_quorum.claim_usable_3_of_3"
    elif blocker == "field threshold failed: external_attestation" or blocker.startswith("external attestation "):
        requirement_id = "external_attestation.pinned_cryptographic_verification"
    elif blocker in {"fixture=true", "claim_usable=false"}:
        requirement_id = "claim_boundary.non_fixture_claim_usable_inputs"
    elif blocker in {
        "score_inflation_M != 0",
        "critical_debt > 0",
        "contradiction_debt > 0",
        "reserved perfect AM+ value used",
    }:
        requirement_id = "claim_boundary.non_fixture_claim_usable_inputs"
    elif blocker == "fracture_suite_passed=false" or blocker.startswith("falsification case "):
        requirement_id = None
    elif blocker.startswith("firewall profile "):
        requirement_id = "aperture_firewall_boundary.external_profile_expansion"
    else:
        requirement_id = None

    meta = _meta(requirement_id)
    return {
        "blocker": blocker,
        "requirement_id": requirement_id,
        "category": meta["category"],
        "evidence_class": meta["evidence_class"],
        "external_evidence_required": meta["external_evidence_required"],
        "repo_owned_code_gap": meta["repo_owned_code_gap"],
    }


def classify_requirement(requirement: dict[str, Any]) -> dict[str, Any]:
    requirement_id = requirement.get("requirement_id")
    if not isinstance(requirement_id, str):
        requirement_id = None
    meta = _meta(requirement_id)
    return {
        "requirement_id": requirement_id,
        "proof_field": requirement.get("proof_field"),
        "category": meta["category"],
        "evidence_class": meta["evidence_class"],
        "external_evidence_required": meta["external_evidence_required"],
        "repo_owned_code_gap": meta["repo_owned_code_gap"],
        "open_atoms": requirement.get("current_open_atoms", []),
        "needed": requirement.get("needed"),
        "machine_check": requirement.get("machine_check"),
    }


def audit_capsule(capsule: dict[str, Any]) -> dict[str, Any]:
    singularity_gate.validate_capsule(capsule)
    declaration = singularity_gate.declaration_report(capsule)
    blocker_classes = [classify_blocker(item) for item in declaration["blockers"]]
    requirement_classes = [classify_requirement(item) for item in declaration["required_evidence"]]
    unclassified_blockers = [
        item["blocker"]
        for item in blocker_classes
        if item["requirement_id"] is None and item["repo_owned_code_gap"] is True
    ]
    repo_owned_gap_count = sum(1 for item in blocker_classes if item["repo_owned_code_gap"] is True)
    external_required_count = sum(1 for item in requirement_classes if item["external_evidence_required"] is True)
    fixture_boundary_active = capsule.get("fixture") is True or capsule.get("claim_usable") is not True
    only_external_evidence_blockers = (
        declaration["allowed"] is False
        and not fixture_boundary_active
        and not unclassified_blockers
        and repo_owned_gap_count == 0
        and all(
            item["external_evidence_required"] is True
            or item["evidence_class"] == "derived_from_open_requirements"
            for item in blocker_classes
        )
    )
    external_or_boundary_or_derived_blockers = all(
        item["external_evidence_required"] is True
        or item["evidence_class"] in {
            "derived_from_open_requirements",
            "non_fixture_claim_usable_input_required",
        }
        for item in blocker_classes
    )
    repo_owned_ceiling_reached = (
        declaration["allowed"] is False
        and repo_owned_gap_count == 0
        and not unclassified_blockers
        and external_required_count > 0
        and external_or_boundary_or_derived_blockers
    )
    if declaration["allowed"]:
        status = "declaration_allowed"
    elif fixture_boundary_active:
        status = "fixture_boundary_active"
    elif repo_owned_gap_count:
        status = "repo_owned_gap_open"
    elif only_external_evidence_blockers:
        status = "external_evidence_only"
    else:
        status = "classified_blocked"

    return {
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "capsule_digest": capsule["capsule_digest"],
        "declaration_allowed": declaration["allowed"],
        "status": status,
        "fixture_boundary_active": fixture_boundary_active,
        "only_external_evidence_blockers": only_external_evidence_blockers,
        "repo_owned_ceiling_reached": repo_owned_ceiling_reached,
        "singularity_possible_without_external_validation": bool(declaration["allowed"]),
        "repo_owned_code_gap_count": repo_owned_gap_count,
        "external_evidence_required_count": external_required_count,
        "unclassified_blockers": unclassified_blockers,
        "blocker_classes": blocker_classes,
        "requirement_classes": requirement_classes,
    }


def score_ceiling_report(capsule: dict[str, Any]) -> dict[str, Any]:
    audit = audit_capsule(capsule)
    external_requirements = [
        item
        for item in audit["requirement_classes"]
        if item["external_evidence_required"] is True
    ]
    highest_no_external_score = capsule["score_AM_plus"] if audit["repo_owned_ceiling_reached"] else None
    return {
        "schema_id": SCORE_CEILING_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "capsule_digest": capsule["capsule_digest"],
        "declaration_allowed": capsule["declaration_allowed"],
        "score_AM_plus": capsule["score_AM_plus"],
        "omega_eff": capsule["omega_eff"],
        "repo_owned_ceiling_reached": audit["repo_owned_ceiling_reached"],
        "singularity_possible_without_external_validation": audit["singularity_possible_without_external_validation"],
        "highest_truthful_no_external_score_AM_plus": highest_no_external_score,
        "repo_owned_code_gap_count": audit["repo_owned_code_gap_count"],
        "external_evidence_required_count": audit["external_evidence_required_count"],
        "fixture_boundary_active": audit["fixture_boundary_active"],
        "required_external_evidence": external_requirements,
        "blockers": [item["blocker"] for item in audit["blocker_classes"]],
        "non_claims": capsule["non_claims"],
    }


def load_and_audit(path: Path | str) -> dict[str, Any]:
    return audit_capsule(load_json_no_floats(path))


def load_and_score_ceiling(path: Path | str) -> dict[str, Any]:
    return score_ceiling_report(load_json_no_floats(path))
