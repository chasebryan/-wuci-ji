"""Aperture Singularity capsule builder and declaration gate."""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from pathlib import Path
from typing import Any

from . import __version__
from . import boundary_debt
from . import external_attestation
from . import firewall_profile
from . import falsification
from . import proof_fields
from . import reproducible_builds
from . import verifier_agreement
from .canonical import canonical_sha256, load_json_no_floats, reject_floats_recursive
from .pathsafe import sha256_file

SCHEMA_ID = "daylight-v20-aperture-singularity-capsule"
SCHEMA_VERSION = "0.1.0"
PROJECT = "wuci-ji"
LAYER_NAME = "Daylight v20 - Aperture Singularity Gate"
D_CAPSULE = "DAYLIGHT-v20-APERTURE-SINGULARITY-CAPSULE:"
D_APERTURE_FIREWALL = "DAYLIGHT-v20-APERTURE-FIREWALL-REPORT:"
D_POLICY = "DAYLIGHT-v20-POLICY:"
D_VERIFIER_AGREEMENT = "DAYLIGHT-v20-VERIFIER-AGREEMENT-BUNDLE:"
D_EXTERNAL_ATTESTATION = "DAYLIGHT-v20-EXTERNAL-ATTESTATION-BUNDLE:"
D_REPRODUCIBLE_BUILD = "DAYLIGHT-v20-REPRODUCIBLE-BUILD-BUNDLE:"
D_FALSIFICATION = "DAYLIGHT-v20-FALSIFICATION-SURVIVAL-BUNDLE:"
D_BOUNDARY_DEBT = "DAYLIGHT-v20-BOUNDARY-DEBT-REPORT:"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
EXAMPLES_ROOT = PACKAGE_ROOT / "examples"

DEFAULT_VERIFIER_BUNDLE = EXAMPLES_ROOT / "verifier-agreement.full-3-of-3.v20.json"
DEFAULT_EXTERNAL_ATTESTATION = EXAMPLES_ROOT / "external-attestation.verified.fixture-blocked.v20.json"
DEFAULT_REPRODUCIBLE_BUILDS = EXAMPLES_ROOT / "reproducible-build.receipts.v20.json"
DEFAULT_FALSIFICATION = EXAMPLES_ROOT / "falsification-survival.v20.json"
DEFAULT_BOUNDARY_DEBT = EXAMPLES_ROOT / "boundary-debt.zero.v20.json"
DEFAULT_FIREWALL_PROFILE_EXPANSION = EXAMPLES_ROOT / "firewall-profile-expansion.v20.json"

REQUIRED_CAPSULE_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "project",
        "layer_name",
        "generated_by",
        "source_commit",
        "release_tag",
        "fixture",
        "claim_usable",
        "input_aperture_capsule_digest",
        "input_aperture_firewall_report_digest",
        "input_firewall_profile_expansion_digest",
        "input_verifier_agreement_bundle_digest",
        "input_external_attestation_bundle_digest",
        "input_reproducible_build_bundle_digest",
        "input_falsification_bundle_digest",
        "input_boundary_debt_report_digest",
        "input_meridian_scorecard_digest",
        "input_event_horizon_scorecard_digest",
        "input_binaric_vector_chain_digest",
        "input_transition_ledger_head",
        "policy_digest",
        "proof_fields",
        "omega_sum",
        "omega_weak",
        "omega_eff",
        "score_AM_plus",
        "score_inflation_M",
        "critical_debt",
        "contradiction_debt",
        "field_thresholds_passed",
        "fracture_suite_passed",
        "cross_verifier_agreement_passed",
        "verifier_quorum",
        "external_attestation_verified",
        "reserved_perfect_value_used",
        "verifier_agreement",
        "external_attestation_summary",
        "reproducible_build_summary",
        "falsification_summary",
        "boundary_debt_summary",
        "firewall_profile_summary",
        "claim_boundary",
        "non_claims",
        "blockers",
        "declaration_allowed",
        "capsule_digest",
    }
)


class SingularityGateError(ValueError):
    pass


def _require_hex(value: Any, name: str, regex: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not regex.fullmatch(value):
        raise SingularityGateError(f"{name} must be a lowercase hex digest of expected length")
    return value


def _require_optional_hex(value: Any, name: str, regex: re.Pattern[str]) -> str | None:
    if value is None:
        return None
    return _require_hex(value, name, regex)


def _v19_capsule_digest(capsule: dict[str, Any]) -> str:
    reject_floats_recursive(capsule, "aperture_capsule")
    body = {key: value for key, value in capsule.items() if key != "capsule_digest"}
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(b"DAYLIGHT-v19-APERTURE-REVIEW-CAPSULE:")
    digest.update(canonical)
    return digest.hexdigest()


def capsule_digest(capsule: dict[str, Any]) -> str:
    reject_floats_recursive(capsule, "capsule")
    body = {key: value for key, value in capsule.items() if key != "capsule_digest"}
    return canonical_sha256(body, D_CAPSULE)


def _sums_text_for_manifest(entries: list[dict[str, Any]]) -> str:
    return "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)


def evaluate_aperture_capsule(
    capsule: dict[str, Any],
    *,
    firewall_profile_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reject_floats_recursive(capsule, "aperture_capsule")
    blockers: list[str] = []
    atoms: dict[str, bool] = {
        "aperture_capsule_bound": isinstance(capsule, dict),
        "aperture_capsule_digest_verified": False,
        "subject_sha256_bound": False,
        "subject_sha3_512_bound": False,
        "subject_size_bound": False,
        "public_manifest_declared": False,
        "sha256sums_consistent": False,
        "firewall_report_bound": False,
        "firewall_passed": False,
        "firewall_profile_pinned": False,
        "claim_boundary_present": False,
        "non_claims_present": False,
        "public_artifact_firewall_negative_matrix_verified": False,
        "firewall_profile_externally_expanded": False,
    }
    if not isinstance(capsule, dict):
        blockers.append("aperture capsule is not an object")
        return {"passed": False, "blockers": blockers, "atoms": atoms}
    if capsule.get("schema_id") != "daylight-v19-aperture-review-capsule":
        blockers.append("input aperture capsule schema is not v19")
    recorded_digest = capsule.get("capsule_digest")
    if isinstance(recorded_digest, str) and HEX64_RE.fullmatch(recorded_digest):
        atoms["aperture_capsule_digest_verified"] = _v19_capsule_digest(capsule) == recorded_digest
    if not atoms["aperture_capsule_digest_verified"]:
        blockers.append("input aperture capsule digest mismatch")
    atoms["subject_sha256_bound"] = isinstance(capsule.get("subject_sha256"), str) and HEX64_RE.fullmatch(capsule["subject_sha256"]) is not None
    atoms["subject_sha3_512_bound"] = isinstance(capsule.get("subject_sha3_512"), str) and HEX128_RE.fullmatch(capsule["subject_sha3_512"]) is not None
    atoms["subject_size_bound"] = isinstance(capsule.get("subject_size"), int) and not isinstance(capsule.get("subject_size"), bool) and capsule["subject_size"] >= 0
    manifest = capsule.get("public_manifest")
    atoms["public_manifest_declared"] = isinstance(manifest, list)
    if isinstance(manifest, list):
        try:
            expected_sums = hashlib.sha256(_sums_text_for_manifest(manifest).encode("utf-8")).hexdigest()
            atoms["sha256sums_consistent"] = capsule.get("public_sha256sums") == expected_sums
        except (KeyError, TypeError):
            atoms["sha256sums_consistent"] = False
    firewall_result = capsule.get("firewall_result")
    atoms["firewall_report_bound"] = isinstance(firewall_result, dict)
    atoms["firewall_passed"] = isinstance(firewall_result, dict) and firewall_result.get("passed") is True
    profile = capsule.get("forbidden_private_material_profile")
    atoms["firewall_profile_pinned"] = (
        isinstance(profile, dict)
        and profile.get("profile_id") == "aperture-bastion-public-v1"
        and isinstance(profile.get("profile_digest"), str)
        and HEX64_RE.fullmatch(profile["profile_digest"]) is not None
    )
    atoms["claim_boundary_present"] = isinstance(capsule.get("claim_boundary"), dict)
    non_claims = capsule.get("non_claims")
    atoms["non_claims_present"] = isinstance(non_claims, list) and bool(non_claims)
    if firewall_profile_summary is not None:
        atoms["public_artifact_firewall_negative_matrix_verified"] = bool(
            firewall_profile_summary["atoms"]["public_artifact_firewall_negative_matrix_verified"]
        )
        atoms["firewall_profile_externally_expanded"] = bool(
            firewall_profile_summary["atoms"]["firewall_profile_externally_expanded"]
        )
    if not atoms["public_artifact_firewall_negative_matrix_verified"]:
        blockers.append("aperture firewall negative-case expansion evidence missing")
    blockers.append("aperture firewall profile external review evidence missing")
    for atom, passed in atoms.items():
        if atom != "firewall_profile_externally_expanded" and not passed:
            blockers.append(f"aperture boundary atom failed: {atom}")
    return {
        "passed": all(atoms.values()),
        "blockers": blockers,
        "atoms": atoms,
        "firewall_profile_id": profile.get("profile_id") if isinstance(profile, dict) else None,
        "public_manifest_count": len(manifest) if isinstance(manifest, list) else 0,
    }


def _load_or_default(path: Path | str | None, default_path: Path) -> dict[str, Any]:
    return load_json_no_floats(Path(path) if path is not None else default_path)


def build_capsule(
    *,
    aperture_capsule_path: Path | str,
    verifier_bundle_path: Path | str | None = None,
    external_attestation_path: Path | str | None = None,
    reproducible_build_path: Path | str | None = None,
    falsification_path: Path | str | None = None,
    boundary_debt_path: Path | str | None = None,
    firewall_profile_path: Path | str | None = None,
    release_tag: str = "v20-aperture-singularity-fixture",
) -> dict[str, Any]:
    aperture_path = Path(aperture_capsule_path)
    aperture = load_json_no_floats(aperture_path)
    source_commit = aperture.get("repo_commit")
    if source_commit != "fixture" and not (isinstance(source_commit, str) and HEX40_RE.fullmatch(source_commit)):
        source_commit = "unknown"
    firewall_profile_bundle = _load_or_default(firewall_profile_path, DEFAULT_FIREWALL_PROFILE_EXPANSION)
    verifier_bundle = _load_or_default(verifier_bundle_path, DEFAULT_VERIFIER_BUNDLE)
    external_bundle = _load_or_default(external_attestation_path, DEFAULT_EXTERNAL_ATTESTATION)
    reproducible_bundle = _load_or_default(reproducible_build_path, DEFAULT_REPRODUCIBLE_BUILDS)
    falsification_bundle = _load_or_default(falsification_path, DEFAULT_FALSIFICATION)
    boundary_bundle = _load_or_default(boundary_debt_path, DEFAULT_BOUNDARY_DEBT)
    firewall_profile_summary = firewall_profile.evaluate_bundle(firewall_profile_bundle)
    aperture_summary = evaluate_aperture_capsule(
        aperture,
        firewall_profile_summary=firewall_profile_summary,
    )
    verifier_summary = verifier_agreement.evaluate_bundle(verifier_bundle, expected_subject=release_tag)
    external_summary = external_attestation.evaluate_bundle(external_bundle)
    reproducible_summary = reproducible_builds.evaluate_bundle(
        reproducible_bundle,
        expected_source_commit=aperture.get("repo_commit")
        if isinstance(aperture.get("repo_commit"), str) and HEX40_RE.fullmatch(aperture["repo_commit"])
        else None,
        expected_artifact_sha256=aperture.get("subject_sha256"),
        expected_artifact_sha3_512=aperture.get("subject_sha3_512"),
        expected_artifact_size=aperture.get("subject_size"),
    )
    falsification_summary = falsification.evaluate_bundle(falsification_bundle)
    boundary_summary = boundary_debt.evaluate_report(boundary_bundle)

    atom_maps = proof_fields.proof_field_atom_map(
        reproducible_build=reproducible_summary,
        aperture_firewall_boundary=aperture_summary,
        independent_verifier_quorum=verifier_summary,
        external_attestation=external_summary,
        falsification_survival=falsification_summary,
    )
    fields = proof_fields.build_proof_fields(atom_maps)
    omega_summary = proof_fields.summarize_omega(fields, Decimal(boundary_summary["debt_omega"]))
    capsule_fixture = (
        bool(boundary_summary["fixture"])
        or verifier_summary["atoms"]["vectors_non_fixture"] is not True
        or reproducible_summary["atoms"]["receipts_non_fixture"] is not True
        or bool(firewall_profile_summary["fixture"])
        or bool(falsification_summary["fixture"])
    )
    capsule_claim_usable = (
        bool(boundary_summary["claim_usable"])
        and verifier_summary["atoms"]["vectors_claim_usable"] is True
        and reproducible_summary["atoms"]["receipts_claim_usable"] is True
        and bool(firewall_profile_summary["claim_usable"])
        and bool(falsification_summary["claim_usable"])
    )

    policy_digest = canonical_sha256(
        {
            "non_claims": boundary_debt.NON_CLAIMS,
            "rules": [
                "NoProof->NoClaim->NoRelease",
                "NoEvidence->NoScore->NoRelease",
                "NoTrace->NoTrust",
                "ManualScore->Reject",
                "FixtureClaimUsable->Reject",
                "SelfSignedExternalClosure->Reject",
                "ReservedPerfectAMPlus->Reject",
                "BoundaryDebtCritical->Reject",
                "VerifierQuorumIncomplete->Reject",
                "ExternalAttestationUnverified->BlockDeclaration",
            ],
        },
        D_POLICY,
    )
    verifier_quorum = "3_of_3" if verifier_summary["quorum"] == "3/3" else verifier_summary["quorum"]
    capsule: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "project": PROJECT,
        "layer_name": LAYER_NAME,
        "generated_by": f"daylight-v20-aperture-singularity/{__version__}",
        "source_commit": source_commit,
        "release_tag": release_tag,
        "fixture": capsule_fixture,
        "claim_usable": capsule_claim_usable,
        "input_aperture_capsule_digest": aperture.get("capsule_digest") if isinstance(aperture.get("capsule_digest"), str) else sha256_file(aperture_path),
        "input_aperture_firewall_report_digest": canonical_sha256(aperture.get("firewall_result", {}), D_APERTURE_FIREWALL),
        "input_firewall_profile_expansion_digest": firewall_profile.bundle_digest(firewall_profile_bundle),
        "input_verifier_agreement_bundle_digest": canonical_sha256(verifier_bundle, D_VERIFIER_AGREEMENT),
        "input_external_attestation_bundle_digest": canonical_sha256(external_bundle, D_EXTERNAL_ATTESTATION),
        "input_reproducible_build_bundle_digest": canonical_sha256(reproducible_bundle, D_REPRODUCIBLE_BUILD),
        "input_falsification_bundle_digest": canonical_sha256(falsification_bundle, D_FALSIFICATION),
        "input_boundary_debt_report_digest": canonical_sha256(boundary_bundle, D_BOUNDARY_DEBT),
        "input_meridian_scorecard_digest": aperture.get("optional_meridian_scorecard_digest"),
        "input_event_horizon_scorecard_digest": aperture.get("optional_event_horizon_scorecard_digest"),
        "input_binaric_vector_chain_digest": aperture.get("optional_binaric_vector_digest"),
        "input_transition_ledger_head": aperture.get("optional_transition_ledger_head"),
        "policy_digest": policy_digest,
        "proof_fields": fields,
        "omega_sum": omega_summary["omega_sum"],
        "omega_weak": omega_summary["omega_weak"],
        "omega_eff": omega_summary["omega_eff"],
        "score_AM_plus": omega_summary["score_AM_plus"],
        "score_inflation_M": boundary_summary["score_inflation_M"],
        "critical_debt": boundary_summary["critical_debt"],
        "contradiction_debt": boundary_summary["contradiction_debt"],
        "field_thresholds_passed": omega_summary["field_thresholds_passed"],
        "fracture_suite_passed": bool(falsification_summary["passed"]),
        "cross_verifier_agreement_passed": bool(verifier_summary["passed"]),
        "verifier_quorum": verifier_quorum,
        "external_attestation_verified": bool(external_summary["verified"]),
        "reserved_perfect_value_used": bool(boundary_summary["reserved_perfect_AM_plus_used"]),
        "verifier_agreement": {
            "passed": verifier_summary["passed"],
            "blockers": verifier_summary["blockers"],
            "quorum": verifier_summary["quorum"],
            "subject": verifier_summary["subject"],
            "expected_subject": verifier_summary["expected_subject"],
            "verifier_families": verifier_summary["verifier_families"],
            "vectors_non_fixture": verifier_summary["atoms"]["vectors_non_fixture"],
            "vectors_claim_usable": verifier_summary["atoms"]["vectors_claim_usable"],
            "subject_matches_expected": verifier_summary["atoms"]["subject_matches_expected"],
            "vector_statement_digests_verified": verifier_summary["atoms"]["vector_statement_digests_verified"],
            "output_schema_matches_v20": verifier_summary["atoms"]["output_schema_matches_v20"],
        },
        "external_attestation_summary": {
            "verified": external_summary["verified"],
            "blockers": external_summary["blockers"],
            "attestation_count": external_summary["attestation_count"],
        },
        "reproducible_build_summary": {
            "passed": reproducible_summary["passed"],
            "blockers": reproducible_summary["blockers"],
            "receipt_count": reproducible_summary["receipt_count"],
            "fixture": reproducible_summary["fixture"],
            "claim_usable": reproducible_summary["claim_usable"],
            "independent_builder_count": reproducible_summary["independent_builder_count"],
            "distinct_environment_count": reproducible_summary["distinct_environment_count"],
        },
        "falsification_summary": {
            "passed": falsification_summary["passed"],
            "blockers": falsification_summary["blockers"],
            "fixture": falsification_summary["fixture"],
            "claim_usable": falsification_summary["claim_usable"],
            "required_case_count": falsification_summary["required_case_count"],
            "survived_case_count": falsification_summary["survived_case_count"],
        },
        "boundary_debt_summary": {
            "passed": boundary_summary["passed"],
            "blockers": boundary_summary["blockers"],
            "critical_debt": boundary_summary["critical_debt"],
            "contradiction_debt": boundary_summary["contradiction_debt"],
            "debt_omega": boundary_summary["debt_omega"],
        },
        "firewall_profile_summary": {
            "passed": firewall_profile_summary["passed"],
            "blockers": firewall_profile_summary["blockers"],
            "profile_id": firewall_profile_summary["profile_id"],
            "profile_digest": firewall_profile_summary["profile_digest"],
            "fixture": firewall_profile_summary["fixture"],
            "claim_usable": firewall_profile_summary["claim_usable"],
            "case_count": firewall_profile_summary["case_count"],
            "required_case_count": firewall_profile_summary["required_case_count"],
        },
        "claim_boundary": boundary_summary["claim_boundary"],
        "non_claims": boundary_debt.NON_CLAIMS,
    }
    capsule["blockers"] = declaration_blockers(capsule)
    capsule["declaration_allowed"] = not capsule["blockers"]
    capsule["capsule_digest"] = capsule_digest(capsule)
    validate_capsule(capsule)
    return capsule


def declaration_blockers(capsule: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    omega_eff = Decimal(str(capsule.get("omega_eff", "0")))
    if omega_eff < proof_fields.OMEGA_THRESHOLD:
        blockers.append("omega_eff below declaration threshold")
    score = capsule.get("score_AM_plus")
    if score == proof_fields.PERFECT_RESERVED_AM_PLUS:
        blockers.append("reserved perfect AM+ value used")
    if score != proof_fields.DECLARATION_TARGET_AM_PLUS:
        blockers.append("score_AM_plus below declaration target")
    if capsule.get("score_inflation_M") != 0:
        blockers.append("score_inflation_M != 0")
    if capsule.get("critical_debt") != 0:
        blockers.append("critical_debt > 0")
    if capsule.get("contradiction_debt") != 0:
        blockers.append("contradiction_debt > 0")
    if capsule.get("field_thresholds_passed") is not True:
        blockers.append("field threshold failure")
        for field in capsule.get("proof_fields", []):
            if isinstance(field, dict) and field.get("threshold_passed") is not True:
                blockers.append(f"field threshold failed: {field.get('field_id')}")
    if capsule.get("fracture_suite_passed") is not True:
        blockers.append("fracture_suite_passed=false")
    if capsule.get("cross_verifier_agreement_passed") is not True:
        blockers.append("cross_verifier_agreement_passed=false")
        for item in capsule.get("verifier_agreement", {}).get("blockers", []):
            if item not in blockers:
                blockers.append(item)
    if capsule.get("verifier_quorum") != "3_of_3":
        quorum = capsule.get("verifier_agreement", {}).get("quorum", capsule.get("verifier_quorum"))
        text = f"verifier quorum incomplete: {quorum}"
        if text not in blockers:
            blockers.append(text)
    if capsule.get("fixture") is True:
        blockers.append("fixture=true")
    if capsule.get("claim_usable") is not True:
        blockers.append("claim_usable=false")
    if capsule.get("external_attestation_verified") is not True:
        blockers.append("external attestation not cryptographically verified")
    if capsule.get("reserved_perfect_value_used") is True:
        blockers.append("reserved perfect AM+ value used")
    for summary_key in (
        "external_attestation_summary",
        "reproducible_build_summary",
        "falsification_summary",
        "boundary_debt_summary",
        "firewall_profile_summary",
    ):
        summary = capsule.get(summary_key)
        if isinstance(summary, dict):
            for item in summary.get("blockers", []):
                if item not in blockers:
                    blockers.append(item)
    return blockers


def validate_capsule(capsule: dict[str, Any]) -> None:
    reject_floats_recursive(capsule, "capsule")
    if not isinstance(capsule, dict):
        raise SingularityGateError("capsule must be an object")
    if set(capsule) != REQUIRED_CAPSULE_KEYS:
        unknown = sorted(set(capsule) - REQUIRED_CAPSULE_KEYS)
        missing = sorted(REQUIRED_CAPSULE_KEYS - set(capsule))
        raise SingularityGateError(f"capsule field set invalid (unknown={unknown}, missing={missing})")
    if capsule["schema_id"] != SCHEMA_ID or capsule["schema_version"] != SCHEMA_VERSION:
        raise SingularityGateError("unsupported v20 capsule schema")
    if capsule["project"] != PROJECT or capsule["layer_name"] != LAYER_NAME:
        raise SingularityGateError("unsupported v20 capsule project or layer")
    if not isinstance(capsule["fixture"], bool) or not isinstance(capsule["claim_usable"], bool):
        raise SingularityGateError("fixture and claim_usable must be boolean")
    if capsule["source_commit"] not in ("fixture", "unknown"):
        _require_hex(capsule["source_commit"], "source_commit", HEX40_RE)
    for key in (
        "input_aperture_capsule_digest",
        "input_aperture_firewall_report_digest",
        "input_firewall_profile_expansion_digest",
        "input_verifier_agreement_bundle_digest",
        "input_external_attestation_bundle_digest",
        "input_reproducible_build_bundle_digest",
        "input_falsification_bundle_digest",
        "input_boundary_debt_report_digest",
        "policy_digest",
    ):
        _require_hex(capsule[key], key, HEX64_RE)
    for key in (
        "input_meridian_scorecard_digest",
        "input_event_horizon_scorecard_digest",
        "input_binaric_vector_chain_digest",
        "input_transition_ledger_head",
    ):
        _require_optional_hex(capsule[key], key, HEX64_RE)
    if not isinstance(capsule["proof_fields"], list) or len(capsule["proof_fields"]) != len(proof_fields.FIELD_ATOMS):
        raise SingularityGateError("proof_fields must contain each v20 proof field")
    field_ids = [field.get("field_id") for field in capsule["proof_fields"] if isinstance(field, dict)]
    if field_ids != list(proof_fields.FIELD_ATOMS):
        raise SingularityGateError("proof_fields must be in canonical field order")
    for key in ("omega_sum", "omega_weak", "omega_eff"):
        Decimal(capsule[key])
    for key in ("score_AM_plus", "score_inflation_M", "critical_debt", "contradiction_debt"):
        if isinstance(capsule[key], bool) or not isinstance(capsule[key], int):
            raise SingularityGateError(f"{key} must be an integer")
    if capsule["score_AM_plus"] == proof_fields.PERFECT_RESERVED_AM_PLUS:
        raise SingularityGateError("reserved perfect AM+ value rejected")
    for key in (
        "field_thresholds_passed",
        "fracture_suite_passed",
        "cross_verifier_agreement_passed",
        "external_attestation_verified",
        "reserved_perfect_value_used",
        "declaration_allowed",
    ):
        if not isinstance(capsule[key], bool):
            raise SingularityGateError(f"{key} must be boolean")
    if not boundary_debt.REQUIRED_NON_CLAIMS.issubset(set(capsule["non_claims"])):
        raise SingularityGateError("capsule non_claims incomplete")
    claim_blockers = boundary_debt.validate_claim_boundary(capsule["claim_boundary"])
    if claim_blockers:
        raise SingularityGateError("; ".join(claim_blockers))
    expected_blockers = declaration_blockers(capsule)
    if capsule["blockers"] != expected_blockers:
        raise SingularityGateError("capsule blockers do not match regenerated declaration gate")
    if capsule["declaration_allowed"] != (not expected_blockers):
        raise SingularityGateError("declaration_allowed does not match blockers")
    if capsule_digest(capsule) != capsule["capsule_digest"]:
        raise SingularityGateError("capsule digest mismatch")


def load_capsule(path: Path | str) -> dict[str, Any]:
    capsule = load_json_no_floats(path)
    validate_capsule(capsule)
    return capsule


def verify_capsule_file(path: Path | str) -> dict[str, Any]:
    capsule = load_capsule(path)
    return declaration_report(capsule) | {"verified": True, "capsule_digest": capsule["capsule_digest"]}


def declaration_report(capsule: dict[str, Any]) -> dict[str, Any]:
    blockers = declaration_blockers(capsule)
    return {
        "allowed": not blockers,
        "decision": "declaration_allowed" if not blockers else "declaration_refused",
        "blockers": blockers,
        "required_evidence": required_evidence(capsule),
        "omega_eff": capsule["omega_eff"],
        "omega_threshold": proof_fields.OMEGA_THRESHOLD_DECIMAL_TEXT,
        "score_AM_plus": capsule["score_AM_plus"],
        "field_thresholds_passed": capsule["field_thresholds_passed"],
        "cross_verifier_agreement_passed": capsule["cross_verifier_agreement_passed"],
        "verifier_quorum": capsule["verifier_quorum"],
        "external_attestation_verified": capsule["external_attestation_verified"],
        "fixture": capsule["fixture"],
        "claim_usable": capsule["claim_usable"],
    }


def required_evidence(capsule: dict[str, Any]) -> list[dict[str, Any]]:
    requirements: list[dict[str, Any]] = []
    field_status = {
        field["field_id"]: field
        for field in capsule.get("proof_fields", [])
        if isinstance(field, dict) and isinstance(field.get("field_id"), str)
    }

    reproducible = field_status.get("reproducible_build")
    if reproducible is not None and reproducible.get("threshold_passed") is not True:
        requirements.append(
            {
                "requirement_id": "reproducible_build.non_fixture_subject_bound_rebuilds",
                "proof_field": "reproducible_build",
                "needed": "two or more independent non-fixture, claim-usable rebuild receipts for the capsule source commit and subject artifact",
                "machine_check": "receipt_digest must recompute, and receipt source commit, SHA-256, SHA3-512, and size must match the bound Aperture capsule subject",
                "current_open_atoms": reproducible.get("open_atoms", []),
            }
        )

    aperture = field_status.get("aperture_firewall_boundary")
    if aperture is not None and aperture.get("threshold_passed") is not True:
        requirements.append(
            {
                "requirement_id": "aperture_firewall_boundary.external_profile_expansion",
                "proof_field": "aperture_firewall_boundary",
                "needed": "external public firewall profile review evidence; repo-owned negative matrix is tracked separately",
                "machine_check": "field atom firewall_profile_externally_expanded must close without adding forbidden claims",
                "current_open_atoms": aperture.get("open_atoms", []),
            }
        )
    verifier = field_status.get("independent_verifier_quorum")
    if verifier is not None and verifier.get("threshold_passed") is not True:
        requirements.append(
            {
                "requirement_id": "independent_verifier_quorum.claim_usable_3_of_3",
                "proof_field": "independent_verifier_quorum",
                "needed": "three or more verifier vectors from distinct families, all non-fixture, all claim-usable, matching the expected subject and v20 output schema, all with matching canonical output digest and verified vector statement digests",
                "machine_check": "verifier bundle passes src.verifier_agreement.evaluate_bundle with expected_subject set to the release tag; each vector_digest recomputes under the verifier-vector domain",
                "current_open_atoms": verifier.get("open_atoms", []),
            }
        )
    external = field_status.get("external_attestation")
    if external is not None and external.get("threshold_passed") is not True:
        requirements.append(
            {
                "requirement_id": "external_attestation.pinned_cryptographic_verification",
                "proof_field": "external_attestation",
                "needed": "scoped non-self external attestations verified by a real pinned signature verifier",
                "machine_check": "cryptographic_signature_verified atom closes; verification_status alone is insufficient",
                "current_open_atoms": external.get("open_atoms", []),
            }
        )
    if capsule.get("fixture") is True or capsule.get("claim_usable") is not True:
        requirements.append(
            {
                "requirement_id": "claim_boundary.non_fixture_claim_usable_inputs",
                "proof_field": "boundary_debt",
                "needed": "non-fixture boundary report and non-fixture evidence inputs marked claim-usable only after upstream evidence passes",
                "machine_check": "fixture=false and claim_usable=true with zero critical/contradiction debt",
                "current_state": {
                    "fixture": capsule.get("fixture"),
                    "claim_usable": capsule.get("claim_usable"),
                },
            }
        )
    if Decimal(str(capsule.get("omega_eff", "0"))) < proof_fields.OMEGA_THRESHOLD:
        requirements.append(
            {
                "requirement_id": "omega_eff.threshold",
                "proof_field": "weakest_field_governor",
                "needed": "all five proof-field families above their thresholds with zero declaration debt",
                "machine_check": "omega_eff >= 20.723265837 and score_AM_plus == 999999999",
                "current_state": {
                    "omega_eff": capsule.get("omega_eff"),
                    "score_AM_plus": capsule.get("score_AM_plus"),
                },
            }
        )
    return requirements


def explain_capsule(capsule: dict[str, Any]) -> dict[str, Any]:
    proofs: list[str] = []
    proofs.append(f"input Aperture capsule digest {capsule['input_aperture_capsule_digest']} is bound")
    proofs.append(f"policy digest {capsule['policy_digest']} binds fail-closed non-claims and gate rules")
    for field in capsule["proof_fields"]:
        proofs.append(
            f"{field['field_id']}: {field['verified_atom_count']}/{field['required_atom_count']} atoms, "
            f"omega {field['omega_i']}, threshold_passed={field['threshold_passed']}"
        )
    proofs.append(f"weakest-field governed omega_eff {capsule['omega_eff']} produces {capsule['score_AM_plus']} AM+")
    return {
        "command": "explain",
        "capsule_digest": capsule["capsule_digest"],
        "declaration_allowed": capsule["declaration_allowed"],
        "proofs": proofs,
        "blockers": capsule["blockers"],
        "non_claims": capsule["non_claims"],
    }
