"""External attestation structural parsing for v20.

This module intentionally does not treat any attestation as declaration-grade
cryptographic verification. Until a real pinned verifier is implemented here,
all bundles carry the blocker "external attestation not cryptographically
verified".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .boundary_debt import REQUIRED_NON_CLAIMS
from .canonical import canonical_sha256, load_json_no_floats, reject_floats_recursive

SCHEMA_ID = "daylight-v20-external-attestation-bundle"
SCHEMA_VERSION = "0.1.0"
D_STATEMENT = "DAYLIGHT-v20-EXTERNAL-ATTESTATION-STATEMENT:"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SELF_SCOPE_DEFAULTS = {"self", "internal", "local", "repo", "harness", "wuci-ji"}
REQUIRED_ATTESTATION_FIELDS = {
    "attestation_id",
    "attestation_type",
    "reviewer_id",
    "reviewer_org_optional",
    "scope",
    "subject_digest",
    "evidence_digest",
    "statement_digest",
    "signature_material",
    "verification_status",
    "verification_method",
    "verified_by",
    "verified_at_digest_or_receipt",
    "self_scope",
    "non_claims_acknowledged",
}


class ExternalAttestationError(ValueError):
    pass


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalAttestationError(f"{name} must be a non-empty string")
    return value


def _require_hex64(value: Any, name: str) -> str:
    text = _require_str(value, name)
    if not HEX64_RE.fullmatch(text):
        raise ExternalAttestationError(f"{name} must be a lowercase SHA-256 hex digest")
    return text


def _validate_signature_material(value: Any, name: str) -> None:
    if not isinstance(value, dict):
        raise ExternalAttestationError(f"{name} must be an object")
    required = {"signature_format", "signature_digest", "key_digest"}
    if set(value) != required:
        raise ExternalAttestationError(f"{name} field set invalid")
    _require_str(value["signature_format"], f"{name}.signature_format")
    _require_hex64(value["signature_digest"], f"{name}.signature_digest")
    _require_hex64(value["key_digest"], f"{name}.key_digest")


def _validate_attestation(attestation: dict[str, Any], index: int) -> list[str]:
    if not isinstance(attestation, dict):
        raise ExternalAttestationError(f"attestations[{index}] must be an object")
    reject_floats_recursive(attestation, f"attestations[{index}]")
    if set(attestation) != REQUIRED_ATTESTATION_FIELDS:
        raise ExternalAttestationError(f"attestations[{index}] field set invalid")
    for key in (
        "attestation_id",
        "attestation_type",
        "reviewer_id",
        "reviewer_org_optional",
        "verification_status",
        "verification_method",
        "verified_by",
    ):
        if key == "reviewer_org_optional" and attestation[key] is None:
            continue
        _require_str(attestation[key], f"attestations[{index}].{key}")
    scope = attestation["scope"]
    if not isinstance(scope, dict) or not scope:
        raise ExternalAttestationError(f"attestations[{index}].scope must be a non-empty object")
    for key, value in scope.items():
        _require_str(key, f"attestations[{index}].scope key")
        _require_str(value, f"attestations[{index}].scope.{key}")
    for key in ("subject_digest", "evidence_digest", "statement_digest", "verified_at_digest_or_receipt"):
        _require_hex64(attestation[key], f"attestations[{index}].{key}")
    _validate_signature_material(attestation["signature_material"], f"attestations[{index}].signature_material")
    self_scope = attestation["self_scope"]
    if not isinstance(self_scope, list):
        raise ExternalAttestationError(f"attestations[{index}].self_scope must be a list")
    aliases: list[str] = []
    for alias in self_scope:
        aliases.append(_require_str(alias, f"attestations[{index}].self_scope"))
    acknowledged = attestation["non_claims_acknowledged"]
    if not isinstance(acknowledged, list):
        raise ExternalAttestationError(f"attestations[{index}].non_claims_acknowledged must be a list")
    for item in acknowledged:
        _require_str(item, f"attestations[{index}].non_claims_acknowledged")
    return aliases


def statement_digest(attestation: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "attestation_id": attestation["attestation_id"],
            "attestation_type": attestation["attestation_type"],
            "reviewer_id": attestation["reviewer_id"],
            "reviewer_org_optional": attestation["reviewer_org_optional"],
            "scope": attestation["scope"],
            "subject_digest": attestation["subject_digest"],
            "evidence_digest": attestation["evidence_digest"],
            "non_claims_acknowledged": attestation["non_claims_acknowledged"],
        },
        D_STATEMENT,
    )


def evaluate_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    reject_floats_recursive(bundle, "external_attestation")
    if not isinstance(bundle, dict):
        raise ExternalAttestationError("external attestation bundle must be an object")
    required = {"schema_id", "schema_version", "self_scope_aliases", "attestations"}
    if set(bundle) != required:
        raise ExternalAttestationError("external attestation bundle field set invalid")
    if bundle["schema_id"] != SCHEMA_ID or bundle["schema_version"] != SCHEMA_VERSION:
        raise ExternalAttestationError("unsupported external attestation bundle schema")
    aliases_value = bundle["self_scope_aliases"]
    if not isinstance(aliases_value, list):
        raise ExternalAttestationError("self_scope_aliases must be a list")
    configured_aliases = {str(alias).lower() for alias in aliases_value}
    configured_aliases.update(SELF_SCOPE_DEFAULTS)
    attestations = bundle["attestations"]
    if not isinstance(attestations, list):
        raise ExternalAttestationError("attestations must be a list")

    blockers: list[str] = []
    all_required_fields = True
    scoped = True
    signer_ok = True
    non_claims_ok = True
    statement_digest_ok = True
    for index, attestation in enumerate(attestations):
        try:
            attestation_aliases = _validate_attestation(attestation, index)
        except ValueError as exc:
            all_required_fields = False
            blockers.append(f"attestation {index} invalid: {exc}")
            continue
        all_aliases = set(configured_aliases)
        all_aliases.update(alias.lower() for alias in attestation_aliases)
        reviewer = attestation["reviewer_id"].lower()
        if reviewer in all_aliases:
            signer_ok = False
            blockers.append(f"external attestation self-scoped signer rejected: {attestation['reviewer_id']}")
        if not attestation["scope"]:
            scoped = False
        acknowledged = set(attestation["non_claims_acknowledged"])
        if not REQUIRED_NON_CLAIMS.issubset(acknowledged):
            non_claims_ok = False
            blockers.append(f"attestation {index} did not acknowledge every required non-claim")
        if attestation["statement_digest"] != statement_digest(attestation):
            statement_digest_ok = False
            blockers.append(f"attestation {index} statement digest mismatch")

    cryptographic_verified = False
    blockers.append("external attestation not cryptographically verified")
    atoms = {
        "attestations_present": bool(attestations),
        "required_fields_present": all_required_fields,
        "attestations_scoped": scoped and bool(attestations),
        "signer_not_self_scoped": signer_ok and bool(attestations),
        "non_claims_acknowledged": non_claims_ok and bool(attestations),
        "statement_digest_verified": statement_digest_ok and bool(attestations),
        "cryptographic_signature_verified": cryptographic_verified,
    }
    return {
        "schema_id": SCHEMA_ID,
        "passed": False,
        "verified": cryptographic_verified,
        "blockers": blockers,
        "attestation_count": len(attestations),
        "self_scope_aliases": sorted(configured_aliases),
        "atoms": atoms,
    }


def load_and_evaluate(path: Path | str) -> dict[str, Any]:
    return evaluate_bundle(load_json_no_floats(path))
