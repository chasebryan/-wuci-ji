"""Independent verifier agreement bundles for v20."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .canonical import canonical_sha256, load_json_no_floats, reject_floats_recursive

SCHEMA_ID = "daylight-v20-verifier-agreement-bundle"
SCHEMA_VERSION = "0.1.0"
OUTPUT_SCHEMA_ID = "daylight-v20-aperture-singularity-capsule"
D_VECTOR = "DAYLIGHT-v20-VERIFIER-VECTOR:"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class VerifierAgreementError(ValueError):
    pass


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerifierAgreementError(f"{name} must be a non-empty string")
    return value


def _require_hex64(value: Any, name: str) -> str:
    text = _require_str(value, name)
    if not HEX64_RE.fullmatch(text):
        raise VerifierAgreementError(f"{name} must be a lowercase SHA-256 hex digest")
    return text


def validate_vector(vector: dict[str, Any], index: int = 0) -> None:
    if not isinstance(vector, dict):
        raise VerifierAgreementError(f"vectors[{index}] must be an object")
    reject_floats_recursive(vector, f"vectors[{index}]")
    required = {
        "vector_id",
        "verifier_family",
        "implementation_digest",
        "canonical_output_digest",
        "output_schema_id",
        "vector_digest",
        "fixture",
        "claim_usable",
    }
    if set(vector) != required:
        raise VerifierAgreementError(f"vectors[{index}] field set invalid")
    _require_str(vector["vector_id"], f"vectors[{index}].vector_id")
    _require_str(vector["verifier_family"], f"vectors[{index}].verifier_family")
    _require_hex64(vector["implementation_digest"], f"vectors[{index}].implementation_digest")
    _require_hex64(vector["canonical_output_digest"], f"vectors[{index}].canonical_output_digest")
    _require_str(vector["output_schema_id"], f"vectors[{index}].output_schema_id")
    _require_hex64(vector["vector_digest"], f"vectors[{index}].vector_digest")
    if not isinstance(vector["fixture"], bool):
        raise VerifierAgreementError(f"vectors[{index}].fixture must be boolean")
    if not isinstance(vector["claim_usable"], bool):
        raise VerifierAgreementError(f"vectors[{index}].claim_usable must be boolean")


def vector_digest(vector: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "vector_id": vector["vector_id"],
            "verifier_family": vector["verifier_family"],
            "implementation_digest": vector["implementation_digest"],
            "canonical_output_digest": vector["canonical_output_digest"],
            "output_schema_id": vector["output_schema_id"],
            "fixture": vector["fixture"],
            "claim_usable": vector["claim_usable"],
        },
        D_VECTOR,
    )


def evaluate_bundle(bundle: dict[str, Any], *, expected_subject: str | None = None) -> dict[str, Any]:
    reject_floats_recursive(bundle, "verifier_agreement")
    if not isinstance(bundle, dict):
        raise VerifierAgreementError("verifier agreement bundle must be an object")
    required = {"schema_id", "schema_version", "subject", "vectors"}
    if set(bundle) != required:
        raise VerifierAgreementError("verifier agreement bundle field set invalid")
    if bundle["schema_id"] != SCHEMA_ID or bundle["schema_version"] != SCHEMA_VERSION:
        raise VerifierAgreementError("unsupported verifier agreement bundle schema")
    subject = _require_str(bundle["subject"], "subject")
    if expected_subject is not None:
        _require_str(expected_subject, "expected_subject")
    vectors = bundle["vectors"]
    if not isinstance(vectors, list):
        raise VerifierAgreementError("vectors must be a list")

    blockers: list[str] = []
    valid_vectors: list[dict[str, Any]] = []
    families: list[str] = []
    output_digests: list[str] = []
    output_schema_ids: list[str] = []
    vector_digests_ok = True
    for index, vector in enumerate(vectors):
        try:
            validate_vector(vector, index)
        except ValueError as exc:
            blockers.append(f"vector {index} invalid: {exc}")
            continue
        valid_vectors.append(vector)
        families.append(vector["verifier_family"])
        output_digests.append(vector["canonical_output_digest"])
        output_schema_ids.append(vector["output_schema_id"])
        if vector["vector_digest"] != vector_digest(vector):
            vector_digests_ok = False
            blockers.append(f"vector {index} digest mismatch")

    if len(families) != len(set(families)):
        duplicates = sorted({family for family in families if families.count(family) > 1})
        raise VerifierAgreementError(f"duplicate verifier family rejected: {', '.join(duplicates)}")

    distinct_count = len(set(families))
    quorum = f"{distinct_count}/3"
    if len(valid_vectors) < 3:
        blockers.append("at least three verifier vectors required")
        blockers.append(f"verifier quorum incomplete: {quorum}")
    if distinct_count < 3:
        if f"verifier quorum incomplete: {quorum}" not in blockers:
            blockers.append(f"verifier quorum incomplete: {quorum}")
    if output_digests and len(set(output_digests)) != 1:
        blockers.append("canonical output digest mismatch")
    subject_matches_expected = expected_subject is not None and subject == expected_subject
    if not subject_matches_expected:
        blockers.append("verifier bundle subject does not match expected release subject")
    output_schema_matches_v20 = bool(valid_vectors) and all(item == OUTPUT_SCHEMA_ID for item in output_schema_ids)
    if not output_schema_matches_v20:
        blockers.append("verifier vector output schema mismatch")
    if not (bool(valid_vectors) and vector_digests_ok):
        blockers.append("verifier vector digest mismatch")
    vectors_non_fixture = bool(valid_vectors) and all(vector["fixture"] is False for vector in valid_vectors)
    vectors_claim_usable = bool(valid_vectors) and all(vector["claim_usable"] is True for vector in valid_vectors)
    if not vectors_non_fixture:
        blockers.append("verifier vectors are fixture evidence")
    if not vectors_claim_usable:
        blockers.append("verifier vectors are not claim-usable")

    passed = not blockers
    atoms = {
        "bundle_present": True,
        "vectors_valid": len(valid_vectors) == len(vectors),
        "vectors_non_fixture": vectors_non_fixture,
        "vectors_claim_usable": vectors_claim_usable,
        "subject_matches_expected": subject_matches_expected,
        "vector_statement_digests_verified": bool(valid_vectors) and vector_digests_ok,
        "at_least_three_vectors": len(valid_vectors) >= 3,
        "three_distinct_verifier_families": distinct_count >= 3,
        "output_schema_matches_v20": output_schema_matches_v20,
        "all_canonical_output_digests_match": bool(output_digests) and len(set(output_digests)) == 1,
        "quorum_3_of_3": distinct_count >= 3 and len(valid_vectors) >= 3,
    }
    return {
        "schema_id": SCHEMA_ID,
        "passed": passed,
        "blockers": blockers,
        "vector_count": len(vectors),
        "valid_vector_count": len(valid_vectors),
        "distinct_family_count": distinct_count,
        "quorum": quorum,
        "subject": subject,
        "expected_subject": expected_subject,
        "verifier_families": families,
        "canonical_output_digest": output_digests[0] if output_digests and len(set(output_digests)) == 1 else None,
        "atoms": atoms,
    }


def load_and_evaluate(path: Path | str) -> dict[str, Any]:
    return evaluate_bundle(load_json_no_floats(path))
