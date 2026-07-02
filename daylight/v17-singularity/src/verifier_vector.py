"""Cross-verifier output vectors for Daylight v17.3."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256, load_json_no_floats, reject_floats_recursive


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
D_VERIFIER_VECTOR = "DAYLIGHT-v17-EVENT-HORIZON-VERIFIER-VECTOR:"
VECTOR_VERSION = "daylight-v17-cross-verifier-vector-v0.1"
VECTOR_BUNDLE_VERSION = "daylight-v17-cross-verifier-vectors-v0.1"
REQUIRED_TRIANGULATION_FAMILIES = {
    "python-reference",
    "rust-independent",
    "zig-or-minimal-c-independent",
}

COMMON_VECTOR_KEYS = [
    "fields_digest",
    "proof_atoms_digest",
    "state_digest",
    "omega_sum_decimal",
    "omega_weak_decimal",
    "omega_eff_decimal",
    "score_AM_plus",
    "residue_AM_plus",
    "declaration_residue_AM_plus",
    "declaration_score_gap_AM_plus",
    "collapse",
    "declared",
    "status",
    "scorecard_predigest",
]

REQUIRED_VECTOR_KEYS = [
    "implementation_family",
    "implementation_digest",
    *COMMON_VECTOR_KEYS,
]


class VerifierVectorError(ValueError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def python_reference_implementation_digest() -> str:
    files = [
        "canonical_json.py",
        "singularity_math.py",
        "registry.py",
        "proof_atoms.py",
        "scorecard.py",
        "event_horizon.py",
        "fracture.py",
        "verifier_vector.py",
    ]
    payload = {
        "implementation_family": "python-reference",
        "files": [
            {
                "path": f"src/{name}",
                "sha256": _sha256_file(PACKAGE_ROOT / "src" / name),
            }
            for name in files
        ],
    }
    return canonical_sha256(payload, D_VERIFIER_VECTOR + "IMPLEMENTATION:")


def scorecard_predigest_from_parts(parts: dict[str, Any]) -> str:
    body = {key: parts[key] for key in COMMON_VECTOR_KEYS if key != "scorecard_predigest"}
    return canonical_sha256(body, D_VERIFIER_VECTOR + "SCORECARD-PREDIGEST:")


def generate_python_reference_vector(card: dict[str, Any]) -> dict[str, Any]:
    vector = {
        "implementation_family": "python-reference",
        "implementation_digest": python_reference_implementation_digest(),
        "fields_digest": card["fields_digest"],
        "proof_atoms_digest": card["proof_atoms_digest"],
        "state_digest": card["state_digest"],
        "omega_sum_decimal": card["omega_sum_decimal"],
        "omega_weak_decimal": card["omega_weak_decimal"],
        "omega_eff_decimal": card["omega_eff_decimal"],
        "score_AM_plus": card["score_AM_plus"],
        "residue_AM_plus": card["declaration_residue_AM_plus"],
        "declaration_residue_AM_plus": card["declaration_residue_AM_plus"],
        "declaration_score_gap_AM_plus": card["declaration_score_gap_AM_plus"],
        "collapse": card["collapse"],
        "declared": card["declared"],
        "status": card["status"],
    }
    vector["scorecard_predigest"] = scorecard_predigest_from_parts(vector)
    validate_vector(vector)
    return vector


def validate_vector(vector: dict[str, Any]) -> None:
    reject_floats_recursive(vector, "verifier_vector")
    if not isinstance(vector, dict):
        raise VerifierVectorError("verifier vector must be an object")
    for key in REQUIRED_VECTOR_KEYS:
        if key not in vector:
            raise VerifierVectorError(f"verifier vector missing {key}")
    for key in ("implementation_family", "implementation_digest", "fields_digest", "proof_atoms_digest", "state_digest", "omega_sum_decimal", "omega_weak_decimal", "omega_eff_decimal", "status", "scorecard_predigest"):
        if not isinstance(vector[key], str) or not vector[key]:
            raise VerifierVectorError(f"{key} must be a non-empty string")
    for key in ("score_AM_plus", "residue_AM_plus", "declaration_residue_AM_plus", "declaration_score_gap_AM_plus"):
        if isinstance(vector[key], bool) or not isinstance(vector[key], int):
            raise VerifierVectorError(f"{key} must be an integer")
        if vector[key] < 0:
            raise VerifierVectorError(f"{key} must be nonnegative")
    for key in ("collapse", "declared"):
        if not isinstance(vector[key], bool):
            raise VerifierVectorError(f"{key} must be boolean")
    expected_predigest = scorecard_predigest_from_parts(vector)
    if vector["scorecard_predigest"] != expected_predigest:
        raise VerifierVectorError("scorecard_predigest mismatch")


def load_vector(path: Path | str) -> dict[str, Any]:
    vector = load_json_no_floats(path)
    validate_vector(vector)
    return vector


def load_vector_bundle(path: Path | str) -> list[dict[str, Any]]:
    payload = load_json_no_floats(path)
    if isinstance(payload, list):
        vectors = payload
    elif isinstance(payload, dict):
        if payload.get("version") != VECTOR_BUNDLE_VERSION:
            raise VerifierVectorError("unsupported verifier vector bundle version")
        vectors = payload.get("vectors")
    else:
        raise VerifierVectorError("verifier vector bundle must be an object or list")
    if not isinstance(vectors, list):
        raise VerifierVectorError("verifier vector bundle vectors must be a list")
    for vector in vectors:
        validate_vector(vector)
    return vectors


def verify_cross_verifier_agreement(vectors: list[dict[str, Any]]) -> dict[str, Any]:
    blockers: list[str] = []
    valid_vectors: list[dict[str, Any]] = []
    families: list[str] = []
    for index, vector in enumerate(vectors):
        try:
            validate_vector(vector)
        except ValueError as exc:
            blockers.append(f"vector {index} invalid: {exc}")
            continue
        valid_vectors.append(vector)
        families.append(vector["implementation_family"])
    if len(families) != len(set(families)):
        blockers.append("implementation_family values must be distinct")
    if valid_vectors:
        reference = valid_vectors[0]
        for index, vector in enumerate(valid_vectors[1:], start=1):
            for key in COMMON_VECTOR_KEYS:
                if vector.get(key) != reference.get(key):
                    blockers.append(f"{key} mismatch at vector {index}")
                    break
    distinct_count = len(set(families))
    quorum = f"{distinct_count}/3"
    if distinct_count < 3:
        blockers.append("at least three verifier vectors required")
        blockers.append(f"verifier quorum incomplete: {quorum}")
    else:
        missing = sorted(REQUIRED_TRIANGULATION_FAMILIES - set(families))
        for family in missing:
            blockers.append(f"required verifier family missing: {family}")
    if blockers:
        if distinct_count == 0:
            status = "none_0_of_3"
        elif (
            distinct_count in (1, 2)
            and all("mismatch" not in item for item in blockers)
            and all("invalid" not in item for item in blockers)
            and all("implementation_family" not in item for item in blockers)
        ):
            status = f"partial_{distinct_count}_of_3"
        else:
            status = "failed"
    else:
        status = "full_3_of_3"
    return {
        "passed": not blockers,
        "blockers": blockers,
        "vector_count": len(vectors),
        "valid_vector_count": len(valid_vectors),
        "distinct_family_count": distinct_count,
        "quorum": quorum,
        "agreement_status": status,
        "implementation_families": families,
    }


def verify_vectors_against_reference(vectors: list[dict[str, Any]], reference: dict[str, Any]) -> dict[str, Any]:
    agreement = verify_cross_verifier_agreement(vectors)
    blockers = list(agreement["blockers"])
    try:
        validate_vector(reference)
    except ValueError as exc:
        blockers.append(f"reference vector invalid: {exc}")
    for index, vector in enumerate(vectors):
        for key in COMMON_VECTOR_KEYS:
            if vector.get(key) != reference.get(key):
                blockers.append(f"{key} does not match reference at vector {index}")
                break
    return {
        "passed": not blockers,
        "blockers": blockers,
        "vector_count": len(vectors),
        "valid_vector_count": agreement["valid_vector_count"],
        "distinct_family_count": agreement["distinct_family_count"],
        "quorum": agreement["quorum"],
        "agreement_status": agreement["agreement_status"],
        "implementation_families": agreement["implementation_families"],
        "reference_implementation_family": reference.get("implementation_family"),
    }
