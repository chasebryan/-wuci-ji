"""Claim boundary and non-claims registry for Aperture Bastion capsules.

A capsule that asserts any forbidden authority claim is invalid even if its
digest was recomputed after the edit. The claim check is semantic, not only
digest-bound.
"""

from __future__ import annotations

from typing import Any

CLAIM_BOUNDARY_VERSION = "aperture-claim-boundary-v1"

FORBIDDEN_AUTHORITY_CLAIMS = (
    "production_cryptography",
    "runtime_containment",
    "host_cleanliness",
    "fips_validation",
    "government_validation",
    "external_certification",
    "whole_system_post_quantum_safety",
    "independent_audit_completed",
    "perfect_daylight_score_from_repo_evidence",
)

CLAIM_STATEMENT = (
    "Aperture Bastion binds subjects, evidence references, and public files to "
    "deterministic digests. It grants no authority beyond those digest bindings."
)

MANDATORY_NON_CLAIMS = (
    "not FIPS validated",
    "not a perfect Daylight score claim from repository-owned evidence",
    "not an independent audit",
    "not externally certified",
    "not government validated",
    "not host cleanliness proof",
    "not production cryptography",
    "not runtime containment or sandboxing",
    "not whole-system post-quantum safe",
)


class ClaimBoundaryError(ValueError):
    pass


def claim_boundary() -> dict[str, Any]:
    boundary: dict[str, Any] = {
        "boundary_version": CLAIM_BOUNDARY_VERSION,
        "statement": CLAIM_STATEMENT,
    }
    for claim in FORBIDDEN_AUTHORITY_CLAIMS:
        boundary[claim] = False
    return boundary


def non_claims() -> list[str]:
    return sorted(MANDATORY_NON_CLAIMS)


def validate_claim_boundary(value: Any) -> None:
    if not isinstance(value, dict):
        raise ClaimBoundaryError("claim_boundary must be an object")
    expected_keys = set(FORBIDDEN_AUTHORITY_CLAIMS) | {"boundary_version", "statement"}
    if set(value) != expected_keys:
        raise ClaimBoundaryError(f"claim_boundary keys must be exactly {sorted(expected_keys)}")
    if value["boundary_version"] != CLAIM_BOUNDARY_VERSION:
        raise ClaimBoundaryError("unsupported claim_boundary version")
    if not isinstance(value["statement"], str) or not value["statement"]:
        raise ClaimBoundaryError("claim_boundary statement must be a non-empty string")
    for claim in FORBIDDEN_AUTHORITY_CLAIMS:
        if value[claim] is not False:
            raise ClaimBoundaryError(f"capsule may not claim {claim}")


def validate_non_claims(value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise ClaimBoundaryError("non_claims must be a non-empty list")
    for item in value:
        if not isinstance(item, str) or not item:
            raise ClaimBoundaryError("non_claims entries must be non-empty strings")
    if len(set(value)) != len(value):
        raise ClaimBoundaryError("non_claims entries must be unique")
    if value != sorted(value):
        raise ClaimBoundaryError("non_claims must be sorted")
    missing = set(MANDATORY_NON_CLAIMS) - set(value)
    if missing:
        raise ClaimBoundaryError(f"mandatory non-claims missing: {sorted(missing)}")
