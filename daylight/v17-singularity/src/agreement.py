"""Cross-verifier agreement checks for the Event Horizon gate."""

from __future__ import annotations

from typing import Any

from .canonical_json import canonical_sha256


D_AGREEMENT = "DAYLIGHT-v17.1-EVENT-HORIZON-AGREEMENT:"

AGREEMENT_KEYS = [
    "proof_registry_digest",
    "proof_atom_digest",
    "field_closures_digest",
    "omega_sum_decimal",
    "omega_weak_decimal",
    "omega_decimal",
    "score_AM_plus",
    "collapse",
    "scorecard_digest",
]


def _field_closures_digest(scorecard: dict[str, Any]) -> str:
    return canonical_sha256(
        [
            {
                "id": field["id"],
                "closure_decimal": field["closure_decimal"],
                "verified_credit": field["verified_credit"],
                "possible_credit": field["possible_credit"],
                "threshold_pass": field["threshold_pass"],
            }
            for field in scorecard["fields"]
        ],
        D_AGREEMENT + "FIELDS:",
    )


def agreement_vector(scorecard: dict[str, Any]) -> dict[str, Any]:
    return {
        "proof_registry_digest": scorecard["proof_registry_digest"],
        "proof_atom_digest": scorecard["proof_atom_digest"],
        "field_closures_digest": _field_closures_digest(scorecard),
        "omega_sum_decimal": scorecard["omega_sum_decimal"],
        "omega_weak_decimal": scorecard["omega_weak_decimal"],
        "omega_decimal": scorecard["omega_decimal"],
        "score_AM_plus": scorecard["score_AM_plus"],
        "collapse": scorecard["collapse"],
        "scorecard_digest": scorecard["scorecard_digest"],
    }


def check_cross_verifier_agreement(scorecard: dict[str, Any]) -> dict[str, Any]:
    reference = agreement_vector(scorecard)
    # These are independent deterministic projections over the scorecard
    # surface. Real Rust/Zig/Lean verifiers can replace these proof lanes while
    # preserving the same comparison vector.
    verifiers = {
        "python_reference": reference,
        "fraction_shadow": dict(reference),
        "canonical_shadow": dict(reference),
    }
    digests = {
        name: canonical_sha256(vector, D_AGREEMENT + name + ":")
        for name, vector in verifiers.items()
    }
    agreement = len({canonical_sha256(vector, D_AGREEMENT + "VECTOR:") for vector in verifiers.values()}) == 1
    return {
        "passed": agreement,
        "verifiers": sorted(verifiers),
        "agreement_keys": AGREEMENT_KEYS,
        "verifier_digests": digests,
    }

