"""Cross-derivation agreement checks for the Event Horizon gate.

Historically this module ran three copies of the same projection and therefore
could never disagree with itself. It now compares two genuinely separate
derivations of the same agreement vector:

* ``scorecard_claimed`` -- the vector as asserted by the (untrusted) scorecard.
* ``independent_rederivation`` -- the same vector rebuilt from the raw field
  registry, proof atoms, and state via :mod:`independent_score` plus a fresh
  recomputation of every digest.

If any element disagrees the check fails, which is what lets the Event Horizon
gate treat agreement as evidence instead of decoration.

Honest boundary: this is an *in-repo* second derivation that shares the Decimal
math kernel. It is not an independent external verifier and not a
second-language verifier; both remain future work. What it proves is that the
numbers a scorecard publishes are the numbers its evidence regenerates.
"""

from __future__ import annotations

from typing import Any

from .canonical_json import canonical_sha256
from . import independent_score
from . import proof_atoms as proof_atoms_mod
from . import registry as registry_mod
from . import scorecard as scorecard_mod


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

DERIVATIONS = ["scorecard_claimed", "independent_rederivation"]


def _field_closures_digest(fields: list[dict[str, Any]]) -> str:
    return canonical_sha256(
        [
            {
                "id": field["id"],
                "closure_decimal": field["closure_decimal"],
                "verified_credit": field["verified_credit"],
                "possible_credit": field["possible_credit"],
                "threshold_pass": field["threshold_pass"],
            }
            for field in fields
        ],
        D_AGREEMENT + "FIELDS:",
    )


def agreement_vector(scorecard: dict[str, Any]) -> dict[str, Any]:
    """Project the agreement vector from a scorecard's own assertions."""

    return {
        "proof_registry_digest": scorecard["proof_registry_digest"],
        "proof_atom_digest": scorecard["proof_atom_digest"],
        "field_closures_digest": _field_closures_digest(scorecard["fields"]),
        "omega_sum_decimal": scorecard["omega_sum_decimal"],
        "omega_weak_decimal": scorecard["omega_weak_decimal"],
        "omega_decimal": scorecard["omega_decimal"],
        "score_AM_plus": scorecard["score_AM_plus"],
        "collapse": scorecard["collapse"],
        "scorecard_digest": scorecard["scorecard_digest"],
    }


def independent_agreement_vector(
    scorecard: dict[str, Any],
    state: dict[str, Any],
    fields_registry: dict[str, Any],
    proof_atom_registry: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild the agreement vector from raw inputs, not from the scorecard.

    The two registry digests and the field-closure digest are recomputed from
    the raw registries and re-derived proof-atom closures. The omega/score/
    collapse values come from the independent scoring path. The scorecard digest
    is recomputed from the scorecard body so a body edited without refreshing
    its digest is caught here as a disagreement.
    """

    scoring = independent_score.rederive_scoring(state, fields_registry, proof_atom_registry)
    return {
        "proof_registry_digest": registry_mod.proof_registry_digest(fields_registry),
        "proof_atom_digest": proof_atoms_mod.proof_atom_registry_digest(proof_atom_registry),
        "field_closures_digest": _field_closures_digest(scoring["fields"]),
        "omega_sum_decimal": scoring["omega_sum_decimal"],
        "omega_weak_decimal": scoring["omega_weak_decimal"],
        "omega_decimal": scoring["omega_decimal"],
        "score_AM_plus": scoring["score_AM_plus"],
        "collapse": scoring["collapse"],
        "scorecard_digest": scorecard_mod.scorecard_digest(scorecard),
    }


def check_cross_verifier_agreement(
    scorecard: dict[str, Any],
    state: dict[str, Any],
    fields_registry: dict[str, Any],
    proof_atom_registry: dict[str, Any],
) -> dict[str, Any]:
    claimed = agreement_vector(scorecard)
    independent = independent_agreement_vector(scorecard, state, fields_registry, proof_atom_registry)

    disagreements = [
        {"key": key, "scorecard_claimed": claimed[key], "independent_rederivation": independent[key]}
        for key in AGREEMENT_KEYS
        if claimed[key] != independent[key]
    ]
    claimed_digest = canonical_sha256(claimed, D_AGREEMENT + "VECTOR:")
    independent_digest = canonical_sha256(independent, D_AGREEMENT + "VECTOR:")

    return {
        "passed": not disagreements and claimed_digest == independent_digest,
        "method": "in-repo-second-derivation",
        "derivations": DERIVATIONS,
        "agreement_keys": AGREEMENT_KEYS,
        "claimed_digest": claimed_digest,
        "independent_digest": independent_digest,
        "disagreements": disagreements,
        "non_claim": "in-repo second derivation shares the Decimal kernel; not an independent external or second-language verifier",
    }
