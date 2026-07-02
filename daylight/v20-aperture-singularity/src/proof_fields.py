"""Evidence-atom based proof-field scoring for v20."""

from __future__ import annotations

from decimal import Decimal, ROUND_FLOOR, getcontext
from typing import Any

getcontext().prec = 100

B = 1_000_000_000
DECLARATION_TARGET_AM_PLUS = 999_999_999
PERFECT_RESERVED_AM_PLUS = 1_000_000_000
OMEGA_THRESHOLD_DECIMAL_TEXT = "20.723265837"
FIELD_OMEGA_THRESHOLD_DECIMAL_TEXT = "4.144653167"
FIELD_CLOSURE_THRESHOLD_DECIMAL_TEXT = "0.984151068"
OMEGA_THRESHOLD = Decimal(OMEGA_THRESHOLD_DECIMAL_TEXT)
FIELD_OMEGA_THRESHOLD = Decimal(FIELD_OMEGA_THRESHOLD_DECIMAL_TEXT)
EPSILON_DENOMINATOR = 1_000_000_000
KAPPA = 5

FIELD_ATOMS: dict[str, list[str]] = {
    "reproducible_build": [
        "receipts_present",
        "receipt_statement_digests_verified",
        "receipts_non_fixture",
        "receipts_claim_usable",
        "at_least_two_independent_builders",
        "distinct_build_environments",
        "same_source_commit",
        "source_commit_matches_capsule",
        "same_build_instructions_digest",
        "same_artifact_sha256",
        "artifact_sha256_matches_subject",
        "same_artifact_sha3_512",
        "artifact_sha3_512_matches_subject",
        "artifact_size_matches_subject",
        "byte_identical_outputs_claimed",
    ],
    "aperture_firewall_boundary": [
        "aperture_capsule_bound",
        "aperture_capsule_digest_verified",
        "subject_sha256_bound",
        "subject_sha3_512_bound",
        "subject_size_bound",
        "public_manifest_declared",
        "sha256sums_consistent",
        "firewall_report_bound",
        "firewall_passed",
        "firewall_profile_pinned",
        "claim_boundary_present",
        "non_claims_present",
        "public_artifact_firewall_negative_matrix_verified",
        "firewall_profile_externally_expanded",
    ],
    "independent_verifier_quorum": [
        "bundle_present",
        "vectors_valid",
        "vectors_non_fixture",
        "vectors_claim_usable",
        "subject_matches_expected",
        "vector_statement_digests_verified",
        "at_least_three_vectors",
        "three_distinct_verifier_families",
        "output_schema_matches_v20",
        "all_canonical_output_digests_match",
        "quorum_3_of_3",
    ],
    "external_attestation": [
        "attestations_present",
        "required_fields_present",
        "attestations_scoped",
        "signer_not_self_scoped",
        "non_claims_acknowledged",
        "statement_digest_verified",
        "cryptographic_signature_verified",
    ],
    "falsification_survival": [
        "digest_edit",
        "manifest_edit",
        "public_file_drift",
        "hidden_file",
        "symlink",
        "hardlink",
        "private_filename",
        "private_directory",
        "private_content_marker",
        "path_traversal",
        "absolute_path",
        "duplicate_json_key",
        "json_float",
        "manual_score_edit",
        "fixture_laundering",
        "fake_external_attestation",
        "self_signed_external_closure",
        "reserved_perfect_am_plus_value",
        "verifier_vector_mismatch",
        "duplicate_verifier_family",
        "critical_boundary_debt",
    ],
}


class ProofFieldError(ValueError):
    pass


def decimal_text(value: Decimal) -> str:
    text = format(+value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _closure_decimal(verified: int, possible: int) -> tuple[Decimal, bool, str]:
    if possible <= 0:
        raise ProofFieldError("possible atom count must be greater than zero")
    if verified < 0 or verified > possible:
        raise ProofFieldError("verified atom count must be in range")
    perfect_reserve_applied = verified == possible
    if perfect_reserve_applied:
        closure = Decimal(EPSILON_DENOMINATOR - 1) / Decimal(EPSILON_DENOMINATOR)
        closure_rational = f"{EPSILON_DENOMINATOR - 1}/{EPSILON_DENOMINATOR}"
    else:
        closure = Decimal(verified) / Decimal(possible)
        closure_rational = f"{verified}/{possible}"
    return closure, perfect_reserve_applied, closure_rational


def _omega_from_closure(closure: Decimal) -> Decimal:
    residue = Decimal(1) - closure
    epsilon = Decimal(1) / Decimal(EPSILON_DENOMINATOR)
    if residue < epsilon:
        residue = epsilon
    return -residue.ln()


def build_field_result(field_id: str, atoms: dict[str, bool]) -> dict[str, Any]:
    required = FIELD_ATOMS.get(field_id)
    if required is None:
        raise ProofFieldError(f"unknown proof field: {field_id}")
    unknown = sorted(set(atoms) - set(required))
    if unknown:
        raise ProofFieldError(f"unknown atoms for {field_id}: {unknown}")
    closed = [atom for atom in required if atoms.get(atom) is True]
    open_atoms = [atom for atom in required if atoms.get(atom) is not True]
    closure, reserve, closure_rational = _closure_decimal(len(closed), len(required))
    omega = _omega_from_closure(closure)
    return {
        "field_id": field_id,
        "required_atom_count": len(required),
        "verified_atom_count": len(closed),
        "closure_rational": closure_rational,
        "closure_decimal": decimal_text(closure),
        "omega_i": decimal_text(omega),
        "omega_threshold": FIELD_OMEGA_THRESHOLD_DECIMAL_TEXT,
        "closure_threshold": FIELD_CLOSURE_THRESHOLD_DECIMAL_TEXT,
        "threshold_passed": omega >= FIELD_OMEGA_THRESHOLD,
        "perfect_reserve_applied": reserve,
        "closed_atoms": closed,
        "open_atoms": open_atoms,
    }


def build_proof_fields(atom_maps: dict[str, dict[str, bool]]) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for field_id in FIELD_ATOMS:
        fields.append(build_field_result(field_id, atom_maps.get(field_id, {})))
    return fields


def summarize_omega(fields: list[dict[str, Any]], debt_omega: Decimal = Decimal(0)) -> dict[str, Any]:
    if not fields:
        raise ProofFieldError("at least one proof field is required")
    omega_values = [Decimal(field["omega_i"]) for field in fields]
    omega_sum = sum(omega_values, Decimal(0))
    omega_min = min(omega_values)
    omega_weak = Decimal(KAPPA) * omega_min
    governed = min(omega_sum, omega_weak)
    omega_eff = governed - debt_omega
    if omega_eff < 0:
        omega_eff = Decimal(0)
    score = score_from_omega(omega_eff)
    return {
        "omega_sum": decimal_text(omega_sum),
        "omega_weak": decimal_text(omega_weak),
        "omega_eff": decimal_text(omega_eff),
        "score_AM_plus": score,
        "field_thresholds_passed": all(field["threshold_passed"] is True for field in fields),
        "weakest_field": fields[omega_values.index(omega_min)]["field_id"],
    }


def score_from_omega(omega_eff: Decimal) -> int:
    if omega_eff <= 0:
        return 0
    if omega_eff >= OMEGA_THRESHOLD:
        return DECLARATION_TARGET_AM_PLUS
    residue = (-omega_eff).exp()
    raw_score = Decimal(B) * (Decimal(1) - residue)
    score = int(raw_score.to_integral_value(rounding=ROUND_FLOOR))
    if score < 0:
        return 0
    if score > DECLARATION_TARGET_AM_PLUS:
        return DECLARATION_TARGET_AM_PLUS
    return score


def proof_field_atom_map(
    *,
    reproducible_build: dict[str, Any],
    aperture_firewall_boundary: dict[str, Any],
    independent_verifier_quorum: dict[str, Any],
    external_attestation: dict[str, Any],
    falsification_survival: dict[str, Any],
) -> dict[str, dict[str, bool]]:
    return {
        "reproducible_build": reproducible_build["atoms"],
        "aperture_firewall_boundary": aperture_firewall_boundary["atoms"],
        "independent_verifier_quorum": independent_verifier_quorum["atoms"],
        "external_attestation": external_attestation["atoms"],
        "falsification_survival": falsification_survival["atoms"],
    }
