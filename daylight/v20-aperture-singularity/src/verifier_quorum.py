"""Daylight v20.3 external verifier-family quorum intake.

This module freezes the canonical verifier-output digest and evaluates the
external 3-of-3 verifier-vector quorum. It closes only the verifier-family
quorum gate; it does not raise scores, certify the project, or open
Singularity by itself.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from . import boundary_debt
from . import external_evidence
from . import singularity_gate
from .canonical import dumps_canonical, load_json_no_floats, loads_json_no_floats, reject_floats_recursive
from .pathsafe import PathSafetyError, read_public_bytes

CANONICAL_OUTPUT_SCHEMA_ID = "daylight.v20.canonical-verifier-output"
CANONICAL_OUTPUT_SCHEMA_VERSION = 1
VERIFIER_CONTRACT = "daylight.v20.verifier-vector-quorum"
QUORUM_REPORT_SCHEMA_ID = "daylight.v20.verifier-family-quorum.report"
QUORUM_REPORT_SCHEMA_VERSION = 1
CANONICAL_OUTPUT_DIGEST_DOMAIN = "DAYLIGHT-v20-CANONICAL-VERIFIER-OUTPUT:"
QUORUM_GATE = "independent_verifier_quorum.claim_usable_3_of_3"
MAX_CANONICAL_OUTPUT_BYTES = 1_000_000

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
RESERVED_FAMILY_TOKENS = external_evidence.FORBIDDEN_IDENTITY_TOKENS | frozenset({"daylight"})

ALLOWED_IMPLEMENTATION_KINDS = frozenset(
    {
        "source-tree",
        "source-tarball",
        "binary",
        "script",
        "reproducible-container",
        "other-declared",
    }
)

REQUIRED_VECTOR_FIELDS = frozenset(
    {
        "vector_id",
        "verifier_family",
        "verifier_family_independence_class",
        "verifier_implementation_digest",
        "verifier_implementation_kind",
        "input_capsule_digest",
        "canonical_output_schema_id",
        "canonical_output_digest",
        "output_digest",
        "decision",
        "fixture",
        "claim_usable",
        "attestation_ref",
    }
)

REQUIRED_CANONICAL_OUTPUT_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "verifier_contract",
        "subject",
        "checks",
        "decision",
        "blocker_vector_digest",
        "non_claims_digest",
        "canonical_output_digest_domain",
    }
)

REQUIRED_CANONICAL_SUBJECT_FIELDS = frozenset(
    {
        "release_tag",
        "source_commit",
        "artifact_sha256",
        "artifact_sha3_512",
        "artifact_size",
        "aperture_capsule_digest",
        "score_ceiling_report_digest",
    }
)

REQUIRED_CANONICAL_CHECK_FIELDS = frozenset(
    {
        "capsule_schema_valid",
        "capsule_digest_recomputed",
        "subject_artifact_digest_bound",
        "public_artifact_manifest_verified",
        "score_ceiling_report_verified",
        "singularity_declaration_refused",
        "non_claims_present",
        "fixture_claim_rejected",
        "external_evidence_gate_fail_closed",
    }
)

BLOCKER_ORDER = [
    "verifier_quorum_missing",
    "verifier_quorum_fewer_than_three",
    "verifier_quorum_more_than_three",
    "verifier_quorum_duplicate_family",
    "verifier_quorum_family_not_external",
    "verifier_quorum_family_reserved_identity",
    "verifier_quorum_fixture_vector",
    "verifier_quorum_claim_usable_false",
    "verifier_quorum_decision_not_pass",
    "verifier_quorum_input_capsule_digest_mismatch",
    "verifier_quorum_output_digest_mismatch",
    "verifier_quorum_output_digest_placeholder",
    "verifier_quorum_implementation_digest_malformed",
    "verifier_quorum_implementation_digest_placeholder",
    "verifier_quorum_duplicate_implementation_digest",
    "verifier_quorum_missing_attestation",
    "verifier_quorum_attestation_invalid",
    "verifier_quorum_attestation_subject_mismatch",
    "verifier_quorum_unpinned_signer",
    "verifier_quorum_internal_signer",
    "verifier_quorum_canonical_output_not_pinned",
    "verifier_quorum_canonical_output_digest_mismatch",
    "verifier_quorum_cannot_open_singularity_alone",
]

WARNING_CODES = ["verifier_quorum_cannot_open_singularity_alone"]

NONCLAIM_BOUNDARY = {
    "no_production_crypto_claim": True,
    "no_runtime_containment_claim": True,
    "no_whole_system_post_quantum_safety_claim": True,
    "no_external_certification_claim": True,
    "no_independent_audit_claim": True,
    "no_government_validation_claim": True,
    "no_fips_validation_claim": True,
    "no_perfect_score_claim": True,
    "no_singularity_claim_from_verifier_quorum_alone": True,
}


class VerifierQuorumError(ValueError):
    pass


def _add(blockers: list[str], code: str) -> None:
    if code not in blockers:
        blockers.append(code)


def _ordered(blockers: list[str]) -> list[str]:
    order = {code: index for index, code in enumerate(BLOCKER_ORDER)}
    return sorted(dict.fromkeys(blockers), key=lambda code: (order.get(code, len(order)), code))


def _placeholder(text: str) -> bool:
    return bool(text) and len(set(text)) == 1


def _valid_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64_RE.fullmatch(value))


def _valid_hex128(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX128_RE.fullmatch(value))


def _tokens(value: str) -> set[str]:
    return {token for token in external_evidence._TOKEN_SPLIT_RE.split(value.lower()) if token}


def _family_reserved(value: str) -> bool:
    return bool(_tokens(value) & RESERVED_FAMILY_TOKENS)


def _load_default_aperture(capsule: dict[str, Any]) -> dict[str, Any] | None:
    path = singularity_gate.EXAMPLES_ROOT / "input-aperture-capsule.source-snapshot.v19.json"
    if not path.is_file():
        return None
    aperture = load_json_no_floats(path)
    if aperture.get("capsule_digest") == capsule.get("input_aperture_capsule_digest"):
        return aperture
    return None


def _artifact_subject(aperture_capsule: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(aperture_capsule, dict):
        return {"sha256": None, "sha3_512": None, "size": None, "manifest": None}
    return {
        "sha256": aperture_capsule.get("subject_sha256"),
        "sha3_512": aperture_capsule.get("subject_sha3_512"),
        "size": aperture_capsule.get("subject_size"),
        "manifest": aperture_capsule.get("public_sha256sums"),
    }


def build_canonical_output(
    capsule: dict[str, Any],
    aperture_capsule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the pinned canonical verifier-output object for one v20 capsule."""
    reject_floats_recursive(capsule, "capsule")
    if aperture_capsule is None:
        aperture_capsule = _load_default_aperture(capsule)
    if aperture_capsule is not None:
        reject_floats_recursive(aperture_capsule, "aperture_capsule")

    try:
        singularity_gate.validate_capsule(capsule)
        capsule_schema_valid = True
    except ValueError:
        capsule_schema_valid = False
    capsule_digest_recomputed = (
        isinstance(capsule.get("capsule_digest"), str)
        and capsule.get("capsule_digest") == singularity_gate.capsule_digest(capsule)
    )
    artifact = _artifact_subject(aperture_capsule)
    subject_artifact_digest_bound = (
        isinstance(aperture_capsule, dict)
        and aperture_capsule.get("capsule_digest") == capsule.get("input_aperture_capsule_digest")
        and _valid_hex64(artifact["sha256"])
        and _valid_hex128(artifact["sha3_512"])
        and isinstance(artifact["size"], int)
        and not isinstance(artifact["size"], bool)
    )
    score_ceiling_digest = external_evidence.score_ceiling_report_digest(capsule)
    non_claims = capsule.get("non_claims")
    blockers = capsule.get("blockers")
    blocker_list = blockers if isinstance(blockers, list) else []
    checks = {
        "capsule_schema_valid": capsule_schema_valid,
        "capsule_digest_recomputed": capsule_digest_recomputed,
        "subject_artifact_digest_bound": subject_artifact_digest_bound,
        "public_artifact_manifest_verified": _valid_hex64(artifact["manifest"]),
        "score_ceiling_report_verified": _valid_hex64(score_ceiling_digest),
        "singularity_declaration_refused": capsule.get("declaration_allowed") is False,
        "non_claims_present": isinstance(non_claims, list)
        and boundary_debt.REQUIRED_NON_CLAIMS.issubset(set(non_claims)),
        "fixture_claim_rejected": capsule.get("fixture") is not True
        or capsule.get("claim_usable") is not True
        or "fixture=true" in blocker_list
        or "claim_usable=false" in blocker_list,
        "external_evidence_gate_fail_closed": capsule.get("external_attestation_verified") is not True
        and capsule.get("declaration_allowed") is False,
    }
    subject = {
        "release_tag": capsule.get("release_tag"),
        "source_commit": capsule.get("source_commit"),
        "artifact_sha256": artifact["sha256"],
        "artifact_sha3_512": artifact["sha3_512"],
        "artifact_size": artifact["size"],
        "aperture_capsule_digest": capsule.get("capsule_digest"),
        "score_ceiling_report_digest": score_ceiling_digest,
    }
    return {
        "schema_id": CANONICAL_OUTPUT_SCHEMA_ID,
        "schema_version": CANONICAL_OUTPUT_SCHEMA_VERSION,
        "verifier_contract": VERIFIER_CONTRACT,
        "subject": subject,
        "checks": checks,
        "decision": "pass" if all(checks.values()) else "fail",
        "blocker_vector_digest": external_evidence.canonical_sha256(blocker_list, "DAYLIGHT-v20-BLOCKER-VECTOR:"),
        "non_claims_digest": external_evidence.canonical_sha256(non_claims if isinstance(non_claims, list) else [], "DAYLIGHT-v20-NON-CLAIMS:"),
        "canonical_output_digest_domain": CANONICAL_OUTPUT_DIGEST_DOMAIN,
    }


def validate_canonical_output(output: Any) -> dict[str, Any]:
    reject_floats_recursive(output, "canonical_verifier_output")
    if not isinstance(output, dict):
        raise VerifierQuorumError("canonical verifier output must be an object")
    if set(output) != REQUIRED_CANONICAL_OUTPUT_FIELDS:
        raise VerifierQuorumError("canonical verifier output field set invalid")
    if output["schema_id"] != CANONICAL_OUTPUT_SCHEMA_ID:
        raise VerifierQuorumError("canonical verifier output schema id mismatch")
    if output["schema_version"] != CANONICAL_OUTPUT_SCHEMA_VERSION:
        raise VerifierQuorumError("canonical verifier output schema version mismatch")
    if output["verifier_contract"] != VERIFIER_CONTRACT:
        raise VerifierQuorumError("canonical verifier output contract mismatch")
    if output["canonical_output_digest_domain"] != CANONICAL_OUTPUT_DIGEST_DOMAIN:
        raise VerifierQuorumError("canonical verifier output digest domain mismatch")
    subject = output["subject"]
    if not isinstance(subject, dict) or set(subject) != REQUIRED_CANONICAL_SUBJECT_FIELDS:
        raise VerifierQuorumError("canonical verifier output subject field set invalid")
    if not isinstance(subject["release_tag"], str) or not subject["release_tag"]:
        raise VerifierQuorumError("canonical verifier output release tag invalid")
    if not isinstance(subject["source_commit"], str) or not singularity_gate.HEX40_RE.fullmatch(subject["source_commit"]):
        raise VerifierQuorumError("canonical verifier output source commit invalid")
    if not _valid_hex64(subject["artifact_sha256"]):
        raise VerifierQuorumError("canonical verifier output artifact sha256 invalid")
    if not _valid_hex128(subject["artifact_sha3_512"]):
        raise VerifierQuorumError("canonical verifier output artifact sha3_512 invalid")
    if isinstance(subject["artifact_size"], bool) or not isinstance(subject["artifact_size"], int) or subject["artifact_size"] < 0:
        raise VerifierQuorumError("canonical verifier output artifact size invalid")
    if not _valid_hex64(subject["aperture_capsule_digest"]):
        raise VerifierQuorumError("canonical verifier output capsule digest invalid")
    if not _valid_hex64(subject["score_ceiling_report_digest"]):
        raise VerifierQuorumError("canonical verifier output score ceiling digest invalid")
    checks = output["checks"]
    if not isinstance(checks, dict) or set(checks) != REQUIRED_CANONICAL_CHECK_FIELDS:
        raise VerifierQuorumError("canonical verifier output checks field set invalid")
    for key, value in checks.items():
        if not isinstance(value, bool):
            raise VerifierQuorumError(f"canonical verifier output check {key} must be boolean")
    if output["decision"] not in ("pass", "fail"):
        raise VerifierQuorumError("canonical verifier output decision invalid")
    if not _valid_hex64(output["blocker_vector_digest"]):
        raise VerifierQuorumError("canonical verifier output blocker vector digest invalid")
    if not _valid_hex64(output["non_claims_digest"]):
        raise VerifierQuorumError("canonical verifier output non-claims digest invalid")
    return output


def canonical_output_bytes(output: dict[str, Any]) -> bytes:
    return dumps_canonical(validate_canonical_output(output))


def canonical_output_digest(output: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(CANONICAL_OUTPUT_DIGEST_DOMAIN.encode("utf-8"))
    digest.update(canonical_output_bytes(output))
    return digest.hexdigest()


def load_canonical_output(path: Path | str) -> dict[str, Any]:
    output_path = Path(path)
    try:
        raw = read_public_bytes(output_path, str(output_path), max_bytes=MAX_CANONICAL_OUTPUT_BYTES)
    except PathSafetyError as exc:
        raise VerifierQuorumError(f"canonical verifier output path rejected: {exc}") from exc
    if len(raw) > MAX_CANONICAL_OUTPUT_BYTES:
        raise VerifierQuorumError(f"canonical verifier output exceeds size limit: {output_path}")
    if b"\x00" in raw:
        raise VerifierQuorumError(f"canonical verifier output contains NUL bytes: {output_path}")
    value = loads_json_no_floats(raw.decode("utf-8"))
    return validate_canonical_output(value)


def _validate_vector_shape(vector: Any, blockers: list[str]) -> dict[str, Any] | None:
    if not isinstance(vector, dict):
        _add(blockers, "verifier_quorum_missing")
        return None
    reject_floats_recursive(vector, "verifier_vector")
    if set(vector) != REQUIRED_VECTOR_FIELDS:
        if "attestation_ref" not in vector:
            _add(blockers, "verifier_quorum_missing_attestation")
        if "canonical_output_schema_id" not in vector:
            _add(blockers, "verifier_quorum_canonical_output_not_pinned")
        if "verifier_implementation_digest" not in vector:
            _add(blockers, "verifier_quorum_implementation_digest_malformed")
        return None
    return vector


def _verify_vector_attestation(
    vector: dict[str, Any],
    attestation_index: dict[str, Any],
    pins: dict[str, dict[str, Any]],
    blockers: list[str],
) -> str | None:
    attestation_ref = vector.get("attestation_ref")
    if not isinstance(attestation_ref, str) or not attestation_ref:
        _add(blockers, "verifier_quorum_missing_attestation")
        return None
    attestation = attestation_index.get(attestation_ref)
    if attestation is None:
        _add(blockers, "verifier_quorum_missing_attestation")
        return attestation_ref
    try:
        external_evidence._validate_pinned_attestation(attestation, 0)
    except ValueError:
        _add(blockers, "verifier_quorum_attestation_invalid")
        return attestation_ref
    if external_evidence.identity_blockers(
        attestation["signer_identity"],
        attestation["signer_independence_class"],
        "verifier vector attestation signer",
    ):
        _add(blockers, "verifier_quorum_internal_signer")
    if attestation["subject_digest"] != external_evidence.verifier_vector_binding_digest(vector):
        _add(blockers, "verifier_quorum_attestation_subject_mismatch")
    if attestation["statement_digest"] != external_evidence.attestation_statement_digest(attestation):
        _add(blockers, "verifier_quorum_attestation_invalid")
    pin = pins.get(attestation["public_key_digest"])
    if pin is None:
        _add(blockers, "verifier_quorum_unpinned_signer")
        return attestation_ref
    if pin.get("signer_identity") != attestation["signer_identity"]:
        _add(blockers, "verifier_quorum_attestation_invalid")
        return attestation_ref
    try:
        if not external_evidence._verify_signature(attestation, pin):
            _add(blockers, "verifier_quorum_attestation_invalid")
    except ValueError:
        _add(blockers, "verifier_quorum_attestation_invalid")
    return attestation_ref


def evaluate_quorum(
    vectors: list[Any] | None,
    attestations: list[Any] | None,
    *,
    subject_capsule_digest: str | None = None,
    pinned_material: dict[str, Any] | None = None,
    capsule: dict[str, Any] | None = None,
    aperture_capsule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings = list(WARNING_CODES)
    vectors = vectors if isinstance(vectors, list) else []
    attestations = attestations if isinstance(attestations, list) else []
    if not vectors:
        _add(blockers, "verifier_quorum_missing")
    if len(vectors) < 3:
        _add(blockers, "verifier_quorum_fewer_than_three")
    if len(vectors) > 3:
        _add(blockers, "verifier_quorum_more_than_three")

    if pinned_material is None:
        pins: dict[str, dict[str, Any]] = {}
    else:
        try:
            pins, pin_blockers = external_evidence.validate_pinned_material(pinned_material)
        except ValueError:
            pins, pin_blockers = {}, ["invalid pinned material"]
        if pin_blockers:
            _add(blockers, "verifier_quorum_unpinned_signer")

    expected_output_digest: str | None = None
    if capsule is None:
        _add(blockers, "verifier_quorum_canonical_output_not_pinned")
    else:
        try:
            expected_output_digest = canonical_output_digest(build_canonical_output(capsule, aperture_capsule))
        except ValueError:
            _add(blockers, "verifier_quorum_canonical_output_not_pinned")

    attestation_index: dict[str, dict[str, Any]] = {}
    for attestation in attestations:
        if isinstance(attestation, dict) and isinstance(attestation.get("attestation_id"), str):
            attestation_index[attestation["attestation_id"]] = attestation

    valid_vectors: list[dict[str, Any]] = []
    families_seen: list[str] = []
    output_digests: list[str] = []
    implementation_digests: list[str] = []
    vector_digests: list[str] = []
    attestation_ids: list[str] = []

    for item in vectors:
        vector = _validate_vector_shape(item, blockers)
        if vector is None:
            continue
        valid_vectors.append(vector)
        families_seen.append(vector["verifier_family"])
        if vector["verifier_family_independence_class"] != external_evidence.REQUIRED_INDEPENDENCE_CLASS:
            _add(blockers, "verifier_quorum_family_not_external")
        if _family_reserved(vector["verifier_family"]):
            _add(blockers, "verifier_quorum_family_reserved_identity")
        if vector["fixture"] is True:
            _add(blockers, "verifier_quorum_fixture_vector")
        if vector["claim_usable"] is not True:
            _add(blockers, "verifier_quorum_claim_usable_false")
        if vector["decision"] != "pass":
            _add(blockers, "verifier_quorum_decision_not_pass")
        implementation_digest = vector["verifier_implementation_digest"]
        if not _valid_hex64(implementation_digest):
            _add(blockers, "verifier_quorum_implementation_digest_malformed")
        elif _placeholder(implementation_digest):
            _add(blockers, "verifier_quorum_implementation_digest_placeholder")
        else:
            implementation_digests.append(implementation_digest)
        if vector["verifier_implementation_kind"] not in ALLOWED_IMPLEMENTATION_KINDS:
            _add(blockers, "verifier_quorum_implementation_digest_malformed")
        if not _valid_hex64(vector["input_capsule_digest"]) or (
            subject_capsule_digest is not None and vector["input_capsule_digest"] != subject_capsule_digest
        ):
            _add(blockers, "verifier_quorum_input_capsule_digest_mismatch")
        output_digest = vector["output_digest"]
        canonical_digest = vector["canonical_output_digest"]
        if not _valid_hex64(output_digest):
            _add(blockers, "verifier_quorum_output_digest_mismatch")
        elif _placeholder(output_digest):
            _add(blockers, "verifier_quorum_output_digest_placeholder")
        else:
            output_digests.append(output_digest)
        if vector["canonical_output_schema_id"] != CANONICAL_OUTPUT_SCHEMA_ID:
            _add(blockers, "verifier_quorum_canonical_output_not_pinned")
        if not _valid_hex64(canonical_digest) or canonical_digest != output_digest:
            _add(blockers, "verifier_quorum_canonical_output_digest_mismatch")
        if expected_output_digest is not None and output_digest != expected_output_digest:
            _add(blockers, "verifier_quorum_canonical_output_digest_mismatch")
        vector_digests.append(external_evidence.verifier_vector_binding_digest(vector))
        attestation_id = _verify_vector_attestation(vector, attestation_index, pins, blockers)
        if attestation_id is not None:
            attestation_ids.append(attestation_id)

    duplicate_families = sorted({family for family in families_seen if families_seen.count(family) > 1})
    if duplicate_families:
        _add(blockers, "verifier_quorum_duplicate_family")
    if len(set(families_seen)) < 3:
        _add(blockers, "verifier_quorum_fewer_than_three")
    if len(set(families_seen)) > 3:
        _add(blockers, "verifier_quorum_more_than_three")
    if len(set(implementation_digests)) != len(implementation_digests):
        _add(blockers, "verifier_quorum_duplicate_implementation_digest")
    if len(set(output_digests)) > 1:
        _add(blockers, "verifier_quorum_output_digest_mismatch")

    blocker_codes = _ordered(blockers)
    accepted = not blocker_codes
    return {
        "schema_id": QUORUM_REPORT_SCHEMA_ID,
        "schema_version": QUORUM_REPORT_SCHEMA_VERSION,
        "accepted": accepted,
        "quorum_closed": accepted,
        "declaration_allowed": False,
        "subject_capsule_digest": subject_capsule_digest,
        "families_seen": sorted(set(families_seen)),
        "output_digest": output_digests[0] if output_digests and len(set(output_digests)) == 1 else None,
        "vector_digests": sorted(vector_digests),
        "implementation_digests": sorted(implementation_digests),
        "attestation_ids": sorted(attestation_ids),
        "closed_gates": [QUORUM_GATE] if accepted else [],
        "still_open_gates": [
            "reproducible_build.non_fixture_subject_bound_rebuilds",
            "aperture_firewall_boundary.external_profile_expansion",
            "external_attestation.pinned_cryptographic_verification",
            "singularity_declaration",
        ],
        "blocker_codes": blocker_codes,
        "warning_codes": warnings,
        "nonclaim_boundary": dict(NONCLAIM_BOUNDARY),
    }


def evaluate_bundle_quorum(
    bundle: dict[str, Any],
    *,
    pinned_material: dict[str, Any] | None = None,
    capsule: dict[str, Any] | None = None,
    aperture_capsule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    subject = bundle.get("subject") if isinstance(bundle, dict) else None
    subject_digest = subject.get("aperture_capsule_digest") if isinstance(subject, dict) else None
    return evaluate_quorum(
        bundle.get("claim_usable_verifier_vectors") if isinstance(bundle, dict) else None,
        bundle.get("pinned_attestations") if isinstance(bundle, dict) else None,
        subject_capsule_digest=subject_digest if isinstance(subject_digest, str) else None,
        pinned_material=pinned_material,
        capsule=capsule,
        aperture_capsule=aperture_capsule,
    )
