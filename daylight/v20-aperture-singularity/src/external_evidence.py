"""Daylight v20 External Evidence Intake.

This module defines the admissibility contract for real external evidence
against the four remaining Singularity blockers:

1. independent rebuild receipts,
2. external firewall-profile review,
3. non-fixture claim-usable 3-of-3 verifier vectors,
4. pinned cryptographic attestation verification.

It is fail-closed. Repo-owned, self-signed, internal, fixture, placeholder,
mismatched, unsigned, or unpinned evidence is rejected. Cryptographic
signature verification is not implemented yet, so every bundle carries the
blocker "pinned cryptographic attestation verification not implemented" and
``external_attestation_verified`` stays false. Nothing in this module raises
the score, marks fixture evidence claim-usable, or opens the declaration gate.

Verification is deterministic and local: no network module is used, and the
result must not depend on wall-clock time, hostname, username, or local paths.
Staleness is digest-defined, not time-defined: evidence binds to the current
capsule, profile, rule, and negative-case digests, and stops binding when any
of them changes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path
from typing import Any

from . import boundary_debt
from . import evidence_audit
from . import firewall_profile
from . import public_artifact
from . import singularity_gate
from .canonical import canonical_sha256, load_json_no_floats, loads_json_no_floats, reject_floats_recursive
from .pathsafe import PathSafetyError, normalize_repo_relative, require_regular_public_file

SCHEMA_ID = "daylight.v20.external-evidence.bundle"
SCHEMA_VERSION = 1
PINNED_MATERIAL_SCHEMA_ID = "daylight.v20.pinned-verification-material"
PINNED_MATERIAL_SCHEMA_VERSION = 1
INTAKE_REPORT_SCHEMA_ID = "daylight-v20-external-evidence-intake-report"
INTAKE_REPORT_SCHEMA_VERSION = "0.1.0"

D_BUNDLE = "DAYLIGHT-v20-EXTERNAL-EVIDENCE-BUNDLE:"
D_REBUILD_RECEIPT = "DAYLIGHT-v20-EXTERNAL-REBUILD-RECEIPT:"
D_FIREWALL_REVIEW = "DAYLIGHT-v20-EXTERNAL-FIREWALL-REVIEW:"
D_VERIFIER_VECTOR = "DAYLIGHT-v20-EXTERNAL-VERIFIER-VECTOR:"
D_ATTESTATION_STATEMENT = "DAYLIGHT-v20-PINNED-ATTESTATION-STATEMENT:"
D_SCORE_CEILING_REPORT = "DAYLIGHT-v20-SCORE-CEILING-REPORT:"
D_FIREWALL_RULES = "DAYLIGHT-v20-FIREWALL-REVIEWED-RULES:"
D_NEGATIVE_CASES = "DAYLIGHT-v20-FIREWALL-NEGATIVE-CASES:"

ATTESTATION_NOT_IMPLEMENTED_BLOCKER = "pinned cryptographic attestation verification not implemented"
FIREWALL_REVIEW_SCOPE = "aperture-public-artifact-firewall-profile"
REQUIRED_INDEPENDENCE_CLASS = "external"
REQUIRED_VERIFIER_FAMILY_COUNT = 3
MIN_REBUILD_RECEIPTS = 2
MAX_SIGNATURE_LENGTH = 8192
MAX_BUNDLE_BYTES = 5_000_000

# Identities containing any of these tokens are never independent. External
# reviewers must choose an identity that does not contain a reserved token.
FORBIDDEN_IDENTITY_TOKENS = frozenset(
    {
        "self",
        "internal",
        "local",
        "repo",
        "repository",
        "harness",
        "fixture",
        "fixtures",
        "unknown",
        "wuci",
        "noxframe",
    }
)

# Algorithms the future pinned verifier is contracted to accept. Anything else
# is rejected now. An algorithm listed here is still not verified until it is
# also a member of IMPLEMENTED_SIGNATURE_ALGORITHMS.
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({"ed25519"})

# Empty until a real deterministic local signature verifier lands. This set
# must only grow together with actual verification code; flipping it without
# implementing verification is fixture laundering.
IMPLEMENTED_SIGNATURE_ALGORITHMS: frozenset[str] = frozenset()

FINDING_LEVELS = frozenset({"none", "minor", "major", "critical", "contradiction"})
BLOCKING_FINDING_LEVELS = frozenset({"critical", "contradiction"})

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PINNED_MATERIAL_REF = "daylight/v20-aperture-singularity/pinned/external-verification-material.v20.json"
PINNED_MATERIAL_PATH = PACKAGE_ROOT / "pinned" / "external-verification-material.v20.json"

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

REQUIRED_BUNDLE_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "subject",
        "independent_rebuild_receipts",
        "firewall_profile_reviews",
        "claim_usable_verifier_vectors",
        "pinned_attestations",
        "bundle_digest",
    }
)

REQUIRED_SUBJECT_FIELDS = frozenset(
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

REQUIRED_REBUILD_RECEIPT_FIELDS = frozenset(
    {
        "receipt_id",
        "builder_identity",
        "builder_independence_class",
        "builder_contact_optional",
        "source_commit",
        "release_tag",
        "build_instructions_digest",
        "environment_digest",
        "artifact_sha256",
        "artifact_sha3_512",
        "artifact_size",
        "byte_reproducible",
        "fixture",
        "claim_usable",
        "attestation_ref",
    }
)

REQUIRED_FIREWALL_REVIEW_FIELDS = frozenset(
    {
        "review_id",
        "reviewer_identity",
        "reviewer_independence_class",
        "review_scope",
        "profile_digest",
        "reviewed_rules_digest",
        "negative_cases_digest",
        "finding_level",
        "fixture",
        "claim_usable",
        "attestation_ref",
    }
)

REQUIRED_VERIFIER_VECTOR_FIELDS = frozenset(
    {
        "vector_id",
        "verifier_family",
        "verifier_implementation_digest",
        "input_capsule_digest",
        "output_digest",
        "decision",
        "fixture",
        "claim_usable",
        "attestation_ref",
    }
)

REQUIRED_PINNED_ATTESTATION_FIELDS = frozenset(
    {
        "attestation_id",
        "subject_digest",
        "statement_digest",
        "signer_identity",
        "signer_independence_class",
        "signature_algorithm",
        "public_key_digest",
        "signature",
        "verification_material_ref",
        "fixture",
        "claim_usable",
    }
)

REQUIRED_PINNED_SIGNER_FIELDS = frozenset(
    {
        "signer_identity",
        "signer_independence_class",
        "signature_algorithm",
        "public_key_digest",
        "public_key_b64",
        "pinned_by_commit",
    }
)


class ExternalEvidenceError(ValueError):
    pass


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalEvidenceError(f"{name} must be a non-empty string")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ExternalEvidenceError(f"{name} must be boolean")
    return value


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExternalEvidenceError(f"{name} must be a nonnegative integer")
    return value


def _is_placeholder_hex(text: str) -> bool:
    return len(set(text)) == 1


def _decode_base64(value: str, name: str) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ExternalEvidenceError(f"{name} must be valid base64 text") from exc
    if not decoded:
        raise ExternalEvidenceError(f"{name} must not decode to empty bytes")
    return decoded


def _require_hex(value: Any, name: str, regex: re.Pattern[str]) -> str:
    text = _require_str(value, name)
    if not regex.fullmatch(text):
        raise ExternalEvidenceError(f"{name} must be a lowercase hex digest of expected length")
    if _is_placeholder_hex(text):
        raise ExternalEvidenceError(f"{name} must not be a placeholder value")
    return text


def identity_blockers(identity: str, independence_class: str, label: str) -> list[str]:
    out: list[str] = []
    tokens = {token for token in _TOKEN_SPLIT_RE.split(identity.lower()) if token}
    forbidden = sorted(tokens & FORBIDDEN_IDENTITY_TOKENS)
    if forbidden:
        out.append(f"{label} identity is not independent: {identity} (forbidden tokens: {', '.join(forbidden)})")
    if independence_class != REQUIRED_INDEPENDENCE_CLASS:
        out.append(f"{label} independence class must be external: {independence_class}")
    return out


def bundle_digest(bundle: dict[str, Any]) -> str:
    body = {key: value for key, value in bundle.items() if key != "bundle_digest"}
    return canonical_sha256(body, D_BUNDLE)


def rebuild_receipt_binding_digest(receipt: dict[str, Any]) -> str:
    body = {key: value for key, value in receipt.items() if key != "attestation_ref"}
    return canonical_sha256(body, D_REBUILD_RECEIPT)


def firewall_review_binding_digest(review: dict[str, Any]) -> str:
    body = {key: value for key, value in review.items() if key != "attestation_ref"}
    return canonical_sha256(body, D_FIREWALL_REVIEW)


def verifier_vector_binding_digest(vector: dict[str, Any]) -> str:
    body = {key: value for key, value in vector.items() if key != "attestation_ref"}
    return canonical_sha256(body, D_VERIFIER_VECTOR)


def attestation_statement_digest(attestation: dict[str, Any]) -> str:
    body = {key: value for key, value in attestation.items() if key not in ("statement_digest", "signature")}
    return canonical_sha256(body, D_ATTESTATION_STATEMENT)


def score_ceiling_report_digest(capsule: dict[str, Any]) -> str:
    return canonical_sha256(evidence_audit.score_ceiling_report(capsule), D_SCORE_CEILING_REPORT)


def firewall_rules_digest() -> str:
    return canonical_sha256(
        {
            "expected_files": list(public_artifact.EXPECTED_FILES),
            "forbidden_suffixes": sorted(public_artifact.FORBIDDEN_SUFFIXES),
            "forbidden_path_parts": sorted(public_artifact.FORBIDDEN_PATH_PARTS),
            "forbidden_name_pattern": public_artifact.FORBIDDEN_NAME_RE.pattern,
            "secret_marker_digests": [hashlib.sha256(marker).hexdigest() for marker in public_artifact.SECRET_MARKERS],
            "max_file_bytes": 5_000_000,
        },
        D_FIREWALL_RULES,
    )


def firewall_negative_cases_digest() -> str:
    return canonical_sha256(
        {
            "profile_id": firewall_profile.PROFILE_ID,
            "required_cases": firewall_profile.REQUIRED_CASES,
        },
        D_NEGATIVE_CASES,
    )


def _validate_subject(subject: Any) -> dict[str, Any]:
    if not isinstance(subject, dict):
        raise ExternalEvidenceError("subject must be an object")
    reject_floats_recursive(subject, "subject")
    if set(subject) != REQUIRED_SUBJECT_FIELDS:
        raise ExternalEvidenceError("subject field set invalid")
    _require_str(subject["release_tag"], "subject.release_tag")
    _require_hex(subject["source_commit"], "subject.source_commit", HEX40_RE)
    _require_hex(subject["artifact_sha256"], "subject.artifact_sha256", HEX64_RE)
    _require_hex(subject["artifact_sha3_512"], "subject.artifact_sha3_512", HEX128_RE)
    _require_int(subject["artifact_size"], "subject.artifact_size")
    _require_hex(subject["aperture_capsule_digest"], "subject.aperture_capsule_digest", HEX64_RE)
    _require_hex(subject["score_ceiling_report_digest"], "subject.score_ceiling_report_digest", HEX64_RE)
    return subject


def _validate_rebuild_receipt(receipt: Any, index: int) -> None:
    if not isinstance(receipt, dict):
        raise ExternalEvidenceError(f"independent_rebuild_receipts[{index}] must be an object")
    reject_floats_recursive(receipt, f"independent_rebuild_receipts[{index}]")
    if set(receipt) != REQUIRED_REBUILD_RECEIPT_FIELDS:
        raise ExternalEvidenceError(f"independent_rebuild_receipts[{index}] field set invalid")
    prefix = f"independent_rebuild_receipts[{index}]"
    _require_str(receipt["receipt_id"], f"{prefix}.receipt_id")
    _require_str(receipt["builder_identity"], f"{prefix}.builder_identity")
    _require_str(receipt["builder_independence_class"], f"{prefix}.builder_independence_class")
    if receipt["builder_contact_optional"] is not None:
        _require_str(receipt["builder_contact_optional"], f"{prefix}.builder_contact_optional")
    _require_hex(receipt["source_commit"], f"{prefix}.source_commit", HEX40_RE)
    _require_str(receipt["release_tag"], f"{prefix}.release_tag")
    _require_hex(receipt["build_instructions_digest"], f"{prefix}.build_instructions_digest", HEX64_RE)
    _require_hex(receipt["environment_digest"], f"{prefix}.environment_digest", HEX64_RE)
    _require_hex(receipt["artifact_sha256"], f"{prefix}.artifact_sha256", HEX64_RE)
    _require_hex(receipt["artifact_sha3_512"], f"{prefix}.artifact_sha3_512", HEX128_RE)
    _require_int(receipt["artifact_size"], f"{prefix}.artifact_size")
    _require_bool(receipt["byte_reproducible"], f"{prefix}.byte_reproducible")
    _require_bool(receipt["fixture"], f"{prefix}.fixture")
    _require_bool(receipt["claim_usable"], f"{prefix}.claim_usable")
    _require_str(receipt["attestation_ref"], f"{prefix}.attestation_ref")


def _validate_firewall_review(review: Any, index: int) -> None:
    if not isinstance(review, dict):
        raise ExternalEvidenceError(f"firewall_profile_reviews[{index}] must be an object")
    reject_floats_recursive(review, f"firewall_profile_reviews[{index}]")
    if set(review) != REQUIRED_FIREWALL_REVIEW_FIELDS:
        raise ExternalEvidenceError(f"firewall_profile_reviews[{index}] field set invalid")
    prefix = f"firewall_profile_reviews[{index}]"
    _require_str(review["review_id"], f"{prefix}.review_id")
    _require_str(review["reviewer_identity"], f"{prefix}.reviewer_identity")
    _require_str(review["reviewer_independence_class"], f"{prefix}.reviewer_independence_class")
    _require_str(review["review_scope"], f"{prefix}.review_scope")
    _require_hex(review["profile_digest"], f"{prefix}.profile_digest", HEX64_RE)
    _require_hex(review["reviewed_rules_digest"], f"{prefix}.reviewed_rules_digest", HEX64_RE)
    _require_hex(review["negative_cases_digest"], f"{prefix}.negative_cases_digest", HEX64_RE)
    finding = _require_str(review["finding_level"], f"{prefix}.finding_level")
    if finding not in FINDING_LEVELS:
        raise ExternalEvidenceError(f"{prefix}.finding_level unsupported: {finding}")
    _require_bool(review["fixture"], f"{prefix}.fixture")
    _require_bool(review["claim_usable"], f"{prefix}.claim_usable")
    _require_str(review["attestation_ref"], f"{prefix}.attestation_ref")


def _validate_verifier_vector(vector: Any, index: int) -> None:
    if not isinstance(vector, dict):
        raise ExternalEvidenceError(f"claim_usable_verifier_vectors[{index}] must be an object")
    reject_floats_recursive(vector, f"claim_usable_verifier_vectors[{index}]")
    if set(vector) != REQUIRED_VERIFIER_VECTOR_FIELDS:
        raise ExternalEvidenceError(f"claim_usable_verifier_vectors[{index}] field set invalid")
    prefix = f"claim_usable_verifier_vectors[{index}]"
    _require_str(vector["vector_id"], f"{prefix}.vector_id")
    _require_str(vector["verifier_family"], f"{prefix}.verifier_family")
    _require_hex(vector["verifier_implementation_digest"], f"{prefix}.verifier_implementation_digest", HEX64_RE)
    _require_hex(vector["input_capsule_digest"], f"{prefix}.input_capsule_digest", HEX64_RE)
    _require_hex(vector["output_digest"], f"{prefix}.output_digest", HEX64_RE)
    decision = _require_str(vector["decision"], f"{prefix}.decision")
    if decision not in ("pass", "fail"):
        raise ExternalEvidenceError(f"{prefix}.decision must be pass or fail")
    _require_bool(vector["fixture"], f"{prefix}.fixture")
    _require_bool(vector["claim_usable"], f"{prefix}.claim_usable")
    _require_str(vector["attestation_ref"], f"{prefix}.attestation_ref")


def _validate_pinned_attestation(attestation: Any, index: int) -> None:
    if not isinstance(attestation, dict):
        raise ExternalEvidenceError(f"pinned_attestations[{index}] must be an object")
    reject_floats_recursive(attestation, f"pinned_attestations[{index}]")
    if set(attestation) != REQUIRED_PINNED_ATTESTATION_FIELDS:
        raise ExternalEvidenceError(f"pinned_attestations[{index}] field set invalid")
    prefix = f"pinned_attestations[{index}]"
    _require_str(attestation["attestation_id"], f"{prefix}.attestation_id")
    _require_hex(attestation["subject_digest"], f"{prefix}.subject_digest", HEX64_RE)
    _require_hex(attestation["statement_digest"], f"{prefix}.statement_digest", HEX64_RE)
    _require_str(attestation["signer_identity"], f"{prefix}.signer_identity")
    _require_str(attestation["signer_independence_class"], f"{prefix}.signer_independence_class")
    _require_str(attestation["signature_algorithm"], f"{prefix}.signature_algorithm")
    _require_hex(attestation["public_key_digest"], f"{prefix}.public_key_digest", HEX64_RE)
    signature = _require_str(attestation["signature"], f"{prefix}.signature")
    if len(signature) > MAX_SIGNATURE_LENGTH:
        raise ExternalEvidenceError(f"{prefix}.signature exceeds maximum length")
    if not BASE64_RE.fullmatch(signature):
        raise ExternalEvidenceError(f"{prefix}.signature must be base64 text")
    signature_bytes = _decode_base64(signature, f"{prefix}.signature")
    if len(set(signature)) == 1 or len(set(signature_bytes)) == 1:
        raise ExternalEvidenceError(f"{prefix}.signature must not be a placeholder value")
    _require_str(attestation["verification_material_ref"], f"{prefix}.verification_material_ref")
    _require_bool(attestation["fixture"], f"{prefix}.fixture")
    _require_bool(attestation["claim_usable"], f"{prefix}.claim_usable")


def validate_pinned_material(material: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Validate the pinned verification material registry.

    Returns (pins keyed by public_key_digest, blockers). Invalid entries are
    never pinned; every problem is reported as a blocker so the registry fails
    closed instead of silently accepting a bad pin.
    """
    if not isinstance(material, dict):
        raise ExternalEvidenceError("pinned verification material must be an object")
    reject_floats_recursive(material, "pinned_verification_material")
    if set(material) != {"schema_id", "schema_version", "non_claims_acknowledged", "pinned_signers"}:
        raise ExternalEvidenceError("pinned verification material field set invalid")
    if material["schema_id"] != PINNED_MATERIAL_SCHEMA_ID or material["schema_version"] != PINNED_MATERIAL_SCHEMA_VERSION:
        raise ExternalEvidenceError("unsupported pinned verification material schema")
    acknowledged = material["non_claims_acknowledged"]
    if not isinstance(acknowledged, list):
        raise ExternalEvidenceError("pinned verification material non_claims_acknowledged must be a list")
    for item in acknowledged:
        _require_str(item, "pinned verification material non_claims_acknowledged item")
    if not boundary_debt.REQUIRED_NON_CLAIMS.issubset(set(acknowledged)):
        raise ExternalEvidenceError("pinned verification material non-claims incomplete")
    signers = material["pinned_signers"]
    if not isinstance(signers, list):
        raise ExternalEvidenceError("pinned_signers must be a list")

    blockers: list[str] = []
    pins: dict[str, dict[str, Any]] = {}
    for index, signer in enumerate(signers):
        try:
            if not isinstance(signer, dict):
                raise ExternalEvidenceError(f"pinned_signers[{index}] must be an object")
            if set(signer) != REQUIRED_PINNED_SIGNER_FIELDS:
                raise ExternalEvidenceError(f"pinned_signers[{index}] field set invalid")
            prefix = f"pinned_signers[{index}]"
            _require_str(signer["signer_identity"], f"{prefix}.signer_identity")
            _require_str(signer["signer_independence_class"], f"{prefix}.signer_independence_class")
            _require_str(signer["signature_algorithm"], f"{prefix}.signature_algorithm")
            _require_hex(signer["public_key_digest"], f"{prefix}.public_key_digest", HEX64_RE)
            key_text = _require_str(signer["public_key_b64"], f"{prefix}.public_key_b64")
            if not BASE64_RE.fullmatch(key_text):
                raise ExternalEvidenceError(f"{prefix}.public_key_b64 must be base64 text")
            public_key_bytes = _decode_base64(key_text, f"{prefix}.public_key_b64")
            if len(set(public_key_bytes)) == 1:
                raise ExternalEvidenceError(f"{prefix}.public_key_b64 must not decode to placeholder bytes")
            if hashlib.sha256(public_key_bytes).hexdigest() != signer["public_key_digest"]:
                raise ExternalEvidenceError(f"{prefix}.public_key_digest does not match public_key_b64")
            _require_hex(signer["pinned_by_commit"], f"{prefix}.pinned_by_commit", HEX40_RE)
        except ValueError as exc:
            blockers.append(f"pinned verification material entry rejected: {exc}")
            continue
        entry_blockers = identity_blockers(
            signer["signer_identity"], signer["signer_independence_class"], f"pinned signer {signer['signer_identity']}"
        )
        if signer["signature_algorithm"] not in SUPPORTED_SIGNATURE_ALGORITHMS:
            entry_blockers.append(
                f"pinned signer {signer['signer_identity']} unsupported signature algorithm: {signer['signature_algorithm']}"
            )
        if signer["public_key_digest"] in pins:
            entry_blockers.append(f"duplicate pinned public key digest: {signer['public_key_digest']}")
        if entry_blockers:
            blockers.extend(entry_blockers)
            continue
        pins[signer["public_key_digest"]] = signer
    return pins, blockers


def load_pinned_material(path: Path | str | None = None) -> dict[str, Any]:
    return load_json_no_floats(Path(path) if path is not None else PINNED_MATERIAL_PATH)


def _verify_signature(attestation: dict[str, Any], pin: dict[str, Any]) -> bool:
    """Pinned-signature verification hook.

    Real verification is not implemented. When it lands it must be a
    deterministic, local, offline check of ``attestation["signature"]``
    against the pinned public key material, and its algorithm must be listed
    in IMPLEMENTED_SIGNATURE_ALGORITHMS. It must never be replaced by a
    constant, an environment probe, or a fixture flag.
    """
    if attestation["signature_algorithm"] not in IMPLEMENTED_SIGNATURE_ALGORITHMS:
        return False
    return False


def _evaluate_attestations(
    attestations: list[Any],
    pins: dict[str, dict[str, Any]],
    pin_blockers: list[str],
) -> dict[str, Any]:
    blockers: list[str] = list(pin_blockers)
    index_by_id: dict[str, dict[str, Any]] = {}
    valid_count = 0
    verified_count = 0
    for index, attestation in enumerate(attestations):
        try:
            _validate_pinned_attestation(attestation, index)
        except ValueError as exc:
            blockers.append(f"attestation {index} invalid: {exc}")
            continue
        attestation_id = attestation["attestation_id"]
        if attestation_id in index_by_id:
            blockers.append(f"duplicate attestation id: {attestation_id}")
            continue
        valid_count += 1
        item_blockers: list[str] = []
        item_blockers.extend(
            identity_blockers(
                attestation["signer_identity"],
                attestation["signer_independence_class"],
                f"attestation {attestation_id} signer",
            )
        )
        if attestation["fixture"] is True:
            item_blockers.append(f"attestation {attestation_id} is fixture evidence")
        if attestation["claim_usable"] is not True:
            item_blockers.append(f"attestation {attestation_id} is not claim-usable")
        if attestation["signature_algorithm"] not in SUPPORTED_SIGNATURE_ALGORITHMS:
            item_blockers.append(
                f"attestation {attestation_id} unsupported signature algorithm: {attestation['signature_algorithm']}"
            )
        if attestation["statement_digest"] != attestation_statement_digest(attestation):
            item_blockers.append(f"attestation {attestation_id} statement digest mismatch")
        try:
            material_ref = normalize_repo_relative(attestation["verification_material_ref"])
        except PathSafetyError as exc:
            material_ref = None
            item_blockers.append(f"attestation {attestation_id} verification material ref rejected: {exc}")
        if material_ref is not None and material_ref != PINNED_MATERIAL_REF:
            item_blockers.append(
                f"attestation {attestation_id} verification material ref is not the pinned registry: {material_ref}"
            )
        pin = pins.get(attestation["public_key_digest"])
        crypto_verified = False
        if pin is None:
            item_blockers.append(f"attestation {attestation_id} public key is not pinned")
        else:
            if pin["signer_identity"] != attestation["signer_identity"]:
                item_blockers.append(f"attestation {attestation_id} signer identity does not match pinned material")
            if pin["signature_algorithm"] != attestation["signature_algorithm"]:
                item_blockers.append(f"attestation {attestation_id} signature algorithm does not match pinned material")
            if not item_blockers:
                crypto_verified = _verify_signature(attestation, pin)
                if not crypto_verified:
                    item_blockers.append(f"attestation {attestation_id} signature is not cryptographically verified")
        if crypto_verified:
            verified_count += 1
        blockers.extend(item_blockers)
        index_by_id[attestation_id] = {
            "attestation": attestation,
            "blockers": item_blockers,
            "crypto_verified": crypto_verified,
            "referenced": False,
        }
    verification_implemented = bool(IMPLEMENTED_SIGNATURE_ALGORITHMS)
    if not verification_implemented:
        blockers.append(ATTESTATION_NOT_IMPLEMENTED_BLOCKER)
    return {
        "attestation_count": len(attestations),
        "valid_shape_count": valid_count,
        "cryptographically_verified_count": verified_count,
        "verification_implemented": verification_implemented,
        "pinned_key_count": len(pins),
        "blockers": blockers,
        "index_by_id": index_by_id,
    }


def _binding_blockers(
    label: str,
    attestation_ref: str,
    binding_digest: str,
    attestation_index: dict[str, dict[str, Any]],
) -> list[str]:
    entry = attestation_index.get(attestation_ref)
    if entry is None:
        return [f"{label} attestation reference not found: {attestation_ref}"]
    entry["referenced"] = True
    out: list[str] = []
    if entry["blockers"]:
        out.append(f"{label} attestation is not admissible: {attestation_ref}")
    if entry["attestation"]["subject_digest"] != binding_digest:
        out.append(f"{label} attestation subject digest does not match evidence item")
    return out


def _evaluate_rebuild_receipts(
    receipts: list[Any],
    subject: dict[str, Any] | None,
    attestation_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    blockers: list[str] = []
    valid: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, receipt in enumerate(receipts):
        try:
            _validate_rebuild_receipt(receipt, index)
        except ValueError as exc:
            blockers.append(f"rebuild receipt {index} invalid: {exc}")
            continue
        receipt_id = receipt["receipt_id"]
        if receipt_id in seen_ids:
            blockers.append(f"duplicate rebuild receipt id: {receipt_id}")
            continue
        seen_ids.add(receipt_id)
        item_blockers: list[str] = []
        label = f"rebuild receipt {receipt_id}"
        item_blockers.extend(
            identity_blockers(receipt["builder_identity"], receipt["builder_independence_class"], f"{label} builder")
        )
        if receipt["fixture"] is True:
            item_blockers.append(f"{label} is fixture evidence")
        if receipt["claim_usable"] is not True:
            item_blockers.append(f"{label} is not claim-usable")
        if receipt["byte_reproducible"] is not True:
            item_blockers.append(f"{label} does not claim a byte-reproducible rebuild")
        if subject is not None:
            if receipt["source_commit"] != subject["source_commit"]:
                item_blockers.append(f"{label} source commit does not match subject")
            if receipt["release_tag"] != subject["release_tag"]:
                item_blockers.append(f"{label} release tag does not match subject")
            if receipt["artifact_sha256"] != subject["artifact_sha256"]:
                item_blockers.append(f"{label} artifact SHA-256 does not match subject")
            if receipt["artifact_sha3_512"] != subject["artifact_sha3_512"]:
                item_blockers.append(f"{label} artifact SHA3-512 does not match subject")
            if receipt["artifact_size"] != subject["artifact_size"]:
                item_blockers.append(f"{label} artifact size does not match subject")
        item_blockers.extend(
            _binding_blockers(label, receipt["attestation_ref"], rebuild_receipt_binding_digest(receipt), attestation_index)
        )
        blockers.extend(item_blockers)
        valid.append(receipt)

    builder_identities = [receipt["builder_identity"].lower() for receipt in valid]
    environment_digests = [receipt["environment_digest"] for receipt in valid]
    if len(valid) < MIN_REBUILD_RECEIPTS:
        blockers.append("fewer than two independent rebuild receipts")
    duplicate_builders = sorted({item for item in builder_identities if builder_identities.count(item) > 1})
    for item in duplicate_builders:
        blockers.append(f"rebuild receipts share the same builder identity: {item}")
    duplicate_environments = sorted({item for item in environment_digests if environment_digests.count(item) > 1})
    for item in duplicate_environments:
        blockers.append(f"rebuild receipts share the same environment digest: {item}")
    return {
        "receipt_count": len(receipts),
        "valid_shape_count": len(valid),
        "independent_builder_count": len(set(builder_identities)),
        "distinct_environment_count": len(set(environment_digests)),
        "blockers": blockers,
    }


def _evaluate_firewall_reviews(
    reviews: list[Any],
    attestation_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    blockers: list[str] = []
    valid_count = 0
    seen_ids: set[str] = set()
    expected_profile_digest = firewall_profile.profile_digest()
    expected_rules_digest = firewall_rules_digest()
    expected_cases_digest = firewall_negative_cases_digest()
    for index, review in enumerate(reviews):
        try:
            _validate_firewall_review(review, index)
        except ValueError as exc:
            blockers.append(f"firewall review {index} invalid: {exc}")
            continue
        review_id = review["review_id"]
        if review_id in seen_ids:
            blockers.append(f"duplicate firewall review id: {review_id}")
            continue
        seen_ids.add(review_id)
        valid_count += 1
        item_blockers: list[str] = []
        label = f"firewall review {review_id}"
        item_blockers.extend(
            identity_blockers(review["reviewer_identity"], review["reviewer_independence_class"], f"{label} reviewer")
        )
        if review["fixture"] is True:
            item_blockers.append(f"{label} is fixture evidence")
        if review["claim_usable"] is not True:
            item_blockers.append(f"{label} is not claim-usable")
        if review["review_scope"] != FIREWALL_REVIEW_SCOPE:
            item_blockers.append(f"{label} scope must be {FIREWALL_REVIEW_SCOPE}: {review['review_scope']}")
        if review["profile_digest"] != expected_profile_digest:
            item_blockers.append(f"{label} does not bind to the current firewall profile digest")
        if review["reviewed_rules_digest"] != expected_rules_digest:
            item_blockers.append(f"{label} does not bind to the current firewall rules digest")
        if review["negative_cases_digest"] != expected_cases_digest:
            item_blockers.append(f"{label} does not bind to the negative case matrix digest")
        if review["finding_level"] in BLOCKING_FINDING_LEVELS:
            item_blockers.append(f"{label} reports blocking finding level: {review['finding_level']}")
        item_blockers.extend(
            _binding_blockers(label, review["attestation_ref"], firewall_review_binding_digest(review), attestation_index)
        )
        blockers.extend(item_blockers)
    if valid_count < 1:
        blockers.append("no external firewall profile review supplied")
    return {
        "review_count": len(reviews),
        "valid_shape_count": valid_count,
        "expected_profile_digest": expected_profile_digest,
        "expected_rules_digest": expected_rules_digest,
        "expected_negative_cases_digest": expected_cases_digest,
        "blockers": blockers,
    }


def _evaluate_verifier_vectors(
    vectors: list[Any],
    subject: dict[str, Any] | None,
    attestation_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    blockers: list[str] = []
    valid: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, vector in enumerate(vectors):
        try:
            _validate_verifier_vector(vector, index)
        except ValueError as exc:
            blockers.append(f"verifier vector {index} invalid: {exc}")
            continue
        vector_id = vector["vector_id"]
        if vector_id in seen_ids:
            blockers.append(f"duplicate verifier vector id: {vector_id}")
            continue
        seen_ids.add(vector_id)
        item_blockers: list[str] = []
        label = f"verifier vector {vector_id}"
        if vector["fixture"] is True:
            item_blockers.append(f"{label} is fixture evidence")
        if vector["claim_usable"] is not True:
            item_blockers.append(f"{label} is not claim-usable")
        if vector["decision"] != "pass":
            item_blockers.append(f"{label} decision is not pass")
        if subject is not None and vector["input_capsule_digest"] != subject["aperture_capsule_digest"]:
            item_blockers.append(f"{label} input capsule digest does not match subject aperture capsule digest")
        item_blockers.extend(
            _binding_blockers(label, vector["attestation_ref"], verifier_vector_binding_digest(vector), attestation_index)
        )
        blockers.extend(item_blockers)
        valid.append(vector)

    families = [vector["verifier_family"] for vector in valid]
    distinct_families = set(families)
    duplicate_families = sorted({family for family in families if families.count(family) > 1})
    for family in duplicate_families:
        blockers.append(f"duplicate verifier family: {family}")
    if len(distinct_families) < REQUIRED_VERIFIER_FAMILY_COUNT:
        blockers.append("fewer than three verifier vector families")
    elif len(distinct_families) > REQUIRED_VERIFIER_FAMILY_COUNT:
        blockers.append("exactly three verifier vector families required")
    output_digests = {vector["output_digest"] for vector in valid}
    if len(output_digests) > 1:
        blockers.append("verifier vector output digest mismatch")
    return {
        "vector_count": len(vectors),
        "valid_shape_count": len(valid),
        "distinct_family_count": len(distinct_families),
        "verifier_families": sorted(distinct_families),
        "blockers": blockers,
    }


def _subject_binding_blockers(
    subject: dict[str, Any] | None,
    capsule: dict[str, Any] | None,
    aperture_capsule: dict[str, Any] | None,
) -> list[str]:
    blockers: list[str] = []
    if subject is None:
        return ["subject invalid, binding checks skipped"]
    if capsule is None:
        blockers.append("subject binding not verified: no v20 capsule supplied")
    else:
        try:
            singularity_gate.validate_capsule(capsule)
        except ValueError as exc:
            blockers.append(f"supplied v20 capsule invalid: {exc}")
            capsule = None
    if capsule is not None:
        if subject["release_tag"] != capsule["release_tag"]:
            blockers.append("subject release tag does not match capsule release tag")
        if subject["source_commit"] != capsule["source_commit"]:
            blockers.append("subject source commit does not match capsule source commit")
        if subject["aperture_capsule_digest"] != capsule["capsule_digest"]:
            blockers.append("subject aperture capsule digest does not match capsule digest")
        if subject["score_ceiling_report_digest"] != score_ceiling_report_digest(capsule):
            blockers.append("subject score ceiling report digest does not match capsule score ceiling report")
    if aperture_capsule is None:
        blockers.append("subject artifact binding not verified: no v19 aperture capsule supplied")
    else:
        if not isinstance(aperture_capsule, dict) or aperture_capsule.get("schema_id") != "daylight-v19-aperture-review-capsule":
            blockers.append("supplied aperture capsule is not a v19 aperture review capsule")
        else:
            if subject["artifact_sha256"] != aperture_capsule.get("subject_sha256"):
                blockers.append("subject artifact SHA-256 does not match aperture capsule subject")
            if subject["artifact_sha3_512"] != aperture_capsule.get("subject_sha3_512"):
                blockers.append("subject artifact SHA3-512 does not match aperture capsule subject")
            if subject["artifact_size"] != aperture_capsule.get("subject_size"):
                blockers.append("subject artifact size does not match aperture capsule subject")
            if capsule is not None and aperture_capsule.get("capsule_digest") != capsule["input_aperture_capsule_digest"]:
                blockers.append("aperture capsule digest does not match capsule input aperture capsule digest")
    return blockers


def evaluate_bundle(
    bundle: dict[str, Any],
    *,
    pinned_material: dict[str, Any] | None = None,
    capsule: dict[str, Any] | None = None,
    aperture_capsule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reject_floats_recursive(bundle, "external_evidence_bundle")
    if not isinstance(bundle, dict):
        raise ExternalEvidenceError("external evidence bundle must be an object")
    if set(bundle) != REQUIRED_BUNDLE_FIELDS:
        raise ExternalEvidenceError("external evidence bundle field set invalid")
    if bundle["schema_id"] != SCHEMA_ID or bundle["schema_version"] != SCHEMA_VERSION:
        raise ExternalEvidenceError("unsupported external evidence bundle schema")
    for key in (
        "independent_rebuild_receipts",
        "firewall_profile_reviews",
        "claim_usable_verifier_vectors",
        "pinned_attestations",
    ):
        if not isinstance(bundle[key], list):
            raise ExternalEvidenceError(f"{key} must be a list")

    blockers: list[str] = []
    recomputed_digest = bundle_digest(bundle)
    declared_digest = bundle.get("bundle_digest")
    digest_verified = declared_digest == recomputed_digest
    if not digest_verified:
        blockers.append("external evidence bundle digest mismatch")

    subject: dict[str, Any] | None
    try:
        subject = _validate_subject(bundle["subject"])
    except ValueError as exc:
        subject = None
        blockers.append(f"subject invalid: {exc}")

    subject_blockers = _subject_binding_blockers(subject, capsule, aperture_capsule)
    blockers.extend(subject_blockers)

    if pinned_material is None:
        pins: dict[str, dict[str, Any]] = {}
        pin_blockers = ["pinned verification material not supplied"]
    else:
        try:
            pins, pin_blockers = validate_pinned_material(pinned_material)
        except ValueError as exc:
            pins = {}
            pin_blockers = [f"pinned verification material invalid: {exc}"]

    attestation_summary = _evaluate_attestations(bundle["pinned_attestations"], pins, pin_blockers)
    attestation_index = attestation_summary.pop("index_by_id")
    blockers.extend(attestation_summary["blockers"])

    rebuild_summary = _evaluate_rebuild_receipts(bundle["independent_rebuild_receipts"], subject, attestation_index)
    blockers.extend(rebuild_summary["blockers"])
    review_summary = _evaluate_firewall_reviews(bundle["firewall_profile_reviews"], attestation_index)
    blockers.extend(review_summary["blockers"])
    vector_summary = _evaluate_verifier_vectors(bundle["claim_usable_verifier_vectors"], subject, attestation_index)
    blockers.extend(vector_summary["blockers"])

    for attestation_id, entry in attestation_index.items():
        if not entry["referenced"]:
            blockers.append(f"attestation not referenced by any evidence item: {attestation_id}")

    external_attestation_verified = (
        attestation_summary["verification_implemented"]
        and attestation_summary["valid_shape_count"] > 0
        and attestation_summary["cryptographically_verified_count"] == attestation_summary["valid_shape_count"]
    )
    admissible = not blockers and external_attestation_verified
    declaration_allowed = bool(capsule["declaration_allowed"]) if isinstance(capsule, dict) else False
    return {
        "schema_id": INTAKE_REPORT_SCHEMA_ID,
        "schema_version": INTAKE_REPORT_SCHEMA_VERSION,
        "bundle_schema_id": SCHEMA_ID,
        "bundle_digest": recomputed_digest,
        "bundle_digest_verified": digest_verified,
        "subject": subject,
        "external_evidence_admissible": admissible,
        "external_attestation_verified": external_attestation_verified,
        "declaration_allowed": declaration_allowed,
        "singularity_possible_without_external_validation": False,
        "rebuild_receipt_count": rebuild_summary["receipt_count"],
        "firewall_review_count": review_summary["review_count"],
        "verifier_vector_count": vector_summary["vector_count"],
        "attestation_count": attestation_summary["attestation_count"],
        "pinned_key_count": attestation_summary["pinned_key_count"],
        "cryptographically_verified_attestation_count": attestation_summary["cryptographically_verified_count"],
        "blockers": blockers,
        "sections": {
            "subject_binding": {"blockers": subject_blockers},
            "independent_rebuild_receipts": rebuild_summary,
            "firewall_profile_reviews": review_summary,
            "claim_usable_verifier_vectors": vector_summary,
            "pinned_attestations": attestation_summary,
        },
    }


def _load_bundle_bytes(path: Path | str) -> dict[str, Any]:
    bundle_path = Path(path)
    require_regular_public_file(bundle_path, str(bundle_path))
    raw = bundle_path.read_bytes()
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ExternalEvidenceError(f"external evidence bundle exceeds size limit: {bundle_path}")
    if b"\x00" in raw:
        raise ExternalEvidenceError(f"external evidence bundle contains NUL bytes: {bundle_path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExternalEvidenceError(f"external evidence bundle is not UTF-8: {bundle_path}") from exc
    value = loads_json_no_floats(text)
    if not isinstance(value, dict):
        raise ExternalEvidenceError("external evidence bundle must be an object")
    return value


def load_and_evaluate(
    bundle_path: Path | str,
    *,
    pinned_material_path: Path | str | None = None,
    capsule_path: Path | str | None = None,
    aperture_capsule_path: Path | str | None = None,
) -> dict[str, Any]:
    bundle = _load_bundle_bytes(bundle_path)
    pinned_material = load_pinned_material(pinned_material_path)
    capsule = load_json_no_floats(capsule_path) if capsule_path is not None else None
    aperture_capsule = load_json_no_floats(aperture_capsule_path) if aperture_capsule_path is not None else None
    return evaluate_bundle(
        bundle,
        pinned_material=pinned_material,
        capsule=capsule,
        aperture_capsule=aperture_capsule,
    )


BLOCKER_GROUPS = [
    {
        "slot_id": "reproducible_build.non_fixture_subject_bound_rebuilds",
        "section": "independent_rebuild_receipts",
        "needed": "two or more independent external rebuild receipts bound to the subject commit and artifact digests, each attested by a pinned external signer",
        "machine_check": "src.external_evidence.evaluate_bundle rebuild receipt section reports no blockers",
    },
    {
        "slot_id": "aperture_firewall_boundary.external_profile_expansion",
        "section": "firewall_profile_reviews",
        "needed": "at least one external firewall-profile review bound to the current profile, rules, and negative-case digests with no blocking finding",
        "machine_check": "src.external_evidence.evaluate_bundle firewall review section reports no blockers",
    },
    {
        "slot_id": "independent_verifier_quorum.claim_usable_3_of_3",
        "section": "claim_usable_verifier_vectors",
        "needed": "exactly three non-fixture claim-usable verifier vectors from distinct families with matching output digests over the subject capsule",
        "machine_check": "src.external_evidence.evaluate_bundle verifier vector section reports no blockers",
    },
    {
        "slot_id": "external_attestation.pinned_cryptographic_verification",
        "section": "pinned_attestations",
        "needed": "pinned external signers plus an implemented deterministic local signature verifier; every attestation must verify",
        "machine_check": "src.external_evidence.evaluate_bundle attestation section reports no blockers and external_attestation_verified is true",
    },
]


def explain_blockers(report: dict[str, Any]) -> dict[str, Any]:
    groups: list[dict[str, Any]] = []
    sections = report.get("sections", {})
    for group in BLOCKER_GROUPS:
        section = sections.get(group["section"], {})
        groups.append(
            {
                "slot_id": group["slot_id"],
                "needed": group["needed"],
                "machine_check": group["machine_check"],
                "open": bool(section.get("blockers")),
                "blockers": section.get("blockers", []),
            }
        )
    grouped = {blocker for group in groups for blocker in group["blockers"]}
    other = [blocker for blocker in report["blockers"] if blocker not in grouped]
    return {
        "schema_id": "daylight-v20-external-evidence-blocker-explanation",
        "schema_version": INTAKE_REPORT_SCHEMA_VERSION,
        "external_evidence_admissible": report["external_evidence_admissible"],
        "external_attestation_verified": report["external_attestation_verified"],
        "declaration_allowed": report["declaration_allowed"],
        "singularity_possible_without_external_validation": report["singularity_possible_without_external_validation"],
        "blocker_groups": groups,
        "bundle_and_subject_blockers": other,
        "blockers": report["blockers"],
    }
