"""Daylight v20.2 independent external rebuild receipt intake.

This verifier accepts a single external rebuild receipt only as evidence for
the rebuild-receipt gate. It does not raise scores, claim certification, or
open Singularity. The receipt must be deterministic, digest-bound, signed by a
pinned external attestation, and explicit about every v20 non-claim boundary.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from . import external_evidence
from .canonical import dumps_canonical, load_json_no_floats, loads_json_no_floats, reject_floats_recursive
from .pathsafe import require_regular_public_file

SCHEMA_VERSION = 1
RECEIPT_KIND = "daylight-v20-independent-rebuild-receipt"
REPORT_SCHEMA_ID = "daylight.v20.rebuild-receipt-intake.report"
REPORT_SCHEMA_VERSION = 1
D_RECEIPT_STATEMENT = "DAYLIGHT-v20-INDEPENDENT-REBUILD-RECEIPT-STATEMENT:"
MAX_RECEIPT_BYTES = 1_000_000

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

REQUIRED_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "receipt_kind",
        "reviewer_identity",
        "reviewer_independence_class",
        "fixture",
        "claim_usable",
        "source_repo",
        "source_commit",
        "source_tag",
        "clean_checkout_declared",
        "build_commands",
        "environment",
        "expected_artifact",
        "produced_artifact",
        "transcript_digest",
        "receipt_statement_digest",
        "attestation_ref",
        "nonclaim_acknowledgement",
    }
)

REQUIRED_ARTIFACT_FIELDS = frozenset(
    {
        "artifact_name",
        "sha256",
        "sha3_512",
        "byte_count",
        "public_manifest_digest",
    }
)

REQUIRED_ENVIRONMENT_FIELDS = frozenset(
    {
        "os_name",
        "os_version",
        "architecture",
        "shell",
        "tool_versions",
        "containerized",
        "notes",
    }
)

REQUIRED_NONCLAIM_FIELDS = frozenset(
    {
        "no_production_crypto_claim",
        "no_runtime_containment_claim",
        "no_whole_system_post_quantum_safety_claim",
        "no_external_certification_claim",
        "no_perfect_score_claim",
        "no_singularity_claim_from_this_receipt_alone",
    }
)

REBUILD_GATE = "reproducible_build.non_fixture_subject_bound_rebuilds"
STILL_OPEN_WITH_RECEIPT = [
    "aperture_firewall_boundary.external_profile_expansion",
    "independent_verifier_quorum.claim_usable_3_of_3",
    "external_attestation.pinned_cryptographic_verification",
    "singularity_declaration",
]
CLAIM_BOUNDARY = (
    "A rebuild receipt records that one external reviewer rebuilt the bound "
    "artifact and observed matching bytes. It is not certification, production "
    "readiness, runtime containment, post-quantum safety, a perfect score, or a "
    "Singularity declaration."
)

FORBIDDEN_IDENTITY_TOKENS = external_evidence.FORBIDDEN_IDENTITY_TOKENS | frozenset({"daylight"})


class RebuildReceiptError(ValueError):
    pass


def _is_placeholder_hex(text: str) -> bool:
    return bool(text) and len(set(text)) == 1


def _add(blockers: list[str], code: str) -> None:
    if code not in blockers:
        blockers.append(code)


def _require_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _valid_hex(value: Any, regex: re.Pattern[str]) -> bool:
    return isinstance(value, str) and bool(regex.fullmatch(value)) and not _is_placeholder_hex(value)


def _identity_has_reserved_token(identity: str) -> bool:
    tokens = {token for token in external_evidence._TOKEN_SPLIT_RE.split(identity.lower()) if token}
    return bool(tokens & FORBIDDEN_IDENTITY_TOKENS)


def receipt_statement_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in ("receipt_statement_digest", "attestation_ref")
    }


def receipt_statement_bytes(receipt: dict[str, Any]) -> bytes:
    return D_RECEIPT_STATEMENT.encode("utf-8") + dumps_canonical(receipt_statement_payload(receipt))


def receipt_statement_digest(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(receipt_statement_bytes(receipt)).hexdigest()


def _expected_artifact_from_aperture(aperture_capsule: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(aperture_capsule, dict):
        return None
    subject_name = "unknown"
    input_subjects = aperture_capsule.get("input_subjects")
    if isinstance(input_subjects, list) and input_subjects and isinstance(input_subjects[0], dict):
        subject_name = str(input_subjects[0].get("subject_path") or subject_name)
    return {
        "artifact_name": subject_name,
        "sha256": aperture_capsule.get("subject_sha256"),
        "sha3_512": aperture_capsule.get("subject_sha3_512"),
        "byte_count": aperture_capsule.get("subject_size"),
        "public_manifest_digest": aperture_capsule.get("public_sha256sums"),
    }


def _validate_artifact_shape(value: Any, blockers: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != REQUIRED_ARTIFACT_FIELDS:
        _add(blockers, "rebuild_receipt_schema_invalid")
        return None
    if _require_str(value.get("artifact_name")) is None:
        _add(blockers, "rebuild_receipt_schema_invalid")
    if not _valid_hex(value.get("sha256"), HEX64_RE):
        _add(blockers, "rebuild_receipt_schema_invalid")
    if not _valid_hex(value.get("sha3_512"), HEX128_RE):
        _add(blockers, "rebuild_receipt_schema_invalid")
    if isinstance(value.get("byte_count"), bool) or not isinstance(value.get("byte_count"), int) or value.get("byte_count") < 0:
        _add(blockers, "rebuild_receipt_schema_invalid")
    if not _valid_hex(value.get("public_manifest_digest"), HEX64_RE):
        _add(blockers, "rebuild_receipt_schema_invalid")
    return value


def _validate_environment_shape(value: Any, blockers: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != REQUIRED_ENVIRONMENT_FIELDS:
        _add(blockers, "rebuild_receipt_schema_invalid")
        return None
    for key in ("os_name", "os_version", "architecture", "shell", "notes"):
        if not isinstance(value.get(key), str):
            _add(blockers, "rebuild_receipt_schema_invalid")
    if not isinstance(value.get("containerized"), bool):
        _add(blockers, "rebuild_receipt_schema_invalid")
    tool_versions = value.get("tool_versions")
    if not isinstance(tool_versions, dict) or not tool_versions:
        _add(blockers, "rebuild_receipt_schema_invalid")
    else:
        for key, item in tool_versions.items():
            if not isinstance(key, str) or not key or not isinstance(item, str) or not item:
                _add(blockers, "rebuild_receipt_schema_invalid")
                break
    return value


def _validate_nonclaims(value: Any, blockers: list[str]) -> None:
    if not isinstance(value, dict) or set(value) != REQUIRED_NONCLAIM_FIELDS:
        _add(blockers, "rebuild_receipt_nonclaim_acknowledgement_missing")
        return
    for key in sorted(REQUIRED_NONCLAIM_FIELDS):
        if value.get(key) is not True:
            _add(blockers, "rebuild_receipt_nonclaim_acknowledgement_missing")
            return


def _verify_attestation(
    receipt: dict[str, Any],
    pins: dict[str, dict[str, Any]],
    pin_blockers: list[str],
    blockers: list[str],
) -> bool:
    attestation = receipt.get("attestation_ref")
    if pin_blockers:
        _add(blockers, "rebuild_receipt_attestation_invalid")
    if not isinstance(attestation, dict):
        _add(blockers, "rebuild_receipt_attestation_invalid")
        return False
    try:
        external_evidence._validate_pinned_attestation(attestation, 0)
    except ValueError:
        _add(blockers, "rebuild_receipt_attestation_invalid")
        return False
    signer_identity = attestation["signer_identity"]
    if _identity_has_reserved_token(signer_identity):
        _add(blockers, "rebuild_receipt_internal_identity")
    if attestation["signer_independence_class"] != external_evidence.REQUIRED_INDEPENDENCE_CLASS:
        _add(blockers, "rebuild_receipt_independence_invalid")
    if attestation["fixture"] is True or attestation["claim_usable"] is not True:
        _add(blockers, "rebuild_receipt_attestation_invalid")
    recomputed = receipt_statement_digest(receipt)
    if attestation["subject_digest"] != recomputed:
        _add(blockers, "rebuild_receipt_attestation_invalid")
    pin = pins.get(attestation["public_key_digest"])
    if pin is None:
        _add(blockers, "rebuild_receipt_attestation_invalid")
        return False
    if pin.get("signer_identity") != signer_identity:
        _add(blockers, "rebuild_receipt_attestation_invalid")
        return False
    try:
        return external_evidence._verify_signature(attestation, pin)
    except ValueError:
        _add(blockers, "rebuild_receipt_attestation_invalid")
        return False


def evaluate_receipt(
    receipt: dict[str, Any],
    *,
    pinned_material: dict[str, Any] | None = None,
    capsule: dict[str, Any] | None = None,
    aperture_capsule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reject_floats_recursive(receipt, "external_rebuild_receipt")
    blockers: list[str] = []
    warnings = ["rebuild_receipt_cannot_open_singularity_alone"]
    if not isinstance(receipt, dict):
        raise RebuildReceiptError("external rebuild receipt must be an object")
    if set(receipt) != REQUIRED_RECEIPT_FIELDS:
        _add(blockers, "rebuild_receipt_schema_invalid")
    if receipt.get("schema_version") != SCHEMA_VERSION or receipt.get("receipt_kind") != RECEIPT_KIND:
        _add(blockers, "rebuild_receipt_schema_invalid")

    reviewer_identity = receipt.get("reviewer_identity")
    if _require_str(reviewer_identity) is None:
        _add(blockers, "rebuild_receipt_schema_invalid")
        reviewer_identity = None
    elif _identity_has_reserved_token(reviewer_identity):
        _add(blockers, "rebuild_receipt_internal_identity")
    if receipt.get("reviewer_independence_class") != external_evidence.REQUIRED_INDEPENDENCE_CLASS:
        _add(blockers, "rebuild_receipt_independence_invalid")
    if receipt.get("fixture") is True:
        _add(blockers, "rebuild_receipt_fixture_not_claim_usable")
    if receipt.get("claim_usable") is not True:
        _add(blockers, "rebuild_receipt_claim_usable_false")
    if _require_str(receipt.get("source_commit")) is None:
        _add(blockers, "rebuild_receipt_missing_source_commit")
    elif not _valid_hex(receipt.get("source_commit"), HEX40_RE):
        _add(blockers, "rebuild_receipt_schema_invalid")
    if _require_str(receipt.get("source_tag")) is None:
        _add(blockers, "rebuild_receipt_missing_source_tag")
    if receipt.get("clean_checkout_declared") is not True:
        _add(blockers, "rebuild_receipt_dirty_checkout")
    if not isinstance(receipt.get("build_commands"), list) or not receipt.get("build_commands"):
        _add(blockers, "rebuild_receipt_schema_invalid")
    else:
        for item in receipt["build_commands"]:
            if not isinstance(item, str) or not item:
                _add(blockers, "rebuild_receipt_schema_invalid")
                break

    expected_artifact = _validate_artifact_shape(receipt.get("expected_artifact"), blockers)
    produced_artifact = _validate_artifact_shape(receipt.get("produced_artifact"), blockers)
    _validate_environment_shape(receipt.get("environment"), blockers)
    _validate_nonclaims(receipt.get("nonclaim_acknowledgement"), blockers)

    transcript_digest = receipt.get("transcript_digest")
    if _require_str(transcript_digest) is None:
        _add(blockers, "rebuild_receipt_missing_transcript_digest")
    elif not isinstance(transcript_digest, str) or not HEX64_RE.fullmatch(transcript_digest):
        _add(blockers, "rebuild_receipt_schema_invalid")
    elif _is_placeholder_hex(transcript_digest):
        _add(blockers, "rebuild_receipt_placeholder_transcript_digest")

    recomputed_digest = receipt_statement_digest(receipt)
    if receipt.get("receipt_statement_digest") != recomputed_digest:
        _add(blockers, "rebuild_receipt_statement_digest_mismatch")

    expected_from_capsule = _expected_artifact_from_aperture(aperture_capsule)
    if expected_artifact is not None and expected_from_capsule is not None:
        for key in ("sha256", "sha3_512", "byte_count", "public_manifest_digest"):
            if expected_artifact.get(key) != expected_from_capsule.get(key):
                _add(blockers, "rebuild_receipt_expected_artifact_digest_mismatch")
                break
    if isinstance(capsule, dict):
        if receipt.get("source_commit") != capsule.get("source_commit"):
            _add(blockers, "rebuild_receipt_expected_artifact_digest_mismatch")
        if receipt.get("source_tag") != capsule.get("release_tag"):
            _add(blockers, "rebuild_receipt_expected_artifact_digest_mismatch")
    if expected_artifact is not None and produced_artifact is not None:
        for key in ("artifact_name", "sha256", "sha3_512", "byte_count", "public_manifest_digest"):
            if expected_artifact.get(key) != produced_artifact.get(key):
                _add(blockers, "rebuild_receipt_produced_artifact_digest_mismatch")
                break

    if pinned_material is None:
        pins: dict[str, dict[str, Any]] = {}
        pin_blockers = ["pinned verification material not supplied"]
    else:
        try:
            pins, pin_blockers = external_evidence.validate_pinned_material(pinned_material)
        except ValueError:
            pins = {}
            pin_blockers = ["pinned verification material invalid"]
    attestation_verified = _verify_attestation(receipt, pins, pin_blockers, blockers)

    accepted = not blockers
    closed_gates = [REBUILD_GATE] if accepted else []
    still_open_gates = list(STILL_OPEN_WITH_RECEIPT)
    if not accepted:
        still_open_gates.insert(0, REBUILD_GATE)
    artifact_digest = produced_artifact.get("sha256") if isinstance(produced_artifact, dict) else None
    return {
        "schema_id": REPORT_SCHEMA_ID,
        "schema_version": REPORT_SCHEMA_VERSION,
        "accepted": accepted,
        "attestation_verified": attestation_verified,
        "blocker_codes": blockers,
        "warning_codes": warnings,
        "closed_gates": closed_gates,
        "still_open_gates": still_open_gates,
        "claim_boundary": CLAIM_BOUNDARY,
        "receipt_digest": recomputed_digest,
        "receipt_statement_digest_valid": receipt.get("receipt_statement_digest") == recomputed_digest,
        "reviewer_identity": reviewer_identity,
        "artifact_digest": artifact_digest,
        "declaration_allowed": False,
        "singularity_possible_without_external_validation": False,
    }


def _load_receipt_bytes(path: Path | str) -> dict[str, Any]:
    receipt_path = Path(path)
    require_regular_public_file(receipt_path, str(receipt_path))
    raw = receipt_path.read_bytes()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise RebuildReceiptError(f"external rebuild receipt exceeds size limit: {receipt_path}")
    if b"\x00" in raw:
        raise RebuildReceiptError(f"external rebuild receipt contains NUL bytes: {receipt_path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RebuildReceiptError(f"external rebuild receipt is not UTF-8: {receipt_path}") from exc
    value = loads_json_no_floats(text)
    if not isinstance(value, dict):
        raise RebuildReceiptError("external rebuild receipt must be an object")
    return value


def load_and_evaluate(
    receipt_path: Path | str,
    *,
    pinned_material_path: Path | str | None = None,
    capsule_path: Path | str | None = None,
    aperture_capsule_path: Path | str | None = None,
) -> dict[str, Any]:
    return evaluate_receipt(
        _load_receipt_bytes(receipt_path),
        pinned_material=external_evidence.load_pinned_material(pinned_material_path),
        capsule=load_json_no_floats(capsule_path) if capsule_path is not None else None,
        aperture_capsule=load_json_no_floats(aperture_capsule_path) if aperture_capsule_path is not None else None,
    )
