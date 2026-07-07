"""Signed external-attestation verification for Daylight v15+ Solstice.

Solstice treats external score mass as signature-bound. The default repository
rootset is empty, so copied Meridian-style non-harness signer strings do not
close external obligations. Tests and demos can supply a rootset with deterministic
HMAC-SHA256 roots; this keeps the verifier dependency-free while making the
signature/root/quorum rules executable.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from .canonical_json import CanonicalJSONError, canonical_bytes, canonical_sha256, load_json_file_no_duplicates
from .semantic_evidence import is_hex_sha256


ATTESTATION_VERSION = "daylight-v15-solstice-external-attestation-v0.1"
ROOTSET_VERSION = "daylight-v15-solstice-external-rootset-v0.1"
SIGNATURE_NAMESPACE = "DAYLIGHT-v15-SOLSTICE-EXTERNAL-ATTESTATION"
ROOTSET_DOMAIN = "DAYLIGHT-v15-SOLSTICE-EXTERNAL-ROOTSET:"
ATTEST_DOMAIN = "DAYLIGHT-v15-SOLSTICE-EXTERNAL-ATTESTATION:"
ATTEST_SET_DOMAIN = "DAYLIGHT-v15-SOLSTICE-EXTERNAL-ATTESTATION-SET:"
ZERO_COMMIT = "0" * 40


class ExternalAttestationError(ValueError):
    pass


def root_key_digest(root_key: str) -> str:
    return hashlib.sha256(root_key.encode("utf-8")).hexdigest()


def rootset_digest(rootset: dict[str, Any] | None) -> str | None:
    if rootset is None:
        return None
    body = {key: value for key, value in rootset.items() if key != "rootset_digest"}
    return canonical_sha256(body, ROOTSET_DOMAIN)


def load_rootset(path: Path | str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = load_json_file_no_duplicates(Path(path), "Solstice external rootset")
    except CanonicalJSONError as exc:
        raise ExternalAttestationError(str(exc)) from exc
    if data.get("rootset_version") != ROOTSET_VERSION:
        raise ExternalAttestationError("unsupported external rootset version")
    expected = data.get("rootset_digest")
    actual = rootset_digest(data)
    if expected is not None and expected != actual:
        raise ExternalAttestationError("external rootset digest mismatch")
    return data


def _attestation_payload(attestation: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in attestation.items() if key != "signature"}


def attestation_digest(attestation: dict[str, Any]) -> str:
    return canonical_sha256(_attestation_payload(attestation), ATTEST_DOMAIN)


def _signature_message(attestation: dict[str, Any]) -> bytes:
    return SIGNATURE_NAMESPACE.encode("utf-8") + b":" + canonical_bytes(_attestation_payload(attestation))


def sign_attestation(attestation: dict[str, Any], root_key: str) -> dict[str, Any]:
    signed = dict(attestation)
    signed["signature"] = hmac.new(root_key.encode("utf-8"), _signature_message(signed), hashlib.sha256).hexdigest()
    return signed


def build_attestation(
    *,
    obligation_id: str,
    external_role: str,
    external_signer_id: str,
    reviewer_identity: str,
    root_key: str,
    reviewed_commit: str = ZERO_COMMIT,
    report_digest: str,
    artifact_digest_target: str,
    transcript_reference: str,
    network_required: bool = False,
) -> dict[str, Any]:
    attestation = {
        "attestation_version": ATTESTATION_VERSION,
        "obligation_id": obligation_id,
        "external_role": external_role,
        "external_signer_id": external_signer_id,
        "reviewer_identity": reviewer_identity,
        "root_key_digest": root_key_digest(root_key),
        "reviewed_commit": reviewed_commit,
        "report_digest": report_digest,
        "artifact_digest_target": artifact_digest_target,
        "transcript_reference": transcript_reference,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "fixture_material_used": False,
        "network_required": network_required,
        "offensive_tooling_included": False,
        "non_claims": [
            "not production authority",
            "not runtime containment",
            "not whole-system post-quantum safety",
        ],
    }
    return sign_attestation(attestation, root_key)


def _roots_for_role(rootset: dict[str, Any], role: str) -> list[dict[str, Any]]:
    roots = rootset.get("allowed_roots", [])
    if not isinstance(roots, list):
        raise ExternalAttestationError("external rootset allowed_roots must be a list")
    return [root for root in roots if root.get("external_role") == role]


def role_policy(rootset: dict[str, Any], role: str) -> dict[str, Any]:
    policies = rootset.get("role_policies", {})
    if not isinstance(policies, dict):
        raise ExternalAttestationError("external rootset role_policies must be an object")
    policy = dict(policies.get(role, {}))
    policy.setdefault("external_role", role)
    policy.setdefault("quorum_k", 1)
    policy.setdefault("reviewed_commit", rootset.get("reviewed_commit", ZERO_COMMIT))
    policy.setdefault("require_distinct_reviewers", True)
    policy.setdefault("require_distinct_root_keys", True)
    return policy


def _root_for_attestation(rootset: dict[str, Any], attestation: dict[str, Any]) -> dict[str, Any] | None:
    for root in _roots_for_role(rootset, str(attestation.get("external_role", ""))):
        if root.get("root_key_digest") == attestation.get("root_key_digest"):
            return root
    return None


def _signature_valid(attestation: dict[str, Any], root: dict[str, Any]) -> bool:
    if root.get("scheme") != "hmac-sha256":
        return False
    root_key = root.get("root_key")
    signature = attestation.get("signature")
    if not isinstance(root_key, str) or not isinstance(signature, str):
        return False
    expected = hmac.new(root_key.encode("utf-8"), _signature_message(attestation), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def valid_external_attestation(
    attestation: dict[str, Any],
    obligation: dict[str, Any],
    rootset: dict[str, Any],
    harness_identity: str,
) -> bool:
    role = obligation.get("external_role")
    policy = role_policy(rootset, str(role))
    if attestation.get("attestation_version") != ATTESTATION_VERSION:
        return False
    if attestation.get("obligation_id") != obligation.get("id"):
        return False
    if attestation.get("external_role") != role or attestation.get("external_role") != policy.get("external_role"):
        return False
    signer = attestation.get("external_signer_id")
    if not isinstance(signer, str) or not signer or signer == harness_identity:
        return False
    if attestation.get("signature_namespace") != SIGNATURE_NAMESPACE:
        return False
    if attestation.get("fixture_material_used") is not False:
        return False
    if attestation.get("offensive_tooling_included") is not False:
        return False
    if attestation.get("reviewed_commit") != policy.get("reviewed_commit"):
        return False
    if not is_hex_sha256(attestation.get("report_digest")):
        return False
    if not is_hex_sha256(attestation.get("artifact_digest_target")):
        return False
    if not isinstance(attestation.get("transcript_reference"), str) or not attestation.get("transcript_reference"):
        return False
    root = _root_for_attestation(rootset, attestation)
    if root is None:
        return False
    return _signature_valid(attestation, root)


def _entry_attestations(entry: dict[str, Any]) -> list[dict[str, Any]]:
    signatures = entry.get("signatures", [])
    if not isinstance(signatures, list):
        return []
    return [item for item in signatures if isinstance(item, dict)]


def attestation_set_digest(attestations: list[dict[str, Any]]) -> str:
    ordered = sorted(attestations, key=lambda item: (str(item.get("reviewer_identity")), str(item.get("root_key_digest"))))
    return canonical_sha256({"attestations": ordered}, ATTEST_SET_DOMAIN)


def closing_attestation_set(
    obligation: dict[str, Any],
    ledger_entries: list[dict[str, Any]],
    rootset: dict[str, Any] | None,
    harness_identity: str,
) -> list[dict[str, Any]]:
    if obligation.get("scope") != "external":
        return []
    candidates: list[dict[str, Any]] = []
    for entry in ledger_entries:
        if entry.get("entry_type") != "external_attestation":
            continue
        if obligation.get("id") not in entry.get("closes_obligations", []):
            continue
        if entry.get("external_signer_id") == harness_identity:
            raise ExternalAttestationError(
                f"self-signed external attestation rejected: {entry.get('entry_id')}"
            )
        if rootset is None:
            continue
        for attestation in _entry_attestations(entry):
            if attestation.get("external_signer_id") != entry.get("external_signer_id"):
                continue
            if valid_external_attestation(attestation, obligation, rootset, harness_identity):
                candidates.append(attestation)

    if rootset is None:
        return []
    policy = role_policy(rootset, str(obligation.get("external_role")))
    quorum = int(policy.get("quorum_k", 1))
    if len(candidates) < quorum:
        return []
    if policy.get("require_distinct_reviewers", True):
        if len({item.get("reviewer_identity") for item in candidates}) < quorum:
            return []
    if policy.get("require_distinct_root_keys", True):
        if len({item.get("root_key_digest") for item in candidates}) < quorum:
            return []
    return candidates[:quorum]
