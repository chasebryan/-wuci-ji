"""Recipient identity and authorization tags."""

from __future__ import annotations

from typing import Any

from .canonical import encode
from .constants import D_AUTHZ, D_POLICY, D_RECIPIENT, D_SUITE, SUITE
from .evidence import evidence_tag
from .errors import D16AWEError
from .hashing import domain_hash, sha256_hex
from .policy import validate_policy


def suite_id() -> str:
    return domain_hash(D_SUITE, SUITE)


def recipient_id(pk_mlkem: bytes, pk_dh: bytes) -> str:
    return sha256_hex(
        encode(
            {
                "suite_id": suite_id(),
                "pk_mlkem_digest": sha256_hex(pk_mlkem),
                "pk_dh_digest": sha256_hex(pk_dh),
            }
        )
    )


def make_recipient_public_key(pk_mlkem: bytes, pk_dh: bytes) -> dict[str, Any]:
    return {
        "version": "daylight-v16-awe-recipient-public-v0.1",
        "suite_id": suite_id(),
        "pk_mlkem": pk_mlkem.hex(),
        "pk_dh": pk_dh.hex(),
        "recipient_id": recipient_id(pk_mlkem, pk_dh),
    }


def _bytes_from_hex(value: str, name: str) -> bytes:
    if not isinstance(value, str):
        raise D16AWEError(f"{name} must be hex text")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise D16AWEError(f"{name} must be valid hex") from exc


def validate_recipient_public_key(pkR: dict[str, Any]) -> dict[str, Any]:
    if pkR.get("suite_id") != suite_id():
        raise D16AWEError("recipient suite id mismatch")
    pk_mlkem = _bytes_from_hex(pkR.get("pk_mlkem"), "pk_mlkem")
    pk_dh = _bytes_from_hex(pkR.get("pk_dh"), "pk_dh")
    expected = recipient_id(pk_mlkem, pk_dh)
    if pkR.get("recipient_id") != expected:
        raise D16AWEError("recipient id mismatch")
    return pkR


def recipient_public_key_digest(pkR: dict[str, Any]) -> str:
    return domain_hash(D_RECIPIENT, validate_recipient_public_key(pkR))


def sender_public_key_digest(sender_public_bundle: dict[str, Any] | None) -> str | None:
    if sender_public_bundle is None:
        return None
    return sha256_hex(encode(sender_public_bundle))


def policy_tag(policy: dict[str, Any]) -> str:
    return domain_hash(D_POLICY, validate_policy(policy))


def authorization_tag(
    context: dict[str, Any],
    policy: dict[str, Any],
    pkR: dict[str, Any],
    sender_public_bundle: dict[str, Any] | None = None,
) -> str:
    policy = validate_policy(policy)
    return domain_hash(
        D_AUTHZ,
        {
            "suite_id": suite_id(),
            "evidence_tag": evidence_tag(context),
            "policy_tag": policy_tag(policy),
            "recipient_public_key_digest": recipient_public_key_digest(pkR),
            "sender_public_key_digest": sender_public_key_digest(sender_public_bundle),
            "daylight_claim_score_M": context["daylight_claim_score_M"],
            "analemma_score_A": context["analemma_score_A"],
            "proof_mass_digest": context["proof_mass_digest"],
            "solstice_scorecard_digest": context["solstice_scorecard_digest"],
            "solstice_artifact_manifest_digest": context["solstice_artifact_manifest_digest"],
            "analemma_registry_digest": context["analemma_registry_digest"],
            "zenith_report_digest": context["zenith_report_digest"],
            "claim_level": context["claim_level"],
            "anti_inflation": {
                "score_inflation_M": context["score_inflation_M"],
                "invariant": "ZenithAdjustedScore_M == DaylightScore_M",
            },
        },
    )
