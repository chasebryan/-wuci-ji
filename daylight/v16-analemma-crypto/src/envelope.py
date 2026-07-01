"""Executable D16-AWE envelope mechanics.

Full real recipient seal/open requires pinned ML-KEM and DHKEM backends. This
module exposes fail-closed real APIs plus a vector lane that consumes externally
supplied KEM material to exercise authorization, key schedule, AEAD, and
commitment logic.
"""

from __future__ import annotations

from typing import Any

from . import aead_ref
from .auth import authorization_tag, suite_id, validate_recipient_public_key
from .canonical import encode
from .constants import D_HEADER, D_SIG, MAGIC, SUITE, VERSION
from .errors import D16AWEError, UnsupportedCryptoBackend
from .evidence import evidence_tag, verify_daylight_v16_evidence
from .hashing import domain_hash, fixed_time_equal, sha3_512_hex
from .kem_hybrid import combine_external_kem_material
from .key_schedule import derive_key_schedule, nonce, plaintext_commitment
from .policy import validate_policy


def seal(*_args: object, **_kwargs: object) -> None:
    raise UnsupportedCryptoBackend("D16-AWE seal requires real pinned ML-KEM/DHKEM backends")


def open_envelope(*_args: object, **_kwargs: object) -> None:
    raise UnsupportedCryptoBackend("D16-AWE open requires real pinned ML-KEM/DHKEM backends")


def _suite_for_header() -> dict[str, Any]:
    return {**SUITE, "suite_id": suite_id()}


def _evidence_summary(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_tag": evidence_tag(context),
        "daylight_claim_score_M": context["daylight_claim_score_M"],
        "analemma_score_A": context["analemma_score_A"],
        "proof_mass_digest": context["proof_mass_digest"],
        "solstice_scorecard_digest": context["solstice_scorecard_digest"],
        "solstice_artifact_manifest_digest": context["solstice_artifact_manifest_digest"],
        "analemma_registry_digest": context["analemma_registry_digest"],
        "zenith_report_digest": context["zenith_report_digest"],
        "claim_level": context["claim_level"],
        "score_inflation_M": context["score_inflation_M"],
    }


def _aad(header: dict[str, Any]) -> bytes:
    header_bytes = encode(header)
    return MAGIC.encode("ascii") + len(header_bytes).to_bytes(4, "little") + header_bytes


def _unsigned_header(
    *,
    pkR: dict[str, Any],
    policy: dict[str, Any],
    context: dict[str, Any],
    kem_bundle: dict[str, Any],
    sequence_number: int,
    sender_public_bundle: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "magic": MAGIC,
        "version": VERSION,
        "suite": _suite_for_header(),
        "recipient_id": pkR["recipient_id"],
        "policy": policy,
        "evidence_summary": _evidence_summary(context),
        "kem_bundle": kem_bundle,
        "nonce_mode": "derived-base-xor-sequence",
        "sequence_number": sequence_number,
        "plaintext_commitment_mode": "hidden-sha3-512",
        "sender_signature_mode": "none" if sender_public_bundle is None else "external",
        "sender_public_bundle": sender_public_bundle,
    }


def seal_with_external_kem_material(
    *,
    pkR: dict[str, Any],
    plaintext: bytes,
    evidence_artifact: dict[str, Any],
    policy: dict[str, Any],
    kem_material: dict[str, str],
    sequence_number: int = 0,
    sender_public_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Seal using externally supplied KEM material for deterministic vectors."""
    pkR = validate_recipient_public_key(pkR)
    policy = validate_policy(policy)
    if policy["require_sender_signature"] or policy["require_backup_signature"]:
        raise UnsupportedCryptoBackend("D16-AWE sender signatures require real pinned ML-DSA/SLH-DSA backends")
    context = verify_daylight_v16_evidence(evidence_artifact, policy)
    auth_tag = authorization_tag(context, policy, pkR, sender_public_bundle)
    kem_bundle, hybrid_secret = combine_external_kem_material(pkR, kem_material, auth_tag)
    h0 = _unsigned_header(
        pkR=pkR,
        policy=policy,
        context=context,
        kem_bundle=kem_bundle,
        sequence_number=sequence_number,
        sender_public_bundle=sender_public_bundle,
    )
    schedule = derive_key_schedule(hybrid_secret, h0, auth_tag)
    commitment = plaintext_commitment(schedule["K_commit"], plaintext, auth_tag)
    header = {**h0, "authorization": {"auth_tag": auth_tag, "commitment": commitment}}
    n = nonce(schedule["N_base"], sequence_number)
    ciphertext, tag = aead_ref.seal(schedule["K_aead"], n, _aad(header), plaintext)
    return {
        "magic": MAGIC,
        "version": VERSION,
        "header": header,
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
        "signatures": [],
    }


def open_with_external_kem_material(
    *,
    pkR: dict[str, Any],
    envelope: dict[str, Any],
    evidence_artifact: dict[str, Any],
    kem_material: dict[str, str],
) -> bytes:
    """Open a vector envelope using externally supplied KEM shared secrets."""
    pkR = validate_recipient_public_key(pkR)
    if envelope.get("magic") != MAGIC or envelope.get("version") != VERSION:
        raise D16AWEError("unsupported envelope")
    header = envelope.get("header")
    if not isinstance(header, dict):
        raise D16AWEError("envelope header must be an object")
    if header.get("magic") != MAGIC or header.get("version") != VERSION:
        raise D16AWEError("unsupported header")
    if header.get("suite") != _suite_for_header():
        raise D16AWEError("suite mismatch")
    if header.get("recipient_id") != pkR["recipient_id"]:
        raise D16AWEError("recipient mismatch")
    policy = validate_policy(header["policy"])
    if policy["require_sender_signature"] or policy["require_backup_signature"]:
        raise UnsupportedCryptoBackend("D16-AWE signature verification requires real pinned ML-DSA/SLH-DSA backends")
    context = verify_daylight_v16_evidence(evidence_artifact, policy)
    sender_public_bundle = header.get("sender_public_bundle")
    auth_tag = authorization_tag(context, policy, pkR, sender_public_bundle)
    sealed_auth = header.get("authorization", {})
    if not fixed_time_equal(auth_tag, sealed_auth.get("auth_tag", "")):
        raise D16AWEError("authorization tag mismatch")
    h0 = {key: value for key, value in header.items() if key != "authorization"}
    kem_bundle, hybrid_secret = combine_external_kem_material(pkR, kem_material, auth_tag)
    if kem_bundle != header["kem_bundle"]:
        raise D16AWEError("KEM bundle mismatch")
    schedule = derive_key_schedule(hybrid_secret, h0, auth_tag)
    try:
        ciphertext = bytes.fromhex(envelope["ciphertext"])
        tag = bytes.fromhex(envelope["tag"])
    except (KeyError, ValueError) as exc:
        raise D16AWEError("ciphertext/tag must be valid hex") from exc
    plaintext = aead_ref.open_aead(
        schedule["K_aead"],
        nonce(schedule["N_base"], header["sequence_number"]),
        _aad(header),
        ciphertext,
        tag,
    )
    if plaintext is None:
        raise D16AWEError("AEAD tag failure")
    commitment = plaintext_commitment(schedule["K_commit"], plaintext, auth_tag)
    if not fixed_time_equal(commitment, sealed_auth.get("commitment", "")):
        raise D16AWEError("commitment mismatch")
    return plaintext


def inspect(envelope: dict[str, Any]) -> dict[str, Any]:
    header = envelope.get("header", {})
    return {
        "magic": envelope.get("magic"),
        "version": envelope.get("version"),
        "recipient_id": header.get("recipient_id"),
        "suite_id": header.get("suite", {}).get("suite_id"),
        "evidence_summary": header.get("evidence_summary"),
        "policy": header.get("policy"),
        "kem_context_digest": header.get("kem_bundle", {}).get("kem_context_digest"),
        "header_digest": domain_hash(D_HEADER, header) if isinstance(header, dict) else None,
        "ciphertext_digest": sha3_512_hex(bytes.fromhex(envelope["ciphertext"])) if "ciphertext" in envelope else None,
        "tag": envelope.get("tag"),
        "signature_body_digest": domain_hash(
            D_SIG,
            {
                "header_digest": domain_hash(D_HEADER, header),
                "ciphertext_digest": sha3_512_hex(bytes.fromhex(envelope["ciphertext"])),
                "tag": envelope.get("tag"),
            },
        )
        if isinstance(header, dict) and "ciphertext" in envelope
        else None,
    }
