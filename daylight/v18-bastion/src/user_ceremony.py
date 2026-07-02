"""Local user-authorization ceremony for Daylight v18 transitions."""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

from .canonical_json import canonical_sha256, reject_floats_recursive


CEREMONY_VERSION = "daylight-v18-bastion-user-ceremony-v0.1"
D_USER_KEY = "DAYLIGHT-v18-BASTION-USER-KEY:"
D_USER_PROOF = "DAYLIGHT-v18-BASTION-USER-PROOF:"
D_TRANSITION = "DAYLIGHT-v18-BASTION-TRANSITION:"
KDF = "pbkdf2-hmac-sha256"
ITERATIONS = 200000
DKLEN = 32

HEX64 = set("0123456789abcdef")


class UserCeremonyError(ValueError):
    pass


def _require_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - HEX64:
        raise UserCeremonyError(f"{name} must be lowercase hex digest length 64")
    return value


def _require_hex(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) % 2:
        raise UserCeremonyError(f"{name} must be non-empty even-length hex")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise UserCeremonyError(f"{name} must be hex") from exc
    return value


def user_id_digest(user_id: str) -> str:
    if not isinstance(user_id, str) or not user_id:
        raise UserCeremonyError("user_id must be a non-empty string")
    return canonical_sha256({"user_id": user_id}, D_USER_KEY)


def deterministic_salt(
    before_vector_digest: str,
    after_vector_digest: str,
    changed_fields: list[str],
    reason: str,
    user_id: str = "local-user",
) -> str:
    _require_digest(before_vector_digest, "before_vector_digest")
    _require_digest(after_vector_digest, "after_vector_digest")
    if not isinstance(changed_fields, list) or not all(isinstance(item, str) for item in changed_fields):
        raise UserCeremonyError("changed_fields must be list[string]")
    if not isinstance(reason, str) or not reason:
        raise UserCeremonyError("reason must be a non-empty string")
    return canonical_sha256(
        {
            "before_vector_digest": before_vector_digest,
            "after_vector_digest": after_vector_digest,
            "changed_fields": changed_fields,
            "reason": reason,
            "user_id_digest": user_id_digest(user_id),
        },
        D_USER_KEY + "SALT:",
    )


def challenge_digest(
    before_vector_digest: str,
    after_vector_digest: str,
    changed_fields: list[str],
    reason: str,
) -> str:
    _require_digest(before_vector_digest, "before_vector_digest")
    _require_digest(after_vector_digest, "after_vector_digest")
    if not isinstance(changed_fields, list) or not all(isinstance(item, str) for item in changed_fields):
        raise UserCeremonyError("changed_fields must be list[string]")
    if not isinstance(reason, str) or not reason:
        raise UserCeremonyError("reason must be a non-empty string")
    return canonical_sha256(
        {
            "before_vector_digest": before_vector_digest,
            "after_vector_digest": after_vector_digest,
            "changed_fields": changed_fields,
            "reason": reason,
        },
        D_USER_PROOF + "CHALLENGE:",
    )


def make_ceremony(
    before_vector_digest: str,
    after_vector_digest: str,
    changed_fields: list[str],
    reason: str,
    *,
    user_id: str = "local-user",
    salt: str | None = None,
) -> dict[str, Any]:
    if salt is None:
        salt = deterministic_salt(before_vector_digest, after_vector_digest, changed_fields, reason, user_id)
    _require_hex(salt, "salt")
    return {
        "ceremony_version": CEREMONY_VERSION,
        "user_id_digest": user_id_digest(user_id),
        "challenge_digest": challenge_digest(before_vector_digest, after_vector_digest, changed_fields, reason),
        "salt": salt,
        "kdf": KDF,
        "iterations": ITERATIONS,
    }


def validate_ceremony(ceremony: dict[str, Any]) -> None:
    reject_floats_recursive(ceremony, "user_ceremony")
    if not isinstance(ceremony, dict):
        raise UserCeremonyError("user_ceremony must be an object")
    allowed = {"ceremony_version", "user_id_digest", "challenge_digest", "salt", "kdf", "iterations"}
    unknown = set(ceremony) - allowed
    if unknown:
        raise UserCeremonyError(f"unknown ceremony fields: {sorted(unknown)}")
    missing = allowed - set(ceremony)
    if missing:
        raise UserCeremonyError(f"missing ceremony fields: {sorted(missing)}")
    if ceremony["ceremony_version"] != CEREMONY_VERSION:
        raise UserCeremonyError("unsupported user ceremony version")
    _require_digest(ceremony["user_id_digest"], "user_id_digest")
    _require_digest(ceremony["challenge_digest"], "challenge_digest")
    _require_hex(ceremony["salt"], "salt")
    if ceremony["kdf"] != KDF:
        raise UserCeremonyError("unsupported user ceremony kdf")
    if isinstance(ceremony["iterations"], bool) or not isinstance(ceremony["iterations"], int):
        raise UserCeremonyError("iterations must be integer")
    if ceremony["iterations"] != ITERATIONS:
        raise UserCeremonyError("unsupported user ceremony iteration count")


def derive_user_key(passphrase: str, salt_hex: str, iterations: int = ITERATIONS) -> bytes:
    if not isinstance(passphrase, str) or passphrase == "":
        raise UserCeremonyError("passphrase must be a non-empty string")
    _require_hex(salt_hex, "salt")
    if iterations != ITERATIONS:
        raise UserCeremonyError("unsupported iteration count")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), bytes.fromhex(salt_hex), iterations, dklen=DKLEN)


def transition_body(transition: dict[str, Any]) -> dict[str, Any]:
    reject_floats_recursive(transition, "transition")
    return {key: value for key, value in transition.items() if key != "user_proof"}


def transition_digest(transition: dict[str, Any]) -> str:
    return canonical_sha256(transition_body(transition), D_TRANSITION)


def proof_for_transition(transition: dict[str, Any], passphrase: str) -> str:
    ceremony = transition.get("user_ceremony")
    if not isinstance(ceremony, dict):
        raise UserCeremonyError("transition missing user_ceremony")
    validate_ceremony(ceremony)
    user_key = derive_user_key(passphrase, ceremony["salt"], ceremony["iterations"])
    digest = transition_digest(transition)
    return hmac.new(user_key, digest.encode("ascii"), hashlib.sha256).hexdigest()


def sign_transition(transition: dict[str, Any], passphrase: str) -> dict[str, Any]:
    signed = dict(transition)
    signed["user_proof"] = proof_for_transition(transition, passphrase)
    return signed


def verify_user_proof(transition: dict[str, Any], passphrase: str) -> bool:
    proof = transition.get("user_proof")
    if not isinstance(proof, str) or len(proof) != 64 or set(proof) - HEX64:
        return False
    expected = proof_for_transition(transition, passphrase)
    return hmac.compare_digest(proof, expected)


def passphrase_from_env(env_name: str) -> str:
    value = os.environ.get(env_name)
    if not value:
        raise UserCeremonyError(f"missing passphrase env: {env_name}")
    return value
