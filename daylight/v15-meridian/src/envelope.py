"""Meridian Authorized Envelope (MAE): encryption governed by Meridian logic.

This is the full realization of v15 Meridian as a cryptographic system. It is the
Daylight v0.6 authorized-envelope pattern made concrete: a real AEAD whose key and
open-gate are bound to evidence-derived, fail-closed obligation logic.

    Seal(plaintext) succeeds only when a scorecard generated from frozen evidence
    verifies and satisfies a policy (minimum score and a set of obligations that
    must be closed). The AEAD key is HKDF-derived from a caller key *and* a
    Meridian authorization tag, and the whole header is the AEAD associated data.

    Open(envelope) is fail-closed: Open = bottom unless the caller's evidence
    re-derives a scorecard that verifies, satisfies the sealed policy, and
    reproduces the exact authorization tag. Only then is the key derived and the
    AEAD tag checked. A tampered scorecard, an inflated score, an unmet policy, or
    a missing obligation yields no key and no plaintext.

So the law is enforced cryptographically:

    NoEvidence(x)  -> NoScore(x)  -> NoSeal(x)
    NoProof(x)     -> NoClaim(x)  -> NoOpen(x)
    ManualScore(x) -> Reject(x)   -> NoOpen(x)

Boundary: research reference, not production cryptography. The cipher
(:mod:`src.aead`) is not constant-time. A scorecard sealed here is a research
access-control demonstration, not a production key-management system.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Any

from . import aead
from . import api
from .canonical_json import CanonicalJSONError, canonical_bytes, canonical_sha256, loads_json_no_duplicates

MAGIC = b"WUCIMAE1"
ENVELOPE_VERSION = "daylight-v15-meridian-mae-v1"
SUITE = "ChaCha20-Poly1305"
NONCE_LEN = 12
TAG_LEN = 16
MAX_HEADER_BYTES = 64 * 1024
AUTH_DOMAIN = "DAYLIGHT-v15-MERIDIAN-MAE-AUTH:"
KDF_INFO_LABEL = b"DAYLIGHT-v15-MERIDIAN-MAE v1 aead-key"
BOUNDARY = (
    "Research reference. Not production cryptography, not constant-time, not "
    "external certification. The AEAD key and open-gate are bound to Meridian "
    "evidence-derived obligation logic."
)


class EnvelopeError(ValueError):
    """Malformed envelope or bad input."""


class EnvelopeRefused(Exception):
    """Fail-closed refusal: Meridian authorization did not hold (Open = bottom)."""


def make_policy(
    registry: dict[str, Any],
    *,
    min_score_M: int,
    required_closed_obligations: list[str] | None = None,
) -> dict[str, Any]:
    known = {ob["id"] for _, ob in api._obligations.iter_obligations(registry)}
    required = sorted(set(required_closed_obligations or []))
    unknown = [ob for ob in required if ob not in known]
    if unknown:
        raise EnvelopeError(f"policy names unknown obligations: {', '.join(unknown)}")
    if not 0 <= int(min_score_M) <= 1_000_000:
        raise EnvelopeError("min_score_M must be between 0 and 1000000")
    return {
        "min_score_M": int(min_score_M),
        "required_closed_obligations": required,
        "obligations_digest": api.registry_digest(registry),
    }


def _closed_ids(scorecard: dict[str, Any]) -> list[str]:
    return sorted(record["obligation_id"] for record in scorecard["closed_obligations"])


def _authorize(scorecard: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    """Return reasons the scorecard fails the policy (empty == authorized)."""
    reasons: list[str] = []
    if scorecard.get("obligations_digest") != policy.get("obligations_digest"):
        reasons.append("obligations_digest does not match policy")
    if int(scorecard.get("final_score_M", -1)) < int(policy["min_score_M"]):
        reasons.append(
            f"final_score_M {scorecard.get('final_score_M')} < policy min_score_M {policy['min_score_M']}"
        )
    closed = set(_closed_ids(scorecard))
    missing = [ob for ob in policy["required_closed_obligations"] if ob not in closed]
    if missing:
        reasons.append("required obligations not closed: " + ", ".join(missing))
    return reasons


def authorization_tag(scorecard: dict[str, Any], policy: dict[str, Any]) -> str:
    binding = {
        "obligations_digest": scorecard["obligations_digest"],
        "scorecard_digest": scorecard["scorecard_digest"],
        "final_score_M": int(scorecard["final_score_M"]),
        "closed_obligation_ids": _closed_ids(scorecard),
        "policy": {
            "min_score_M": int(policy["min_score_M"]),
            "required_closed_obligations": sorted(policy["required_closed_obligations"]),
            "obligations_digest": policy["obligations_digest"],
        },
    }
    return canonical_sha256(binding, AUTH_DOMAIN)


def _header_bytes(header: dict[str, Any]) -> bytes:
    return canonical_bytes(header)


def _aad(header_bytes: bytes) -> bytes:
    return MAGIC + struct.pack("<I", len(header_bytes)) + header_bytes


def _derive_key(caller_key: bytes, header_bytes: bytes, auth_tag: str) -> bytes:
    if len(caller_key) != 32:
        raise EnvelopeError("caller key must be 32 bytes")
    salt = aead.sha256(MAGIC + header_bytes)
    info = KDF_INFO_LABEL + b":" + auth_tag.encode("ascii")
    return aead.hkdf_sha256(caller_key, salt=salt, info=info, length=32)


def seal(
    *,
    plaintext: bytes,
    caller_key: bytes,
    ledger_path: Path | str,
    corpus_path: Path | str,
    policy: dict[str, Any],
    nonce: bytes | None = None,
    obligations_path: Path | str = api.DEFAULT_OBLIGATIONS,
) -> bytes:
    """Authorize from evidence, then AEAD-encrypt. Fail-closed if unauthorized."""
    scorecard, _, _ = api.generate_scorecard(
        ledger_path=ledger_path, corpus_path=corpus_path, obligations_path=obligations_path, command="mae-seal"
    )
    verdict = api.verify_scorecard(
        scorecard, obligations_path=obligations_path, ledger_path=ledger_path, corpus_path=corpus_path
    )
    if not verdict.ok:
        raise EnvelopeRefused(f"scorecard did not verify: {verdict.error}")
    reasons = _authorize(scorecard, policy)
    if reasons:
        raise EnvelopeRefused("seal refused (NoScore -> NoSeal): " + "; ".join(reasons))

    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise EnvelopeError("nonce must be 12 bytes")
    auth_tag = authorization_tag(scorecard, policy)
    header = {
        "magic": MAGIC.decode("ascii"),
        "version": ENVELOPE_VERSION,
        "suite": SUITE,
        "nonce": nonce.hex(),
        "policy": {
            "min_score_M": int(policy["min_score_M"]),
            "required_closed_obligations": sorted(policy["required_closed_obligations"]),
            "obligations_digest": policy["obligations_digest"],
        },
        "authorization": {
            "obligations_version": scorecard["obligations_version"],
            "obligations_digest": scorecard["obligations_digest"],
            "scorecard_digest": scorecard["scorecard_digest"],
            "final_score_M": int(scorecard["final_score_M"]),
            "authorization_tag": auth_tag,
        },
        "boundary": BOUNDARY,
    }
    header_bytes = _header_bytes(header)
    key = _derive_key(caller_key, header_bytes, auth_tag)
    ciphertext, tag = aead.chacha20_poly1305_encrypt(key, nonce, _aad(header_bytes), plaintext)
    return _aad(header_bytes) + ciphertext + tag


def parse(envelope: bytes) -> dict[str, Any]:
    """Parse the public framing without any key or authorization (keyless)."""
    if len(envelope) < len(MAGIC) + 4:
        raise EnvelopeError("envelope too short")
    if envelope[: len(MAGIC)] != MAGIC:
        raise EnvelopeError("bad magic")
    header_len = struct.unpack("<I", envelope[len(MAGIC):len(MAGIC) + 4])[0]
    if header_len <= 0 or header_len > MAX_HEADER_BYTES:
        raise EnvelopeError("envelope header length is outside the supported bound")
    header_start = len(MAGIC) + 4
    header_end = header_start + header_len
    if len(envelope) < header_end + TAG_LEN:
        raise EnvelopeError("truncated envelope")
    header_bytes = envelope[header_start:header_end]
    try:
        header = loads_json_no_duplicates(header_bytes, "Meridian envelope header")
    except CanonicalJSONError as exc:
        raise EnvelopeError(f"malformed envelope header: {exc}") from exc
    if not isinstance(header, dict):
        raise EnvelopeError("envelope header is not an object")
    ciphertext = envelope[header_end:len(envelope) - TAG_LEN]
    tag = envelope[len(envelope) - TAG_LEN:]
    return {
        "header": header,
        "header_bytes": header_bytes,
        "ciphertext": ciphertext,
        "tag": tag,
    }


def inspect(envelope: bytes) -> dict[str, Any]:
    """Keyless metadata: version, suite, nonce, policy, authorization, sizes."""
    parsed = parse(envelope)
    header = parsed["header"]
    return {
        "magic": header.get("magic"),
        "version": header.get("version"),
        "suite": header.get("suite"),
        "nonce": header.get("nonce"),
        "policy": header.get("policy"),
        "authorization": header.get("authorization"),
        "ciphertext_len": len(parsed["ciphertext"]),
        "tag": parsed["tag"].hex(),
        "header_sha256": aead.sha256(parsed["header_bytes"]).hex(),
        "boundary": header.get("boundary"),
    }


def open_envelope(
    *,
    envelope: bytes,
    caller_key: bytes,
    ledger_path: Path | str,
    corpus_path: Path | str,
    obligations_path: Path | str = api.DEFAULT_OBLIGATIONS,
) -> bytes:
    """Re-authorize from evidence, then AEAD-decrypt. Open = bottom if unauthorized."""
    parsed = parse(envelope)
    header = parsed["header"]
    if header.get("magic") != MAGIC.decode("ascii") or header.get("version") != ENVELOPE_VERSION:
        raise EnvelopeError("unsupported envelope version")
    policy = header.get("policy")
    sealed_auth = header.get("authorization", {})
    if not isinstance(policy, dict) or "min_score_M" not in policy:
        raise EnvelopeError("envelope header missing policy")

    # Re-derive the scorecard from the caller's evidence and re-authorize.
    scorecard, _, _ = api.generate_scorecard(
        ledger_path=ledger_path, corpus_path=corpus_path, obligations_path=obligations_path, command="mae-open"
    )
    verdict = api.verify_scorecard(
        scorecard, obligations_path=obligations_path, ledger_path=ledger_path, corpus_path=corpus_path
    )
    if not verdict.ok:
        raise EnvelopeRefused(f"open refused (NoProof -> NoOpen): scorecard did not verify: {verdict.error}")
    reasons = _authorize(scorecard, policy)
    if reasons:
        raise EnvelopeRefused("open refused (policy not satisfied): " + "; ".join(reasons))

    recomputed_tag = authorization_tag(scorecard, policy)
    if recomputed_tag != sealed_auth.get("authorization_tag"):
        raise EnvelopeRefused("open refused: evidence does not reproduce the sealed authorization")

    key = _derive_key(caller_key, parsed["header_bytes"], recomputed_tag)
    plaintext = aead.chacha20_poly1305_decrypt(
        key, bytes.fromhex(header["nonce"]), _aad(parsed["header_bytes"]), parsed["ciphertext"], parsed["tag"]
    )
    if plaintext is None:
        raise EnvelopeRefused("open refused: AEAD tag verification failed (wrong key or tampered ciphertext)")
    return plaintext
