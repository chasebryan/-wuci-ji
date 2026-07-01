"""Hybrid KEM combiner over externally supplied KEM outputs.

This module does not implement ML-KEM or DHKEM. It combines ciphertexts, public
key digests, and already-derived shared secrets supplied by a real backend or by
deterministic test vectors.
"""

from __future__ import annotations

import struct
from typing import Any

from .auth import suite_id, validate_recipient_public_key
from .constants import D_KEM
from .errors import D16AWEError, UnsupportedCryptoBackend
from .hashing import domain_hash, domain_hash_bytes, hkdf_extract_sha384, sha256_hex


def real_hybrid_encapsulate(*_args: object, **_kwargs: object) -> None:
    raise UnsupportedCryptoBackend("D16-AWE requires a real pinned ML-KEM/DHKEM backend")


def real_hybrid_decapsulate(*_args: object, **_kwargs: object) -> None:
    raise UnsupportedCryptoBackend("D16-AWE requires a real pinned ML-KEM/DHKEM backend")


def _len_prefix(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _bytes_from_hex(value: str, name: str) -> bytes:
    if not isinstance(value, str):
        raise D16AWEError(f"{name} must be hex text")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise D16AWEError(f"{name} must be valid hex") from exc
    if not data:
        raise D16AWEError(f"{name} must not be empty")
    return data


def combine_external_kem_material(pkR: dict[str, Any], material: dict[str, str], auth_tag: str) -> tuple[dict[str, Any], bytes]:
    """Return public kem bundle and hybrid secret from externally supplied material."""
    pkR = validate_recipient_public_key(pkR)
    mlkem_ct = _bytes_from_hex(material.get("mlkem_ct"), "mlkem_ct")
    dh_ct = _bytes_from_hex(material.get("dh_ct"), "dh_ct")
    ss_mlkem = _bytes_from_hex(material.get("ss_mlkem"), "ss_mlkem")
    ss_dh = _bytes_from_hex(material.get("ss_dh"), "ss_dh")
    pk_mlkem = _bytes_from_hex(pkR["pk_mlkem"], "pk_mlkem")
    pk_dh = _bytes_from_hex(pkR["pk_dh"], "pk_dh")
    kem_context = {
        "suite_id": suite_id(),
        "auth_tag": auth_tag,
        "mlkem_id": "ML-KEM-1024",
        "mlkem_pk_digest": sha256_hex(pk_mlkem),
        "mlkem_ct_digest": sha256_hex(mlkem_ct),
        "dhkem_id": "DHKEM-P384-HKDF-SHA384",
        "dh_pk_digest": sha256_hex(pk_dh),
        "dh_ct_digest": sha256_hex(dh_ct),
    }
    expected_digest = domain_hash(D_KEM, kem_context)
    if material.get("kem_context_digest") not in (None, expected_digest):
        raise D16AWEError("kem_context_digest mismatch")
    ikm = _len_prefix(ss_mlkem) + _len_prefix(ss_dh)
    hybrid_secret = hkdf_extract_sha384(domain_hash_bytes(D_KEM, kem_context), ikm)
    kem_bundle = {
        "version": "daylight-v16-awe-hybrid-kem-v0.1",
        "mlkem_id": "ML-KEM-1024",
        "mlkem_ct": mlkem_ct.hex(),
        "dhkem_id": "DHKEM-P384-HKDF-SHA384",
        "dh_ct": dh_ct.hex(),
        "kem_context_digest": expected_digest,
    }
    return kem_bundle, hybrid_secret
