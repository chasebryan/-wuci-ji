"""D16-AWE HKDF-SHA384 key schedule, nonce, and commitment logic."""

from __future__ import annotations

from typing import Any

from .canonical import encode
from .constants import D_COMMIT, D_EXTRACT, D_EXPAND, D_EXPORT, D_HEADER
from .errors import D16AWEError
from .hashing import domain_hash, domain_hash_bytes, hkdf_expand_sha384, hkdf_extract_sha384, sha3_512, sha3_512_hex


def header_digest(header_without_auth: dict[str, Any]) -> str:
    return domain_hash(D_HEADER, header_without_auth)


def derive_key_schedule(hybrid_secret: bytes, header_without_auth: dict[str, Any], auth_tag: str) -> dict[str, Any]:
    transcript_digest = header_digest(header_without_auth)
    salt = domain_hash_bytes(
        D_EXTRACT,
        {
            "suite_id": header_without_auth["suite"]["suite_id"],
            "transcript_digest": transcript_digest,
            "auth_tag": auth_tag,
        },
    )
    prk = hkdf_extract_sha384(salt, hybrid_secret)
    info_base = {
        "suite_id": header_without_auth["suite"]["suite_id"],
        "transcript_digest": transcript_digest,
        "auth_tag": auth_tag,
    }
    k_aead = hkdf_expand_sha384(prk, D_EXPAND.encode("ascii") + b"aead-key" + encode(info_base), 32)
    n_base = hkdf_expand_sha384(prk, D_EXPAND.encode("ascii") + b"nonce-base" + encode(info_base), 12)
    k_commit = hkdf_expand_sha384(prk, D_EXPAND.encode("ascii") + b"commit-key" + encode(info_base), 32)
    k_export = hkdf_expand_sha384(prk, D_EXPORT.encode("ascii") + b"exporter" + encode(info_base), 32)
    return {
        "transcript_digest": transcript_digest,
        "K_aead": k_aead,
        "N_base": n_base,
        "K_commit": k_commit,
        "K_export": k_export,
    }


def nonce(n_base: bytes, sequence_number: int) -> bytes:
    if len(n_base) != 12:
        raise D16AWEError("N_base must be 12 bytes")
    if not isinstance(sequence_number, int) or isinstance(sequence_number, bool):
        raise D16AWEError("sequence_number must be an integer")
    if sequence_number < 0 or sequence_number >= 2**64:
        raise D16AWEError("sequence_number out of range")
    seq96 = b"\x00\x00\x00\x00" + sequence_number.to_bytes(8, "big")
    return bytes(left ^ right for left, right in zip(n_base, seq96))


def plaintext_commitment(k_commit: bytes, plaintext: bytes, auth_tag: str) -> str:
    plaintext_digest_bytes = sha3_512(plaintext)
    return domain_hash(
        D_COMMIT,
        {
            "auth_tag": auth_tag,
            "plaintext_digest": plaintext_digest_bytes.hex(),
            "keyed_blind": sha3_512_hex(k_commit + plaintext_digest_bytes),
        },
    )
