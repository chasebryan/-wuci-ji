"""Domain-separated hashing helpers."""

from __future__ import annotations

import hashlib
import hmac

from .canonical import encode


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def sha3_512_hex(data: bytes) -> str:
    return sha3_512(data).hex()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def domain_hash_bytes(domain: str, value: object) -> bytes:
    return sha3_512(domain.encode("ascii") + encode(value))


def domain_hash(domain: str, value: object) -> str:
    return domain_hash_bytes(domain, value).hex()


def hkdf_extract_sha384(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha384).digest()


def hkdf_expand_sha384(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0 or length > 255 * hashlib.sha384().digest_size:
        raise ValueError("invalid HKDF-SHA384 output length")
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha384).digest()
        okm += block
        counter += 1
    return okm[:length]


def fixed_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
