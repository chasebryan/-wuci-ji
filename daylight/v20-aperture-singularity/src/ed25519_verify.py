"""Small deterministic Ed25519 verifier for pinned Daylight v20 attestations.

This module is intentionally verifier-only. It exists to check raw 64-byte
Ed25519 signatures against raw 32-byte pinned public keys without network,
wall-clock, hostname, username, local path, or optional package dependencies.
It is part of the Daylight v20 evidence intake contract and is not a
production-cryptography claim.
"""

from __future__ import annotations

import hashlib

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


class Ed25519VerificationError(ValueError):
    pass


def _inv(value: int) -> int:
    return pow(value, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int:
    y2 = (y * y) % _P
    xx = ((y2 - 1) * _inv((_D * y2 + 1) % _P)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise Ed25519VerificationError("ed25519 point is not on curve")
    if (x & 1) != sign:
        x = (-x) % _P
    if x == 0 and sign:
        raise Ed25519VerificationError("ed25519 point has invalid sign")
    return x


def _decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != PUBLIC_KEY_BYTES:
        raise Ed25519VerificationError("ed25519 point must be 32 bytes")
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = encoded[31] >> 7
    if y >= _P:
        raise Ed25519VerificationError("ed25519 point y coordinate out of range")
    x = _recover_x(y, sign)
    return (x, y, 1, (x * y) % _P)


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = point
    z_inv = _inv(z)
    affine_x = (x * z_inv) % _P
    affine_y = (y * z_inv) % _P
    encoded = bytearray(affine_y.to_bytes(32, "little"))
    encoded[31] |= (affine_x & 1) << 7
    return bytes(encoded)


def _point_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _point_equal(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _t1 = left
    x2, y2, z2, _t2 = right
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _is_identity(point: tuple[int, int, int, int]) -> bool:
    return _point_equal(point, _IDENTITY)


def _in_main_subgroup(point: tuple[int, int, int, int]) -> bool:
    return _is_identity(_scalar_mult(_L, point))


_BASE_Y = (4 * _inv(5)) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
_BASE_POINT = (_BASE_X, _BASE_Y, 1, (_BASE_X * _BASE_Y) % _P)


def _decode_public_key(public_key: bytes) -> tuple[int, int, int, int]:
    point = _decode_point(public_key)
    if _is_identity(point) or not _in_main_subgroup(point):
        raise Ed25519VerificationError("ed25519 public key rejected")
    return point


def _hash_to_scalar(*parts: bytes) -> int:
    digest = hashlib.sha512()
    for part in parts:
        digest.update(part)
    return int.from_bytes(digest.digest(), "little") % _L


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff signature is a valid Ed25519 signature for message."""
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise Ed25519VerificationError("ed25519 public key must be 32 bytes")
    if len(signature) != SIGNATURE_BYTES:
        return False

    public_point = _decode_public_key(public_key)
    try:
        r_point = _decode_point(signature[:32])
    except Ed25519VerificationError:
        return False
    if _is_identity(r_point) or not _in_main_subgroup(r_point):
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False

    h = _hash_to_scalar(signature[:32], public_key, message)
    left = _scalar_mult(s, _BASE_POINT)
    right = _point_add(r_point, _scalar_mult(h, public_point))
    return _point_equal(left, right)
