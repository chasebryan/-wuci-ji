"""ChaCha20-Poly1305 AEAD and HKDF-SHA256, pure standard library.

This is a faithful, vector-checked reference implementation of RFC 8439
(ChaCha20-Poly1305) and RFC 5869 (HKDF). It is the cipher the Meridian Authorized
Envelope encrypts with. Correctness is proven against the published RFC test
vectors in ``tests/test_aead_vectors.py``.

Boundary: this is a research reference, not production cryptography. It is written
for clarity and determinism, not constant-time execution, and it is not
side-channel hardened. Do not use it to protect real secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Iterable

_MASK32 = 0xFFFFFFFF
_P1305 = (1 << 130) - 5


def _rotl32(value: int, count: int) -> int:
    value &= _MASK32
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """The RFC 8439 ChaCha20 block function (64-byte keystream block)."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    constants = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    state = list(constants)
    state += list(struct.unpack("<8I", key))
    state.append(counter & _MASK32)
    state += list(struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):  # 20 rounds == 10 column+diagonal double rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 stream XOR (RFC 8439 section 2.4)."""
    output = bytearray(len(data))
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset:offset + 64]
        for i, byte in enumerate(chunk):
            output[offset + i] = byte ^ block[i]
    return bytes(output)


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    """Poly1305 one-time authenticator (RFC 8439 section 2.5)."""
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset:offset + 16]
        n = int.from_bytes(chunk, "little") + (1 << (8 * len(chunk)))
        acc = ((acc + n) * r) % _P1305
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """Derive a one-time Poly1305 key from a ChaCha20 block (RFC 8439 2.6)."""
    return chacha20_block(key, 0, nonce)[:32]


def _pad16(data: bytes) -> bytes:
    extra = len(data) % 16
    return b"\x00" * (16 - extra) if extra else b""


def _aead_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return b"".join(
        (
            aad,
            _pad16(aad),
            ciphertext,
            _pad16(ciphertext),
            struct.pack("<Q", len(aad)),
            struct.pack("<Q", len(ciphertext)),
        )
    )


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """AEAD seal (RFC 8439 section 2.8). Returns (ciphertext, 16-byte tag)."""
    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20(key, 1, nonce, plaintext)
    tag = poly1305_mac(_aead_mac_data(aad, ciphertext), otk)
    return ciphertext, tag


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
    """AEAD open (RFC 8439 section 2.8). Returns plaintext, or None on tag failure."""
    otk = poly1305_key_gen(key, nonce)
    expected = poly1305_mac(_aead_mac_data(aad, ciphertext), otk)
    if not hmac.compare_digest(expected, tag):
        return None
    return chacha20(key, 1, nonce, ciphertext)


def hkdf_sha256(ikm: bytes, *, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """HKDF-SHA256 extract-and-expand (RFC 5869)."""
    if length > 255 * 32:
        raise ValueError("HKDF cannot produce more than 255*HashLen bytes")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def concat(*parts: Iterable[bytes]) -> bytes:
    return b"".join(parts)
