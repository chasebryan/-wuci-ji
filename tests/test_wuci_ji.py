#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("WUCI_JI_BIN", ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


def run(args: list[str], data: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*RUNNER, str(BIN), *args],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_sha256(payload: bytes) -> None:
    proc = run(["sha256"], payload)
    expected = hashlib.sha256(payload).hexdigest() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (payload[:32], actual, expected)


def assert_hmac_sha256(key: bytes, payload: bytes) -> None:
    proc = run(["hmac-sha256", key.hex()], payload)
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (payload[:32], actual, expected)


def hkdf_sha256_ref(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def assert_hkdf_sha256(salt: bytes, info: bytes, ikm: bytes) -> None:
    proc = run(["hkdf-sha256", salt.hex(), info.hex()], ikm)
    expected = hkdf_sha256_ref(salt, ikm, info).hex() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (ikm[:32], actual, expected)


def poly1305_ref(key: bytes, message: bytes) -> bytes:
    r = bytearray(key[:16])
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252
    r_int = int.from_bytes(r, "little")
    s_int = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r_int) % p
    return ((acc + s_int) % (1 << 128)).to_bytes(16, "little")


def assert_poly1305(key: bytes, payload: bytes) -> bytes:
    proc = run(["poly1305", key.hex()], payload)
    expected = poly1305_ref(key, payload).hex() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (payload[:32], actual, expected)
    return bytes.fromhex(actual.strip())


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    mask = 0xFFFFFFFF

    def rotl32(value: int, bits: int) -> int:
        return ((value << bits) & mask) | (value >> (32 - bits))

    state[a] = (state[a] + state[b]) & mask
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & mask
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & mask
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & mask
    state[b] = rotl32(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    constants = b"expand 32-byte k"
    state = [
        *[int.from_bytes(constants[i : i + 4], "little") for i in range(0, 16, 4)],
        *[int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)],
        counter,
        *[int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)],
    ]
    working = state.copy()
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    return b"".join(
        ((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
        for i in range(16)
    )


def chacha20_ref(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    out = bytearray()
    remaining = memoryview(data)
    block_counter = counter
    while remaining:
        block = chacha20_block(key, nonce, block_counter)
        take = min(len(remaining), len(block))
        out.extend(a ^ b for a, b in zip(remaining[:take], block[:take]))
        remaining = remaining[take:]
        block_counter = (block_counter + 1) & 0xFFFFFFFF
    return bytes(out)


def assert_chacha20(key: bytes, nonce: bytes, counter: int, payload: bytes) -> bytes:
    proc = run(["chacha20", key.hex(), nonce.hex(), f"{counter:08x}"], payload)
    expected = chacha20_ref(key, nonce, counter, payload)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert proc.stdout == expected
    return proc.stdout


def pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else b"\0" * (16 - rem)


def aead_tag_ref(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    otk = chacha20_block(key, nonce, 0)[:32]
    mac_data = (
        ciphertext
        + pad16(ciphertext)
        + (0).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )
    return poly1305_ref(otk, mac_data)


def aead_seal_ref(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    ciphertext = chacha20_ref(key, nonce, 1, plaintext)
    return ciphertext + aead_tag_ref(key, nonce, ciphertext)


def assert_aead(key: bytes, nonce: bytes, plaintext: bytes) -> None:
    sealed = run(["aead-seal", key.hex(), nonce.hex()], plaintext)
    expected = aead_seal_ref(key, nonce, plaintext)
    assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
    assert sealed.stdout == expected

    ciphertext, tag = sealed.stdout[:-16], sealed.stdout[-16:]
    opened = run(["aead-open", key.hex(), nonce.hex(), tag.hex()], ciphertext)
    assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
    assert opened.stdout == plaintext

    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    rejected = run(["aead-open", key.hex(), nonce.hex(), bad_tag.hex()], ciphertext)
    assert rejected.returncode != 0
    assert rejected.stdout == b""


def main() -> None:
    selftest = run(["selftest"])
    assert selftest.returncode == 0, selftest.stderr.decode("utf-8", "replace")
    assert selftest.stdout == b"wuci-ji selftest: PASS\n"

    assert_sha256(b"")
    assert_sha256(b"abc")
    assert_sha256(b"a" * 55)
    assert_sha256(b"a" * 56)
    assert_sha256(b"a" * 57)
    assert_sha256(b"a" * 64)
    assert_sha256(b"a" * 65)
    assert_sha256((b"wuci-ji\0" * 8192) + b"end")

    key = bytes(range(32))
    assert_hmac_sha256(key, b"")
    assert_hmac_sha256(key, b"Hi There")
    assert_hmac_sha256(key, (b"authenticated-data\0" * 4096) + b"end")

    salt = bytes(range(32, 64))
    info = bytes(range(64, 96))
    assert_hkdf_sha256(salt, info, b"")
    assert_hkdf_sha256(salt, info, b"abc")
    assert_hkdf_sha256(salt, info, (b"ikm-material\0" * 4096) + b"end")

    poly_key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    poly_msg = b"Cryptographic Forum Research Group"
    poly_tag = assert_poly1305(poly_key, poly_msg)
    assert poly_tag == bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
    assert_poly1305(poly_key, b"")
    assert_poly1305(poly_key, b"a" * 15)
    assert_poly1305(poly_key, b"a" * 16)
    assert_poly1305(poly_key, b"a" * 17)
    assert_poly1305(bytes(range(32)), (b"poly1305-data\0" * 4096) + b"end")

    rfc_plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only "
        b"one tip for the future, sunscreen would be it."
    )
    rfc_ciphertext = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    rfc_key = bytes(range(32))
    rfc_nonce = bytes.fromhex("000000000000004a00000000")
    encrypted = assert_chacha20(rfc_key, rfc_nonce, 1, rfc_plaintext)
    assert encrypted == rfc_ciphertext
    decrypted = assert_chacha20(rfc_key, rfc_nonce, 1, encrypted)
    assert decrypted == rfc_plaintext
    assert_chacha20(rfc_key, bytes.fromhex("000000090000004a00000000"), 1, b"x" * 4097)

    assert_aead(rfc_key, rfc_nonce, b"")
    assert_aead(rfc_key, rfc_nonce, b"abc")
    assert_aead(rfc_key, rfc_nonce, rfc_plaintext)
    assert_aead(
        bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0"
                      "473917c1402b80099dca5cbc207075c0"),
        bytes.fromhex("000000000102030405060708"),
        (b"sealed-data\0" * 8192) + b"end",
    )


if __name__ == "__main__":
    main()
