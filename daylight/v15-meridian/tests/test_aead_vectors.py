from __future__ import annotations

import unittest

from src import aead


class AeadVectorTests(unittest.TestCase):
    """Correctness against published RFC test vectors (this is what makes the
    cipher real and verifiable, not a toy)."""

    def test_chacha20_keystream_rfc8439_2_4_2(self) -> None:
        key = bytes(range(32))
        nonce = bytes.fromhex("000000000000004a00000000")
        keystream = aead.chacha20(key, 1, nonce, b"\x00" * 23)
        self.assertEqual(keystream.hex(), "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06")

    def test_chacha20_block_rfc8439_2_3_2(self) -> None:
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        block = aead.chacha20_block(key, 1, nonce)
        self.assertEqual(block[:16].hex(), "10f1e7e4d13b5915500fdd1fa32071c4")

    def test_poly1305_mac_rfc8439_2_5_2(self) -> None:
        key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        message = b"Cryptographic Forum Research Group"
        self.assertEqual(aead.poly1305_mac(message, key).hex(), "a8061dc1305136c6c22b8baf0c0127a9")

    def test_aead_encrypt_rfc8439_2_8_2(self) -> None:
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you only "
            b"one tip for the future, sunscreen would be it."
        )
        ciphertext, tag = aead.chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
        self.assertEqual(
            ciphertext.hex(),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116",
        )
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")

    def test_aead_decrypt_roundtrip_and_tamper(self) -> None:
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = b"meridian aead reference"
        ciphertext, tag = aead.chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
        self.assertEqual(aead.chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag), plaintext)
        self.assertIsNone(aead.chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, bytes(16)))
        self.assertIsNone(aead.chacha20_poly1305_decrypt(key, nonce, aad + b"x", ciphertext, tag))
        flipped = bytearray(ciphertext)
        flipped[0] ^= 1
        self.assertIsNone(aead.chacha20_poly1305_decrypt(key, nonce, aad, bytes(flipped), tag))

    def test_hkdf_sha256_rfc5869_case1(self) -> None:
        okm = aead.hkdf_sha256(
            bytes.fromhex("0b" * 22),
            salt=bytes.fromhex("000102030405060708090a0b0c"),
            info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            length=42,
        )
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )


if __name__ == "__main__":
    unittest.main()
