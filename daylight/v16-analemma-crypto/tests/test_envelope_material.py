from __future__ import annotations

import unittest

from src.envelope import open_envelope, open_with_external_kem_material, seal, seal_with_external_kem_material
from src.errors import D16AWEError, UnsupportedCryptoBackend

from tests.helpers import base_policy, clone, evidence_artifact, kem_material, recipient


class EnvelopeMaterialTests(unittest.TestCase):
    def test_vector_lane_round_trip(self) -> None:
        envelope = seal_with_external_kem_material(
            pkR=recipient(),
            plaintext=b"d16-awe vector plaintext",
            evidence_artifact=evidence_artifact(),
            policy=base_policy(),
            kem_material=kem_material(),
        )
        opened = open_with_external_kem_material(
            pkR=recipient(),
            envelope=envelope,
            evidence_artifact=evidence_artifact(),
            kem_material=kem_material(),
        )
        self.assertEqual(opened, b"d16-awe vector plaintext")

    def test_tampered_ciphertext_fails_closed(self) -> None:
        envelope = seal_with_external_kem_material(
            pkR=recipient(),
            plaintext=b"payload",
            evidence_artifact=evidence_artifact(),
            policy=base_policy(),
            kem_material=kem_material(),
        )
        raw = bytearray.fromhex(envelope["ciphertext"])
        raw[0] ^= 1
        envelope["ciphertext"] = raw.hex()
        with self.assertRaisesRegex(D16AWEError, "AEAD"):
            open_with_external_kem_material(
                pkR=recipient(),
                envelope=envelope,
                evidence_artifact=evidence_artifact(),
                kem_material=kem_material(),
            )

    def test_wrong_evidence_fails_closed(self) -> None:
        envelope = seal_with_external_kem_material(
            pkR=recipient(),
            plaintext=b"payload",
            evidence_artifact=evidence_artifact(),
            policy=base_policy(),
            kem_material=kem_material(),
        )
        wrong = evidence_artifact()
        wrong["context"]["zenith_report_digest"] = "11" * 64
        with self.assertRaisesRegex(D16AWEError, "authorization tag mismatch"):
            open_with_external_kem_material(
                pkR=recipient(),
                envelope=envelope,
                evidence_artifact=wrong,
                kem_material=kem_material(),
            )

    def test_wrong_kem_material_fails_closed(self) -> None:
        envelope = seal_with_external_kem_material(
            pkR=recipient(),
            plaintext=b"payload",
            evidence_artifact=evidence_artifact(),
            policy=base_policy(),
            kem_material=kem_material(),
        )
        wrong_material = clone(kem_material())
        wrong_material["ss_mlkem"] = ("22" * 64)
        with self.assertRaisesRegex(D16AWEError, "AEAD"):
            open_with_external_kem_material(
                pkR=recipient(),
                envelope=envelope,
                evidence_artifact=evidence_artifact(),
                kem_material=wrong_material,
            )

    def test_real_backend_apis_fail_closed(self) -> None:
        with self.assertRaises(UnsupportedCryptoBackend):
            seal()
        with self.assertRaises(UnsupportedCryptoBackend):
            open_envelope()

    def test_signature_policy_requires_real_backend(self) -> None:
        policy = clone(base_policy())
        policy["require_sender_signature"] = True
        with self.assertRaises(UnsupportedCryptoBackend):
            seal_with_external_kem_material(
                pkR=recipient(),
                plaintext=b"payload",
                evidence_artifact=evidence_artifact(),
                policy=policy,
                kem_material=kem_material(),
            )


if __name__ == "__main__":
    unittest.main()
