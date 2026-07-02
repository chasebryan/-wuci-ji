import unittest
from decimal import Decimal

from src import proof_fields


class ProofFieldTests(unittest.TestCase):
    def test_complete_field_uses_perfect_reserve(self):
        atoms = {atom: True for atom in proof_fields.FIELD_ATOMS["reproducible_build"]}
        result = proof_fields.build_field_result("reproducible_build", atoms)
        self.assertTrue(result["threshold_passed"])
        self.assertTrue(result["perfect_reserve_applied"])
        self.assertEqual(result["closure_rational"], "999999999/1000000000")

    def test_partial_field_fails_threshold(self):
        atoms = {
            "attestations_present": True,
            "required_fields_present": True,
            "attestations_scoped": True,
            "signer_not_self_scoped": True,
            "non_claims_acknowledged": True,
            "cryptographic_signature_verified": False,
        }
        result = proof_fields.build_field_result("external_attestation", atoms)
        self.assertFalse(result["threshold_passed"])
        self.assertIn("cryptographic_signature_verified", result["open_atoms"])

    def test_score_caps_at_declaration_target_not_reserved_value(self):
        score = proof_fields.score_from_omega(Decimal(proof_fields.OMEGA_THRESHOLD_DECIMAL_TEXT))
        self.assertEqual(score, proof_fields.DECLARATION_TARGET_AM_PLUS)
        self.assertNotEqual(score, proof_fields.PERFECT_RESERVED_AM_PLUS)


if __name__ == "__main__":
    unittest.main()
