import unittest
from pathlib import Path

from src import verifier_agreement
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]


def _make_non_fixture_claim_usable(bundle):
    for vector in bundle["vectors"]:
        vector["fixture"] = False
        vector["claim_usable"] = True
        vector["vector_digest"] = verifier_agreement.vector_digest(vector)
    return bundle


class VerifierAgreementTests(unittest.TestCase):
    def test_partial_two_of_three_is_structural_but_blocked(self):
        result = verifier_agreement.load_and_evaluate(ROOT / "examples/verifier-agreement.partial-2-of-3.v20.json")
        self.assertFalse(result["passed"])
        self.assertEqual(result["quorum"], "2/3")
        self.assertIn("verifier quorum incomplete: 2/3", result["blockers"])
        self.assertIn("verifier bundle subject does not match expected release subject", result["blockers"])

    def test_full_fixture_three_of_three_is_not_claim_usable(self):
        result = verifier_agreement.evaluate_bundle(
            load_json_no_floats(ROOT / "examples/verifier-agreement.full-3-of-3.v20.json"),
            expected_subject="v20-aperture-singularity-fixture",
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["distinct_family_count"], 3)
        self.assertTrue(result["atoms"]["subject_matches_expected"])
        self.assertTrue(result["atoms"]["output_schema_matches_v20"])
        self.assertTrue(result["atoms"]["vector_statement_digests_verified"])
        self.assertIn("verifier vectors are fixture evidence", result["blockers"])
        self.assertIn("verifier vectors are not claim-usable", result["blockers"])

    def test_full_non_fixture_three_of_three_passes_agreement_field(self):
        bundle = _make_non_fixture_claim_usable(
            load_json_no_floats(ROOT / "examples/verifier-agreement.full-3-of-3.v20.json")
        )
        result = verifier_agreement.evaluate_bundle(bundle, expected_subject="v20-aperture-singularity-fixture")
        self.assertTrue(result["passed"])
        self.assertEqual(result["quorum"], "3/3")

    def test_subject_mismatch_blocks_agreement_field(self):
        bundle = _make_non_fixture_claim_usable(
            load_json_no_floats(ROOT / "examples/verifier-agreement.full-3-of-3.v20.json")
        )
        result = verifier_agreement.evaluate_bundle(bundle, expected_subject="different-release")
        self.assertFalse(result["passed"])
        self.assertIn("verifier bundle subject does not match expected release subject", result["blockers"])

    def test_output_schema_mismatch_blocks_agreement_field(self):
        bundle = _make_non_fixture_claim_usable(
            load_json_no_floats(ROOT / "examples/verifier-agreement.full-3-of-3.v20.json")
        )
        bundle["vectors"][0]["output_schema_id"] = "other-schema"
        bundle["vectors"][0]["vector_digest"] = verifier_agreement.vector_digest(bundle["vectors"][0])
        result = verifier_agreement.evaluate_bundle(bundle, expected_subject="v20-aperture-singularity-fixture")
        self.assertFalse(result["passed"])
        self.assertIn("verifier vector output schema mismatch", result["blockers"])

    def test_vector_digest_mismatch_blocks_agreement_field(self):
        bundle = _make_non_fixture_claim_usable(
            load_json_no_floats(ROOT / "examples/verifier-agreement.full-3-of-3.v20.json")
        )
        bundle["vectors"][0]["vector_digest"] = "0" * 64
        result = verifier_agreement.evaluate_bundle(bundle, expected_subject="v20-aperture-singularity-fixture")
        self.assertFalse(result["passed"])
        self.assertIn("vector 0 digest mismatch", result["blockers"])
        self.assertIn("verifier vector digest mismatch", result["blockers"])

    def test_duplicate_verifier_family_rejects(self):
        bundle = load_json_no_floats(ROOT / "examples/verifier-agreement.full-3-of-3.v20.json")
        bundle["vectors"][2]["verifier_family"] = "python-reference"
        with self.assertRaises(ValueError):
            verifier_agreement.evaluate_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
