import unittest
from pathlib import Path

from src import reproducible_builds
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SNAPSHOT_COMMIT = "3ef88e6f1f74115cc8284db970a951c35e5873d2"


def _refresh_receipt_digests(bundle):
    for receipt in bundle["receipts"]:
        receipt["receipt_digest"] = reproducible_builds.receipt_digest(receipt)
    return bundle


class ReproducibleBuildTests(unittest.TestCase):
    def test_fixture_receipts_are_structural_but_not_claim_usable(self):
        result = reproducible_builds.load_and_evaluate(ROOT / "examples/reproducible-build.receipts.v20.json")
        self.assertFalse(result["passed"])
        self.assertTrue(result["fixture"])
        self.assertFalse(result["claim_usable"])
        self.assertIn("reproducible build receipts are fixture evidence", result["blockers"])
        self.assertIn("reproducible build receipts are not claim-usable", result["blockers"])
        self.assertEqual(result["independent_builder_count"], 2)
        self.assertEqual(result["distinct_environment_count"], 2)
        self.assertTrue(result["atoms"]["receipt_statement_digests_verified"])

    def test_non_fixture_subject_bound_receipts_pass(self):
        bundle = load_json_no_floats(ROOT / "examples/reproducible-build.receipts.v20.json")
        bundle["fixture"] = False
        bundle["claim_usable"] = True
        result = reproducible_builds.evaluate_bundle(
            bundle,
            expected_source_commit=SOURCE_SNAPSHOT_COMMIT,
            expected_artifact_sha256="bdaefb595dfc1f7ce15a297abafb240ae36a5134e9b7e184eef58f5e6cfd67d3",
            expected_artifact_sha3_512="083183439a2082d81736b59cd3e081e6d83fbde71849a7650f814bd43922f523d0704c95351cafc6e87d7d78e9720f0248f53ee8b005ce4620b62a98c34ef446",
            expected_artifact_size=84,
        )
        self.assertTrue(result["passed"])
        self.assertTrue(result["atoms"]["source_commit_matches_capsule"])
        self.assertTrue(result["atoms"]["artifact_sha256_matches_subject"])
        self.assertTrue(result["atoms"]["receipt_statement_digests_verified"])

    def test_receipt_digest_mismatch_blocks(self):
        bundle = load_json_no_floats(ROOT / "examples/reproducible-build.receipts.v20.json")
        bundle["fixture"] = False
        bundle["claim_usable"] = True
        bundle["receipts"][0]["receipt_digest"] = "0" * 64
        result = reproducible_builds.evaluate_bundle(
            bundle,
            expected_source_commit=SOURCE_SNAPSHOT_COMMIT,
            expected_artifact_sha256="bdaefb595dfc1f7ce15a297abafb240ae36a5134e9b7e184eef58f5e6cfd67d3",
            expected_artifact_sha3_512="083183439a2082d81736b59cd3e081e6d83fbde71849a7650f814bd43922f523d0704c95351cafc6e87d7d78e9720f0248f53ee8b005ce4620b62a98c34ef446",
            expected_artifact_size=84,
        )
        self.assertFalse(result["passed"])
        self.assertIn("receipt 0 digest mismatch", result["blockers"])
        self.assertIn("reproducible build receipt digest mismatch", result["blockers"])

    def test_missing_independence_blocks(self):
        bundle = load_json_no_floats(ROOT / "examples/reproducible-build.receipts.v20.json")
        bundle["receipts"][1]["builder_id"] = bundle["receipts"][0]["builder_id"]
        bundle["receipts"][1]["builder_family"] = bundle["receipts"][0]["builder_family"]
        bundle["receipts"][1]["environment_digest"] = bundle["receipts"][0]["environment_digest"]
        _refresh_receipt_digests(bundle)
        result = reproducible_builds.evaluate_bundle(bundle)
        self.assertFalse(result["passed"])
        self.assertIn("reproducible build independence missing: fewer than two independent builders", result["blockers"])


if __name__ == "__main__":
    unittest.main()
