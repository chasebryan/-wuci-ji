import unittest
from pathlib import Path

from src import firewall_profile
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]


class FirewallProfileTests(unittest.TestCase):
    def test_firewall_profile_expansion_bundle_passes_repo_owned_atom(self):
        result = firewall_profile.load_and_evaluate(ROOT / "examples/firewall-profile-expansion.v20.json")
        self.assertTrue(result["passed"])
        self.assertTrue(result["atoms"]["public_artifact_firewall_negative_matrix_verified"])
        self.assertFalse(result["atoms"]["firewall_profile_externally_expanded"])
        self.assertFalse(result["fixture"])
        self.assertTrue(result["claim_usable"])

    def test_missing_case_blocks_profile_expansion(self):
        bundle = load_json_no_floats(ROOT / "examples/firewall-profile-expansion.v20.json")
        bundle["cases"] = [item for item in bundle["cases"] if item["case_id"] != "symlink"]
        result = firewall_profile.evaluate_bundle(bundle)
        self.assertFalse(result["passed"])
        self.assertIn("missing firewall profile case: symlink", result["blockers"])

    def test_case_digest_mismatch_blocks_profile_expansion(self):
        bundle = load_json_no_floats(ROOT / "examples/firewall-profile-expansion.v20.json")
        bundle["cases"][0]["observed_reasons"] = ["different_reason"]
        result = firewall_profile.evaluate_bundle(bundle)
        self.assertFalse(result["passed"])
        self.assertIn("firewall case evidence digest mismatch: unexpected_file", result["blockers"])


if __name__ == "__main__":
    unittest.main()
