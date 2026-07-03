import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "daylight/npt/v1"))

from daylight_npt.evidence import digest_literal_valid, evaluate_claim
from daylight_npt.registry import load_registry


class EvidenceTests(unittest.TestCase):
    def test_json_equals_score_evidence(self):
        registry = load_registry(ROOT / "daylight/npt/v1/number-claims.registry.json")
        claim = next(item for item in registry["claims"] if item["id"] == "npt.fixture.registered_score")
        self.assertEqual(evaluate_claim(claim, ROOT), (True, "json_equals"))

    def test_json_ratio_percent_evidence(self):
        registry = load_registry(ROOT / "daylight/npt/v1/number-claims.registry.json")
        claim = next(item for item in registry["claims"] if item["id"] == "npt.fixture.recomputed_percent")
        self.assertEqual(evaluate_claim(claim, ROOT), (True, "json_ratio_percent"))

    def test_digest_format(self):
        self.assertTrue(digest_literal_valid("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
        self.assertFalse(digest_literal_valid("SHA-256: 0123456789abcdefnothex"))


if __name__ == "__main__":
    unittest.main()

