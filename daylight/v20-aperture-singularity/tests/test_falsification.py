import unittest
from pathlib import Path

from src import falsification
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]


class FalsificationTests(unittest.TestCase):
    def test_required_negative_corpus_passes(self):
        result = falsification.load_and_evaluate(ROOT / "examples/falsification-survival.v20.json")
        self.assertTrue(result["passed"])
        self.assertFalse(result["fixture"])
        self.assertTrue(result["claim_usable"])
        self.assertEqual(result["survived_case_count"], len(falsification.REQUIRED_CASES))

    def test_missing_case_blocks(self):
        bundle = load_json_no_floats(ROOT / "examples/falsification-survival.v20.json")
        bundle["results"] = [item for item in bundle["results"] if item["case_id"] != "json_float"]
        result = falsification.evaluate_bundle(bundle)
        self.assertFalse(result["passed"])
        self.assertIn("missing falsification case: json_float", result["blockers"])

    def test_case_digest_mismatch_blocks(self):
        bundle = load_json_no_floats(ROOT / "examples/falsification-survival.v20.json")
        bundle["results"][0]["outcome"] = "accepted"
        result = falsification.evaluate_bundle(bundle)
        self.assertFalse(result["passed"])
        self.assertIn("falsification evidence digest mismatch: digest_edit", result["blockers"])
        self.assertFalse(result["atoms"]["digest_edit"])


if __name__ == "__main__":
    unittest.main()
