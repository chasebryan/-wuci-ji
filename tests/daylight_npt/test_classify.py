import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "daylight/npt/v1"))

from daylight_npt.classify import classify_token
from daylight_npt.extract import extract_tokens_from_text
from daylight_npt.registry import load_registry


REGISTRY = load_registry(ROOT / "daylight/npt/v1/number-claims.registry.json")


def codes(text):
    found = []
    for token in extract_tokens_from_text(text, "fixture.md"):
        found.extend(finding.code for finding in classify_token(token, REGISTRY, ROOT))
    return found


class ClassifyTests(unittest.TestCase):
    def test_percent_mismatch(self):
        self.assertIn("NPT003_PERCENT_RATIO_MISMATCH", codes("998,200 / 1,000,000 equals 99.83%"))

    def test_invalid_digest(self):
        self.assertIn("NPT007_INVALID_DIGEST_LITERAL", codes("SHA-256: 0123456789abcdefnothex"))

    def test_mixed_case_digest_label_is_not_a_bypass(self):
        sixty_three = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
        self.assertIn("NPT007_INVALID_DIGEST_LITERAL", codes(f"Sha-256: {sixty_three}"))
        self.assertIn("NPT007_INVALID_DIGEST_LITERAL", codes(f"sha-256: {sixty_three}"))
        valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        self.assertNotIn("NPT007_INVALID_DIGEST_LITERAL", codes(f"Sha-256: {valid}"))

    def test_high_precision_percent_requires_method_or_evidence(self):
        self.assertIn(
            "NPT008_FALSE_PRECISION",
            codes("The dashboard reports 99.9999999% accuracy without a recomputation path."),
        )
        self.assertNotIn(
            "NPT008_FALSE_PRECISION",
            codes("The generated evidence recomputes 99.9999999% from the registered method."),
        )
        self.assertNotIn("NPT008_FALSE_PRECISION", codes("Coverage is 99.82% per the registered evidence."))

    def test_endorsement_implication(self):
        self.assertIn("NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION", codes("DaylightNPT certifies 100% of scores."))
        self.assertIn("NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION", codes("DaylightNPT proves all AI number data is accurate for version 1."))

    def test_precision_superlative_boundary(self):
        failing = codes("This score is as precise as current technology allows: 99.99999%.")
        passing = codes(
            "This score is as precise as current technology allows: 99.99999%, with method named, "
            "evidence source declared, recomputation path listed, and limitation boundary stated."
        )
        self.assertIn("NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION", failing)
        self.assertNotIn("NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION", passing)


if __name__ == "__main__":
    unittest.main()
