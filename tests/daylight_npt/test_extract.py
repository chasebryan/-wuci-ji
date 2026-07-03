import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "daylight/npt/v1"))

from daylight_npt.extract import extract_tokens_from_text


class ExtractTests(unittest.TestCase):
    def test_extracts_numeric_forms(self):
        text = "Score 998,200M / 1,000,000M; 3-of-3; 99.82%; v20.3; 2026-07-02"
        kinds = [token.kind for token in extract_tokens_from_text(text, "fixture.md")]
        self.assertIn("score", kinds)
        self.assertIn("quorum", kinds)
        self.assertIn("percent", kinds)
        self.assertIn("version", kinds)
        self.assertIn("date", kinds)

    def test_ignores_fenced_code_blocks(self):
        text = "Before 42\n```text\nscore 1,000,000M / 1,000,000M\n```\nAfter 3-of-3"
        values = [token.value_raw for token in extract_tokens_from_text(text, "fixture.md")]
        self.assertIn("42", values)
        self.assertIn("3-of-3", values)
        self.assertNotIn("1,000,000M / 1,000,000M", values)


if __name__ == "__main__":
    unittest.main()

