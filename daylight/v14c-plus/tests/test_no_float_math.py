from __future__ import annotations

import ast
import unittest
from pathlib import Path

from src import scoring


class NoFloatMathTests(unittest.TestCase):
    def test_parse_fraction_rejects_float(self) -> None:
        with self.assertRaises(scoring.ScoreError):
            scoring.parse_fraction(1.0)

    def test_compute_score_rejects_float(self) -> None:
        with self.assertRaises(scoring.ScoreError):
            scoring.compute_score([("q1_doctrine_master_law", 1.0)], [("q1_doctrine_master_law", "1/1")])

    def test_scoring_source_has_no_float_constants(self) -> None:
        tree = ast.parse(Path(scoring.__file__).read_text(encoding="utf-8"))
        floats = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, float)]
        self.assertEqual(floats, [])


if __name__ == "__main__":
    unittest.main()
