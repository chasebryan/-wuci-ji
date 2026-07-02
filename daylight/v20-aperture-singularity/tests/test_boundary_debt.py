import unittest
from pathlib import Path

from src import boundary_debt
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]


class BoundaryDebtTests(unittest.TestCase):
    def test_zero_debt_fixture_is_not_claim_usable(self):
        result = boundary_debt.load_and_evaluate(ROOT / "examples/boundary-debt.zero.v20.json")
        self.assertTrue(result["passed"])
        self.assertTrue(result["fixture"])
        self.assertFalse(result["claim_usable"])
        self.assertEqual(result["critical_debt"], 0)

    def test_critical_debt_blocks_declaration(self):
        result = boundary_debt.load_and_evaluate(ROOT / "examples/boundary-debt.critical.reject.v20.json")
        self.assertFalse(result["passed"])
        self.assertEqual(result["critical_debt"], 1)
        self.assertIn("critical boundary debt present", result["blockers"])

    def test_fixture_claim_usable_rejects(self):
        report = load_json_no_floats(ROOT / "examples/boundary-debt.zero.v20.json")
        report["claim_usable"] = True
        result = boundary_debt.evaluate_report(report)
        self.assertFalse(result["passed"])
        self.assertIn("fixture claim usable rejected", result["blockers"])


if __name__ == "__main__":
    unittest.main()
