from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import analemma
from tests import helpers


class AnalemmaProgressAndDebtTests(unittest.TestCase):
    def test_internal_fuzz_evidence_increases_A_self_without_D_claim_inflation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            evidence = helpers.write_json(root, "analemma-evidence.json", {
                "fuzz_campaigns": [{
                    "target": "parser",
                    "crash_count": 0,
                    "triaged_crash_count": 0,
                    "coverage_report_digest": "a" * 64
                }]
            })
            report, _ = analemma.build_report(artifact, evidence_path=evidence)
        self.assertEqual(report["D_claim_M"], 998900)
        self.assertEqual(report["score_inflation_M"], 0)
        self.assertEqual(report["proof_mass"], 126000)
        self.assertGreater(report["A_self_A"], 1000000)
        self.assertIn("a.fuzz.parser.adversarial", report["closed_units"])

    def test_regression_debt_subtracts_more_than_reopened_credit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            history = helpers.write_json(root, "analemma-history.json", {
                "previous_closed_units": ["a.fuzz.parser.adversarial"],
                "previous_analemma_score_A": 1188679,
                "best_analemma_score_A": 1188679
            })
            report, _ = analemma.build_report(artifact, history_path=history)
        self.assertEqual(report["regression_debt"], 40000)
        self.assertEqual(report["proof_mass"], 66000)
        self.assertLess(report["A_self_A"], 1000000)
        self.assertIn("a.fuzz.parser.adversarial", report["reopened_units"])

    def test_staleness_debt_lowers_A_self_until_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            history = helpers.write_json(root, "analemma-history.json", {
                "stale_units": ["a.solstice.manifest.replayable"]
            })
            report, _ = analemma.build_report(artifact, history_path=history)
        self.assertEqual(report["staleness_debt"], 24000)
        self.assertEqual(report["proof_mass"], 82000)
        self.assertLess(report["A_self_A"], 1000000)
        self.assertIn("a.solstice.manifest.replayable", report["stale_units"])


if __name__ == "__main__":
    unittest.main()
