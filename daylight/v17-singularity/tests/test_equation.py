from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import singularity
from tests import helpers


class SingularityEquationTests(unittest.TestCase):
    def test_example_closures_reach_declared_target(self) -> None:
        closures = {
            "claim": singularity.closure_scaled_from_decimal_text("0.998900"),
            "self": singularity.closure_scaled_from_decimal_text("0.900000"),
            "artifact": singularity.closure_scaled_from_decimal_text("0.995000"),
            "replay": singularity.closure_scaled_from_decimal_text("0.950000"),
            "implementation": singularity.closure_scaled_from_decimal_text("0.950000"),
            "fuzz": singularity.closure_scaled_from_decimal_text("0.900000"),
            "formal": singularity.closure_scaled_from_decimal_text("0.900000"),
            "crypto": singularity.closure_scaled_from_decimal_text("0.950000"),
            "falsification": singularity.closure_scaled_from_decimal_text("0.900000"),
            "boundary": singularity.closure_scaled_from_decimal_text("0.950000"),
        }
        registry = singularity.load_registry()
        weights = {field["id"]: field["weight_centi"] for field in registry["fields"]}
        result = singularity.score_from_scaled_closures(closures, weights)
        self.assertEqual(result["score_AM_plus"], 999_999_999)
        self.assertTrue(result["declared"])
        self.assertGreaterEqual(result["omega"], singularity.LN_B)

    def test_current_verified_artifacts_do_not_declare_without_v17_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            solstice, zenith, analemma = helpers.build_upstream(Path(tmp))
            scorecard, _ = singularity.build_scorecard(
                solstice_artifact_dir=solstice,
                zenith_report_dir=zenith,
                analemma_report_dir=analemma,
            )
        self.assertEqual(scorecard["score_inflation"]["score_inflation_M"], 0)
        self.assertFalse(scorecard["declared"])
        self.assertLess(scorecard["score_AM_plus"], 999_999_999)
        self.assertFalse(scorecard["collapse_state"]["collapsed"])

    def test_self_progress_closure_is_zero_at_baseline(self) -> None:
        self.assertEqual(singularity.self_progress_closure(106000, 106000), 0)


if __name__ == "__main__":
    unittest.main()

