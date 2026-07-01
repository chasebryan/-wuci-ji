from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import analemma
from tests import helpers


class AnalemmaBaselineTests(unittest.TestCase):
    def test_current_solstice_artifact_is_baseline_self_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = helpers.build_solstice_artifact(Path(tmp))
            report, resolution = analemma.build_report(artifact)
        self.assertEqual(report["D_claim_M"], 998900)
        self.assertEqual(report["A_self_A"], 1000000)
        self.assertEqual(report["E_trust_M"], 0)
        self.assertEqual(report["C_level"], "C1_replayable_public_artifact")
        self.assertEqual(report["score_inflation_M"], 0)
        self.assertEqual(report["closed_credit"], 106000)
        self.assertEqual(report["proof_mass"], 106000)
        self.assertEqual(report["proof_mass_growth_basis_points"], 0)
        self.assertEqual(report["delta_since_baseline_A"], 0)
        self.assertEqual(resolution["proof_mass"], report["proof_mass"])

    def test_design_next_score_example_is_exact_integer_math(self) -> None:
        self.assertEqual(analemma.analemma_score_A(620000, 500000), 1240000)
        self.assertEqual(analemma.proof_mass_growth_basis_points(620000, 500000), 2400)

    def test_registry_base_credit_formula_is_exact(self) -> None:
        registry = analemma.load_registry()
        self.assertEqual(registry["baseline_proof_mass"], 106000)
        baseline_units = [
            "a.solstice.scorecard.structural",
            "a.solstice.artifact.executable",
            "a.solstice.output_ledger.replayable",
            "a.solstice.manifest.replayable",
            "a.solstice.weights.structural",
            "a.solstice.resolution.replayable",
            "a.solstice.semantic_corpus.replayable",
            "a.solstice.claim_boundary.structural",
            "a.solstice.manual_score.executable",
            "a.analemma.no_score_inflation.executable",
        ]
        credits = {unit["id"]: unit["base_credit"] for unit in registry["proof_units"]}
        self.assertEqual(sum(credits[uid] for uid in baseline_units), registry["baseline_proof_mass"])


if __name__ == "__main__":
    unittest.main()
