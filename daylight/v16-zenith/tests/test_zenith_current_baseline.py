from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import zenith_contract, zenith_verifier
from tests import helpers


class ZenithCurrentBaselineTests(unittest.TestCase):
    def test_current_solstice_artifact_is_hermetic_without_score_inflation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = helpers.build_solstice_artifact(Path(tmp))
            report, resolution = zenith_verifier.build_report(artifact_dir)
        self.assertEqual(report["solstice_score_M"], 998900)
        self.assertEqual(report["zenith_adjusted_score_M"], 998900)
        self.assertEqual(report["score_inflation_M"], 0)
        self.assertEqual(report["zenith_level"], "Z3_HERMETIC_SOLSTICE")
        self.assertEqual(report["axis_values"]["z1_hermetic_solstice_artifact"], 1000)
        self.assertEqual(report["axis_values"]["z5_semantic_evidence_replay"], 1000)
        self.assertEqual(report["axis_values"]["z10_boundary_discipline"], 1000)
        self.assertEqual(report["zenith_assurance_M"], 280000)
        self.assertEqual(resolution["zenith_assurance_M"], report["zenith_assurance_M"])

    def test_contract_weights_are_exact(self) -> None:
        self.assertEqual(sum(zenith_contract.Z_AXIS_WEIGHT_M.values()), 1_000_000)
        for axis in zenith_contract.Z_AXES:
            total = sum(ob["weight"] for ob in zenith_contract.Z_OBLIGATIONS if ob["axis_id"] == axis)
            self.assertEqual(total, 1000, axis)


if __name__ == "__main__":
    unittest.main()
