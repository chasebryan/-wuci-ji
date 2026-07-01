from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import analemma
from tests import helpers


class AnalemmaReportArtifactTests(unittest.TestCase):
    def test_report_artifact_hashes_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            out = root / "analemma"
            manifest = analemma.build_report_artifact(artifact, out_dir=out)
            analemma.verify_report_dir(out)
        self.assertEqual(manifest["D_claim_M"], 998900)
        self.assertEqual(manifest["A_self_A"], 1000000)
        self.assertEqual(manifest["score_inflation_M"], 0)


if __name__ == "__main__":
    unittest.main()
