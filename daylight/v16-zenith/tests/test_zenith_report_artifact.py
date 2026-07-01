from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import zenith_verifier
from tests import helpers


class ZenithReportArtifactTests(unittest.TestCase):
    def test_report_artifact_hashes_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            out = root / "zenith"
            manifest = zenith_verifier.build_report_artifact(
                solstice_artifact_dir=artifact,
                out_dir=out,
            )
            zenith_verifier.verify_report_dir(out)
        self.assertEqual(manifest["score_inflation_M"], 0)
        self.assertEqual(manifest["zenith_level"], "Z3_HERMETIC_SOLSTICE")


if __name__ == "__main__":
    unittest.main()
