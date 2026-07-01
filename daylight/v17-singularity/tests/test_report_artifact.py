from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src import singularity
from tests import helpers


class SingularityReportArtifactTests(unittest.TestCase):
    def test_report_artifact_hashes_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            out = root / "singularity"
            manifest = singularity.build_report_artifact(
                solstice_artifact_dir=solstice,
                zenith_report_dir=zenith,
                analemma_report_dir=analemma,
                out_dir=out,
            )
            singularity.verify_report_dir(out)
        self.assertEqual(manifest["score_AM_plus"], manifest["score_AM_plus"])
        self.assertFalse(manifest["declared"])
        self.assertFalse(manifest["collapse_state"]["collapsed"])

    def test_scorecard_edit_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            scorecard, _ = singularity.build_scorecard(
                solstice_artifact_dir=solstice,
                zenith_report_dir=zenith,
                analemma_report_dir=analemma,
            )
            scorecard["score_AM_plus"] += 1
            with self.assertRaises(singularity.SingularityError):
                singularity.verify_scorecard_integrity(scorecard)

    def test_field_closure_edit_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            scorecard, _ = singularity.build_scorecard(
                solstice_artifact_dir=solstice,
                zenith_report_dir=zenith,
                analemma_report_dir=analemma,
            )
            scorecard["fields"]["claim"]["closure_pptrillion"] -= 1
            scorecard["singularity_digest"] = singularity.scorecard_digest(scorecard)
            with self.assertRaises(singularity.SingularityError):
                singularity.verify_scorecard_integrity(scorecard)


if __name__ == "__main__":
    unittest.main()

