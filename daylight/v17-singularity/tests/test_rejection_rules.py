from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src import singularity
from src.canonical_json import sha256_bytes
from tests import helpers


class SingularityRejectionRuleTests(unittest.TestCase):
    def test_float_evidence_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            evidence = root / "float-evidence.json"
            evidence.write_text('{"version":"daylight-v17-singularity-evidence-v0.1","debt_events":[{"debt_micro":1.5}]}\n', encoding="utf-8")
            with self.assertRaises(Exception):
                singularity.build_scorecard(
                    solstice_artifact_dir=solstice,
                    zenith_report_dir=zenith,
                    analemma_report_dir=analemma,
                    evidence_path=evidence,
                )

    def test_manual_score_evidence_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            evidence = helpers.write_json(root, "manual.json", {
                "version": "daylight-v17-singularity-evidence-v0.1",
                "score_AM_plus": 999999999,
            })
            with self.assertRaises(singularity.SingularityError):
                singularity.build_scorecard(
                    solstice_artifact_dir=solstice,
                    zenith_report_dir=zenith,
                    analemma_report_dir=analemma,
                    evidence_path=evidence,
                )

    def test_release_facing_overclaim_collapses_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            evidence = helpers.write_json(root, "overclaim.json", {
                "version": "daylight-v17-singularity-evidence-v0.1",
                "release_facing": True,
                "declared_claims": {"production_allowed": True},
            })
            scorecard, _ = singularity.build_scorecard(
                solstice_artifact_dir=solstice,
                zenith_report_dir=zenith,
                analemma_report_dir=analemma,
                evidence_path=evidence,
            )
        self.assertEqual(scorecard["score_AM_plus"], 0)
        self.assertTrue(scorecard["collapse_state"]["collapsed"])
        self.assertIn("production_allowed", scorecard["collapse_state"]["reasons"])

    def test_open_critical_break_collapses_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            evidence = helpers.write_json(root, "break.json", {
                "version": "daylight-v17-singularity-evidence-v0.1",
                "break_ledger": [{
                    "id": "break.forged_scorecard",
                    "class": "B5_forged_scorecard_accepted",
                    "resolved": False,
                }],
            })
            scorecard, _ = singularity.build_scorecard(
                solstice_artifact_dir=solstice,
                zenith_report_dir=zenith,
                analemma_report_dir=analemma,
                evidence_path=evidence,
            )
        self.assertEqual(scorecard["score_AM_plus"], 0)
        self.assertTrue(scorecard["collapse_state"]["collapsed"])

    def test_zenith_score_inflation_rejected_even_when_hashes_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solstice, zenith, analemma = helpers.build_upstream(root)
            report_path = zenith / "zenith-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["score_inflation_M"] = 1
            report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            manifest_path = zenith / "zenith-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["outputs"]["zenith-report.json"]["sha256"] = sha256_bytes(report_path.read_bytes())
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            sums = "".join(
                f"{sha256_bytes((zenith / name).read_bytes())}  {name}\n"
                for name in sorted(list(manifest["outputs"]) + ["zenith-manifest.json"])
            )
            (zenith / "SHA256SUMS").write_text(sums, encoding="utf-8")
            with self.assertRaises(singularity.SingularityError):
                singularity.build_scorecard(
                    solstice_artifact_dir=solstice,
                    zenith_report_dir=zenith,
                    analemma_report_dir=analemma,
                )


if __name__ == "__main__":
    unittest.main()

