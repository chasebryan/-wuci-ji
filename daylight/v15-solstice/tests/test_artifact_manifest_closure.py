from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src import artifact_verify
from tests import helpers


class ArtifactManifestClosureTests(unittest.TestCase):
    def test_artifact_verifier_checks_manifest_and_output_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path, corpus_path = helpers.write_seed_inputs(root)
            out_dir = root / "artifact"
            artifact_verify.build_artifact(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                out_dir=out_dir,
                command_label="test",
            )
            artifact_verify.verify_artifact_dir(out_dir)

            scorecard_path = out_dir / "scorecard.v15-solstice.json"
            scorecard = json.loads(scorecard_path.read_text(encoding="utf-8"))
            scorecard["score_body"]["final_score_M"] = 998901
            scorecard_path.write_text(json.dumps(scorecard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaises(artifact_verify.ArtifactError):
                artifact_verify.verify_artifact_dir(out_dir)


if __name__ == "__main__":
    unittest.main()
