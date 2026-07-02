from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import horizon_release


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"


class HorizonReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifact = self.root / "dist.tar.gz"
        self.artifact.write_bytes(b"release artifact")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_research_release_gate_passes(self) -> None:
        release = self.root / "dist.tar.gz.dhr"
        capsule = horizon_release.prepare_release(
            artifact_path=self.artifact,
            output_path=release,
            state_path=CURRENT_STATE,
            mode="research",
        )
        self.assertEqual(capsule["release_status"], "research_release_allowed")
        result = horizon_release.gate_release(release_path=release, artifact_path=self.artifact, state_path=CURRENT_STATE)
        self.assertTrue(result["gate_allowed"])
        self.assertEqual(result["decision"], "research_release_allowed")

    def test_production_gate_refuses(self) -> None:
        release = self.root / "prod.tar.gz.dhr"
        horizon_release.prepare_release(
            artifact_path=self.artifact,
            output_path=release,
            state_path=CURRENT_STATE,
            mode="production",
        )
        result = horizon_release.gate_release(release_path=release, artifact_path=self.artifact, state_path=CURRENT_STATE)
        self.assertFalse(result["gate_allowed"])
        self.assertEqual(result["decision"], "production_release_refused")
        self.assertIn("production_allowed=false", result["blockers"])

    def test_declaration_policy_rejects_current_score(self) -> None:
        release = self.root / "declaration.tar.gz.dhr"
        horizon_release.prepare_release(
            artifact_path=self.artifact,
            output_path=release,
            state_path=CURRENT_STATE,
            mode="declaration",
        )
        result = horizon_release.gate_release(release_path=release, artifact_path=self.artifact, state_path=CURRENT_STATE)
        self.assertFalse(result["gate_allowed"])
        self.assertIn("cross_verifier_agreement_passed=false", result["blockers"])
        self.assertIn("declaration release requires declared=true", result["blockers"])

    def test_artifact_digest_mismatch_rejects(self) -> None:
        release = self.root / "dist.tar.gz.dhr"
        horizon_release.prepare_release(
            artifact_path=self.artifact,
            output_path=release,
            state_path=CURRENT_STATE,
            mode="research",
        )
        self.artifact.write_bytes(b"modified artifact")
        result = horizon_release.verify_release(release_path=release, artifact_path=self.artifact, state_path=CURRENT_STATE)
        self.assertFalse(result["verified"])
        self.assertIn("artifact digest mismatch", result["blockers"])


if __name__ == "__main__":
    unittest.main()
