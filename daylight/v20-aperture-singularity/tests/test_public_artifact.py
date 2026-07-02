import tempfile
import unittest
from pathlib import Path

from src import public_artifact

ROOT = Path(__file__).resolve().parents[1]


class PublicArtifactTests(unittest.TestCase):
    def test_public_artifact_builds_and_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            tar_path = Path(tmp) / "public-review-artifact.tar.gz"
            firewall_report = Path(tmp) / "firewall-report.v20.json"
            report = public_artifact.build_public_artifact(
                ROOT / "examples/aperture-singularity-capsule.fixture.v20.json",
                out,
                force=True,
                tar_path=tar_path,
                firewall_report_path=firewall_report,
            )
            self.assertTrue(report["firewall_ok"])
            self.assertTrue(tar_path.is_file())
            self.assertEqual(Path(report["firewall_report_path"]), firewall_report)
            self.assertTrue(firewall_report.is_file())
            for name in public_artifact.EXPECTED_FILES:
                self.assertTrue((out / name).is_file(), name)
            scan = public_artifact.scan_public_root(out)
            self.assertTrue(scan["ok"], scan["violations"])

    def test_public_artifact_detects_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            public_artifact.build_public_artifact(
                ROOT / "examples/aperture-singularity-capsule.fixture.v20.json",
                out,
                force=True,
                tar_path=Path(tmp) / "public-review-artifact.tar.gz",
            )
            (out / public_artifact.BLOCKER_VECTOR_FILENAME).write_text("drift\n", encoding="utf-8")
            scan = public_artifact.scan_public_root(out)
            self.assertFalse(scan["ok"])
            reasons = {item["reason"] for item in scan["violations"]}
            self.assertIn("sha256sum_mismatch", reasons)
            self.assertIn("sha3_512sum_mismatch", reasons)


if __name__ == "__main__":
    unittest.main()
