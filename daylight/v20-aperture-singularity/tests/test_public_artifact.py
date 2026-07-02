import tempfile
import tarfile
import unittest
from io import BytesIO
from pathlib import Path

from src import public_artifact
from src.canonical import json_bytes, load_json_no_floats

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
            manifest = load_json_no_floats(out / public_artifact.MANIFEST_FILENAME)
            self.assertEqual(manifest["schema_id"], "daylight-v20-public-artifact-manifest")
            self.assertEqual(manifest["release_tag"], "v20-aperture-singularity-fixture")
            self.assertFalse(manifest["declaration_allowed"])
            self.assertEqual(manifest["expected_files"], public_artifact.EXPECTED_FILES)
            self.assertEqual(len(manifest["schema_digests"]), len(public_artifact.EVIDENCE_SCHEMA_FILENAMES))
            self.assertEqual(
                {entry["path"] for entry in manifest["files"]},
                set(public_artifact.EXPECTED_FILES) - public_artifact.MANIFEST_EXCLUDED_FROM_FILE_ENTRIES,
            )
            slots = load_json_no_floats(out / public_artifact.EVIDENCE_SLOT_CONTRACTS_FILENAME)
            self.assertEqual(slots["schema_id"], "daylight-v20-external-evidence-slot-contracts")
            self.assertEqual({slot["slot_id"] for slot in slots["slots"]}, {
                "reproducible_build.non_fixture_subject_bound_rebuilds",
                "aperture_firewall_boundary.external_profile_expansion",
                "independent_verifier_quorum.claim_usable_3_of_3",
                "external_attestation.pinned_cryptographic_verification",
            })
            ceiling = load_json_no_floats(out / public_artifact.SCORE_CEILING_FILENAME)
            self.assertEqual(ceiling["schema_id"], "daylight-v20-score-ceiling-report")
            self.assertTrue(ceiling["repo_owned_ceiling_reached"])
            self.assertFalse(ceiling["singularity_possible_without_external_validation"])
            self.assertEqual(ceiling["highest_truthful_no_external_score_AM_plus"], ceiling["score_AM_plus"])
            directory_verify = public_artifact.verify_public_artifact(
                out,
                expected_release_tag="v20-aperture-singularity-fixture",
            )
            self.assertTrue(directory_verify["ok"], directory_verify["blockers"])
            tar_verify = public_artifact.verify_public_artifact(
                tar_path,
                expected_release_tag="v20-aperture-singularity-fixture",
            )
            self.assertTrue(tar_verify["ok"], tar_verify["blockers"])
            self.assertEqual(tar_verify["artifact_type"], "tar.gz")
            self.assertRegex(tar_verify["tar_sha256"], r"^[0-9a-f]{64}$")

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

    def test_public_artifact_verify_rejects_release_tag_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            public_artifact.build_public_artifact(
                ROOT / "examples/aperture-singularity-capsule.fixture.v20.json",
                out,
                force=True,
                tar_path=Path(tmp) / "public-review-artifact.tar.gz",
            )
            report = public_artifact.verify_public_artifact(out, expected_release_tag="not-this-release")
            self.assertFalse(report["ok"])
            self.assertIn("manifest release_tag does not match expected release tag", report["blockers"])

    def test_public_artifact_verify_rejects_bundle_digest_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            public_artifact.build_public_artifact(
                ROOT / "examples/aperture-singularity-capsule.fixture.v20.json",
                out,
                force=True,
                tar_path=Path(tmp) / "public-review-artifact.tar.gz",
            )
            swapped = load_json_no_floats(ROOT / "examples/verifier-agreement.partial-2-of-3.v20.json")
            (out / public_artifact.VERIFIER_BUNDLE_FILENAME).write_bytes(json_bytes(swapped))
            capsule = load_json_no_floats(out / public_artifact.CAPSULE_FILENAME)
            (out / public_artifact.MANIFEST_FILENAME).write_bytes(
                json_bytes(public_artifact._public_artifact_manifest(out, capsule))
            )
            public_artifact._write_sums(out)
            report = public_artifact.verify_public_artifact(out)
            self.assertFalse(report["ok"])
            self.assertIn(
                "verifier-agreement.bundle.json canonical digest does not match capsule input_verifier_agreement_bundle_digest",
                report["blockers"],
            )

    def test_public_artifact_rejects_tar_inside_public_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            with self.assertRaises(ValueError):
                public_artifact.build_public_artifact(
                    ROOT / "examples/aperture-singularity-capsule.fixture.v20.json",
                    out,
                    force=True,
                    tar_path=out / "inside.tar.gz",
                )

    def test_public_artifact_verify_rejects_tar_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / "bad.tar.gz"
            with tarfile.open(tar_path, "w:gz") as archive:
                data = b"bad\n"
                info = tarfile.TarInfo("../escape")
                info.size = len(data)
                archive.addfile(info, BytesIO(data))
            with self.assertRaises(ValueError):
                public_artifact.verify_public_artifact(tar_path)

    def test_public_artifact_verify_rejects_tar_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / "bad-link.tar.gz"
            with tarfile.open(tar_path, "w:gz") as archive:
                info = tarfile.TarInfo(public_artifact.CAPSULE_FILENAME)
                info.type = tarfile.SYMTYPE
                info.linkname = "target"
                archive.addfile(info)
            with self.assertRaises(ValueError):
                public_artifact.verify_public_artifact(tar_path)


if __name__ == "__main__":
    unittest.main()
