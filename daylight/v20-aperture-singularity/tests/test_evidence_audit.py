import unittest
from pathlib import Path

from src import evidence_audit
from src import singularity_gate

ROOT = Path(__file__).resolve().parents[1]


class EvidenceAuditTests(unittest.TestCase):
    def test_fixture_capsule_blockers_are_classified(self):
        capsule = singularity_gate.load_capsule(ROOT / "examples/aperture-singularity-capsule.fixture.v20.json")
        report = evidence_audit.audit_capsule(capsule)
        self.assertEqual(report["status"], "fixture_boundary_active")
        self.assertTrue(report["fixture_boundary_active"])
        self.assertFalse(report["only_external_evidence_blockers"])
        self.assertEqual(report["unclassified_blockers"], [])
        self.assertEqual(report["repo_owned_code_gap_count"], 0)
        requirement_ids = {item["requirement_id"] for item in report["requirement_classes"]}
        self.assertIn("reproducible_build.non_fixture_subject_bound_rebuilds", requirement_ids)
        self.assertIn("external_attestation.pinned_cryptographic_verification", requirement_ids)

    def test_unknown_blocker_is_repo_owned_gap(self):
        item = evidence_audit.classify_blocker("new unclassified blocker")
        self.assertIsNone(item["requirement_id"])
        self.assertTrue(item["repo_owned_code_gap"])
        self.assertFalse(item["external_evidence_required"])


if __name__ == "__main__":
    unittest.main()
