import tempfile
import unittest
from pathlib import Path

from src import proof_fields
from src import singularity_gate
from src.canonical import json_bytes, load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]


class SingularityGateTests(unittest.TestCase):
    def test_fixture_capsule_verifies_and_refuses_declaration(self):
        capsule = singularity_gate.load_capsule(ROOT / "examples/aperture-singularity-capsule.fixture.v20.json")
        self.assertFalse(capsule["declaration_allowed"])
        self.assertTrue(capsule["fixture"])
        self.assertFalse(capsule["claim_usable"])
        for key in (
            "input_verifier_agreement_bundle_digest",
            "input_external_attestation_bundle_digest",
            "input_reproducible_build_bundle_digest",
            "input_falsification_bundle_digest",
            "input_boundary_debt_report_digest",
        ):
            self.assertRegex(capsule[key], r"^[0-9a-f]{64}$")
        self.assertNotIn("verifier quorum incomplete: 2/3", capsule["blockers"])
        self.assertEqual(capsule["verifier_quorum"], "3_of_3")
        self.assertIn("verifier vectors are fixture evidence", capsule["blockers"])
        self.assertIn("verifier vectors are not claim-usable", capsule["blockers"])
        self.assertIn("external attestation not cryptographically verified", capsule["blockers"])
        self.assertIn("field threshold failed: reproducible_build", capsule["blockers"])
        self.assertIn("reproducible build receipts are fixture evidence", capsule["blockers"])
        self.assertIn("reproducible build artifact SHA-256 does not match capsule subject", capsule["blockers"])
        reproducible_field = next(field for field in capsule["proof_fields"] if field["field_id"] == "reproducible_build")
        self.assertIn("receipts_non_fixture", reproducible_field["open_atoms"])
        self.assertIn("source_commit_matches_capsule", reproducible_field["open_atoms"])
        aperture_field = next(field for field in capsule["proof_fields"] if field["field_id"] == "aperture_firewall_boundary")
        self.assertIn("public_artifact_firewall_negative_matrix_verified", aperture_field["closed_atoms"])
        self.assertIn("firewall_profile_externally_expanded", aperture_field["open_atoms"])
        self.assertLess(int(capsule["score_AM_plus"]), proof_fields.DECLARATION_TARGET_AM_PLUS)
        report = singularity_gate.declaration_report(capsule)
        requirement_ids = {item["requirement_id"] for item in report["required_evidence"]}
        self.assertIn("reproducible_build.non_fixture_subject_bound_rebuilds", requirement_ids)
        self.assertIn("external_attestation.pinned_cryptographic_verification", requirement_ids)
        self.assertIn("independent_verifier_quorum.claim_usable_3_of_3", requirement_ids)

    def test_build_capsule_default_is_deterministic(self):
        built = singularity_gate.build_capsule(
            aperture_capsule_path=ROOT.parent / "v19-aperture-bastion/examples/expected-capsule.v19.json"
        )
        committed = load_json_no_floats(ROOT / "examples/aperture-singularity-capsule.fixture.v20.json")
        self.assertEqual(built, committed)

    def test_fixture_inputs_propagate_even_with_non_fixture_boundary_report(self):
        boundary = load_json_no_floats(ROOT / "examples/boundary-debt.zero.v20.json")
        boundary["fixture"] = False
        boundary["claim_usable"] = True
        with tempfile.TemporaryDirectory() as tmp:
            boundary_path = Path(tmp) / "boundary.nonfixture.json"
            boundary_path.write_bytes(json_bytes(boundary))
            capsule = singularity_gate.build_capsule(
                aperture_capsule_path=ROOT.parent / "v19-aperture-bastion/examples/expected-capsule.v19.json",
                boundary_debt_path=boundary_path,
            )
        self.assertTrue(capsule["fixture"])
        self.assertFalse(capsule["claim_usable"])
        self.assertIn("fixture=true", capsule["blockers"])
        self.assertIn("claim_usable=false", capsule["blockers"])
        self.assertTrue(capsule["boundary_debt_summary"]["passed"])

    def test_reserved_perfect_value_rejects_verification(self):
        capsule = load_json_no_floats(ROOT / "examples/aperture-singularity-capsule.fixture.v20.json")
        capsule["score_AM_plus"] = proof_fields.PERFECT_RESERVED_AM_PLUS
        capsule["blockers"] = singularity_gate.declaration_blockers(capsule)
        capsule["capsule_digest"] = singularity_gate.capsule_digest(capsule)
        with self.assertRaises(ValueError):
            singularity_gate.validate_capsule(capsule)


if __name__ == "__main__":
    unittest.main()
