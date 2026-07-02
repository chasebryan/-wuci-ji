import tempfile
import unittest
from pathlib import Path

from src import external_evidence
from src import public_artifact
from src.canonical import json_bytes, load_json_no_floats, loads_json_no_floats
from tests import support_external_evidence as support

ROOT = Path(__file__).resolve().parents[1]

EXAMPLE_EXPECTATIONS = {
    "external-evidence.empty.reject.json": "fewer than two independent rebuild receipts",
    "external-evidence.self-signed.reject.json": "signer identity is not independent",
    "external-evidence.internal-reviewer.reject.json": "reviewer identity is not independent",
    "external-evidence.fixture.reject.json": "is fixture evidence",
    "external-evidence.digest-mismatch.reject.json": "external evidence bundle digest mismatch",
    "external-evidence.unpinned-key.reject.json": "public key is not pinned",
    "external-evidence.valid-shape.nonclaim.json": "public key is not pinned",
}


class ExternalEvidenceIntakeTests(unittest.TestCase):
    def test_every_example_bundle_is_rejected(self):
        for name, needle in EXAMPLE_EXPECTATIONS.items():
            report = external_evidence.load_and_evaluate(
                ROOT / "examples" / name,
                capsule_path=support.CAPSULE_PATH,
                aperture_capsule_path=support.APERTURE_PATH,
            )
            self.assertFalse(report["external_evidence_admissible"], name)
            self.assertFalse(report["external_attestation_verified"], name)
            self.assertFalse(report["declaration_allowed"], name)
            self.assertFalse(report["singularity_possible_without_external_validation"], name)
            self.assertIn(external_evidence.ATTESTATION_NOT_IMPLEMENTED_BLOCKER, report["blockers"], name)
            self.assertTrue(support.has_blocker(report, needle), f"{name}: {report['blockers']}")

    def test_empty_bundle_reports_all_missing_sections(self):
        report = external_evidence.load_and_evaluate(
            ROOT / "examples/external-evidence.empty.reject.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )
        self.assertTrue(support.has_blocker(report, "fewer than two independent rebuild receipts"))
        self.assertTrue(support.has_blocker(report, "no external firewall profile review supplied"))
        self.assertTrue(support.has_blocker(report, "fewer than three verifier vector families"))
        self.assertTrue(report["bundle_digest_verified"])
        self.assertEqual(report["attestation_count"], 0)

    def test_bundle_digest_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["bundle_digest"] = support.sha256_text("not the canonical bundle digest")
        report = support.evaluate(bundle, capsule, aperture)
        self.assertFalse(report["bundle_digest_verified"])
        self.assertTrue(support.has_blocker(report, "external evidence bundle digest mismatch"))

    def test_resealed_bundle_with_swapped_subject_still_rejected(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["subject"]["artifact_sha256"] = support.sha256_text("laundered artifact")
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(report["bundle_digest_verified"])
        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "subject artifact SHA-256 does not match aperture capsule subject"))
        self.assertTrue(support.has_blocker(report, "artifact SHA-256 does not match subject"))

    def test_valid_shape_nonclaim_remains_inadmissible(self):
        report = external_evidence.load_and_evaluate(
            ROOT / "examples/external-evidence.valid-shape.nonclaim.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )
        self.assertTrue(report["bundle_digest_verified"])
        self.assertFalse(report["external_evidence_admissible"])
        self.assertFalse(report["external_attestation_verified"])
        allowed = (
            "public key is not pinned",
            "attestation is not admissible",
            external_evidence.ATTESTATION_NOT_IMPLEMENTED_BLOCKER,
        )
        for blocker in report["blockers"]:
            self.assertTrue(any(kind in blocker for kind in allowed), blocker)

    def test_missing_capsule_fails_closed(self):
        report = external_evidence.load_and_evaluate(ROOT / "examples/external-evidence.valid-shape.nonclaim.json")
        self.assertTrue(support.has_blocker(report, "subject binding not verified: no v20 capsule supplied"))
        self.assertTrue(
            support.has_blocker(report, "subject artifact binding not verified: no v19 aperture capsule supplied")
        )

    def test_missing_pinned_material_fails_closed(self):
        bundle, capsule, aperture = support.full_bundle()
        report = external_evidence.evaluate_bundle(bundle, capsule=capsule, aperture_capsule=aperture)
        self.assertTrue(support.has_blocker(report, "pinned verification material not supplied"))
        self.assertTrue(support.has_blocker(report, "public key is not pinned"))

    def test_fixture_laundering_identity_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{"builder_identity": "fixture-farm-3"}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "builder identity is not independent: fixture-farm-3"))

    def test_placeholder_digests_are_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{"build_instructions_digest": "8" * 64}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "must not be a placeholder value"))

    def test_duplicate_json_keys_and_floats_reject(self):
        with self.assertRaises(ValueError):
            loads_json_no_floats('{"schema_id": "a", "schema_id": "b"}')
        bundle, capsule, aperture = support.full_bundle()
        bundle["subject"]["artifact_size"] = 1.5
        with self.assertRaises(ValueError):
            support.evaluate(bundle, capsule, aperture)

    def test_orphan_attestation_rejects(self):
        bundle, capsule, aperture = support.full_bundle()
        item = support.build_receipt(bundle["subject"], 9)
        _bound, orphan = support.attest(
            item,
            external_evidence.rebuild_receipt_binding_digest(item),
            "test-att-orphan",
            "test-orphan.example.org",
        )
        bundle["pinned_attestations"].append(orphan)
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "attestation not referenced by any evidence item: test-att-orphan"))

    def test_bundle_file_with_nul_bytes_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.json"
            path.write_bytes(b'{"schema_id": "daylight.v20.external-evidence.bundle"\x00}')
            with self.assertRaises(ValueError):
                external_evidence.load_and_evaluate(path)

    def test_schema_files_match_module_contracts(self):
        cases = [
            ("external-evidence.bundle.schema.json", external_evidence.REQUIRED_BUNDLE_FIELDS),
            ("independent-rebuild-receipt.schema.json", external_evidence.REQUIRED_REBUILD_RECEIPT_FIELDS),
            ("firewall-profile-review.schema.json", external_evidence.REQUIRED_FIREWALL_REVIEW_FIELDS),
            ("verifier-vector-claim-usable.schema.json", external_evidence.REQUIRED_VERIFIER_VECTOR_FIELDS),
            ("pinned-attestation.schema.json", external_evidence.REQUIRED_PINNED_ATTESTATION_FIELDS),
        ]
        for filename, required in cases:
            schema = load_json_no_floats(ROOT / "schema" / filename)
            self.assertEqual(schema["$id"], filename)
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(required), filename)
        bundle_schema = load_json_no_floats(ROOT / "schema/external-evidence.bundle.schema.json")
        self.assertEqual(bundle_schema["properties"]["schema_id"]["const"], external_evidence.SCHEMA_ID)
        self.assertEqual(bundle_schema["properties"]["schema_version"]["const"], external_evidence.SCHEMA_VERSION)
        self.assertEqual(
            set(bundle_schema["properties"]["subject"]["required"]),
            set(external_evidence.REQUIRED_SUBJECT_FIELDS),
        )

    def test_public_artifact_swapped_evidence_bundle_rejected_after_manifest_regen(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            public_artifact.build_public_artifact(
                ROOT / "examples/aperture-singularity-capsule.fixture.v20.json",
                out,
                force=True,
                tar_path=Path(tmp) / "public-review-artifact.tar.gz",
            )
            swapped = load_json_no_floats(ROOT / "examples/external-attestation.self-signed.reject.v20.json")
            (out / public_artifact.EXTERNAL_ATTESTATION_FILENAME).write_bytes(json_bytes(swapped))
            capsule = load_json_no_floats(out / public_artifact.CAPSULE_FILENAME)
            (out / public_artifact.MANIFEST_FILENAME).write_bytes(
                json_bytes(public_artifact._public_artifact_manifest(out, capsule))
            )
            public_artifact._write_sums(out)
            report = public_artifact.verify_public_artifact(out)
            self.assertFalse(report["ok"])
            self.assertIn(
                "external-attestation.bundle.json canonical digest does not match capsule input_external_attestation_bundle_digest",
                report["blockers"],
            )

    def test_explain_blockers_groups_the_four_slots(self):
        report = external_evidence.load_and_evaluate(
            ROOT / "examples/external-evidence.empty.reject.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )
        explanation = external_evidence.explain_blockers(report)
        self.assertFalse(explanation["external_evidence_admissible"])
        self.assertFalse(explanation["singularity_possible_without_external_validation"])
        slot_ids = {group["slot_id"] for group in explanation["blocker_groups"]}
        self.assertEqual(
            slot_ids,
            {
                "reproducible_build.non_fixture_subject_bound_rebuilds",
                "aperture_firewall_boundary.external_profile_expansion",
                "independent_verifier_quorum.claim_usable_3_of_3",
                "external_attestation.pinned_cryptographic_verification",
            },
        )
        self.assertTrue(all(group["open"] for group in explanation["blocker_groups"]))


if __name__ == "__main__":
    unittest.main()
