import base64
import copy
import hashlib
import unittest
from pathlib import Path

from src import boundary_debt
from src import external_evidence
from src.canonical import load_json_no_floats

from tests import support_external_evidence as support

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _blocker_text(report):
    return "\n".join(report["blockers"])


class ExternalEvidenceTests(unittest.TestCase):
    def test_programmatic_full_bundle_closes_structure_but_not_crypto(self):
        bundle, capsule, aperture = support.full_bundle()
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry)

        self.assertTrue(report["bundle_digest_verified"])
        self.assertFalse(report["external_evidence_admissible"])
        self.assertFalse(report["external_attestation_verified"])
        self.assertFalse(report["declaration_allowed"])
        self.assertEqual(report["sections"]["subject_binding"]["blockers"], [])
        for section in (
            "independent_rebuild_receipts",
            "firewall_profile_reviews",
            "claim_usable_verifier_vectors",
        ):
            blockers = report["sections"][section]["blockers"]
            self.assertTrue(blockers)
            self.assertTrue(all("attestation is not admissible" in item for item in blockers), blockers)
        self.assertEqual(report["sections"]["claim_usable_verifier_vectors"]["distinct_family_count"], 3)
        self.assertEqual(report["pinned_key_count"], 6)
        blockers = _blocker_text(report)
        self.assertIn(external_evidence.ATTESTATION_NOT_IMPLEMENTED_BLOCKER, blockers)
        self.assertIn("signature is not cryptographically verified", blockers)

    def test_default_valid_shape_example_is_nonclaim_until_pinned_crypto_exists(self):
        report = external_evidence.load_and_evaluate(
            EXAMPLES / "external-evidence.valid-shape.nonclaim.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )

        self.assertTrue(report["bundle_digest_verified"])
        self.assertFalse(report["external_evidence_admissible"])
        self.assertFalse(report["external_attestation_verified"])
        self.assertEqual(report["sections"]["subject_binding"]["blockers"], [])
        self.assertEqual(report["sections"]["claim_usable_verifier_vectors"]["distinct_family_count"], 3)
        self.assertEqual(report["pinned_key_count"], 0)
        blockers = _blocker_text(report)
        self.assertIn("public key is not pinned", blockers)
        self.assertIn(external_evidence.ATTESTATION_NOT_IMPLEMENTED_BLOCKER, blockers)

    def test_empty_bundle_rejects_required_external_slots(self):
        report = external_evidence.load_and_evaluate(
            EXAMPLES / "external-evidence.empty.reject.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )

        blockers = _blocker_text(report)
        self.assertFalse(report["external_evidence_admissible"])
        self.assertIn("fewer than two independent rebuild receipts", blockers)
        self.assertIn("no external firewall profile review supplied", blockers)
        self.assertIn("fewer than three verifier vector families", blockers)

    def test_bundle_digest_mismatch_rejects(self):
        report = external_evidence.load_and_evaluate(
            EXAMPLES / "external-evidence.digest-mismatch.reject.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )

        self.assertFalse(report["bundle_digest_verified"])
        self.assertIn("external evidence bundle digest mismatch", report["blockers"])

    def test_fixture_and_self_scoped_examples_reject(self):
        fixture_report = external_evidence.load_and_evaluate(
            EXAMPLES / "external-evidence.fixture.reject.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )
        self.assertIn("is fixture evidence", _blocker_text(fixture_report))

        self_report = external_evidence.load_and_evaluate(
            EXAMPLES / "external-evidence.self-signed.reject.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )
        self.assertIn("identity is not independent", _blocker_text(self_report))

        internal_report = external_evidence.load_and_evaluate(
            EXAMPLES / "external-evidence.internal-reviewer.reject.json",
            capsule_path=support.CAPSULE_PATH,
            aperture_capsule_path=support.APERTURE_PATH,
        )
        blockers = _blocker_text(internal_report)
        self.assertIn("identity is not independent", blockers)
        self.assertIn("independence class must be external", blockers)

    def test_duplicate_verifier_family_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"verifier_family": "alpha-independent"}, {}, {"verifier_family": "alpha-independent"}]
        )
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry)

        blockers = report["sections"]["claim_usable_verifier_vectors"]["blockers"]
        self.assertIn("duplicate verifier family: alpha-independent", blockers)
        self.assertIn("fewer than three verifier vector families", blockers)

    def test_rebuild_receipts_require_independent_builders_and_environments(self):
        shared_env = support.sha256_text("shared environment")
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[
                {"builder_identity": "same-builder.example.org", "environment_digest": shared_env},
                {"builder_identity": "same-builder.example.org", "environment_digest": shared_env},
            ]
        )
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry)

        blockers = report["sections"]["independent_rebuild_receipts"]["blockers"]
        self.assertIn("rebuild receipts share the same builder identity: same-builder.example.org", blockers)
        self.assertIn(f"rebuild receipts share the same environment digest: {shared_env}", blockers)

    def test_pinned_material_requires_nonclaims_and_key_digest_binding(self):
        key = b"external reviewer public key material"
        digest = hashlib.sha256(key).hexdigest()
        registry = copy.deepcopy(support.load_registry())
        registry["pinned_signers"] = [
            {
                "signer_identity": "external-reviewer.example.org",
                "signer_independence_class": "external",
                "signature_algorithm": "ed25519",
                "public_key_digest": digest,
                "public_key_b64": base64.b64encode(key).decode("ascii"),
                "pinned_by_commit": support.load_capsule()["source_commit"],
            }
        ]

        pins, blockers = external_evidence.validate_pinned_material(registry)
        self.assertEqual(blockers, [])
        self.assertIn(digest, pins)

        missing_nonclaim = copy.deepcopy(registry)
        missing_nonclaim["non_claims_acknowledged"] = list(boundary_debt.REQUIRED_NON_CLAIMS)[:-1]
        with self.assertRaisesRegex(ValueError, "non-claims incomplete"):
            external_evidence.validate_pinned_material(missing_nonclaim)

        mismatched = copy.deepcopy(registry)
        mismatched["pinned_signers"][0]["public_key_digest"] = hashlib.sha256(b"wrong key").hexdigest()
        pins, blockers = external_evidence.validate_pinned_material(mismatched)
        self.assertEqual(pins, {})
        self.assertIn("public_key_digest does not match public_key_b64", _blocker_text({"blockers": blockers}))

        placeholder = copy.deepcopy(registry)
        placeholder_key = b"\x00" * 32
        placeholder["pinned_signers"][0]["public_key_digest"] = hashlib.sha256(placeholder_key).hexdigest()
        placeholder["pinned_signers"][0]["public_key_b64"] = base64.b64encode(placeholder_key).decode("ascii")
        pins, blockers = external_evidence.validate_pinned_material(placeholder)
        self.assertEqual(pins, {})
        self.assertIn("public_key_b64 must not decode to placeholder bytes", _blocker_text({"blockers": blockers}))

    def test_external_evidence_documentation_schemas_track_code_contracts(self):
        bundle_schema = load_json_no_floats(ROOT / "schema/external-evidence.bundle.schema.json")
        self.assertEqual(bundle_schema["properties"]["schema_id"]["const"], external_evidence.SCHEMA_ID)
        self.assertEqual(bundle_schema["properties"]["schema_version"]["const"], external_evidence.SCHEMA_VERSION)
        self.assertEqual(set(bundle_schema["required"]), external_evidence.REQUIRED_BUNDLE_FIELDS)

        receipt_schema = load_json_no_floats(ROOT / "schema/independent-rebuild-receipt.schema.json")
        self.assertEqual(set(receipt_schema["required"]), external_evidence.REQUIRED_REBUILD_RECEIPT_FIELDS)

        review_schema = load_json_no_floats(ROOT / "schema/firewall-profile-review.schema.json")
        self.assertEqual(set(review_schema["required"]), external_evidence.REQUIRED_FIREWALL_REVIEW_FIELDS)

        vector_schema = load_json_no_floats(ROOT / "schema/verifier-vector-claim-usable.schema.json")
        self.assertEqual(set(vector_schema["required"]), external_evidence.REQUIRED_VERIFIER_VECTOR_FIELDS)

        attestation_schema = load_json_no_floats(ROOT / "schema/pinned-attestation.schema.json")
        self.assertEqual(set(attestation_schema["required"]), external_evidence.REQUIRED_PINNED_ATTESTATION_FIELDS)


if __name__ == "__main__":
    unittest.main()
