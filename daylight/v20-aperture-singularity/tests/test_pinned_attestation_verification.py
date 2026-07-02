import base64
import unittest

from src import external_evidence
from tests import support_external_evidence as support


class PinnedAttestationVerificationTests(unittest.TestCase):
    def test_unpinned_key_rejects(self):
        bundle, capsule, aperture = support.full_bundle()
        report = support.evaluate(bundle, capsule, aperture)
        self.assertEqual(report["pinned_key_count"], 0)
        self.assertTrue(support.has_blocker(report, "public key is not pinned"))

    def test_pinned_key_is_still_not_cryptographically_verified(self):
        bundle, capsule, aperture = support.full_bundle()
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertGreater(report["pinned_key_count"], 0)
        self.assertFalse(support.has_blocker(report, "public key is not pinned"))
        self.assertTrue(support.has_blocker(report, "signature is not cryptographically verified"))
        self.assertIn(external_evidence.ATTESTATION_NOT_IMPLEMENTED_BLOCKER, report["blockers"])
        self.assertFalse(report["external_attestation_verified"])
        self.assertFalse(report["external_evidence_admissible"])
        self.assertEqual(report["cryptographically_verified_attestation_count"], 0)

    def test_verification_hook_is_not_implemented(self):
        self.assertEqual(external_evidence.IMPLEMENTED_SIGNATURE_ALGORITHMS, frozenset())
        bundle, _capsule, _aperture = support.full_bundle()
        registry = support.pin_registry_for(bundle)
        attestation = bundle["pinned_attestations"][0]
        pin = registry["pinned_signers"][0]
        self.assertFalse(external_evidence._verify_signature(attestation, pin))
        self.assertEqual(
            external_evidence.ATTESTATION_NOT_IMPLEMENTED_BLOCKER,
            "pinned cryptographic attestation verification not implemented",
        )

    def test_unsupported_signature_algorithm_rejects(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"signature_algorithm": "rsa-sha256"})
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "unsupported signature algorithm: rsa-sha256"))

    def test_statement_digest_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["pinned_attestations"][0]["signer_identity"] = "renamed-signer.example.org"
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "statement digest mismatch"))

    def test_subject_digest_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"subject_digest": support.sha256_text("not the evidence item")},
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "attestation subject digest does not match evidence item"))

    def test_self_scoped_signer_rejects(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"signer_identity": "harness-bot"})
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "signer identity is not independent: harness-bot"))

    def test_non_external_signer_class_rejects(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"signer_independence_class": "repo"})
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "signer independence class must be external: repo"))

    def test_fixture_attestation_rejects(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"fixture": True})
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "is fixture evidence"))

    def test_not_claim_usable_attestation_rejects(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"claim_usable": False})
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "is not claim-usable"))

    def test_absolute_verification_material_ref_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"verification_material_ref": "/etc/verification-material.json"},
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "verification material ref rejected"))

    def test_traversal_verification_material_ref_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"verification_material_ref": "daylight/../secrets.json"},
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "verification material ref rejected"))

    def test_wrong_verification_material_ref_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"verification_material_ref": "daylight/v20-aperture-singularity/examples/other.json"},
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "verification material ref is not the pinned registry"))

    def test_placeholder_signature_rejects(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"signature": "AAAA"})
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "signature must not be a placeholder value"))

    def test_invalid_base64_signature_rejects(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"signature": "not base64!!"})
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "signature must be base64 text"))

    def test_registry_rejects_key_digest_that_does_not_match_material(self):
        bundle, capsule, aperture = support.full_bundle()
        registry = support.pin_registry_for(bundle)
        registry["pinned_signers"][0]["public_key_b64"] = base64.b64encode(b"different key material").decode()
        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "public_key_digest does not match public_key_b64"))

    def test_registry_rejects_duplicate_pins(self):
        bundle, capsule, aperture = support.full_bundle()
        registry = support.pin_registry_for(bundle)
        registry["pinned_signers"].append(dict(registry["pinned_signers"][0]))
        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "duplicate pinned public key digest"))

    def test_registry_rejects_reserved_identity(self):
        bundle, capsule, aperture = support.full_bundle()
        registry = support.pin_registry_for(bundle)
        registry["pinned_signers"][0]["signer_identity"] = "wuci-ji-release"
        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "pinned signer wuci-ji-release identity is not independent"))

    def test_registry_requires_non_claims(self):
        bundle, capsule, aperture = support.full_bundle()
        registry = support.load_registry()
        registry["non_claims_acknowledged"] = ["not production cryptography"]
        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "pinned verification material invalid"))

    def test_committed_registry_is_valid_and_empty(self):
        registry = support.load_registry()
        pins, blockers = external_evidence.validate_pinned_material(registry)
        self.assertEqual(pins, {})
        self.assertEqual(blockers, [])

    def test_pinned_identity_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle()
        registry = support.pin_registry_for(bundle)
        bundle["pinned_attestations"][0]["signer_identity"] = "someone-else.example.org"
        bundle["pinned_attestations"][0]["statement_digest"] = external_evidence.attestation_statement_digest(
            bundle["pinned_attestations"][0]
        )
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "signer identity does not match pinned material"))


if __name__ == "__main__":
    unittest.main()
