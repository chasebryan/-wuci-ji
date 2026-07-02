import unittest

from src import external_evidence
from tests import support_external_evidence as support


class IndependentRebuildReceiptTests(unittest.TestCase):
    def test_fewer_than_two_receipts_rejects(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "fewer than two independent rebuild receipts"))

    def test_duplicate_builder_identity_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{}, {"builder_identity": "test-rebuilder-1.example.org"}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(
            support.has_blocker(report, "rebuild receipts share the same builder identity: test-rebuilder-1.example.org")
        )

    def test_duplicate_environment_digest_rejects(self):
        shared = support.sha256_text("one shared environment")
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{"environment_digest": shared}, {"environment_digest": shared}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "rebuild receipts share the same environment digest"))

    def test_source_commit_mismatch_rejects(self):
        other_commit = support.sha256_text("some other commit")[:40]
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{"source_commit": other_commit}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "source commit does not match subject"))

    def test_release_tag_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{"release_tag": "some-other-release"}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "release tag does not match subject"))

    def test_artifact_sha256_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{"artifact_sha256": support.sha256_text("wrong artifact")}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "artifact SHA-256 does not match subject"))

    def test_artifact_sha3_512_mismatch_rejects(self):
        import hashlib

        wrong = hashlib.sha3_512(b"wrong artifact").hexdigest()
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{"artifact_sha3_512": wrong}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "artifact SHA3-512 does not match subject"))

    def test_artifact_size_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{"artifact_size": 4096}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "artifact size does not match subject"))

    def test_fixture_receipt_rejects(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{"fixture": True}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "rebuild receipt test-rebuild-1 is fixture evidence"))

    def test_not_claim_usable_receipt_rejects(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{"claim_usable": False}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "rebuild receipt test-rebuild-1 is not claim-usable"))

    def test_non_byte_reproducible_receipt_rejects(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{"byte_reproducible": False}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "does not claim a byte-reproducible rebuild"))

    def test_internal_builder_identity_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{"builder_identity": "local-lab"}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "builder identity is not independent: local-lab"))

    def test_non_external_independence_class_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{"builder_independence_class": "internal"}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "builder independence class must be external: internal"))

    def test_missing_attestation_reference_rejects(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["independent_rebuild_receipts"][0]["attestation_ref"] = "no-such-attestation"
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "attestation reference not found: no-such-attestation"))

    def test_missing_attestation_ref_field_rejects_shape(self):
        bundle, capsule, aperture = support.full_bundle()
        del bundle["independent_rebuild_receipts"][0]["attestation_ref"]
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "rebuild receipt 0 invalid"))
        self.assertTrue(support.has_blocker(report, "field set invalid"))

    def test_tampered_receipt_breaks_attestation_binding(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["independent_rebuild_receipts"][0]["environment_digest"] = support.sha256_text("tampered environment")
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(
            support.has_blocker(report, "rebuild receipt test-rebuild-1 attestation subject digest does not match evidence item")
        )

    def test_duplicate_receipt_id_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            receipt_overs=[{}, {"receipt_id": "test-rebuild-1", "environment_digest": support.sha256_text("env dup")}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "duplicate rebuild receipt id: test-rebuild-1"))
        self.assertTrue(support.has_blocker(report, "fewer than two independent rebuild receipts"))

    def test_receipt_binding_digest_excludes_attestation_ref(self):
        bundle, _capsule, _aperture = support.full_bundle()
        receipt = dict(bundle["independent_rebuild_receipts"][0])
        digest_before = external_evidence.rebuild_receipt_binding_digest(receipt)
        receipt["attestation_ref"] = "renamed-attestation"
        self.assertEqual(external_evidence.rebuild_receipt_binding_digest(receipt), digest_before)


if __name__ == "__main__":
    unittest.main()
