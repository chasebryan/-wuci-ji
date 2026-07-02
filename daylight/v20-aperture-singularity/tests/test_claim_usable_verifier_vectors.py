import unittest

from tests import support_external_evidence as support


class ClaimUsableVerifierVectorTests(unittest.TestCase):
    def test_fewer_than_three_vectors_rejects(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "fewer than three verifier vector families"))

    def test_more_than_three_families_rejects(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{}, {}, {}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "exactly three verifier vector families required"))

    def test_duplicate_verifier_family_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{}, {"verifier_family": "alpha-independent"}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "duplicate verifier family: alpha-independent"))
        self.assertTrue(support.has_blocker(report, "fewer than three verifier vector families"))

    def test_output_digest_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{}, {"output_digest": support.sha256_text("divergent verifier output")}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "verifier vector output digest mismatch"))

    def test_input_capsule_digest_mismatch_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"input_capsule_digest": support.sha256_text("some other capsule")}, {}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(
            support.has_blocker(report, "input capsule digest does not match subject aperture capsule digest")
        )

    def test_fail_decision_rejects(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{"decision": "fail"}, {}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "verifier vector test-vector-1 decision is not pass"))

    def test_fixture_vector_rejects(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{"fixture": True}, {}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "verifier vector test-vector-1 is fixture evidence"))

    def test_not_claim_usable_vector_rejects(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{"claim_usable": False}, {}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "verifier vector test-vector-1 is not claim-usable"))

    def test_missing_attestation_reference_rejects(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["claim_usable_verifier_vectors"][0]["attestation_ref"] = "no-such-attestation"
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "attestation reference not found: no-such-attestation"))

    def test_tampered_vector_breaks_attestation_binding(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["claim_usable_verifier_vectors"][0]["verifier_implementation_digest"] = support.sha256_text("tampered impl")
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(
            support.has_blocker(report, "verifier vector test-vector-1 attestation subject digest does not match evidence item")
        )

    def test_duplicate_vector_id_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{}, {"vector_id": "test-vector-1"}, {}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "duplicate verifier vector id: test-vector-1"))

    def test_unsupported_decision_rejects_shape(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{"decision": "maybe"}, {}, {}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "decision must be pass or fail"))


if __name__ == "__main__":
    unittest.main()
