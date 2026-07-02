import unittest

from src import external_evidence
from src import firewall_profile
from tests import support_external_evidence as support


class FirewallProfileReviewTests(unittest.TestCase):
    def test_internal_reviewer_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            review_overs=[{"reviewer_identity": "internal-review-team", "reviewer_independence_class": "internal"}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "reviewer identity is not independent: internal-review-team"))
        self.assertTrue(support.has_blocker(report, "reviewer independence class must be external: internal"))

    def test_critical_finding_rejects(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"finding_level": "critical"}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "reports blocking finding level: critical"))

    def test_contradiction_finding_rejects(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"finding_level": "contradiction"}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "reports blocking finding level: contradiction"))

    def test_minor_finding_is_not_a_blocking_level(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"finding_level": "minor"}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertFalse(support.has_blocker(report, "reports blocking finding level"))

    def test_wrong_scope_rejects(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"review_scope": "entire-system-review"}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(
            support.has_blocker(report, "scope must be aperture-public-artifact-firewall-profile: entire-system-review")
        )

    def test_stale_profile_digest_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            review_overs=[{"profile_digest": support.sha256_text("stale profile")}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "does not bind to the current firewall profile digest"))

    def test_stale_rules_digest_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            review_overs=[{"reviewed_rules_digest": support.sha256_text("stale rules")}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "does not bind to the current firewall rules digest"))

    def test_stale_negative_cases_digest_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            review_overs=[{"negative_cases_digest": support.sha256_text("stale cases")}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "does not bind to the negative case matrix digest"))

    def test_fixture_review_rejects(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"fixture": True}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "firewall review test-firewall-review-1 is fixture evidence"))

    def test_not_claim_usable_review_rejects(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"claim_usable": False}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "firewall review test-firewall-review-1 is not claim-usable"))

    def test_no_reviews_rejects(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "no external firewall profile review supplied"))

    def test_unsupported_finding_level_rejects_shape(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"finding_level": "excellent"}])
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "finding_level unsupported: excellent"))
        self.assertTrue(support.has_blocker(report, "no external firewall profile review supplied"))

    def test_duplicate_review_id_rejects(self):
        bundle, capsule, aperture = support.full_bundle(
            review_overs=[{}, {"review_id": "test-firewall-review-1"}],
        )
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(support.has_blocker(report, "duplicate firewall review id: test-firewall-review-1"))

    def test_expected_digests_are_deterministic_and_current(self):
        first = external_evidence.firewall_rules_digest()
        second = external_evidence.firewall_rules_digest()
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        cases = external_evidence.firewall_negative_cases_digest()
        self.assertRegex(cases, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, cases)
        review = support.build_review()
        self.assertEqual(review["profile_digest"], firewall_profile.profile_digest())

    def test_tampered_review_breaks_attestation_binding(self):
        bundle, capsule, aperture = support.full_bundle()
        bundle["firewall_profile_reviews"][0]["finding_level"] = "minor"
        support.reseal(bundle)
        report = support.evaluate(bundle, capsule, aperture)
        self.assertTrue(
            support.has_blocker(
                report, "firewall review test-firewall-review-1 attestation subject digest does not match evidence item"
            )
        )


if __name__ == "__main__":
    unittest.main()
