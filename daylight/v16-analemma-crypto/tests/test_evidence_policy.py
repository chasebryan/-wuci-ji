from __future__ import annotations

import unittest

from src.errors import D16AWEError
from src.evidence import evidence_tag, verify_daylight_v16_evidence

from tests.helpers import base_policy, clone, evidence_artifact


class EvidencePolicyTests(unittest.TestCase):
    def test_verifies_policy_aware_evidence(self) -> None:
        context = verify_daylight_v16_evidence(evidence_artifact(), base_policy())
        self.assertEqual(context["score_inflation_M"], 0)
        self.assertEqual(context["proof_mass"], 620_000)
        self.assertEqual(context["analemma_score_A"], 1_240_000)
        self.assertEqual(len(evidence_tag(context)), 128)

    def test_rejects_score_inflation(self) -> None:
        artifact = evidence_artifact()
        artifact["context"]["score_inflation_M"] = 1
        with self.assertRaisesRegex(D16AWEError, "score_inflation"):
            verify_daylight_v16_evidence(artifact, base_policy())

    def test_rejects_missing_required_obligation(self) -> None:
        artifact = evidence_artifact()
        artifact["closed_obligations"] = ["o.solstice.scorecard"]
        with self.assertRaisesRegex(D16AWEError, "required obligations"):
            verify_daylight_v16_evidence(artifact, base_policy())

    def test_rejects_missing_required_proof_unit(self) -> None:
        artifact = evidence_artifact()
        artifact["closed_proof_units"] = ["u.solstice.scorecard"]
        with self.assertRaisesRegex(D16AWEError, "required proof units"):
            verify_daylight_v16_evidence(artifact, base_policy())

    def test_rejects_runtime_and_pq_overclaim_policy(self) -> None:
        policy = clone(base_policy())
        policy["require_runtime_containment"] = True
        with self.assertRaisesRegex(D16AWEError, "runtime containment"):
            verify_daylight_v16_evidence(evidence_artifact(), policy)

        policy = clone(base_policy())
        policy["require_whole_system_pq_safety"] = True
        with self.assertRaisesRegex(D16AWEError, "PQ safety"):
            verify_daylight_v16_evidence(evidence_artifact(), policy)

    def test_rejects_digest_mismatch(self) -> None:
        policy = clone(base_policy())
        policy["required_solstice_scorecard_digest"] = "00" * 64
        with self.assertRaisesRegex(D16AWEError, "scorecard_digest"):
            verify_daylight_v16_evidence(evidence_artifact(), policy)


if __name__ == "__main__":
    unittest.main()
