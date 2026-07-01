from __future__ import annotations

import unittest

from src.auth import authorization_tag
from src.envelope import _unsigned_header
from src.evidence import verify_daylight_v16_evidence
from src.kem_hybrid import combine_external_kem_material
from src.key_schedule import derive_key_schedule, nonce, plaintext_commitment

from tests.helpers import base_policy, clone, evidence_artifact, kem_material, recipient


class KeyScheduleTests(unittest.TestCase):
    def test_authorization_tag_changes_when_policy_changes(self) -> None:
        pkR = recipient()
        artifact = evidence_artifact()
        policy = base_policy()
        context = verify_daylight_v16_evidence(artifact, policy)
        first = authorization_tag(context, policy, pkR)
        changed_policy = clone(policy)
        changed_policy["min_daylight_claim_score_M"] = 998_900
        second = authorization_tag(context, changed_policy, pkR)
        self.assertNotEqual(first, second)

    def test_key_schedule_shapes_and_nonce(self) -> None:
        pkR = recipient()
        policy = base_policy()
        context = verify_daylight_v16_evidence(evidence_artifact(), policy)
        auth_tag = authorization_tag(context, policy, pkR)
        kem_bundle, hybrid_secret = combine_external_kem_material(pkR, kem_material(), auth_tag)
        h0 = _unsigned_header(
            pkR=pkR,
            policy=policy,
            context=context,
            kem_bundle=kem_bundle,
            sequence_number=7,
            sender_public_bundle=None,
        )
        schedule = derive_key_schedule(hybrid_secret, h0, auth_tag)
        self.assertEqual(len(schedule["transcript_digest"]), 128)
        self.assertEqual(len(schedule["K_aead"]), 32)
        self.assertEqual(len(schedule["N_base"]), 12)
        self.assertEqual(len(schedule["K_commit"]), 32)
        self.assertEqual(len(schedule["K_export"]), 32)
        self.assertEqual(len(nonce(schedule["N_base"], 7)), 12)

    def test_commitment_is_keyed(self) -> None:
        commitment_a = plaintext_commitment(b"a" * 32, b"secret", "ab" * 64)
        commitment_b = plaintext_commitment(b"b" * 32, b"secret", "ab" * 64)
        self.assertNotEqual(commitment_a, commitment_b)


if __name__ == "__main__":
    unittest.main()
