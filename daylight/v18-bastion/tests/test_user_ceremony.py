from __future__ import annotations

import copy
import unittest

from src import transition_ledger, user_ceremony


BEFORE = "a" * 64
AFTER = "b" * 64
CHANGED = ["file_sha256", "file_sha3_512", "section_digests"]


class UserCeremonyTests(unittest.TestCase):
    def _transition(self) -> dict:
        return {
            "transition_version": transition_ledger.TRANSITION_VERSION,
            "transition_id": "transition-0001",
            "before_vector_digest": BEFORE,
            "after_vector_digest": AFTER,
            "changed_fields": CHANGED,
            "reason": "user-approved update",
            "user_ceremony": user_ceremony.make_ceremony(BEFORE, AFTER, CHANGED, "user-approved update"),
            "accepted": True,
            "boundary": "research local user authorization proof; not production identity",
        }

    def test_deterministic_challenge_digest(self) -> None:
        one = user_ceremony.challenge_digest(BEFORE, AFTER, CHANGED, "user-approved update")
        two = user_ceremony.challenge_digest(BEFORE, AFTER, CHANGED, "user-approved update")
        self.assertEqual(one, two)

    def test_passphrase_proof_verifies(self) -> None:
        signed = user_ceremony.sign_transition(self._transition(), "passphrase")
        self.assertTrue(user_ceremony.verify_user_proof(signed, "passphrase"))

    def test_wrong_passphrase_fails(self) -> None:
        signed = user_ceremony.sign_transition(self._transition(), "passphrase")
        self.assertFalse(user_ceremony.verify_user_proof(signed, "wrong"))

    def test_modified_transition_fails_proof(self) -> None:
        signed = user_ceremony.sign_transition(self._transition(), "passphrase")
        signed["reason"] = "changed"
        self.assertFalse(user_ceremony.verify_user_proof(signed, "passphrase"))

    def test_modified_before_digest_fails_proof(self) -> None:
        signed = user_ceremony.sign_transition(self._transition(), "passphrase")
        signed["before_vector_digest"] = "c" * 64
        self.assertFalse(user_ceremony.verify_user_proof(signed, "passphrase"))

    def test_modified_after_digest_fails_proof(self) -> None:
        signed = user_ceremony.sign_transition(self._transition(), "passphrase")
        signed["after_vector_digest"] = "d" * 64
        self.assertFalse(user_ceremony.verify_user_proof(signed, "passphrase"))

    def test_missing_passphrase_env_fails(self) -> None:
        with self.assertRaises(user_ceremony.UserCeremonyError):
            user_ceremony.passphrase_from_env("DAYLIGHT_BASTION_TEST_MISSING")

    def test_json_float_in_ceremony_rejects(self) -> None:
        ceremony = copy.deepcopy(self._transition()["user_ceremony"])
        ceremony["iterations"] = 200000.0
        with self.assertRaises(ValueError):
            user_ceremony.validate_ceremony(ceremony)


if __name__ == "__main__":
    unittest.main()
