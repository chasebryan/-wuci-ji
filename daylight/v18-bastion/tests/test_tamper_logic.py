from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import binaric_vector, tamper_logic, transition_ledger


USER_VERIFICATION = "a" * 64


class TamperLogicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.subject = self.root / "subject.bin"
        self.subject.write_bytes(b"before")
        self.before = binaric_vector.measure_subject(subject_path="subject.bin", base_dir=self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _after(self, *, user: bool = False) -> dict:
        self.subject.write_bytes(b"after")
        return binaric_vector.measure_subject(
            subject_path="subject.bin",
            base_dir=self.root,
            previous_vector_digest=self.before["vector_digest"],
            user_verification_digest=USER_VERIFICATION if user else None,
        )

    def test_tamper_without_user_verification_rejects(self) -> None:
        after = self._after(user=False)
        result = tamper_logic.tamper_check(self.before, after)
        self.assertFalse(result["transition_allowed"])
        self.assertEqual(result["status"], "tamper_rejected")
        self.assertIn("transition record required", result["blockers"])

    def test_tamper_with_user_verification_records_pending_state(self) -> None:
        after = self._after(user=True)
        result = tamper_logic.tamper_check(self.before, after, legacy_digest_marker=True)
        self.assertTrue(result["transition_allowed"])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "tamper_user_verified_pending_acceptance")

    def test_tamper_with_user_verification_rejects_without_legacy_flag(self) -> None:
        after = self._after(user=True)
        result = tamper_logic.tamper_check(self.before, after)
        self.assertFalse(result["transition_allowed"])
        self.assertIn("transition record required", result["blockers"])

    def test_policy_change_without_user_verification_rejects(self) -> None:
        after = dict(self.before)
        after["previous_vector_digest"] = self.before["vector_digest"]
        after["policy_digest"] = "b" * 64
        after["vector_digest"] = binaric_vector.vector_digest(after)
        result = tamper_logic.tamper_check(self.before, after)
        self.assertFalse(result["transition_allowed"])
        self.assertIn("transition record required", result["blockers"])

    def test_scorecard_change_without_user_verification_rejects(self) -> None:
        after = dict(self.before)
        after["previous_vector_digest"] = self.before["vector_digest"]
        after["event_horizon_scorecard_digest"] = "c" * 64
        after["vector_digest"] = binaric_vector.vector_digest(after)
        result = tamper_logic.tamper_check(self.before, after)
        self.assertFalse(result["transition_allowed"])
        self.assertIn("transition record required", result["blockers"])

    def test_previous_vector_chain_break_rejects(self) -> None:
        after = self._after(user=True)
        after["previous_vector_digest"] = "d" * 64
        after["vector_digest"] = binaric_vector.vector_digest(after)
        result = tamper_logic.tamper_check(self.before, after)
        self.assertFalse(result["transition_allowed"])
        self.assertIn("transition record required", result["blockers"])

    def test_tamper_with_signed_transition_and_ledger_passes(self) -> None:
        after = self._after(user=False)
        transition = transition_ledger.propose_transition(self.before, after, reason="user-approved update")
        signed = transition_ledger.sign_transition(transition, "fixture-passphrase")
        records = [{"ledger_version": transition_ledger.LEDGER_VERSION, "genesis_head": transition_ledger.GENESIS_HEAD}]
        records.append(transition_ledger.make_entry(signed, transition_ledger.GENESIS_HEAD, 1))
        result = tamper_logic.tamper_check(
            self.before,
            after,
            transition=signed,
            ledger_records=records,
            passphrase="fixture-passphrase",
        )
        self.assertTrue(result["transition_allowed"])
        self.assertTrue(result["accepted"])
        self.assertEqual(result["status"], "tamper_transition_accepted")


if __name__ == "__main__":
    unittest.main()
