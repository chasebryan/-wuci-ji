from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from src import binaric_vector, tamper_logic, transition_ledger


PASSPHRASE = "daylight-v18-fixture-passphrase"


class TransitionLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.subject = self.root / "subject.bin"
        self.subject.write_bytes(b"before")
        self.before = binaric_vector.measure_subject(subject_path="subject.bin", base_dir=self.root)
        self.subject.write_bytes(b"after")
        self.after = binaric_vector.measure_subject(
            subject_path="subject.bin",
            base_dir=self.root,
            previous_vector_digest=self.before["vector_digest"],
        )
        self.transition = transition_ledger.propose_transition(self.before, self.after, reason="user-approved update")
        self.signed = transition_ledger.sign_transition(self.transition, PASSPHRASE)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _ledger_records(self) -> list[dict]:
        genesis = {"ledger_version": transition_ledger.LEDGER_VERSION, "genesis_head": transition_ledger.GENESIS_HEAD}
        return [genesis, transition_ledger.make_entry(self.signed, transition_ledger.GENESIS_HEAD, 1)]

    def test_valid_transition_verifies(self) -> None:
        result = transition_ledger.verify_transition(self.before, self.after, self.signed, passphrase=PASSPHRASE)
        self.assertTrue(result["transition_valid"])

    def test_changed_fields_must_equal_actual_diff(self) -> None:
        transition = copy.deepcopy(self.transition)
        transition["changed_fields"] = sorted(transition["changed_fields"] + ["policy_digest"])
        signed = transition_ledger.sign_transition(transition, PASSPHRASE)
        result = transition_ledger.verify_transition(self.before, self.after, signed, passphrase=PASSPHRASE)
        self.assertFalse(result["transition_valid"])
        self.assertIn("changed_fields does not match actual diff", result["blockers"])

    def test_missing_user_proof_rejects(self) -> None:
        result = transition_ledger.verify_transition(self.before, self.after, self.transition, passphrase=PASSPHRASE)
        self.assertFalse(result["transition_valid"])
        self.assertTrue(any("missing user_proof" in blocker for blocker in result["blockers"]))

    def test_invalid_user_proof_rejects(self) -> None:
        signed = dict(self.signed)
        signed["user_proof"] = "0" * 64
        result = transition_ledger.verify_transition(self.before, self.after, signed, passphrase=PASSPHRASE)
        self.assertFalse(result["transition_valid"])
        self.assertIn("user proof invalid", result["blockers"])

    def test_accepted_false_rejects(self) -> None:
        transition = dict(self.transition)
        transition["accepted"] = False
        signed = transition_ledger.sign_transition(transition, PASSPHRASE)
        result = transition_ledger.verify_transition(self.before, self.after, signed, passphrase=PASSPHRASE)
        self.assertFalse(result["transition_valid"])
        self.assertIn("accepted must be true", result["blockers"])

    def test_before_vector_digest_mismatch_rejects(self) -> None:
        transition = dict(self.transition)
        transition["before_vector_digest"] = "c" * 64
        signed = transition_ledger.sign_transition(transition, PASSPHRASE)
        result = transition_ledger.verify_transition(self.before, self.after, signed, passphrase=PASSPHRASE)
        self.assertFalse(result["transition_valid"])
        self.assertIn("before_vector_digest mismatch", result["blockers"])

    def test_after_vector_digest_mismatch_rejects(self) -> None:
        transition = dict(self.transition)
        transition["after_vector_digest"] = "d" * 64
        signed = transition_ledger.sign_transition(transition, PASSPHRASE)
        result = transition_ledger.verify_transition(self.before, self.after, signed, passphrase=PASSPHRASE)
        self.assertFalse(result["transition_valid"])
        self.assertIn("after_vector_digest mismatch", result["blockers"])

    def test_policy_digest_change_without_transition_rejects(self) -> None:
        after = copy.deepcopy(self.before)
        after["previous_vector_digest"] = self.before["vector_digest"]
        after["policy_digest"] = "b" * 64
        after["vector_digest"] = binaric_vector.vector_digest(after)
        result = tamper_logic.tamper_check(self.before, after)
        self.assertFalse(result["transition_allowed"])
        self.assertIn("transition record required", result["blockers"])

    def test_scorecard_digest_change_without_transition_rejects(self) -> None:
        after = copy.deepcopy(self.before)
        after["previous_vector_digest"] = self.before["vector_digest"]
        after["event_horizon_scorecard_digest"] = "c" * 64
        after["vector_digest"] = binaric_vector.vector_digest(after)
        result = tamper_logic.tamper_check(self.before, after)
        self.assertFalse(result["transition_allowed"])
        self.assertIn("transition record required", result["blockers"])

    def test_previous_vector_chain_break_rejects_even_with_user_proof(self) -> None:
        after = copy.deepcopy(self.after)
        after["previous_vector_digest"] = "d" * 64
        after["vector_digest"] = binaric_vector.vector_digest(after)
        transition = transition_ledger.propose_transition(self.before, after, reason="user-approved update")
        signed = transition_ledger.sign_transition(transition, PASSPHRASE)
        result = transition_ledger.verify_transition(self.before, after, signed, passphrase=PASSPHRASE)
        self.assertFalse(result["transition_valid"])
        self.assertIn("previous_vector_digest chain break", result["blockers"])

    def test_ledger_genesis_verifies(self) -> None:
        result = transition_ledger.verify_ledger_records([
            {"ledger_version": transition_ledger.LEDGER_VERSION, "genesis_head": transition_ledger.GENESIS_HEAD}
        ])
        self.assertTrue(result["ledger_valid"])
        self.assertEqual(result["head"], transition_ledger.GENESIS_HEAD)

    def test_ledger_append_verifies(self) -> None:
        result = transition_ledger.verify_ledger_records(self._ledger_records())
        self.assertTrue(result["ledger_valid"])

    def test_ledger_previous_head_mismatch_rejects(self) -> None:
        records = self._ledger_records()
        records[1]["previous_head"] = "0" * 64
        result = transition_ledger.verify_ledger_records(records)
        self.assertFalse(result["ledger_valid"])
        self.assertIn("ledger previous_head mismatch", result["blockers"][0])

    def test_duplicate_entry_id_rejects(self) -> None:
        records = self._ledger_records()
        second = transition_ledger.make_entry(self.signed, records[1]["head"], 1)
        records.append(second)
        result = transition_ledger.verify_ledger_records(records)
        self.assertFalse(result["ledger_valid"])
        self.assertIn("duplicate entry_id", result["blockers"][0])

    def test_duplicate_transition_digest_rejects(self) -> None:
        records = self._ledger_records()
        second = transition_ledger.make_entry(self.signed, records[1]["head"], 2)
        records.append(second)
        result = transition_ledger.verify_ledger_records(records)
        self.assertFalse(result["ledger_valid"])
        self.assertIn("duplicate transition_digest", result["blockers"][0])


if __name__ == "__main__":
    unittest.main()
