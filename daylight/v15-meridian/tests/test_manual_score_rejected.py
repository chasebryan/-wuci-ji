from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from src import daylight_harness
from tests import helpers


class ManualScoreRejectedTests(unittest.TestCase):
    def _seed_scorecard(self, root: Path):
        ledger_path, corpus_path = helpers.write_seed_inputs(root)
        scorecard, _, _ = daylight_harness.generate_scorecard(
            ledger_path=ledger_path, corpus_path=corpus_path, command="test"
        )
        return scorecard, ledger_path, corpus_path

    def test_manual_override_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scorecard, _, _ = self._seed_scorecard(Path(tmp))
        scorecard["manual_override"] = True
        with self.assertRaises(daylight_harness.HarnessError):
            daylight_harness.verify_scorecard(scorecard)

    def test_manual_edit_flag_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scorecard, _, _ = self._seed_scorecard(Path(tmp))
        scorecard["manual_edit_allowed"] = True
        with self.assertRaises(daylight_harness.HarnessError):
            daylight_harness.verify_scorecard(scorecard)

    def test_inflating_a_q_value_is_rejected_even_when_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scorecard, _, _ = self._seed_scorecard(Path(tmp))
        # Inflate q2 to a perfect 1/1, fix its term and the totals, and reseal the
        # digest. The closed-obligation set still only supports 999/1000, so the
        # re-derivation rejects the manual score.
        tampered = copy.deepcopy(scorecard)
        for pair in tampered["q_vector"]:
            if pair[0] == "q2_formalism_mathematical_density":
                pair[1] = "1/1"
        for term in tampered["term_contributions_M"]:
            if term["q_id"] == "q2_formalism_mathematical_density":
                term["q_value"] = "1/1"
                term["contribution_M"] = 110000
        tampered["final_score_M"] = 999010
        tampered["scorecard_digest"] = daylight_harness.scorecard_digest(tampered)
        with self.assertRaises(daylight_harness.HarnessError):
            daylight_harness.verify_scorecard(tampered)

    def test_fabricated_external_credit_is_rejected_against_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scorecard, ledger_path, corpus_path = self._seed_scorecard(Path(tmp))
            tampered = copy.deepcopy(scorecard)
            tampered["closed_obligations"].append(
                {
                    "obligation_id": "o.q11.external_falsification_program",
                    "q_id": "q11_external_falsification_readiness",
                    "scope": "external",
                    "weight": 10,
                    "evidence_kind": "ledger",
                    "evidence_class": "external_attestation",
                    "evidence_digest": "fabricated",
                }
            )
            tampered["closed_obligations"].sort(key=lambda row: row["obligation_id"])
            for pair in tampered["q_vector"]:
                if pair[0] == "q11_external_falsification_readiness":
                    pair[1] = "1/1"
            for term in tampered["term_contributions_M"]:
                if term["q_id"] == "q11_external_falsification_readiness":
                    term["q_value"] = "1/1"
                    term["contribution_M"] = 20000
            tampered["final_score_M"] = 999100
            tampered["residue_to_perfect_M"] = 900
            tampered["unified_score_rational"] = "9991/10000"
            tampered["unified_score_decimal"] = "0.9991"
            tampered["scorecard_digest"] = daylight_harness.scorecard_digest(tampered)
            with self.assertRaises(daylight_harness.HarnessError):
                daylight_harness.verify_scorecard(
                    tampered, ledger_path=ledger_path, corpus_path=corpus_path
                )

    def test_registry_pin_rejects_tampered_obligations_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scorecard, _, _ = self._seed_scorecard(Path(tmp))
        scorecard["obligations_digest"] = "0" * 64
        scorecard["scorecard_digest"] = daylight_harness.scorecard_digest(scorecard)
        with self.assertRaises(daylight_harness.HarnessError):
            daylight_harness.verify_scorecard(scorecard)


if __name__ == "__main__":
    unittest.main()
