from __future__ import annotations

import unittest

from src import downgrade, obligations
from tests.helpers import OBLIGATIONS


class DowngradeRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = obligations.load_registry(OBLIGATIONS)
        self.ceiling = [[name, value] for name, value in self._text(obligations.internal_ceiling_q_vector(self.registry))]

    @staticmethod
    def _text(q_vector):
        from src import scoring

        return [(name, scoring.fraction_text(value)) for name, value in q_vector]

    def test_recomputed_q_drop_emits_provisional(self) -> None:
        recomputed = [list(pair) for pair in self.ceiling]
        for pair in recomputed:
            if pair[0] == "q2_formalism_mathematical_density":
                pair[1] = "499/1000"
        result = downgrade.evaluate_downgrade(
            claimed_q=self.ceiling, recomputed_q=recomputed, claim_state="candidate"
        )
        self.assertEqual(result["claim_state"], "provisional")
        self.assertEqual(result["events"][0]["reason"], "recomputed_q_below_claimed_q")

    def test_self_signed_external_attestation_forces_rejected(self) -> None:
        result = downgrade.evaluate_downgrade(
            claimed_q=self.ceiling,
            recomputed_q=self.ceiling,
            claim_state="candidate",
            self_signed_external_attestation=True,
        )
        self.assertEqual(result["claim_state"], "rejected")
        self.assertTrue(any(e["reason"] == "self_signed_external_attestation" for e in result["events"]))

    def test_invalid_digest_forces_rejected(self) -> None:
        result = downgrade.evaluate_downgrade(
            claimed_q=self.ceiling,
            recomputed_q=self.ceiling,
            claim_state="candidate",
            scorecard_digest_valid=False,
        )
        self.assertEqual(result["claim_state"], "rejected")

    def test_unresolved_external_falsification_lowers_to_provisional(self) -> None:
        result = downgrade.evaluate_downgrade(
            claimed_q=self.ceiling,
            recomputed_q=self.ceiling,
            claim_state="candidate",
            unresolved_external_falsification=True,
        )
        self.assertEqual(result["claim_state"], "provisional")


if __name__ == "__main__":
    unittest.main()
