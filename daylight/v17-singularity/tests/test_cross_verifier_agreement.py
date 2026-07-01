from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from src import agreement, proof_atoms, registry, scorecard


ROOT = Path(__file__).resolve().parents[1]
BASELINE_STATE = ROOT / "examples" / "state.baseline.json"
CURRENT_SCORECARD = ROOT / "examples" / "current-scorecard.v17.json"


class CrossVerifierAgreementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = scorecard.load_state(BASELINE_STATE)
        self.fields = registry.load_fields_registry()
        self.atoms = proof_atoms.load_proof_atom_registry()
        self.card = scorecard.build_scorecard(self.state, self.fields, self.atoms)

    def _check(self, card: dict) -> dict:
        return agreement.check_cross_verifier_agreement(card, self.state, self.fields, self.atoms)

    def _redigest(self, card: dict) -> dict:
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        return card

    def _disagreeing_keys(self, result: dict) -> set[str]:
        return {row["key"] for row in result["disagreements"]}

    def test_clean_baseline_agrees(self) -> None:
        result = self._check(self.card)
        self.assertTrue(result["passed"])
        self.assertEqual(result["disagreements"], [])
        self.assertEqual(result["claimed_digest"], result["independent_digest"])

    def test_committed_current_scorecard_agrees(self) -> None:
        card = json.loads(CURRENT_SCORECARD.read_text(encoding="utf-8"))
        result = self._check(card)
        self.assertTrue(result["passed"], msg=result["disagreements"])

    def test_score_edit_is_caught_even_after_redigest(self) -> None:
        # A tampered score with a refreshed digest defeats digest-only checks;
        # only the evidence re-derivation still disagrees on the number itself.
        card = copy.deepcopy(self.card)
        card["score_AM_plus"] = card["score_AM_plus"] + 1
        self._redigest(card)
        result = self._check(card)
        self.assertFalse(result["passed"])
        self.assertIn("score_AM_plus", self._disagreeing_keys(result))
        self.assertNotIn("scorecard_digest", self._disagreeing_keys(result))

    def test_flipped_threshold_pass_is_caught_by_field_digest(self) -> None:
        card = copy.deepcopy(self.card)
        card["fields"][0]["threshold_pass"] = not card["fields"][0]["threshold_pass"]
        self._redigest(card)
        result = self._check(card)
        self.assertFalse(result["passed"])
        self.assertEqual(self._disagreeing_keys(result), {"field_closures_digest"})

    def test_inflated_field_credit_is_caught(self) -> None:
        card = copy.deepcopy(self.card)
        card["fields"][1]["verified_credit"] = card["fields"][1]["possible_credit"]
        self._redigest(card)
        result = self._check(card)
        self.assertFalse(result["passed"])
        self.assertIn("field_closures_digest", self._disagreeing_keys(result))

    def test_swapped_registry_digest_is_caught(self) -> None:
        card = copy.deepcopy(self.card)
        card["proof_registry_digest"] = "0" * 64
        self._redigest(card)
        result = self._check(card)
        self.assertFalse(result["passed"])
        self.assertEqual(self._disagreeing_keys(result), {"proof_registry_digest"})

    def test_body_edit_without_redigest_breaks_digest(self) -> None:
        card = copy.deepcopy(self.card)
        card["omega_decimal"] = "999"
        # No re-digest: the stored digest no longer matches the body.
        result = self._check(card)
        self.assertFalse(result["passed"])
        keys = self._disagreeing_keys(result)
        self.assertIn("omega_decimal", keys)
        self.assertIn("scorecard_digest", keys)


if __name__ == "__main__":
    unittest.main()
