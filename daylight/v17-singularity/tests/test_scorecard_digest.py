from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from src import proof_atoms, registry, scorecard
from src.canonical_json import json_bytes


BASELINE_STATE = "daylight/v17-singularity/examples/state.baseline.json"


class ScorecardDigestTests(unittest.TestCase):
    def _card(self) -> tuple[dict, dict, dict, dict]:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        state = scorecard.load_state(BASELINE_STATE)
        return scorecard.build_scorecard(state, fields, atoms), state, fields, atoms

    def test_generated_scorecard_verifies(self) -> None:
        card, state, fields, atoms = self._card()
        scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_score_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["score_AM_plus"] += 1
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_omega_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["omega_decimal"] = "0"
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_debt_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["debt_uomega"] = 1
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_field_credit_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["fields"][0]["verified_credit"] -= 1
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_scorecard_digest_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["scorecard_digest"] = "0" * 64
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_registry_digest_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["proof_registry_digest"] = "0" * 64
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_state_digest_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["state_digest"] = "0" * 64
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_proof_atom_digest_is_rejected(self) -> None:
        card, state, fields, atoms = self._card()
        card["proof_atom_digest"] = "0" * 64
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)


if __name__ == "__main__":
    unittest.main()
