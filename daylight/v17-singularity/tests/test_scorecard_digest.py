from __future__ import annotations

import copy
import unittest

from src import proof_atoms, registry, scorecard


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"
FIXTURE_STATE = "daylight/v17-singularity/examples/state.declaration-fixture.json"


class ScorecardDigestTests(unittest.TestCase):
    def _card(self, state_path: str = CURRENT_STATE) -> tuple[dict, dict, dict, dict]:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        state = scorecard.load_state(state_path)
        return scorecard.build_scorecard(state, fields, atoms), state, fields, atoms

    def _assert_rejects(self, card: dict, state: dict, fields: dict, atoms: dict) -> None:
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_generated_current_scorecard_verifies(self) -> None:
        card, state, fields, atoms = self._card()
        scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_generated_fixture_scorecard_verifies_as_scorecard(self) -> None:
        card, state, fields, atoms = self._card(FIXTURE_STATE)
        self.assertEqual(card["score_AM_plus"], 999_999_999)
        self.assertFalse(card["claim_usable"])
        scorecard.verify_scorecard_object(card, state, fields, atoms)

    def test_edited_score_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["score_AM_plus"] += 1
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        self._assert_rejects(card, state, fields, atoms)

    def test_edited_omega_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["omega_eff_decimal"] = "0"
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        self._assert_rejects(card, state, fields, atoms)

    def test_edited_field_credit_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["fields"][0]["verified_credit"] -= 1
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        self._assert_rejects(card, state, fields, atoms)

    def test_edited_debt_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["debt_uomega"] = 1
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        self._assert_rejects(card, state, fields, atoms)

    def test_edited_fields_digest_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["fields_digest"] = "0" * 64
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        self._assert_rejects(card, state, fields, atoms)

    def test_edited_proof_atom_digest_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["proof_atoms_digest"] = "0" * 64
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        self._assert_rejects(card, state, fields, atoms)

    def test_edited_state_digest_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["state_digest"] = "0" * 64
        card["scorecard_digest"] = scorecard.scorecard_digest(card)
        self._assert_rejects(card, state, fields, atoms)

    def test_edited_scorecard_digest_fails(self) -> None:
        card, state, fields, atoms = self._card()
        card["scorecard_digest"] = "0" * 64
        self._assert_rejects(card, state, fields, atoms)


if __name__ == "__main__":
    unittest.main()
