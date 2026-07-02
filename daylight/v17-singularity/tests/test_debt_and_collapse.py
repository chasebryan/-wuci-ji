from __future__ import annotations

import copy
import unittest

from src import proof_atoms, registry, scorecard


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"


class DebtAndCollapseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fields = registry.load_fields_registry()
        self.atoms = proof_atoms.load_proof_atom_registry()
        self.state = scorecard.load_state(CURRENT_STATE)

    def _score(self, state: dict) -> dict:
        return scorecard.build_scorecard(state, self.fields, self.atoms)

    def test_contradiction_debt_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["contradiction_debt"] = 1
        card = self._score(state)
        self.assertTrue(card["collapse"])
        self.assertEqual(card["score_AM_plus"], 0)

    def test_critical_break_debt_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["critical_break_debt"] = 1
        card = self._score(state)
        self.assertTrue(card["collapse"])
        self.assertEqual(card["score_AM_plus"], 0)

    def test_manual_score_detected_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["manual_score_detected"] = True
        self.assertEqual(self._score(state)["status"], "singularity_collapsed")

    def test_forged_scorecard_accepted_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["forged_scorecard_accepted"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_opens_without_policy_evidence_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["opens_without_policy_evidence"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_severe_boundary_overclaim_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["severe_boundary_overclaim"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_score_inflation_nonzero_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["score_inflation_M"] = 1
        card = self._score(state)
        self.assertTrue(card["collapse"])
        self.assertEqual(card["score_AM_plus"], 0)

    def test_nonzero_debt_lowers_but_does_not_collapse(self) -> None:
        clean = self._score(self.state)
        state = copy.deepcopy(self.state)
        state["debt_uomega"] = 1_000_000
        card = self._score(state)
        self.assertFalse(card["collapse"])
        self.assertLess(card["score_AM_plus"], clean["score_AM_plus"])


if __name__ == "__main__":
    unittest.main()
